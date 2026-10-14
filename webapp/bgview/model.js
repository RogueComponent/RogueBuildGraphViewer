/* bgview/model.js -- graph model + tag dataflow.
 *
 * Port of bgview/model.py. Builds Graph/Node from the evaluator's flat,
 * post-Expand/ForEach/Include execution-order trace (V23). Two things it has
 * to get exactly right:
 *
 *   V2/R7: every node IMPLICITLY produces `#<NodeName>`, and an explicit
 *   @Produces entry equal to the node name is de-duplicated rather than
 *   doubled. Missing this is the single largest false-positive source in the
 *   whole tool -- a plain reference to a node's default output (Epic's
 *   `#Create Three Named Outputs` exists ONLY as an implicit output) would
 *   otherwise look like a dangling, unproduced tag.
 *
 *   R2/R3 polarity: schema.isTagOutput decides PRODUCES; every other
 *   attribute is scanned for `#Name` tokens, each CONSUMED. Applied
 *   uniformly, with no per-task-name table anywhere in this file --
 *   schema.js already answered the polarity question straight from the xsd.
 *
 * `Node/@Requires` does double duty: it declares a dependency AND consumes
 * any `#tag` in it (R23 -- requiring a node by NAME really does carry its
 * output across the agent boundary; R24 disproves "cross-agent Requires is
 * broken" entirely). `Node/@After` is ordering-only and carries no files.
 *
 * Names are matched case-INSENSITIVELY but STORED with the source's own
 * casing, so every lookup folds at compare time rather than normalising on
 * the way in.
 */
"use strict";

import { isTag, splitList } from "./lexer.js";

export class Node {
  constructor(o) {
    this.name = o.name;
    this.agent = o.agent;
    this.line = o.line;
    this.file = o.file;
    this.produces = o.produces;   // Set: explicit @Produces + implicit '#'+name
    this.creates = o.creates;     // Set: tags made by task TagList attrs in this node
    this.consumes = o.consumes;   // Set: '#tags' referenced by non-TagList attrs
    this.requires = o.requires;   // raw @Requires tokens
    this.after = o.after;         // raw @After tokens -- order-only, no file transfer
    this.endLine = o.endLine || 0;
  }
  get lineSpan() { return [this.line, Math.max(this.endLine, this.line)]; }
}

export class Graph {
  constructor(o) {
    this.nodes = o.nodes;                   // Map name -> Node
    this.agents = o.agents;                 // Map agent -> [node names]
    this.aggregates = o.aggregates;         // Map name -> raw @Requires tokens
    this.labels = o.labels;                 // Map name -> raw @Requires tokens
    this.tagProvenance = o.tagProvenance;   // Map tag -> [Contribution]
  }

  /** V2/R8: resolve a bare Requires/After token to the node name(s) it means.
   *  A `#`-prefixed name resolves to that tag's producers. A bare name
   *  resolves node -> aggregate -> agent, in that EXACT precedence: the first
   *  kind that matches wins outright, even if a later kind would also match
   *  (they are separate identifier spaces in the engine). */
  resolveRef(name) {
    if (isTag(name)) return this.producersOf(name);
    return this._resolveBare(name, new Set());
  }

  _resolveBare(name, seen) {
    // No trim(): names are matched case-insensitively but otherwise EXACTLY.
    // Measured: Tests/DDCVerify.xml has a node whose expanded name really is
    // "Compile Win64 " -- trailing space and all -- because ProjectName
    // collides with a built-in. That space is part of its identity; trimming
    // would make the name unresolvable.
    const folded = name.toLowerCase();
    // Empty token, or an aggregate-requires-aggregate cycle: never guess,
    // never recurse forever -- denote nothing.
    if (!folded || seen.has(folded)) return [];
    const seen2 = new Set(seen); seen2.add(folded);

    for (const nodeName of this.nodes.keys()) {
      if (nodeName.toLowerCase() === folded) return [nodeName];
    }
    for (const [aggName, tokens] of this.aggregates) {
      if (aggName.toLowerCase() === folded) {
        const out = [];
        for (const token of tokens) {
          for (const r of (isTag(token) ? this.producersOf(token) : this._resolveBare(token, seen2))) {
            if (!out.includes(r)) out.push(r);
          }
        }
        return out;
      }
    }
    for (const [agentName, nodeNames] of this.agents) {
      if (agentName.toLowerCase() === folded) return [...nodeNames];
    }
    return [];
  }

  /** Node names producing `tag`, counting implicit default outputs (V2/R7). */
  producersOf(tag) {
    const folded = tag.toLowerCase();
    const out = [];
    for (const [name, node] of this.nodes) {
      for (const p of node.produces) {
        if (p.toLowerCase() === folded) { out.push(name); break; }
      }
    }
    return out;
  }
}

/** V2: an explicit @Produces entry equal to the node name is de-duplicated.
 *  Whichever spelling is offered FIRST wins, and callers control that by call
 *  order -- the implicit '#'+name is always added before explicit tokens, so
 *  the node's own Name= casing wins any collision. */
function addDeduped(target, foldedSeen, candidate) {
  const folded = candidate.toLowerCase();
  if (!foldedSeen.has(folded)) { foldedSeen.add(folded); target.add(candidate); }
}

/** Merge tokens into bucket[name], deduped, preserving first-seen order.
 *
 * Aggregate/Label declarations sharing a Name legitimately recur across
 * mutually-exclusive Do/Switch branches, and this tool walks EVERY branch --
 * so a second same-named declaration must MERGE, not replace. Measured:
 * BuildEditorAndTools.xml declares <Label Name="Win64"> twice, and a plain
 * assign would let the second (incidentally empty) one truncate the first's
 * Requires to nothing.
 */
function mergeRequires(bucket, name, tokens) {
  if (!bucket.has(name)) bucket.set(name, []);
  const existing = bucket.get(name);
  for (const token of tokens) if (!existing.includes(token)) existing.push(token);
}

/** D5 evidence: the raw Files/FileLists value a producing task read from.
 *  Files takes priority; FileLists is unused across the whole 19-file corpus
 *  but CONTRACTS.md names both, so it falls back rather than dropping it. */
function sourceSpec(attrs) {
  return attrs.get("Files") || attrs.get("FileLists") || "";
}

/** Build the graph + tag dataflow from ev.resolved in one linear pass.
 *
 * A <Node>'s own entry always precedes every entry for elements inside its
 * body (the evaluator emits the Node leaf before walking children), so
 * `nodes` already holds the owning Node when a body element is reached.
 */
export function build(ev, schema) {
  const nodes = new Map();
  const agents = new Map();
  const aggregates = new Map();
  const labels = new Map();
  const tagProvenance = new Map();

  for (const r of ev.resolved) {
    const tag = r.elem.tag;

    if (tag === "Agent") {
      // Seed even a node-less agent: an empty swimlane is still a real
      // agent, and Graph.agents stays an honest inventory.
      const name = r.attrs.get("Name") || "";
      if (!agents.has(name)) agents.set(name, []);

    } else if (tag === "Aggregate") {
      mergeRequires(aggregates, r.attrs.get("Name") || "", splitList(r.attrs.get("Requires") || ""));

    } else if (tag === "Label") {
      // Label/@Name is optional; a nameless label can never be the target of
      // a bare-name reference, so there is nothing to key it under.
      const name = r.attrs.get("Name") || "";
      if (name) mergeRequires(labels, name, splitList(r.attrs.get("Requires") || ""));

    } else if (tag === "Node") {
      const nodeName = r.attrs.get("Name") || "";
      const produces = new Set();
      const foldedSeen = new Set();
      addDeduped(produces, foldedSeen, "#" + nodeName);   // V2/R7, added FIRST
      for (const produced of splitList(r.attrs.get("Produces") || "")) {
        addDeduped(produces, foldedSeen, produced);
      }
      const requires = splitList(r.attrs.get("Requires") || "");
      const after = splitList(r.attrs.get("After") || "");

      // Ceiling, same as the Python's: last-declaration-wins on a duplicate
      // Node Name. ForEach-substituted names keep real scripts collision
      // free, and a genuine duplicate is invalid input -- the engine needs
      // unique node identities to schedule at all. Unlike Aggregate/Label,
      // which legitimately reuse a Name across exclusive branches.
      nodes.set(nodeName, new Node({
        name: nodeName,
        agent: r.agent || "",
        line: r.elem.line,
        file: r.elem.file,
        produces,
        creates: new Set(),
        consumes: new Set(requires.filter(isTag)),   // R23: Requires consumes its own #tags
        requires,
        after,                                        // order-only: NOT scanned for consumption
        endLine: r.elem.endLine,
      }));
      const agentKey = r.agent || "";
      if (!agents.has(agentKey)) agents.set(agentKey, []);
      agents.get(agentKey).push(nodeName);

    } else if (r.node) {
      // A task -- or any other element, Do/Switch/Case/ForEach wrappers
      // included, deliberately NOT filtered by tag name so no per-task table
      // ever creeps in here -- inside a Node body.
      const node = nodes.get(r.node);
      if (!node) continue;
      for (const [attr, value] of r.attrs) {
        if (schema.isTagOutput(tag, attr)) {
          const producedTags = splitList(value);
          if (!producedTags.length) continue;
          const contribution = {
            sourceSpec: sourceSpec(r.attrs),
            filter: r.attrs.get("Filter") || "",
            except: r.attrs.get("Except") || "",
            line: r.elem.line,
          };
          for (const producedTag of producedTags) {
            node.creates.add(producedTag);
            if (!tagProvenance.has(producedTag)) tagProvenance.set(producedTag, []);
            tagProvenance.get(producedTag).push(contribution);
          }
        } else {
          for (const token of splitList(value)) if (isTag(token)) node.consumes.add(token);
        }
      }
    }
    // else: outside any <Node> body -- the produce/consume rule is about a
    // node's OWN dataflow; there is nothing here to attribute it to.
  }

  return [new Graph({ nodes, agents, aggregates, labels, tagProvenance }), []];
}

export class UnknownTarget extends Error {
  constructor(name) { super(name); this.name = "UnknownTarget"; }
}

/** Node names reachable from `targets`, following Requires and After.
 *  Throws UnknownTarget rather than returning empty -- V28: a typo'd target
 *  must not silently produce an empty graph that looks like success. */
export function closure(graph, targets) {
  const seen = new Set();
  const stack = [];
  for (const t of targets) {
    const resolved = graph.resolveRef(t);
    if (!resolved.length) throw new UnknownTarget(t);
    stack.push(...resolved);
  }
  while (stack.length) {
    const name = stack.pop();
    if (seen.has(name) || !graph.nodes.has(name)) continue;
    seen.add(name);
    const node = graph.nodes.get(name);
    for (const token of node.requires.concat(node.after)) stack.push(...graph.resolveRef(token));
  }
  return seen;
}
