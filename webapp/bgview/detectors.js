/* bgview/detectors.js -- D2..D20. Port of bgview/detectors.py.
 *
 * Every detector here encodes a measured decision, not a hunch, and the
 * comments say which. The recurring discipline is V20's: when a proof cannot
 * be completed, ABSTAIN. A false positive costs more than a miss, because the
 * whole pitch of this tool is that the engine under-reports -- a noisy
 * replacement is worse than the silence it was meant to fix.
 */
"use strict";

import { UNKNOWN, Opt, classify, evaluate as algEvaluate } from "./algebra.js";
import { CondParseError, parse as parseCondition } from "./condition.js";
import { BUILTINS } from "./evaluator.js";
import { Finding, Severity } from "./findings.js";
import { applySlice, hadEmptyEntry, isTag, iterRefs, splitList } from "./lexer.js";

/* Python's sorted() compares strings by code point. localeCompare does NOT
 * (it puts 'a' before 'B'), and using it would silently reorder messages and
 * change which duplicate survives. Every sort below uses this. */
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const sorted = (xs) => [...xs].sort(cmp);
const lower = (s) => String(s).toLowerCase();
const foldSet = (it) => new Set([...it].map(lower));

/** Run every detector and return the combined list, de-duplicated by exact
 *  field equality. A ForEach/Expand-repeated element yields one Resolved
 *  entry per iteration (V23), and several detectors key off those, so a
 *  defect on a repeated source line would otherwise surface as N identical
 *  findings. Purely positional de-dup: it never collapses distinct
 *  occurrences at different lines. */
export function runAll(graph, ev, schema) {
  const findings = [
    ...d18(graph, ev, schema), ...d19(graph, ev, schema), ...d20(graph, ev, schema),
    ...d2(graph, ev, schema), ...d3(graph, ev, schema), ...d4(graph, ev, schema),
    ...d5(graph, ev, schema), ...d6(graph, ev, schema), ...d7(graph, ev, schema),
    ...d8(graph, ev, schema), ...d9(graph, ev, schema), ...d10(graph, ev, schema),
    ...d11(graph, ev, schema), ...d12(graph, ev, schema), ...d13(graph, ev, schema),
    ...d15(graph, ev, schema), ...d16(graph, ev, schema),
    ...d22(graph, ev, schema),
  ];
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    const key = [f.file, f.line, f.severity, f.detector, f.message, f.node, f.tag].join("\u0000");
    if (!seen.has(key)) { seen.add(key); out.push(f); }
  }
  return out;
}

/* --------- shared tag-dataflow site harvesting (D2/D3/D4) --------------
 * Mirrors model.build's produce/consume rule exactly, but keeps the
 * per-occurrence element+attr location that Node.creates/consumes (bare
 * sets) discard -- so these can point at a real file:line (V15). */

function consumptionSites(ev, schema) {
  const sites = [];
  for (const r of ev.resolved) {
    if (r.elem.tag === "Node") {
      const nodeName = r.attrs.get("Name") || "";
      for (const token of splitList(r.attrs.get("Requires") || "")) {
        if (isTag(token)) sites.push([token, nodeName, r.elem, "Requires"]);
      }
    } else if (r.node) {
      for (const [attr, value] of r.attrs) {
        // @After is order-only (R23): no file transfer, so it never
        // contributes to consumption. Matches model.js precisely.
        if (attr === "After") continue;
        if (schema.isTagOutput(r.elem.tag, attr)) continue;
        for (const token of splitList(value)) if (isTag(token)) sites.push([token, r.node, r.elem, attr]);
      }
    }
  }
  return sites;
}

function creationSites(ev, schema) {
  const sites = [];
  for (const r of ev.resolved) {
    if (!r.node) continue;
    for (const [attr, value] of r.attrs) {
      if (!schema.isTagOutput(r.elem.tag, attr)) continue;
      for (const token of splitList(value)) sites.push([token, r.node, r.elem, attr]);
    }
  }
  return sites;
}

/* ---- D2: tag consumed, never produced anywhere (warn) ------------------
 * "Produced" counts BOTH ways a tag can exist: exported via some node's
 * @Produces, OR created node-locally and consumed within that SAME node --
 * the latter never needs to escape, so it is not a defect. Measured: four
 * tags in the target file are created and consumed inside one node with no
 * @Produces; checking producersOf alone misclassified all four. */
function d2(graph, ev, schema) {
  const out = [];
  for (const [tag, nodeName, elem, attr] of consumptionSites(ev, schema)) {
    // D18 owns this site, at `error`. The distinction is real and
    // observable: an unresolvable tag in Node/@Requires is a HARD engine
    // error, whereas a tag consumed by a task attribute is only a runtime
    // file-set lookup -- which is why Epic's own BuildEditorAndTools.xml
    // builds fine despite #BinaryFiles never being produced.
    if (elem.tag === "Node" && attr === "Requires") continue;
    const node = graph.nodes.get(nodeName);
    const folded = lower(tag);
    const createdLocally = node && foldSet(node.creates).has(folded);
    if (createdLocally || graph.producersOf(tag).length) continue;
    out.push(new Finding({
      file: elem.file, line: elem.line, severity: Severity.WARN, detector: "D2",
      message: `Tag '${tag}' is consumed by ${elem.tag}/@${attr} but produced nowhere in the graph`,
      node: nodeName, tag,
    }));
  }
  return out;
}

/* ---- D3: tag in @Produces, unconsumed in-graph (info) ----------------- */
function d3(graph, ev, schema) {
  // V3 vs V4: only EXPLICITLY-authored @Produces counts as public API here,
  // re-derived from the raw attribute rather than Node.produces (which also
  // folds in the always-present implicit output). Flagging every node's
  // implicit default output as unconsumed would flood real graphs.
  const consumedAnywhere = new Set();
  for (const node of graph.nodes.values()) for (const c of node.consumes) consumedAnywhere.add(lower(c));
  const out = [];
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Node") continue;
    const nodeName = r.attrs.get("Name") || "";
    for (const producedTag of splitList(r.attrs.get("Produces") || "")) {
      if (consumedAnywhere.has(lower(producedTag))) continue;
      out.push(new Finding({
        file: r.elem.file, line: r.elem.line, severity: Severity.INFO, detector: "D3",
        message: `Tag '${producedTag}' is declared in Node/@Produces but never consumed anywhere in the graph`,
        node: nodeName, tag: producedTag,
      }));
    }
  }
  return out;
}

/* ---- D4: tag created in node, not in @Produces, unconsumed there ------ */
function d4(graph, ev, schema) {
  const out = [];
  for (const [tag, nodeName, elem, attr] of creationSites(ev, schema)) {
    const node = graph.nodes.get(nodeName);
    if (!node) continue;
    const folded = lower(tag);
    if (foldSet(node.produces).has(folded)) continue;   // declared -- V3 territory
    if (foldSet(node.consumes).has(folded)) continue;   // used in this node -- not dead
    out.push(new Finding({
      file: elem.file, line: elem.line, severity: Severity.WARN, detector: "D4",
      message: `Tag '${tag}' is created by ${elem.tag}/@${attr} but is not in Node/@Produces ` +
               `and is never consumed within node '${nodeName}' -- cannot escape the node, provably dead`,
      node: nodeName, tag,
    }));
  }
  return out;
}

/* ---- D5: provably-empty tag (warn, V20) ------------------------------- */

function hasWildcard(spec) { return spec.includes("*") || spec.includes("?") || spec.includes("..."); }

/** Python fnmatch on Windows: normcase both sides (lowercase, '/'->'\\')
 *  then glob-match, where '*' matches ANY run including separators. Written
 *  out rather than approximated with a loose regex, because getting '*' or
 *  the character class wrong silently changes which files a Filter is
 *  believed to select, and D5 turns that into a `warn`. */
function fnmatchWin(name, pattern) {
  const norm = (s) => s.toLowerCase().replace(/\//g, "\\");
  const n = norm(name);
  const p = norm(pattern);
  let re = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "*") re += "[\\s\\S]*";
    else if (c === "?") re += "[\\s\\S]";
    else if (c === "[") {
      let j = i + 1;
      if (j < p.length && (p[j] === "!" || p[j] === "^")) j++;
      if (j < p.length && p[j] === "]") j++;
      while (j < p.length && p[j] !== "]") j++;
      if (j >= p.length) { re += "\\["; }
      else {
        let inner = p.slice(i + 1, j).replace(/\\/g, "\\\\");
        if (inner[0] === "!") inner = "^" + inner.slice(1);
        re += "[" + inner + "]";
        i = j;
      }
    } else re += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  try { return new RegExp("^(?:" + re + ")$").test(n); } catch { return false; }
}

/** Does a wildcard-free literal path match ANY pattern in a ';'-list?
 *  Checked against the full spec AND its trailing filename component, since
 *  "*.pdb" conventionally matches an extension anywhere in a path. */
function matchesPattern(literal, filterPatterns) {
  const norm = literal.replace(/\\/g, "/");
  const basename = norm.slice(norm.lastIndexOf("/") + 1);
  for (const pattern of splitList(filterPatterns)) {
    if (fnmatchWin(norm, pattern) || fnmatchWin(basename, pattern)) return true;
  }
  return false;
}

/** Syntactic subsumption ONLY: every pattern in `filterPatterns` appears
 *  verbatim among `exceptValue`'s entries. No semantic pattern reasoning --
 *  V20 is a hard gate: syntactic, not clever. */
function patternSubsumes(filterPatterns, exceptValue) {
  const filterItems = splitList(filterPatterns);
  if (!filterItems.length) return false;
  const exceptItems = splitList(exceptValue);
  return filterItems.every((f) => exceptItems.includes(f));
}

function itemDisjointFromFilter(item, filterPattern, tagProvenance, visiting) {
  if (isTag(item)) return tagDisjointFromFilter(item, filterPattern, tagProvenance, visiting);
  if (hasWildcard(item)) return false;              // unresolvable (V20)
  return !matchesPattern(item, filterPattern);
}

function tagDisjointFromFilter(tag, filterPattern, tagProvenance, visiting) {
  if (visiting.has(tag)) return false;              // never assume disjoint through a cycle
  const contributions = tagProvenance.get(tag);
  if (!contributions || !contributions.length) return false;  // no provenance -- unresolvable
  const visiting2 = new Set(visiting); visiting2.add(tag);
  for (const c of contributions) {
    if (patternSubsumes(filterPattern, c.except)) continue;   // proven disjoint via its own Except
    const items = splitList(c.sourceSpec);
    if (!items.length) return false;                          // blank Files -- unresolvable
    for (const item of items) {
      if (!itemDisjointFromFilter(item, filterPattern, tagProvenance, visiting2)) return false;
    }
  }
  return true;
}

function d5(graph, ev, schema) {
  const out = [];
  for (const r of ev.resolved) {
    // R29: exactly two task types carry both a tag output and filter
    // semantics -- Tag (Filter/Except) and Copy (Exclude). This handles ONLY
    // Tag, deliberately (§B.4). They are OPPOSITE polarity: Tag/@Filter
    // SELECTS, Copy/@Exclude REMOVES. The proof below fires when every
    // contributor is DISJOINT from the pattern, which for Tag means nothing
    // was selected => empty. For Copy, disjoint means nothing was removed =>
    // everything copied => decidedly NOT empty. Reusing it would
    // false-positive on nearly every Copy with an Exclude.
    if (r.elem.tag !== "Tag") continue;
    const filterPattern = r.attrs.get("Filter") || "";
    const withValue = r.attrs.get("With") || "";
    if (!filterPattern || !withValue) continue;
    const filesValue = r.attrs.get("Files") || r.attrs.get("FileLists") || "";
    const items = splitList(filesValue);
    if (!items.length) continue;
    if (!items.every((i) => itemDisjointFromFilter(i, filterPattern, graph.tagProvenance, new Set()))) continue;
    for (const targetTag of splitList(withValue)) {
      out.push(new Finding({
        file: r.elem.file, line: r.elem.line, severity: Severity.WARN, detector: "D5",
        message: `Tag '${targetTag}' is provably empty -- every contributor to ` +
                 `'${filesValue}' is disjoint from Filter='${filterPattern}'`,
        node: r.node, tag: targetTag,
      }));
    }
  }
  return out;
}

/* ---- D6: SetVersion not an ancestor of Compile (info) ----------------- */

/** BFS over the Requires graph. Only `requires` is followed, never `after`
 *  -- R23/R24: only Requires transfers build products; After is order-only. */
function hasPathToAny(graph, start, targets) {
  if (targets.has(start)) return true;
  const visited = new Set([start]);
  const queue = [start];
  while (queue.length) {
    const node = graph.nodes.get(queue.pop());
    if (!node) continue;
    for (const token of node.requires) {
      for (const name of graph.resolveRef(token)) {
        if (targets.has(name)) return true;
        if (!visited.has(name)) { visited.add(name); queue.push(name); }
      }
    }
  }
  return false;
}

function d6(graph, ev, schema) {
  const compileNodes = new Set();
  const setVersionNodes = new Set();
  for (const r of ev.resolved) {
    if (!r.node) continue;
    if (r.elem.tag === "Compile") compileNodes.add(r.node);
    else if (r.elem.tag === "SetVersion") setVersionNodes.add(r.node);
  }
  const out = [];
  for (const nodeName of sorted(compileNodes)) {
    if (hasPathToAny(graph, nodeName, setVersionNodes)) continue;
    const node = graph.nodes.get(nodeName);
    if (!node) continue;
    const message = setVersionNodes.size
      ? `Node '${nodeName}' contains a Compile task but has no dependency path (via Requires) ` +
        `to a SetVersion-bearing node (${sorted(setVersionNodes).map((n) => `'${n}'`).join(" or ")}); ` +
        `may stamp a stale version`
      : `Node '${nodeName}' contains a Compile task but the graph has no SetVersion-bearing ` +
        `node at all; may stamp a stale version`;
    out.push(new Finding({
      file: node.file, line: node.line, severity: Severity.INFO, detector: "D6", message, node: nodeName,
    }));
  }
  return out;
}

/* ---- D7: cross-agent dep whose transferred set is provably empty ------
 * V13: a cross-agent Requires is normal and fine by default (R23/R24) --
 * flag ONLY when the target's output is PROVABLY empty. Deliberately narrow:
 * fires only when the target has no @Produces AND zero task children, so it
 * provably ran nothing. That is the one shape provable without a table of
 * which task types register build products (only SetVersion is documented). */
function d7(graph, ev, schema) {
  const explicitProduces = new Map();
  const nodeHasNoChildren = new Map();
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Node") continue;
    const name = r.attrs.get("Name") || "";
    explicitProduces.set(name, splitList(r.attrs.get("Produces") || ""));
    nodeHasNoChildren.set(name, r.elem.children.length === 0);
  }
  const out = [];
  for (const [aName, aNode] of graph.nodes) {
    for (const token of aNode.requires) {
      if (isTag(token)) continue;              // names its producer directly
      const resolved = graph.resolveRef(token);
      if (resolved.length !== 1) continue;     // ambiguous -- abstain
      const bName = resolved[0];
      const bNode = graph.nodes.get(bName);
      if (!bNode || bNode.agent === aNode.agent) continue;
      if ((explicitProduces.get(bName) || []).length || !nodeHasNoChildren.get(bName)) continue;
      out.push(new Finding({
        file: aNode.file, line: aNode.line, severity: Severity.WARN, detector: "D7",
        message: `Node '${aName}' declares a cross-agent dependency on '${bName}' ` +
                 `(agent '${bNode.agent}'), whose transferred output is provably empty ` +
                 `(no @Produces, no tasks in its body)`,
        node: aName,
      }));
    }
  }
  return out;
}

/* ---- D8/D9: defined-but-never-referenced (info) -----------------------
 * V23: uses ev.propReads/propDefs directly, already computed during the
 * POST-Expand walk. A doc-order rescan gives 3 false positives on
 * Examples/Macros.xml (R22); reusing the evaluator's own trace sidesteps
 * that class of bug rather than re-deriving it. */
function d8(graph, ev, schema) {
  const readNames = new Set(ev.propReads.map(([name]) => name));
  const out = [];
  for (const [name, elem, idx] of ev.propDefs) {
    if (readNames.has(name)) continue;
    out.push(new Finding({
      file: elem.file, line: elem.line, severity: Severity.INFO, detector: "D8",
      message: `Property '${name}' is defined but never referenced`,
      node: ev.resolved[idx].node,
    }));
  }
  return out;
}

function d9(graph, ev, schema) {
  const readNames = new Set(ev.propReads.map(([name]) => name));
  const out = [];
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Option") continue;
    const name = r.attrs.get("Name") || "";
    if (!name || readNames.has(name)) continue;
    out.push(new Finding({
      file: r.elem.file, line: r.elem.line, severity: Severity.INFO, detector: "D9",
      message: `Option '${name}' is declared but never referenced`,
      node: r.node,
    }));
  }
  return out;
}

/* ---- D22: boolean-looking <Option> without a Restrict (info, hygiene) ----
 * An <Option> whose DefaultValue is "true"/"false" is a switch, and a switch
 * with no Restrict accepts ANY string on a manual run: `-set:WithDDC=ture`
 * is a value to the engine, not an error, and engine truthiness ("true",
 * case-insensitive, nothing else) reads it as FALSE -- the typo silently
 * flips the switch off. Restrict="true|false" makes it a hard parse-time
 * error. Info, never warn: the script is correct as written and the engine
 * is silent; this is hygiene for the run someone types by hand. Mirrors
 * detectors.py::_d22 exactly. */
const BOOL_DEFAULTS = new Set(["true", "false"]);

function d22(graph, ev, schema) {
  const out = [];
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Option") continue;
    const name = r.attrs.get("Name") || "";
    const def = r.attrs.get("DefaultValue") || "";
    if (!name || !BOOL_DEFAULTS.has(def.trim().toLowerCase())) continue;
    if ((r.attrs.get("Restrict") || "").trim()) continue;
    out.push(new Finding({
      file: r.elem.file, line: r.elem.line, severity: Severity.INFO, detector: "D22",
      message: `Option '${name}' defaults to '${def}' but has no Restrict; add Restrict="true|false" ` +
        `so a mistyped value on a manual run (-set:${name}=ture) is rejected instead of being read as false`,
      node: r.node,
    }));
  }
  return out;
}

/* ---- D10: trailing ';' / empty list entry (info, never warn per V6) ----
 * Ceiling: attributes this tool already treats as ';'-lists. NOT every
 * attribute -- most BalancedStringType attrs (Message, Description,
 * Arguments) are free text the engine never splits, and flagging a stray ';'
 * inside prose would be noise rather than harmless list styling. */
const LIST_ATTR_NAMES = new Set(["Requires", "OptionalRequires", "After", "Files", "FileLists", "Filter", "Except"]);

function d10(graph, ev, schema) {
  const out = [];
  for (const r of ev.resolved) {
    const tag = r.elem.tag;
    for (const [attr, value] of r.attrs) {
      if (!value) continue;
      if (!(schema.isTagOutput(tag, attr) || LIST_ATTR_NAMES.has(attr))) continue;
      if (!hadEmptyEntry(value)) continue;
      // WHERE the empty entry came from, because the two sources read
      // identically and only one of them is visible. A literal ';' you can
      // point at; an entry left by an expansion that produced nothing you
      // cannot -- and on the target file that expansion is the downstream
      // effect of a D1 on the SAME line, so the old wording made a
      // cause-and-effect pair look like a stray duplicate.
      const raw = Object.prototype.hasOwnProperty.call(r.elem.attrib, attr) ? r.elem.attrib[attr] : "";
      let why;
      if (hadEmptyEntry(raw)) {
        why = "trailing or duplicate ';'";
      } else {
        // Only refs can have introduced it: no refs would mean raw and
        // expanded agree, which the branch above already handled.
        const names = [...new Set(iterRefs(raw).map((ref) => ref.name))];
        if (names.length === 1) why = `'$(${names[0]})' expanded to nothing`;
        // Several candidates. Naming one would be a guess, and deciding
        // between them means re-expanding entry by entry -- unsound, since a
        // property value may legitimately contain ';' (R20's accumulator).
        else why = "an expansion produced nothing; no literal ';' in the source";
      }
      out.push(new Finding({
        file: r.elem.file, line: r.elem.line, severity: Severity.INFO, detector: "D10",
        message: `${tag}/@${attr} has an empty list entry (${why})`,
        node: r.node,
      }));
    }
  }
  return out;
}

/* ---- D11: schema-required attr empty on EVERY reachable option-set ----
 * Fires only when NO possible invocation can BOTH fill the attribute AND
 * keep it load-bearing. Force every <Option>-declared name in the raw text
 * to a non-empty sentinel (a real --set can always do that), then check the
 * result is non-empty AND every guard that could gate the element out still
 * evaluates non-False (V10: UNKNOWN counts as holding; only a provable False
 * blocks). Deliberately a HYPOTHETICAL pass: unlike every other detector it
 * never emits a finding of its own on a bad reference -- it answers yes/no. */
const R14_STRUCTURAL = new Set([
  "Include", "Option", "Property", "Regex", "StringOp", "EnvVar", "Macro", "Extend",
  "Agent", "Aggregate", "Artifact", "Report", "Badge", "Label", "Trace", "Warning",
  "Error", "Do", "Switch", "ForEach", "Expand", "Node",
]);

const WITNESS_SENTINEL = "nonempty";   // same shape as algebra.js's sample:
// a leading control char no real XML attribute value can contain, so a witness
// can never be mistaken for a value a script could actually supply.

function baseEnvFor(ev) {
  const env = new Map(BUILTINS);
  for (const [name, opt] of ev.options) env.set(name, opt.default);
  for (const [name, , idx] of ev.propDefs) env.set(name, ev.resolved[idx].attrs.get("Value") || "");
  return env;
}

/** casefolded name -> raw If= texts of every <Property> whose accumulator
 *  Value list includes that name -- the "$(X);NodeName" idiom used to pull a
 *  node conditionally into a Requires-style aggregation. */
function inclusionGates(ev) {
  const gates = new Map();
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Property" || !r.rawIf) continue;
    for (const item of splitList(r.attrs.get("Value") || "")) {
      const k = lower(item);
      if (!gates.has(k)) gates.set(k, []);
      gates.get(k).push(r.rawIf);
    }
  }
  return gates;
}

/** Minimal resolver for the witness test only: same right-to-left order as
 *  the real expander, but purely hypothetical -- an absent name resolves to
 *  "" silently (this reasons about a POSSIBLE invocation, so it must never
 *  emit or throw), and a null-valued entry stays inert so it cannot loop. */
function witnessSubstitute(text, env) {
  let result = text;
  let searchEnd = result.length;
  const inert = new Set();
  for (;;) {
    const refs = iterRefs(result).filter((r) => r.start < searchEnd && !inert.has(r.raw));
    if (!refs.length) return result;
    const ref = refs[refs.length - 1];
    if (ref.name.includes("$(")) { searchEnd = ref.start; continue; }
    const value = env.has(ref.name) ? env.get(ref.name) : "";
    if (value === null || value === undefined) { inert.add(ref.raw); searchEnd = ref.start; continue; }
    const replacement = ref.malformed ? value : applySlice(value, ref.sliceN);
    result = result.slice(0, ref.start) + replacement + result.slice(ref.end);
    searchEnd = result.length;
  }
}

function gateTextsFor(elem, nodeName, gates) {
  const texts = [];
  let walk = elem;
  while (walk) {
    const rawIf = walk.attrib.If;
    if (rawIf) texts.push(rawIf);
    walk = walk.parent;
  }
  if (nodeName) texts.push(...(gates.get(lower(nodeName)) || []));
  return texts;
}

function someInvocationFills(rawValue, gateTexts, baseEnv, options) {
  const env = new Map(baseEnv);
  for (const ref of iterRefs(rawValue)) if (options.has(ref.name)) env.set(ref.name, WITNESS_SENTINEL);
  if (!witnessSubstitute(rawValue, env)) return false;
  for (const gateText of gateTexts) {
    let ast;
    try { ast = parseCondition(gateText); }
    catch (e) {
      if (e instanceof CondParseError) continue;   // never let an uncertain gate prove anything
      throw e;
    }
    if (algEvaluate(ast, env) === false) return false;
  }
  return true;
}

function d11(graph, ev, schema) {
  const baseEnv = baseEnvFor(ev);
  const gates = inclusionGates(ev);
  const out = [];
  for (const r of ev.resolved) {
    const tag = r.elem.tag;
    if (R14_STRUCTURAL.has(tag) || !schema.knownElement(tag)) continue;
    for (const attr of sorted(schema.requiredAttrs(tag))) {
      if (r.attrs.get(attr) !== "") continue;
      const rawVal = Object.prototype.hasOwnProperty.call(r.elem.attrib, attr) ? r.elem.attrib[attr] : "";
      if (someInvocationFills(rawVal, gateTextsFor(r.elem, r.node, gates), baseEnv, ev.options)) continue;
      let message = `${tag}/@${attr} is required but resolves to an empty string on every reachable option-set`;
      if (rawVal) message += ` (source: '${rawVal}')`;
      out.push(new Finding({
        file: r.elem.file, line: r.elem.line, severity: Severity.WARN, detector: "D11",
        message, node: r.node,
      }));
    }
  }
  return out;
}

/* ---- D12: guard unsat -> warn; tautological -> info -------------------
 * Two corpus-measured refinements over a direct classify(), both toward MORE
 * caution:
 *   1. baseEnv excludes the builtins entirely. A builtin's runtime value is
 *      unknowable to static analysis, so `If="$(IsBuildMachine)"` -- a
 *      legitimate "only on CI" pattern -- would otherwise always see "false"
 *      and be called unsat. Left unresolved it evaluates UNKNOWN, correctly.
 *   2. Every referenced Option's domain is widened with "true"/"false". R21
 *      measured 30/136 real conditions are bare-boolean option checks, and
 *      the default sample has no reason to equal "true" -- Epic's `Horde`
 *      option defaults to the compound STRING "$(IsBuildMachine) And
 *      $(IsHordeEnv)", so `If="$(Horde)"` was misclassified unsat even
 *      though `--set Horde=true` obviously satisfies it. */
class D12Opt extends Opt {
  domain() {
    const base = super.domain();
    return base.concat(["true", "false"].filter((s) => !base.includes(s)));
  }
}

function d12(graph, ev, schema) {
  const opts = new Map();
  for (const [name, o] of ev.options) opts.set(name, new D12Opt(o.name, o.default, o.restrict));
  const baseEnv = new Map();
  const out = [];
  for (const r of ev.resolved) {
    const rawIf = r.rawIf;
    if (!rawIf || !rawIf.trim()) continue;
    // A condition with ZERO refs (a pure literal like "2 < 1") has no
    // config-dependent ambiguity: classify would still call it correctly,
    // but it is trivially visible and adds nothing. Corpus-measured, this
    // shape is how Examples/Properties.xml demonstrates each operator --
    // tutorial content, not a defect.
    if (!iterRefs(rawIf).length) continue;
    let ast;
    try { ast = parseCondition(rawIf); }
    catch (e) {
      if (e instanceof CondParseError) continue;   // cannot parse -- never guess
      throw e;
    }
    const verdict = classify(ast, opts, baseEnv);
    if (verdict === "unsat") {
      out.push(new Finding({
        file: r.elem.file, line: r.elem.line, severity: Severity.WARN, detector: "D12",
        message: `Guard If="${rawIf}" is unsatisfiable -- this branch can never run`,
        node: r.node,
      }));
    } else if (verdict === "taut") {
      out.push(new Finding({
        file: r.elem.file, line: r.elem.line, severity: Severity.INFO, detector: "D12",
        message: `Guard If="${rawIf}" is tautological -- always true, the condition is redundant`,
        node: r.node,
      }));
    }
    // contingent/unknown -> neither (V10/V14).
  }
  return out;
}

/* ---- D13: dead-on-arrival property definition (warn) ------------------
 * Narrower than "never read anywhere" -- that degenerate case is D8's job
 * (info) and must NOT also trip this. D13 fires only when a definition is
 * provably CLOBBERED: the very next event touching the name is an
 * UNCONDITIONAL redefinition. A read later proves it was observed. A GUARDED
 * redefinition proves nothing (it might not run) -- skip past and keep
 * looking rather than assume it wins the race.
 *
 * "Unconditional" means neither the element NOR any ancestor carries If= --
 * measured: IncrementalCompare.xml redefines a property with a bare
 * <Property/>, but inside a guarded <Do>, and a later Requires does observe
 * the first definition whenever that guard is false.
 *
 * The equal-index tie-break is not arbitrary: for an accumulator step
 * (Value="$(X);more") the evaluator records the self-referential READ of the
 * old value strictly BEFORE that element's own def entry. Both land at the
 * same index, but the read is causally first -- which is what keeps R20's 37
 * real accumulator occurrences from tripping this. */
function hasAnyGuard(elem) {
  let walk = elem;
  while (walk) {
    if (walk.attrib.If) return true;
    walk = walk.parent;
  }
  return false;
}

function d13(graph, ev, schema) {
  const READ = 0, DEF = 1;
  const eventsByName = new Map();
  const defsByName = new Map();
  for (const [name, , idx] of ev.propDefs) {
    if (!eventsByName.has(name)) eventsByName.set(name, []);
    eventsByName.get(name).push([idx, DEF]);
    if (!defsByName.has(name)) defsByName.set(name, []);
    defsByName.get(name).push(idx);
  }
  for (const [name, , idx] of ev.propReads) {
    if (!eventsByName.has(name)) eventsByName.set(name, []);
    eventsByName.get(name).push([idx, READ]);
  }

  const out = [];
  for (const [name, defIndices] of defsByName) {
    // (index, kind) with READ(0) before DEF(1) at an equal index.
    const events = [...eventsByName.get(name)].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    const posOfDef = new Map();
    events.forEach(([idx, kind], pos) => { if (kind === DEF) posOfDef.set(idx, pos); });
    for (const idx of defIndices) {
      let isDead = false;
      for (let p = posOfDef.get(idx) + 1; p < events.length; p++) {
        const [nxtIdx, nxtKind] = events[p];
        if (nxtKind === READ) break;                              // observed -- live
        if (!hasAnyGuard(ev.resolved[nxtIdx].elem)) { isDead = true; break; }
        // guarded redefinition: cannot prove it runs -- keep scanning
      }
      if (!isDead) continue;
      const elem = ev.resolved[idx].elem;
      out.push(new Finding({
        file: elem.file, line: elem.line, severity: Severity.WARN, detector: "D13",
        message: `Property '${name}' is dead on arrival -- it is unconditionally redefined ` +
                 `before this value is ever read`,
        node: ev.resolved[idx].node,
      }));
    }
  }
  return out;
}

/* ---- D15: Agent/@Type is a literal, not option-driven (info) ---------- */
function d15(graph, ev, schema) {
  const out = [];
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Agent") continue;
    // RAW source text, not the expanded value: an option-driven Type
    // expands to something with zero refs left in it, indistinguishable
    // from a hardcoded literal if checked post-expansion.
    const rawType = Object.prototype.hasOwnProperty.call(r.elem.attrib, "Type") ? r.elem.attrib.Type : "";
    if (!rawType) continue;
    if (iterRefs(rawType).length) continue;
    out.push(new Finding({
      file: r.elem.file, line: r.elem.line, severity: Severity.INFO, detector: "D15",
      message: `Agent/@Type="${rawType}" is a hardcoded literal, not option-driven`,
      node: null,
    }));
  }
  return out;
}

/* ---- D16: dir path written by another node, no tag flow (info) --------
 * R30: this allowlist is IRREDUCIBLE, not a shortcut. BuildGraph.cs registers
 * both FileReference and DirectoryReference as BalancedString, so the XSD
 * erases the distinction, and the C# type does not help either -- Copy/@From,
 * Copy/@To and Zip/@FromDir are plain `string`. "This attribute names a
 * directory another node fills" is a semantic judgement no machine-readable
 * source encodes. */
const DIR_WRITE_ATTRS = [["Copy", "To"], ["Move", "To"], ["Strip", "OutputDir"], ["Unzip", "ToDir"]];
const DIR_READ_ATTRS = [["Copy", "From"], ["Move", "From"], ["Zip", "FromDir"], ["Strip", "BaseDir"], ["Tag", "BaseDir"]];

/** Windows-first path comparison (§C: case-insensitive, both separators). */
function normPath(value) {
  return value.trim().replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
}

function d16(graph, ev, schema) {
  const writers = new Map();
  for (const r of ev.resolved) {
    if (!r.node) continue;
    for (const [taskTag, attr] of DIR_WRITE_ATTRS) {
      if (r.elem.tag !== taskTag) continue;
      const value = r.attrs.get(attr) || "";
      if (!value) continue;
      const k = normPath(value);
      if (!writers.has(k)) writers.set(k, new Set());
      writers.get(k).add(r.node);
    }
  }
  const out = [];
  for (const r of ev.resolved) {
    if (!r.node) continue;
    for (const [taskTag, attr] of DIR_READ_ATTRS) {
      if (r.elem.tag !== taskTag) continue;
      const value = r.attrs.get(attr) || "";
      if (!value) continue;
      const others = [...(writers.get(normPath(value)) || [])].filter((n) => n !== r.node);
      if (!others.length) continue;
      out.push(new Finding({
        file: r.elem.file, line: r.elem.line, severity: Severity.INFO, detector: "D16",
        message: `${r.elem.tag}/@${attr} reads directory '${value}', written by node(s) ` +
                 `${pyList(sorted(others))} with no tag flow connecting them (breaks if agents split)`,
        node: r.node,
      }));
    }
  }
  return out;
}

/** Python's repr of a list of strings, which the D16 message interpolates
 *  directly. Reproduced so messages stay byte-identical to the reference
 *  implementation's. */
function pyList(items) {
  return "[" + items.map((s) => "'" + s.replace(/\\/g, "\\\\").replace(/'/g, "\\'") + "'").join(", ") + "]";
}

/* ---- D18: engine HARD-ERROR conditions (V31) -------------------------- */

/** True if `elem` or any ancestor carries If=. Deliberately conservative: it
 *  never tries to EVALUATE the guard. bgview unions every branch, so a
 *  reference and the node satisfying it can share a guard yet look
 *  inconsistent once unioned -- measured on IncrementalCompare.xml. D18 emits
 *  `error`, so it must only speak when certain (V33). */
function underAGuard(elem) {
  let node = elem;
  while (node) {
    if (node.attrib.If) return true;
    node = node.parent;
  }
  return false;
}

function* refTokensWithLocation(graph, ev) {
  for (const r of ev.resolved) {
    if (underAGuard(r.elem)) continue;
    const tag = r.elem.tag;
    if (tag === "Node") {
      for (const attr of ["Requires", "After", "OptionalRequires"]) {
        for (const token of splitList(r.attrs.get(attr) || "")) yield [token, r.elem, `Node/@${attr}`];
      }
    } else if (["Aggregate", "Label", "Report", "Badge"].includes(tag)) {
      for (const attr of ["Requires", "Include", "Exclude", "Nodes", "Targets"]) {
        for (const token of splitList(r.attrs.get(attr) || "")) yield [token, r.elem, `${tag}/@${attr}`];
      }
    }
  }
}

const NAMED_OBJECT_TAGS = new Set(["Node", "Agent", "Aggregate", "Report", "Label", "Artifact", "Badge"]);
// BgSchema.cs:203, kept literal: it is a C# const the schema generator bakes
// into a name regex, not something Schema.xsd exposes.
const ILLEGAL_NAME_CHARS = new Set(['^', '<', '>', ':', '"', '/', '\\', '|', '?', '*']);

/** Why ValidateName would reject `name`, or null.
 *  R33 is precise and the boundary is not the obvious one: it never trims, so
 *  a SINGLE trailing space is ACCEPTED -- which is exactly how a node name
 *  ends up genuinely unreferenceable while still being legal. Only
 *  CONSECUTIVE spaces are an error, so this must never test trim(). */
function invalidObjectNameReason(name) {
  if (name === "") return "the name is empty";
  for (let idx = 0; idx < name.length; idx++) {
    const char = name[idx];
    if (idx > 0 && char === " " && name[idx - 1] === " ") return "it contains consecutive spaces";
    const code = char.codePointAt(0);
    if (code < 32 || ILLEGAL_NAME_CHARS.has(char)) {
      const shown = code < 32 ? pyRepr(char) : `'${char}'`;
      return `it contains the illegal character ${shown}`;
    }
  }
  return null;
}

/** Python's repr() for a single control character, so the message matches. */
function pyRepr(ch) {
  const code = ch.codePointAt(0);
  const named = { 9: "\\t", 10: "\\n", 13: "\\r" };
  if (named[code]) return `'${named[code]}'`;
  return `'\\x${code.toString(16).padStart(2, "0")}'`;
}

function d18(graph, ev, schema) {
  const out = [];

  // (a) Unresolvable reference, plus the did-you-mean variant for a missing '#'.
  const seen = new Set();
  for (const [token, elem, where] of refTokensWithLocation(graph, ev)) {
    if (graph.resolveRef(token).length) continue;
    // A '$(...)' that survived expansion is already D1's; do not double-report.
    if (token.includes("$(")) continue;
    let hint = "";
    if (!token.startsWith("#") && graph.resolveRef("#" + token).length) hint = `; did you mean '#${token}'?`;
    const key = [elem.file, elem.line, token].join("\u0000");
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(new Finding({
      file: elem.file, line: elem.line, severity: Severity.ERROR, detector: "D18",
      message: `${where} references '${token}', which resolves to no node, ` +
               `aggregate, agent or tag${hint} (engine reports an error)`,
    }));
  }

  // (b) Two nodes generating the same output tag. A silent data hazard:
  //     which producer wins is not something the author controls.
  const allProduced = new Set();
  for (const n of graph.nodes.values()) for (const t of n.produces) allProduced.add(t);
  for (const tag of sorted(allProduced)) {
    const producers = graph.producersOf(tag);
    if (producers.length > 1) {
      const node = graph.nodes.get(producers[1]);
      out.push(new Finding({
        file: node.file, line: node.line, severity: Severity.ERROR, detector: "D18",
        message: `Output tag '${tag}' is generated by more than one node ` +
                 `(${sorted(producers).join(", ")}) (engine reports an error)`,
        node: producers[1], tag,
      }));
    }
  }

  // (d) Duplicate object name. The namespace is EXACTLY what
  //     BgGraphDef.ContainsName checks: node | report | aggregate -- agents
  //     and labels are NOT in it. That matters: Epic deliberately names an
  //     <Agent> and its <Node> both "HLOD Setup", and duplicate agents merge.
  //     Including agents produced 3 measured false positives.
  const declared = new Map();
  for (const r of ev.resolved) {
    if (!["Node", "Aggregate", "Report"].includes(r.elem.tag)) continue;
    const name = r.attrs.get("Name") || "";
    if (!name || underAGuard(r.elem)) continue;
    const k = lower(name);
    if (!declared.has(k)) declared.set(k, []);
    declared.get(k).push([name, r.elem, r.elem.tag]);
  }
  for (const folded of sorted(declared.keys())) {
    const decls = declared.get(folded);
    // De-dup by source position: a ForEach body re-emits the same element
    // once per value, which is one declaration, not N.
    const positions = new Set(decls.map(([, e]) => `${e.file}\u0000${e.line}`));
    if (positions.size > 1) {
      const [name, elem] = decls[decls.length - 1];
      const kinds = sorted(new Set(decls.map(([, , k]) => k))).join(", ");
      out.push(new Finding({
        file: elem.file, line: elem.line, severity: Severity.ERROR, detector: "D18",
        message: `'${name}' is declared more than once (${kinds}); node, report ` +
                 `and aggregate names share one namespace (engine reports an error)`,
      }));
    }
  }

  // (c) An <Option>'s own DefaultValue violating its own Restrict.
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Option") continue;
    const restrict = r.attrs.get("Restrict") || "";
    if (!restrict) continue;
    const def = r.attrs.get("DefaultValue") || "";
    if (restrict.includes("$(") || def.includes("$(")) continue;   // D1's business
    let ok;
    try {
      // Python's re.fullmatch anchors both ends; the non-capturing group is
      // what makes a top-level alternation ("a|b") anchor as a whole.
      ok = new RegExp("^(?:" + restrict + ")$", "i").test(def);
    } catch { continue; }   // a .NET regex JS cannot compile: stay silent, never guess
    if (!ok) {
      out.push(new Finding({
        file: r.elem.file, line: r.elem.line, severity: Severity.ERROR, detector: "D18",
        message: `Option '${r.attrs.get("Name") || ""}' has DefaultValue ` +
                 `'${def}', which does not match its own Restrict ` +
                 `'${restrict}' (engine reports an error)`,
      }));
    }
  }

  // (e) An output tag not beginning with '#'. The engine DROPS such an entry
  //     from the node's outputs entirely, so the tag silently never exists --
  //     which is exactly why it is worth saying.
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Node") continue;
    for (const token of splitList(r.attrs.get("Produces") || "")) {
      if (token.startsWith("#") || token.includes("$(")) continue;
      if (underAGuard(r.elem)) continue;
      out.push(new Finding({
        file: r.elem.file, line: r.elem.line, severity: Severity.ERROR, detector: "D18",
        message: `Node/@Produces entry '${token}' does not begin with '#'; ` +
                 `the engine rejects it and the tag is never produced (engine reports an error)`,
        node: r.attrs.get("Name") || null,
      }));
    }
  }

  // (f) A node declaring the same output twice -- a literal duplicate, or
  //     @Produces naming the node's OWN implicit '#<NodeName>' output.
  //     The second is easy to get wrong: BgNodeDef builds Outputs as
  //     ['#'+Name] ++ outputNames.Where(x => x != Name), but the filter
  //     compares the BARE name while :1531 already rejected every entry not
  //     starting with '#' -- so the filter is dead and '#Foo' on node 'Foo'
  //     duplicates rather than collapsing. D18(b) cannot see either shape:
  //     model.build de-duplicates produces into a Set first. Reads RAW.
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Node" || underAGuard(r.elem)) continue;
    const nodeName = r.attrs.get("Name") || "";
    const implicit = lower(`#${nodeName}`);
    const seenOutputs = new Set();
    for (const token of splitList(r.attrs.get("Produces") || "")) {
      if (token.includes("$(") || !token.startsWith("#")) continue;   // (e) owns the unhashed case
      const folded = lower(token);
      if (seenOutputs.has(folded) || folded === implicit) {
        const why = (folded === implicit && !seenOutputs.has(folded))
          ? "duplicates the node's own implicit default output"
          : "is listed more than once";
        out.push(new Finding({
          file: r.elem.file, line: r.elem.line, severity: Severity.ERROR, detector: "D18",
          message: `Node '${nodeName}' output '${token}' ${why} (engine reports an error)`,
          node: nodeName || null, tag: token,
        }));
      }
      seenOutputs.add(folded);
    }
  }

  // (g) A name ValidateName rejects.
  for (const r of ev.resolved) {
    if (!NAMED_OBJECT_TAGS.has(r.elem.tag)) continue;
    if (!r.attrs.has("Name")) continue;
    const name = r.attrs.get("Name");
    if (name.includes("$(") || underAGuard(r.elem)) continue;
    const reason = invalidObjectNameReason(name);
    if (reason) {
      out.push(new Finding({
        file: r.elem.file, line: r.elem.line, severity: Severity.ERROR, detector: "D18",
        message: `<${r.elem.tag}> name '${name}' is invalid: ${reason} (engine reports an error)`,
      }));
    }
  }

  // (h) An <Artifact> naming a tag no node produces. <Artifact> is not in
  //     (a)'s element list, so (a) never saw it. The subtlety is the DEFAULT:
  //     with @Tag absent the engine substitutes '#<Name>' and validates THAT,
  //     so an <Artifact> with no @Tag is still a checked reference.
  const producedTags = new Set();
  for (const n of graph.nodes.values()) for (const t of n.produces) producedTags.add(lower(t));
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Artifact" || underAGuard(r.elem)) continue;
    const artName = r.attrs.get("Name") || "";
    const tag = (r.attrs.get("Tag") || "") || (artName ? `#${artName}` : "");
    if (!tag || tag.includes("$(")) continue;
    if (producedTags.has(lower(tag))) continue;
    const how = (r.attrs.get("Tag") || "") ? "" : " (defaulted from its @Name)";
    out.push(new Finding({
      file: r.elem.file, line: r.elem.line, severity: Severity.ERROR, detector: "D18",
      message: `Artifact '${artName}' references tag '${tag}'${how}, which no ` +
               `node produces (engine reports an error)`,
      tag,
    }));
  }

  return out;
}

/* ---- D19: cross-agent ordering error ---------------------------------
 * The only engine diagnostic purely about the AGENT BOUNDARY -- one of the
 * three invisible semantics §G exists to expose -- and it is invisible in the
 * source: every name involved resolves fine, so nothing looks wrong at any
 * single site. Reachable ONLY by REOPENING an agent, since references resolve
 * against the graph built so far. Transitive, because the engine compares
 * against an already-closed dependency set, and a two-hop path through an
 * innocent-looking intermediate is exactly what a human reviewer misses. */
function agentDeclarationOrder(ev) {
  const order = new Map();
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Agent") continue;
    const name = lower(r.attrs.get("Name") || "");
    if (name && !order.has(name)) order.set(name, order.size);
  }
  return order;
}

function d19(graph, ev, schema) {
  const agentOrder = agentDeclarationOrder(ev);
  if (agentOrder.size < 2) return [];   // a single agent can never be reopened around another

  const agentDisplay = new Map();
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Agent") continue;
    const written = r.attrs.get("Name") || "";
    if (written && !agentDisplay.has(lower(written))) agentDisplay.set(lower(written), written);
  }

  const direct = new Map();
  const nodeAgent = new Map();
  const nodeSite = new Map();
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Node") continue;
    const rawName = r.attrs.get("Name") || "";
    if (!rawName) continue;
    const folded = lower(rawName);
    nodeAgent.set(folded, lower(r.agent || ""));
    if (!nodeSite.has(folded)) nodeSite.set(folded, [rawName, r.elem]);
    if (!direct.has(folded)) direct.set(folded, new Set());
    const targets = direct.get(folded);
    for (const attr of ["Requires", "OptionalRequires", "After"]) {
      for (const token of splitList(r.attrs.get(attr) || "")) {
        for (const name of graph.resolveRef(token)) targets.add(lower(name));
      }
    }
  }

  const closureOf = (start) => {
    const seen = new Set();
    const stack = [...(direct.get(start) || [])];
    while (stack.length) {
      const current = stack.pop();
      if (seen.has(current)) continue;
      seen.add(current);
      stack.push(...(direct.get(current) || []));
    }
    return seen;
  };

  const out = [];
  for (const folded of sorted(nodeSite.keys())) {
    const [rawName, elem] = nodeSite.get(folded);
    // V33: bgview unions every branch, so a dependency existing on only one
    // branch is not PROVABLY misordered. `error` stays silent.
    if (underAGuard(elem)) continue;
    const ownAgent = nodeAgent.get(folded) || "";
    const ownIdx = agentOrder.get(ownAgent);
    if (ownIdx === undefined) continue;
    for (const dep of sorted(closureOf(folded))) {
      const depAgent = nodeAgent.get(dep);
      if (depAgent === undefined) continue;
      const depIdx = agentOrder.get(depAgent);
      if (depIdx === undefined || depIdx <= ownIdx) continue;
      const depName = nodeSite.has(dep) ? nodeSite.get(dep)[0] : dep;
      out.push(new Finding({
        file: elem.file, line: elem.line, severity: Severity.ERROR, detector: "D19",
        message: `Node '${rawName}' depends on '${depName}', which belongs to ` +
                 `agent '${agentDisplay.get(depAgent) || depAgent}' -- declared after the first definition of ` +
                 `agent '${agentDisplay.get(ownAgent) || ownAgent}'. Reopening an agent cannot pull in ` +
                 `work scheduled later (engine reports an error)`,
        node: rawName,
      }));
    }
  }
  return out;
}

/* ---- D20: engine WARNINGS nothing else reports (V31, second half) -----
 * All three are INTRA-element: each compares attributes of a single element
 * against each other, never one element against another. That is why none
 * needs V33's guard exemption -- there is no cross-branch union that could
 * make a guarded case look broken. */
function d20(graph, ev, schema) {
  const out = [];
  for (const r of ev.resolved) {
    const tag = r.elem.tag;

    // (a) :1488 -- "Optional input is also a required input". Harmless at
    //     runtime, but it always means the author believed one of the two
    //     declarations was doing something, and it is not.
    if (tag === "Node") {
      const required = new Map();
      for (const t of splitList(r.attrs.get("Requires") || "")) required.set(lower(t), t);
      const optional = new Set(splitList(r.attrs.get("OptionalRequires") || "").map(lower));
      for (const folded of sorted([...required.keys()].filter((k) => optional.has(k)))) {
        out.push(new Finding({
          file: r.elem.file, line: r.elem.line, severity: Severity.WARN, detector: "D20",
          message: `Node '${r.attrs.get("Name") || ""}' lists '${required.get(folded)}' in both ` +
                   `@Requires and @OptionalRequires; the required one wins and the ` +
                   `optional declaration has no effect (engine reports a warning)`,
          node: r.attrs.get("Name") || null,
        }));
      }

    // (b) :1110 -- "Argument is listed multiple times".
    } else if (tag === "Macro") {
      const seenArgs = new Set();
      for (const attr of ["Arguments", "OptionalArguments"]) {
        for (const arg of splitList(r.attrs.get(attr) || "")) {
          const folded = lower(arg);
          if (seenArgs.has(folded)) {
            out.push(new Finding({
              file: r.elem.file, line: r.elem.line, severity: Severity.WARN, detector: "D20",
              message: `Macro '${r.attrs.get("Name") || ""}' lists argument '${arg}' ` +
                       `more than once (engine reports a warning)`,
            }));
          }
          seenArgs.add(folded);
        }
      }

    // (c) :1705 -- the engine does NOT split on the string the author wrote;
    //     it silently falls back to ';', so the loop iterates over something
    //     other than what the script says.
    } else if (tag === "ForEach") {
      const separator = r.attrs.get("Separator") || "";
      if (separator.length > 1 && !separator.includes("$(")) {
        out.push(new Finding({
          file: r.elem.file, line: r.elem.line, severity: Severity.WARN, detector: "D20",
          message: `<ForEach> Separator '${separator}' is more than one character; ` +
                   `the engine ignores it and splits on ';' instead (engine reports a warning)`,
        }));
      }
    }
  }
  return out;
}
