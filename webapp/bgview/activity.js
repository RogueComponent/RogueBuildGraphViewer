/* bgview/activity.js -- which nodes would actually run under ONE option-set.
 *
 * The evaluator walks every branch on purpose (the union, V33): a static
 * tool cannot know which option-set a real run will use, so it reports what
 * ANY run could produce. This module answers the narrower question a reader
 * asks once they have picked values -- "which of these nodes run for
 * Shipping?" -- WITHOUT changing the walk. It is a lens over the union (V58):
 * every guard's `If` text, as the evaluator already expanded it under the
 * option-set, is parsed and evaluated to true / false / UNKNOWN (V59), and a
 * node is active only if every guard around it is true. Nothing is removed
 * here or in the renderer; the renderer dims (V60).
 *
 * Three-valued on purpose. `Exists()` touches a filesystem this tool does
 * not have, an unexpanded `$(RootDir)` has no value while preprocessing, and
 * a condition the parser rejects proves nothing -- all three are "unknown",
 * never coerced to false (that would hide a node that may well run) and
 * never to true (that would show one that may not).
 *
 * What "around it" means. A node's guards are its own `If`, plus every
 * guarded element whose span CONTAINS it in the same file (its Agent, a Do,
 * a Switch Case, a ForEach), plus -- when its file was brought in by an
 * <Include> -- that Include's guard and everything enclosing the Include,
 * recursively. Containment is decided on the resolved entries the evaluator
 * emitted, and for a body a ForEach emits once per value, the container
 * that counts is the LAST one emitted before the node's own entry: that is
 * the iteration the node belongs to, and its `If` was expanded with that
 * iteration's loop value.
 */
"use strict";

import { parse, CondParseError } from "./condition.js";
import { evaluate as evalCondition, UNKNOWN } from "./algebra.js";
import { splitList } from "./lexer.js";
import { resolveInclude } from "./evaluator.js";
import { normCase } from "./findings.js";

/** Verdict of one guard text as the evaluator expanded it. */
export function decide(expandedIf) {
  if (expandedIf === null || expandedIf === undefined) return "active";
  const text = String(expandedIf);
  // A reference the evaluator could not expand (a null built-in such as
  // RootDir) has no value to decide on. Not even parsed: an honest unknown.
  if (text.includes("$(")) return "unknown";
  let ast;
  try {
    ast = parse(text);
  } catch (err) {
    if (err instanceof CondParseError) return "unknown";
    throw err;
  }
  const verdict = evalCondition(ast, new Map());
  if (verdict === UNKNOWN) return "unknown";
  return verdict ? "active" : "inactive";
}

/** Kleene AND over verdicts: one false decides; else one unknown decides. */
export function combine(states) {
  if (states.includes("inactive")) return "inactive";
  if (states.includes("unknown")) return "unknown";
  return "active";
}

const base = (p) => String(p).split("/").pop();
const isGuarded = (r) => r.rawIf !== null && r.rawIf !== undefined;
const spanEnd = (r) => r.elem.endLine || r.elem.line;

/**
 * @param {{graph, ev, includes}} result  a pipeline result (activity is attached to it)
 * @returns {{nodes: Map<string,{state:string, guards:object[]}>,
 *            agents: Map<string,{state:string, guards:object[]}>,
 *            counts: {active:number, inactive:number, unknown:number}}}
 */
export function activity({ graph, ev, includes }) {
  const resolved = ev.resolved;

  const guardOf = (r, owner) => {
    const text = r.attrs.has("If") ? r.attrs.get("If") : r.rawIf;
    return {
      owner,                       // "node" | "agent" | "<Tag> at file:line" | "Include at file:line"
      tag: r.elem.tag,
      name: r.attrs.get("Name") || "",
      file: r.elem.file,
      line: r.elem.line,
      raw: r.rawIf,
      text,
      verdict: decide(text),
    };
  };
  const ownerLabel = (r) =>
    r.elem.tag === "Agent" ? `Agent ${r.attrs.get("Name") || ""}` : `${r.elem.tag} at ${base(r.elem.file)}:${r.elem.line}`;

  /** Guarded containers of the entry at `idx`: same file, span holds the
   *  entry's span, emitted BEFORE it -- the last emission per element wins
   *  (the iteration this entry belongs to). Excluded: the entry's own
   *  element re-emitted by an earlier iteration, Nodes (a node never
   *  contains a node) and leaf tasks (a self-closing <Log If=.../> on the
   *  same line "spans" the node but holds nothing). Spans, not identity of
   *  lines: a <Do> and its <Node> on one line is still a Do around a Node. */
  const containersOf = (idx, depth = 0) => {
    const me = resolved[idx];
    const file = me.elem.file, s0 = me.elem.line, s1 = spanEnd(me);
    const lastPerElement = new Map();
    for (let i = 0; i < idx; i++) {
      const r = resolved[i];
      if (!isGuarded(r) || r.elem === me.elem || r.elem.tag === "Node" || r.elem.file !== file) continue;
      if (!r.elem.children.length) continue;
      if (r.elem.line <= s0 && spanEnd(r) >= s1) lastPerElement.set(r.elem, r);
    }
    const out = [...lastPerElement.values()].map((r) => guardOf(r, ownerLabel(r)));
    out.push(...expandGuards(idx, depth));
    return out;
  };

  /** A node written inside a <Macro> body runs where the macro is
   *  <Expand>ed, so the Expand's guards -- and whatever encloses the Expand
   *  -- are its guards too. Spans cannot see that (the body's elements live
   *  at the Macro's lines, the guard at the Expand's), but emission order
   *  can: the body is emitted right after the Expand entry that triggered
   *  it, so the LAST Expand of that macro before this entry is the one. */
  const expandGuards = (idx, depth) => {
    if (depth > 8) return [];                           // macros expanding macros, bounded
    const me = resolved[idx];
    const macro = resolved.find((r) =>
      r.elem.tag === "Macro" && r.elem !== me.elem && r.elem.file === me.elem.file &&
      r.elem.line <= me.elem.line && spanEnd(r) >= spanEnd(me));
    if (!macro) return [];
    const macroName = macro.attrs.get("Name") || "";
    let expandIdx = -1;
    for (let i = idx - 1; i >= 0; i--) {
      const r = resolved[i];
      if (r.elem.tag === "Expand" && (r.attrs.get("Name") || "") === macroName) { expandIdx = i; break; }
    }
    if (expandIdx < 0) return [];
    const exp = resolved[expandIdx];
    const out = [];
    if (isGuarded(exp)) out.push(guardOf(exp, `Expand at ${base(exp.elem.file)}:${exp.elem.line}`));
    out.push(...containersOf(expandIdx, depth + 1));
    out.push(...fileGuards(exp.elem.file, expandIdx));
    return out;
  };

  // Which picked file an include's resolved key actually landed on (a tail
  // match stores the fragment under a different key than the one asked for).
  const matchedTo = new Map(((includes && includes.matched) || []).map((m) => [normCase(m.requested), m.matched]));

  /** Guards that reach a whole FILE from outside it: the <Include If=...>
   *  that brought it in (the last one emitted before `beforeIdx`), what
   *  encloses that Include, and -- recursively -- what reaches ITS file. */
  const fileGuardsMemo = new Map();
  const fileGuards = (file, beforeIdx, seen) => {
    const key = `${normCase(file)}@${beforeIdx}`;
    if (fileGuardsMemo.has(key)) return fileGuardsMemo.get(key);
    const chain = seen || new Set();
    if (chain.has(normCase(file))) return [];           // a cycle: the evaluator already reported it
    chain.add(normCase(file));
    let includeIdx = -1;
    for (let i = 0; i < beforeIdx; i++) {
      const r = resolved[i];
      if (r.elem.tag !== "Include") continue;
      for (const rel of splitList(r.attrs.get("Script") || "")) {
        const requested = resolveInclude(r.elem.file, rel);
        const target = matchedTo.get(normCase(requested)) || requested;
        if (normCase(target) === normCase(file)) includeIdx = i;
      }
    }
    const out = [];
    if (includeIdx >= 0) {
      const inc = resolved[includeIdx];
      if (isGuarded(inc)) out.push(guardOf(inc, `Include at ${base(inc.elem.file)}:${inc.elem.line}`));
      out.push(...containersOf(includeIdx));
      out.push(...fileGuards(inc.elem.file, includeIdx, chain));
    }
    fileGuardsMemo.set(key, out);
    return out;
  };

  const guardsAround = (idx, ownLabel) => {
    const r = resolved[idx];
    const guards = [];
    if (isGuarded(r)) guards.push(guardOf(r, ownLabel));
    guards.push(...containersOf(idx));
    guards.push(...fileGuards(r.elem.file, idx));
    return guards;
  };

  const nodes = new Map();
  const counts = { active: 0, inactive: 0, unknown: 0 };
  for (const name of graph.nodes.keys()) {
    const idx = resolved.findIndex((r) => r.elem.tag === "Node" && (r.attrs.get("Name") || "") === name);
    const guards = idx >= 0 ? guardsAround(idx, "node") : [];
    const state = combine(guards.map((g) => g.verdict));
    nodes.set(name, { state, guards });
    counts[state]++;
  }

  // A lane is as alive as its most alive opening: an agent re-opened under
  // two guards runs if either holds.
  const agents = new Map();
  for (const agentName of graph.agents.keys()) {
    const openings = [];
    resolved.forEach((r, i) => {
      if (r.elem.tag === "Agent" && (r.attrs.get("Name") || "") === agentName) openings.push(i);
    });
    const per = openings.map((i) => {
      const guards = guardsAround(i, "agent");
      return { state: combine(guards.map((g) => g.verdict)), guards };
    });
    const states = per.map((p) => p.state);
    const state = !states.length || states.includes("active") ? "active"
      : states.includes("unknown") ? "unknown" : "inactive";
    agents.set(agentName, { state, guards: per.flatMap((p) => p.guards) });
  }

  return { nodes, agents, counts };
}
