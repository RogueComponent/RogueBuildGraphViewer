/* bgview/algebra.js -- symbolic evaluation over an abstract string domain.
 *
 * Port of bgview/algebra.py. Answers "can this guard ever be true / can it
 * ever be false" without a SAT solver, by enumerating the options a
 * condition actually references over a small abstract domain.
 *
 * The rule that keeps it honest is V10: `Exists()` touches the filesystem,
 * so it is OPAQUE and a condition holding one is neither unsat nor
 * tautological. UNKNOWN is a real third value here, never a stand-in for
 * false -- guessing either way manufactures confidently-wrong findings,
 * which is the one failure mode this whole tool exists to avoid.
 */
"use strict";

import { iterRefs, applySlice } from "./lexer.js";

/** Opaque -- cannot be decided symbolically. A unique symbol rather than
 *  null/undefined, both of which JS coerces silently: `if (UNKNOWN)` on a
 *  null would quietly mean "false", which is exactly the V10 mistake. Every
 *  check below is an explicit `=== UNKNOWN`. */
export const UNKNOWN = Symbol("UNKNOWN");

/* A Restrict that is nothing but '|'-separated literal branches -- no regex
 * metacharacters. Grounded against every Restrict= shipped in the corpus:
 * literal alternations really do look like "true|false", "Win64|Linux|Mac",
 * "Development|Debug|Shipping". Every OTHER real Restrict is an actual regex
 * (".+", "[^ ]*", "^[0-9]{1,4}$", ...) and each contains a character outside
 * this class, so it correctly falls through to abstract sampling. */
const LITERAL_BRANCH = /^[A-Za-z0-9_\- ]+$/;

/* "Definitely nonempty, definitely not a real value" sample. Starts with a
 * raw SOH so it can never collide with a real option value -- XML 1.0
 * forbids unescaped control characters in attribute content, so no shipped
 * DefaultValue can equal this. */
const NONEMPTY_SAMPLE = "nonempty";

function literalAlternationDomain(restrict) {
  if (!restrict) return null;
  const branches = restrict.split("|");
  return branches.every((b) => LITERAL_BRANCH.test(b)) ? branches : null;
}

/** The finite value list a literal-alternation `Restrict` allows, or null
 *  when the Restrict is a real regex (or absent). Exported for the web
 *  Options panel, which turns a finite domain into a <select>; the rule is
 *  the same one classify() enumerates over, so the panel and the symbolic
 *  algebra cannot disagree about what "the possible values" are. */
export const literalDomain = (restrict) => literalAlternationDomain(restrict || null);

function dedupe(items) {
  const seen = new Set();
  const out = [];
  for (const item of items) if (!seen.has(item)) { seen.add(item); out.push(item); }
  return out;
}

/** One <Option>, as needed for symbolic enumeration. */
export class Opt {
  constructor(name, def, restrict) { this.name = name; this.default = def; this.restrict = restrict; }

  /** The finite set of sample values classify() enumerates over. A Restrict
   *  that is a simple literal alternation contributes those literals exactly
   *  -- the option can ONLY hold one of them, so there is nothing to
   *  abstract. Anything else falls back to {default, empty, nonempty}:
   *  emptiness tests are 37 of the corpus's 136 conditions (R21), so "" has
   *  to be in the sample. */
  domain() {
    const literals = this.restrict ? literalAlternationDomain(this.restrict) : null;
    if (literals) return literals;
    return dedupe([this.default, "", NONEMPTY_SAMPLE]);
  }

  static fromObject(d) { return new Opt(d.name, d.default || "", d.restrict ?? null); }
}

/* Scalars flowing through evalNode are boolean | number | string | UNKNOWN.
 * JS has no bool-is-int subtype problem, but it has a worse one: `==`
 * coerces. Everything below compares explicitly. */

function asStr(value) {
  if (value === true) return "True";
  if (value === false) return "False";
  if (typeof value === "number") return String(value);
  return value;
}

/** V18 numeric operand. An already-numeric scalar (a Length() result) is
 *  used as-is; a string is accepted only if it parses CLEANLY as an integer.
 *  Booleans are excluded: a bare true/false is never numeric in a condition.
 *
 *  Deliberately not Number(): that accepts "", " ", "0x10", "1e3" and "1.5",
 *  none of which Python's int() takes, and each would silently change a
 *  comparison's verdict. */
function tryInt(value) {
  if (typeof value === "boolean") return null;
  if (typeof value === "number") return Number.isInteger(value) ? value : null;
  if (typeof value !== "string") return null;
  const t = value.trim();
  if (!/^[+-]?\d+$/.test(t)) return null;
  const n = Number(t);
  return Number.isSafeInteger(n) ? n : null;
}

/** Engine truthiness: true iff the string form equals "true"
 *  case-insensitively -- NOT C-style nonzero-is-true. */
function toBool(value) {
  if (value === UNKNOWN) return UNKNOWN;
  return asStr(value).toLowerCase() === "true";
}

/** Resolve every `$(...)` against `env`, honouring the ':N' slice.
 *
 * Mirrors the engine's mutate-and-rescan order: repeatedly take the LAST
 * (rightmost-starting) ref, resolve, splice, re-scan -- which is what
 * resolves "$(Outer$(Inner))" inner-first without relying on a position
 * captured before an earlier splice shifted it.
 *
 * A name absent from `env` makes the WHOLE leaf UNKNOWN -- never silently
 * empty, which would manufacture false unsat/taut verdicts. A name PRESENT
 * with a null value (the RootDir builtin) is left as literal text, V12(b),
 * and tracked in `inert` so the rescan never re-picks it: splicing a ref's
 * own raw text over itself is a no-op and would loop forever.
 */
function substitute(text, env) {
  let s = text;
  const inert = new Set();
  for (;;) {
    const refs = iterRefs(s).filter((r) => !inert.has(r.raw));
    if (!refs.length) return s;
    const ref = refs[refs.length - 1];
    if (!env.has(ref.name)) return UNKNOWN;
    const value = env.get(ref.name);
    if (value === null || value === undefined) { inert.add(ref.raw); continue; }
    s = s.slice(0, ref.start) + applySlice(value, ref.sliceN) + s.slice(ref.end);
  }
}

function evalNode(node, env) {
  switch (node.kind) {
    case "Or": return evalOr(node, env);
    case "And": return evalAnd(node, env);
    case "Cmp": return evalCmp(node, env);
    case "Not": {
      const operand = toBool(evalNode(node.operand, env));
      return operand === UNKNOWN ? UNKNOWN : !operand;
    }
    case "Call": return evalCall(node, env);
    case "Str": case "Ident": return substitute(node.value, env);
    default: throw new TypeError(`unrecognised condition AST node: ${node.kind}`);
  }
}

/** Kleene (strong 3-valued) AND. `False And <anything>` is False without
 *  evaluating the right side at all -- so `false And Exists('x')` decides
 *  False and never touches the opaque call. */
function evalAnd(node, env) {
  const left = toBool(evalNode(node.left, env));
  if (left === false) return false;
  const right = toBool(evalNode(node.right, env));
  if (left === true) return right;
  // left UNKNOWN: a False on the right still forces False.
  return right === false ? false : UNKNOWN;
}

/** Kleene OR, mirroring evalAnd. */
function evalOr(node, env) {
  const left = toBool(evalNode(node.left, env));
  if (left === true) return true;
  const right = toBool(evalNode(node.right, env));
  if (left === false) return right;
  return right === true ? true : UNKNOWN;
}

function evalCmp(node, env) {
  const left = evalNode(node.left, env);
  const right = evalNode(node.right, env);
  if (left === UNKNOWN || right === UNKNOWN) return UNKNOWN;
  const op = node.op;
  if (op === "==" || op === "!=") {
    // V19: scalar comparison is case-INsensitive throughout.
    const equal = asStr(left).toLowerCase() === asStr(right).toLowerCase();
    return op === "==" ? equal : !equal;
  }
  const li = tryInt(left);
  const ri = tryInt(right);
  if (li === null || ri === null) return UNKNOWN;
  switch (op) {
    case "<": return li < ri;
    case "<=": return li <= ri;
    case ">": return li > ri;
    case ">=": return li >= ri;
    default: throw new TypeError(`unrecognised comparison operator: ${op}`);
  }
}

function evalCall(node, env) {
  switch (node.name) {
    case "Exists":
      // V10: touches the filesystem. Opaque whatever the argument is --
      // never even evaluate it, let alone guess.
      return UNKNOWN;
    case "HasTrailingSlash": {
      // V10a: syntactically decidable, unlike Exists.
      const arg = evalNode(node.args[0], env);
      if (arg === UNKNOWN) return UNKNOWN;
      const s = asStr(arg);
      return s.endsWith("/") || s.endsWith("\\");
    }
    case "Length": {
      const arg = evalNode(node.args[0], env);
      if (arg === UNKNOWN) return UNKNOWN;
      return asStr(arg).length;             // number -- feeds the V18 numeric compare
    }
    case "Contains": {
      const hay = evalNode(node.args[0], env);
      if (hay === UNKNOWN) return UNKNOWN;
      const needle = evalNode(node.args[1], env);
      if (needle === UNKNOWN) return UNKNOWN;
      return asStr(hay).includes(asStr(needle));
    }
    case "ContainsItem": {
      const hay = evalNode(node.args[0], env);
      if (hay === UNKNOWN) return UNKNOWN;
      const needle = evalNode(node.args[1], env);
      if (needle === UNKNOWN) return UNKNOWN;
      const sep = evalNode(node.args[2], env);
      if (sep === UNKNOWN) return UNKNOWN;
      const hayS = asStr(hay), needleS = asStr(needle), sepS = asStr(sep);
      // An empty separator is treated as "no delimiter found" (the whole
      // haystack is one item) rather than an error. No corpus usage passes
      // one; this only has to not crash.
      const items = sepS ? hayS.split(sepS) : [hayS];
      return items.includes(needleS);
    }
    default:
      throw new TypeError(`unrecognised Call name: ${node.name}`);
  }
}

/** Evaluate `ast` against one concrete env (Map name -> value, where value
 *  may be null for a null-valued builtin). Returns a boolean, or UNKNOWN. */
export function evaluate(ast, env) { return toBool(evalNode(ast, env)); }

/* Real conditions reference 1-3 options (compound And/Or is only 4 of 136,
 * R21), so this cap is never hit on real input -- it exists purely so a
 * pathological condition cannot hang the tab. */
const ENUM_CAP = 4096;

/** Every `$(Name)` base name appearing anywhere in the AST's leaves.
 *  Deliberately over-collects; classify() intersects against the real option
 *  set, so extras are discarded there rather than filtered twice. */
function referencedRefNames(node) {
  switch (node.kind) {
    case "Or": case "And": case "Cmp":
      return new Set([...referencedRefNames(node.left), ...referencedRefNames(node.right)]);
    case "Not": return referencedRefNames(node.operand);
    case "Call": {
      const names = new Set();
      for (const arg of node.args) for (const n of referencedRefNames(arg)) names.add(n);
      return names;
    }
    case "Str": case "Ident":
      return new Set(iterRefs(node.value).map((r) => r.name));
    default: throw new TypeError(`unrecognised condition AST node: ${node.kind}`);
  }
}

/** Bounded-enumeration satisfiability classification.
 *
 *   any combination UNKNOWN      -> "unknown"  (V10/V14: opaque is neither)
 *   every combination true       -> "taut"
 *   every combination false      -> "unsat"
 *   a mix                        -> "contingent"
 *   product exceeds the cap      -> "unknown"  (honest degradation, checked
 *                                   BEFORE enumerating so nothing can hang)
 *
 * @param opts  Map name -> Opt
 * @param baseEnv Map name -> value
 */
export function classify(ast, opts, baseEnv) {
  const referenced = [...referencedRefNames(ast)].filter((n) => opts.has(n)).sort();
  const domains = referenced.map((n) => opts.get(n).domain());

  let total = 1;
  for (const d of domains) total *= Math.max(d.length, 1);
  if (total > ENUM_CAP) return "unknown";

  let sawTrue = false;
  let sawFalse = false;
  const combos = cartesian(domains);
  for (const combo of combos) {
    const env = new Map(baseEnv);
    referenced.forEach((name, i) => env.set(name, combo[i]));
    const outcome = evaluate(ast, env);
    if (outcome === UNKNOWN) return "unknown";
    if (outcome) sawTrue = true; else sawFalse = true;
  }
  if (sawTrue && sawFalse) return "contingent";
  return sawTrue ? "taut" : "unsat";
}

/** itertools.product. With no domains it yields ONE empty combination --
 *  not zero -- which is what makes a condition referencing no options still
 *  get evaluated once against baseEnv. */
function cartesian(domains) {
  let out = [[]];
  for (const d of domains) {
    const next = [];
    for (const prefix of out) for (const v of d) next.push([...prefix, v]);
    out = next;
  }
  return out;
}
