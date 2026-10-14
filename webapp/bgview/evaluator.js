/* bgview/evaluator.js -- scope stack, property expansion, control flow.
 *
 * Port of bgview/evaluator.py. This is where the two semantics §G calls
 * invisible actually live: parse-time top-to-bottom expansion (V11) and the
 * scope stack (R6).
 *
 * The one design point worth restating, because it looks like a bug until
 * you know why: `If=` is CAPTURED but never EVALUATED. Every branch of every
 * Switch/Case is walked, and a Do/ForEach body is always entered. The tool
 * reports the union of what any option-set could produce; deciding a guard
 * is the condition algebra's job (D12), and a detector that acts on a
 * guarded declaration has to say so (V33).
 */
"use strict";

import { Finding, Severity } from "./findings.js";
import { splitList, iterRefs, applySlice } from "./lexer.js";
import { BgError } from "./loader.js";

/* V22/R17: the engine built-ins, pre-loaded so D1 never fires on them.
 * Values are plausible static stand-ins -- this is static analysis of SOURCE,
 * so there is no real P4 branch or host to query.
 *
 * RootDir is null ON PURPOSE: the engine genuinely leaves it null while
 * preprocessing, and V12 case (b) exists to make that survivable. In JS the
 * distinction between "absent" and "present but null" is easy to lose, so
 * lookups below return an explicit {found, value} pair rather than leaning on
 * `undefined`.
 *
 * ProjectFile/ProjectName/ProjectDir are deliberately ABSENT. The engine sets
 * them only when a project is supplied; defining them unconditionally was a
 * real modelling bug (§B.5) that manufactured four phantom errors on Epic's
 * corpus. Sixteen, not nineteen. */
export const BUILTINS = new Map(Object.entries({
  Branch: "Unknown",
  Depot: "Unknown",
  EscapedBranch: "Unknown",
  Change: "0",
  CodeChange: "0",
  IsBuildMachine: "false",
  HostPlatform: "Win64",
  HostArchitecture: "X64",
  RestrictedFolderNames: "NotForLicensees;NoRedist;CarefullyRedist",
  RestrictedFolderFilter: ".../NotForLicensees/...;.../NoRedist/...;.../CarefullyRedist/...",
  DataDrivenPlatforms: "Windows;Android;IOS;Mac;Linux",
  EngineMajorVersion: "5",
  EngineMinorVersion: "8",
  EnginePatchVersion: "0",
  EngineCompatibleChange: "0",
})).set("RootDir", null);

// The Python carries `assert len(BUILTINS) == 16`, and it earned its keep --
// it caught exactly the §B.5 change. Kept, as a throw at module load.
if (BUILTINS.size !== 16) {
  throw new Error(`expected 16 unconditional built-ins, got ${BUILTINS.size}`);
}

const MAX_EXPAND_DEPTH = 32;

// R14 kinds that need generic attribute expansion and one Resolved entry --
// no child walk, no name binding.
const LEAF_STRUCTURAL = new Set([
  "Regex", "StringOp", "Aggregate", "Artifact", "Report",
  "Badge", "Label", "Trace", "Warning", "Error",
]);

/* ------------------------------------------------------------ paths ---- */

/** Resolve `rel` against the directory of `fromFile`, POSIX-style.
 *
 * The browser has no `pathlib`. Paths here are virtual (they name entries in
 * the picked-file map, not a disk), so this only has to be consistent with
 * how the picker keys that map -- but it must still collapse `.`/`..` and
 * unify separators, because BuildGraph scripts mix `\` and `/` freely and
 * `<Include Script="../Shared.xml"/>` is ordinary.
 */
export function resolveInclude(fromFile, rel) {
  const base = String(fromFile).replace(/\\/g, "/").split("/").slice(0, -1);
  const parts = String(rel).replace(/\\/g, "/").split("/");
  const out = parts[0] === "" ? [""] : base.slice();
  for (const part of parts) {
    if (part === "" || part === ".") continue;
    if (part === "..") { if (out.length) out.pop(); continue; }
    out.push(part);
  }
  return out.join("/");
}

/* ------------------------------------------------------- evaluator ---- */

class Evaluator {
  constructor(schema, overrides, loaderFn) {
    this._schema = schema;
    this._overrides = overrides || new Map();
    this._loader = loaderFn;

    // V11/R6: scope stack, seeded with a COPY of BUILTINS so one run can
    // never leak into another. Matches the engine, which seeds its one
    // global scope before reading a single element.
    this._scopes = [new Map(BUILTINS)];
    // Parallel to _scopes: names written in some CHILD of that scope. Drives D21.
    this._shadow = [new Set()];
    this._agentStack = [];
    this._nodeStack = [];
    this._includeStack = [];
    this._expandDepth = 0;
    this._macros = new Map();

    this.resolved = [];
    this.findings = [];
    this.options = new Map();
    this.propDefs = [];
    this.propReads = [];
    this.sources = new Map();
  }

  _recordSource(root) {
    // First one wins: a diamond include reads the same file twice and both
    // reads are the same text, so overwriting only churns.
    if (root.file && !this.sources.has(root.file)) this.sources.set(root.file, root.sourceText);
  }

  _enterScope() { this._scopes.push(new Map()); this._shadow.push(new Set()); }
  _leaveScope() { this._scopes.pop(); this._shadow.pop(); }

  /** R6: innermost-first, first hit wins. `{found:true, value:null}` is the
   *  V12(b) "defined but null" case, which is NOT the same as not found. */
  _lookup(name) {
    for (let i = this._scopes.length - 1; i >= 0; i--) {
      if (this._scopes[i].has(name)) return { found: true, value: this._scopes[i].get(name) };
    }
    return { found: false, value: null };
  }

  /** SetPropertyValue (R6): target the OUTERMOST scope already holding
   *  `name`, else the current one. Also maintains the engine's shadow stack
   *  and emits D21 (R44). `elem === null` suppresses the check, which is what
   *  built-in seeding wants -- the engine seeds with a null element too. */
  _assign(name, value, elem) {
    let idx = 0;
    while (idx < this._scopes.length - 1 && !this._scopes[idx].has(name)) idx++;

    const folded = name.toLowerCase();  // the shadow sets are OrdinalIgnoreCase
    if (elem && this._shadow[idx].has(folded)) {
      this._finding(elem, "D21", Severity.ERROR,
        `Property '${name}' was already used in a child scope; the engine ` +
        `refuses this. Move the definition before the earlier use if they ` +
        `are meant to share scope, or use a different name ` +
        `(engine reports an error)`);
      // The engine returns WITHOUT assigning. We assign anyway and keep
      // going: a script in this state never builds, so there is no real
      // downstream state to be faithful to, and leaving the name unbound
      // would manufacture cascading D1s that say nothing new.
    } else {
      for (let outer = 0; outer < idx; outer++) this._shadow[outer].add(folded);
    }
    this._scopes[idx].set(name, value);
  }

  _currentNode() { return this._nodeStack.length ? this._nodeStack[this._nodeStack.length - 1] : null; }

  _finding(elem, detector, severity, message) {
    this.findings.push(new Finding({
      file: elem.file, line: elem.line, severity, detector, message, node: this._currentNode(),
    }));
  }

  /** Expand every `$(...)` against the scope stack AS IT STANDS NOW (V11).
   *
   * Mirrors ExpandProperties' right-to-left mutate-and-rescan: repeatedly
   * resolve the rightmost unresolved reference, so nested refs resolve
   * inside-out. `searchEnd` reproduces the engine's LastIndexOf bound --
   * once an occurrence is left untouched (V12 outcome b), the next search is
   * restricted to strictly BEFORE its start, so the same un-substituted
   * occurrence is never re-selected. Without that bound this loop either
   * spins forever or double-counts the propReads entry and double-reports a
   * malformed slice.
   */
  _expand(elem, text, resolvedIndex) {
    let result = text;
    let searchEnd = result.length;
    for (;;) {
      const refs = iterRefs(result).filter((r) => r.start < searchEnd);
      if (!refs.length) return result;
      const ref = refs[refs.length - 1];

      if (ref.name.includes("$(")) {
        // iterRefs sorts innermost-last so refs[-1] should never look like
        // this; guard defensively rather than treat a dynamic partial name
        // as a lookup key.
        searchEnd = ref.start;
        continue;
      }

      this.propReads.push([ref.name, elem, resolvedIndex]);
      const { found, value } = this._lookup(ref.name);

      if (ref.malformed) {
        // V12a: the engine's Int32.Parse would THROW. We survive by
        // reporting once and substituting best-effort so this occurrence is
        // always consumed, hence never double-reported.
        this._finding(elem, "D1", Severity.WARN,
          `Property reference '${ref.raw}' has a malformed ':N' slice`);
        const replacement = (found && value !== null) ? value : "";
        result = result.slice(0, ref.start) + replacement + result.slice(ref.end);
        searchEnd = result.length;
        continue;
      }
      if (!found) {                                   // V12 outcome (a)
        this._finding(elem, "D1", Severity.WARN, `Property '${ref.name}' is not defined`);
        result = result.slice(0, ref.start) + result.slice(ref.end);
        searchEnd = result.length;
        continue;
      }
      if (value === null) {
        // V12 outcome (b): defined but null -- NO finding, and the literal
        // "$(Name)" text stays verbatim in the output.
        searchEnd = ref.start;
        continue;
      }
      result = result.slice(0, ref.start) + applySlice(value, ref.sliceN) + result.slice(ref.end);
      searchEnd = result.length;
    }
  }

  /** Expand every attribute and record one Resolved entry, in EXECUTION
   *  order (V23) -- at the moment this element is visited, not doc order. */
  _emitLeaf(elem) {
    const idx = this.resolved.length;
    const attrs = new Map();
    for (const [k, v] of Object.entries(elem.attrib)) attrs.set(k, this._expand(elem, v, idx));
    const resolved = {
      elem, attrs,
      agent: this._agentStack.length ? this._agentStack[this._agentStack.length - 1] : null,
      node: this._nodeStack.length ? this._nodeStack[this._nodeStack.length - 1] : null,
      rawIf: Object.prototype.hasOwnProperty.call(elem.attrib, "If") ? elem.attrib.If : null,
      expandDepth: this._expandDepth,
    };
    this.resolved.push(resolved);
    return resolved;
  }

  _walkBody(children) { for (const child of children) this._visit(child); }

  _visit(elem) {
    switch (elem.tag) {
      case "Include": return this._handleInclude(elem);
      case "Option": return this._handleOption(elem);
      case "Property": return this._handleProperty(elem);
      case "EnvVar": return this._handleEnvVar(elem);
      case "Macro": return this._handleMacro(elem);
      case "Extend": return this._handleExtend(elem);
      case "Agent": return this._handleAgent(elem);
      case "Node": return this._handleNode(elem);
      case "Do": return this._handleDo(elem);
      case "Switch": return this._handleSwitch(elem);
      case "ForEach": return this._handleForEach(elem);
      case "Expand": return this._handleExpand(elem);
      default:
        if (LEAF_STRUCTURAL.has(elem.tag) || this._schema.knownElement(elem.tag)) {
          this._emitLeaf(elem);
          return;
        }
        // V9: loud, never a silent skip. Children are NOT walked -- their
        // shape is unknown, so there is nothing safe to recurse into.
        this._finding(elem, "D14", Severity.WARN, `Unsupported/unrecognized element <${elem.tag}>`);
    }
  }

  _handleInclude(elem) {
    const r = this._emitLeaf(elem);
    for (const rel of splitList(r.attrs.get("Script") || "")) {
      const key = resolveInclude(elem.file, rel);
      if (this._includeStack.includes(key)) {
        // A real cycle would recurse until the stack blows. A DIAMOND is not
        // a cycle -- `key` is checked against the ANCESTOR chain only, not a
        // global seen-set, so legitimate repeated includes from different
        // branches still resolve, matching the engine's default.
        this._finding(elem, "D14", Severity.WARN,
          `Include cycle: '${rel}' (resolved to '${key}') is already being included`);
        continue;
      }
      this._includeStack.push(key);
      try {
        let includedRoot;
        try {
          includedRoot = this._loader(key);
        } catch (exc) {
          // V47: a script including a file we cannot read is a DEFECT IN
          // THAT SCRIPT, not a reason to abandon the analysis -- and in a
          // browser, where someone can pick a single .xml, every sibling
          // include is missing by construction. Report it the way V9 reports
          // everything else we cannot model, and keep walking, so what comes
          // after the include is still analysed.
          if (!(exc instanceof BgError)) throw exc;
          this._finding(elem, "D14", Severity.WARN,
            `Cannot read included script '${rel}' (resolved to '${key}'): ${exc.message}`);
          continue;
        }
        this._recordSource(includedRoot);
        this._walkBody(includedRoot.children);
      } finally {
        this._includeStack.pop();
      }
    }
  }

  _handleOption(elem) {
    const r = this._emitLeaf(elem);
    const name = r.attrs.get("Name") || "";
    if (!name) return;
    // R26: already defined by an earlier Property/Option/EnvVar -- the
    // engine does NOT re-register or reassign, it only validates Restrict
    // against the existing value. Leave it alone.
    if (this._lookup(name).found) return;
    const def = r.attrs.get("DefaultValue") || "";
    const restrict = r.attrs.has("Restrict") ? r.attrs.get("Restrict") : null;
    const value = this._overrides.has(name) ? this._overrides.get(name) : def;
    this._assign(name, value, elem);
    this.options.set(name, { name, default: def, restrict });
  }

  _handleProperty(elem) {
    const r = this._emitLeaf(elem);
    const idx = this.resolved.length - 1;
    const name = r.attrs.get("Name") || "";
    if (!name) return;
    this._assign(name, r.attrs.get("Value") || "", elem);
    this.propDefs.push([name, elem, idx]);
  }

  _handleEnvVar(elem) {
    const r = this._emitLeaf(elem);
    const idx = this.resolved.length - 1;
    const name = r.attrs.get("Name") || "";
    if (!name) return;
    // Never reads a real environment: this is static analysis of SOURCE, and
    // binding to whatever machine happens to run the tool would make
    // findings differ between machines. "" is also the engine's own fallback
    // for an unset variable, so it is faithful, not merely safe.
    this._assign(name, "", elem);
    this.propDefs.push([name, elem, idx]);
  }

  _handleMacro(elem) {
    const r = this._emitLeaf(elem);   // records <Macro>; body NOT walked now
    const name = r.attrs.get("Name") || "";
    if (!name) return;
    if (this._macros.has(name)) {
      // D17/V31: the engine LogErrors here. Being silent where the engine
      // itself errors is a coverage hole. Keep-first matches what the engine
      // does after it reports.
      this._finding(elem, "D17", Severity.ERROR,
        `Macro '${name}' has already been declared; ` +
        `this duplicate declaration is ignored (engine reports an error)`);
      return;
    }
    const required = splitList(r.attrs.get("Arguments") || "");
    const optional = splitList(r.attrs.get("OptionalArguments") || "");
    this._macros.set(name, {
      name, argOrder: required.concat(optional), numRequired: required.length, containers: [elem],
    });
  }

  _handleExtend(elem) {
    const r = this._emitLeaf(elem);
    const name = r.attrs.get("Name") || "";
    const macro = this._macros.get(name);
    if (macro) macro.containers.push(elem);
    else {
      this._finding(elem, "D17", Severity.ERROR,
        `Extend refers to macro '${name}', which has not been declared`);
    }
  }

  _handleAgent(elem) {
    const r = this._emitLeaf(elem);
    this._agentStack.push(r.attrs.get("Name") || "");
    this._enterScope();                      // ReadAgentBodyAsync: EnterScope()
    try { this._walkBody(elem.children); }
    finally { this._leaveScope(); this._agentStack.pop(); }
  }

  _handleNode(elem) {
    const r = this._emitLeaf(elem);
    this._nodeStack.push(r.attrs.get("Name") || "");
    this._enterScope();                      // ReadNodeBodyAsync: EnterScope()
    try { this._walkBody(elem.children); }
    finally { this._leaveScope(); this._nodeStack.pop(); }
  }

  _handleDo(elem) {
    this._emitLeaf(elem);
    // No new scope (ReadBlockAsync has none) and no If= evaluation: the body
    // is always walked.
    this._walkBody(elem.children);
  }

  _handleSwitch(elem) {
    this._emitLeaf(elem);
    for (const branch of elem.children) {
      // Every direct child is its own branch -- ReadSwitchAsync does not
      // actually check the tag name. The engine stops at the first match;
      // we walk them ALL, exposing the union of possible bodies.
      this._emitLeaf(branch);
      this._walkBody(branch.children);
    }
  }

  _handleForEach(elem) {
    const r = this._emitLeaf(elem);
    const name = r.attrs.get("Name") || "";
    const values = splitList(r.attrs.get("Values") || "");
    if (!name) return;
    // ONE scope for the whole loop, matching ReadForEachAsync: EnterScope()
    // once, then the loop variable is MUTATED per iteration rather than the
    // scope being re-entered -- so a <Property> written in the body on
    // iteration 1 is still visible on iteration 2, same as the engine.
    this._enterScope();
    try {
      for (const value of values) {
        this._scopes[this._scopes.length - 1].set(name, value);
        this._walkBody(elem.children);       // V23: body emitted once per value
      }
    } finally { this._leaveScope(); }
  }

  _handleExpand(elem) {
    const r = this._emitLeaf(elem);          // expands ALL attrs once, args included
    const name = r.attrs.get("Name") || "";
    const macro = this._macros.get(name);
    if (!macro) {
      // The graph is genuinely broken here -- a whole body silently fails to
      // expand -- so error, not warn.
      this._finding(elem, "D17", Severity.ERROR,
        `Expand refers to macro '${name}', which does not exist; ` +
        `its body contributes nothing to the graph`);
      return;
    }
    if (this._expandDepth >= MAX_EXPAND_DEPTH) {
      this._finding(elem, "D14", Severity.WARN,
        `Macro '${name}' expansion exceeds max recursion depth (${MAX_EXPAND_DEPTH}); ` +
        `further expansion suppressed`);
      return;
    }

    // R15: arguments are values ALREADY expanded (by _emitLeaf above) in the
    // scope stack as it stands at the EXPANSION site. That is the whole
    // mechanism behind "a macro body resolves in the lexical scope of the
    // expansion site": bind those resolved values into one new scope, then
    // walk the body using the current stack, exactly as ReadExpandAsync does.
    const bound = new Map();
    for (const a of macro.argOrder) if (r.attrs.has(a)) bound.set(a, r.attrs.get(a));

    // Engine LogWarns "does not take an argument" -- almost always a typo'd
    // argument name, which otherwise silently does nothing.
    const argSet = new Set(macro.argOrder);
    const supplied = [...r.attrs.keys()].filter((k) => k !== "Name" && k !== "If" && !argSet.has(k));
    for (const s of supplied.sort()) {
      this._finding(elem, "D17", Severity.WARN,
        `Macro '${name}' does not take an argument '${s}'; it is ignored`);
    }

    const missing = macro.argOrder.slice(0, macro.numRequired).filter((a) => !bound.has(a));
    if (missing.length) {
      // Engine LogWarns, then SKIPS the expansion. Skipping silently is the
      // dangerous part: an entire macro body vanishes with no trace.
      for (const argName of missing) {
        this._finding(elem, "D17", Severity.WARN,
          `Macro '${name}' is missing required argument '${argName}'; ` +
          `the whole macro body is skipped`);
      }
      return;
    }
    for (const argName of macro.argOrder) if (!bound.has(argName)) bound.set(argName, "");

    this._enterScope();
    for (const [argName, value] of bound) this._scopes[this._scopes.length - 1].set(argName, value);
    this._expandDepth += 1;
    try {
      for (const container of macro.containers) this._walkBody(container.children);
    } finally { this._expandDepth -= 1; this._leaveScope(); }
  }
}

/** The three project-conditional built-ins. Without a project they stay
 *  undefined, exactly as in a real engine run with no -project= (§B.5). */
export function projectProperties(projectPath) {
  const p = String(projectPath).replace(/\\/g, "/");
  const dir = p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "";
  const base = p.slice(p.lastIndexOf("/") + 1);
  const stem = base.includes(".") ? base.slice(0, base.lastIndexOf(".")) : base;
  return new Map([["ProjectFile", p], ["ProjectName", stem], ["ProjectDir", dir]]);
}

/** Walk `root` top-to-bottom (V11), expanding properties (V12/V12a) and
 *  resolving control flow into a flat, POST-expansion execution-order trace
 *  (V23). `If=` is captured raw but never evaluated -- every branch is taken. */
export function evaluate(root, schema, overrides, loaderFn, project) {
  const ev = new Evaluator(schema, overrides, loaderFn);
  if (project) for (const [k, v] of projectProperties(project)) ev._scopes[0].set(k, v);
  ev._recordSource(root);
  ev._walkBody(root.children);
  return {
    resolved: ev.resolved,
    findings: ev.findings,
    options: ev.options,
    propDefs: ev.propDefs,
    propReads: ev.propReads,
    sources: ev.sources,
  };
}
