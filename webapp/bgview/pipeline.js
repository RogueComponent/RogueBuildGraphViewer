/* bgview/pipeline.js -- the one analysis pipeline.
 *
 *   schema -> loadString -> evaluate -> build -> runAll
 *
 * Everything that decides what a finding IS goes through here, so the picker
 * and any future caller cannot drift apart. Same reason the Python has a
 * pipeline module: V46 says one pipeline, and the way you get that is by
 * having exactly one place that lists these calls.
 *
 * The caller supplies a `files` Map of virtual path -> text. There is no
 * filesystem in a browser, and there does not need to be: <Include> only
 * ever needs paths relative to the including file, which is a lookup, not
 * an I/O operation.
 */
"use strict";

import { loadString, BgError } from "./loader.js";
import { evaluate, resolveInclude } from "./evaluator.js";
import { splitList } from "./lexer.js";
import { build } from "./model.js";
import { runAll } from "./detectors.js";
import { sortFindings, normCase } from "./findings.js";
import { literalDomain } from "./algebra.js";
import { activity } from "./activity.js";

/** Path -> case-folded segments, with `.`/`..` and empties dropped. Shared
 *  with the shell's "find the missing includes in a folder" flow, so both
 *  sides agree on what "the same path" means. */
export const pathSegments = (s, keepCase = false) => {
  // keepCase is for walking a real directory handle, where a case-sensitive
  // filesystem needs the author's spelling; matching always folds case.
  const src = keepCase ? String(s) : normCase(s);
  const parts = src.replace(/\\/g, "/").split("/").filter((x) => x && x !== "." && x !== "..");
  // An unexpanded `$(RootDir)` -- the built-in is null while preprocessing,
  // so the reference survives as text -- means "from the engine root". What
  // precedes it is the including file's directory, prepended by the relative
  // resolution, and says nothing about where the file is. Dropped.
  const marker = parts.findLastIndex((x) => x.includes("$("));
  return marker >= 0 ? parts.slice(marker + 1) : parts;
};

/** A path with a wildcard names a SET of files. bgview does not expand
 *  those (neither implementation does), so no single picked file can stand
 *  in for one -- the base `Inc/X.xml` next to the script is precisely NOT
 *  the per-platform overlays `Platforms/star/Build/Inc/X.xml` means. */
export const hasWildcard = (s) => /[*?]/.test(String(s));

/** The least a tail match may rest on: the file name plus TWO agreeing
 *  parent folders. A two-segment agreement (`Inc/X.xml`) is what a script's
 *  own base file shares with every overlay of the same name elsewhere in an
 *  engine tree, so it is no evidence at all about which one was meant. */
export const MIN_TAIL_SEGMENTS = 3;

/** Trailing-segment agreement between two segment lists: how many segments
 *  match from the end, or -1 when the SHORTER list does not match in full.
 *  One scoring rule for the loader's tail match and the shell's candidate
 *  ranking -- two copies would be free to disagree about which file an
 *  include means. */
export function scoreTail(want, have) {
  const n = Math.min(want.length, have.length);
  let k = 0;
  while (k < n && want[want.length - 1 - k] === have[have.length - 1 - k]) k++;
  return k < n ? -1 : k;
}

/**
 * @param {string} entry   virtual path of the script to analyse
 * @param {Map<string,string>} files  virtual path -> file text
 * @param {Schema} schema
 * @param {Map<string,string>} overrides  option-set, as the CLI's `--set NAME=VALUE`.
 *        Changes VALUES only -- what `$(Option)` expands to -- never which
 *        branches are walked (V58). Default: every <Option>'s DefaultValue.
 * @returns {{graph, findings, ev, entryFile, counts, includes, options, overrides, activity}}
 */
export function analyse(entry, files, schema, overrides = new Map()) {
  // Case-insensitive lookup, because BuildGraph scripts are authored on
  // Windows and an <Include Script="../Shared.xml"/> may not match the
  // picker's casing. Built once per run rather than per include.
  const byNorm = new Map();
  for (const [path, text] of files) byNorm.set(normCase(path), { path, text });

  // Include bookkeeping, returned with the report so the shell can SAY what
  // happened (V28: never silent): which includes were not in the pick, and
  // which were found only by matching the tail of their path.
  const includes = { missing: [], matched: [] };

  /** Second chance for an include the exact key misses.
   *
   *  The picked folder is the browser's whole filesystem, and real scripts
   *  reach outside it: `../../../Engine/Build/Graph/Tasks/Inc/X.xml` climbs
   *  above the folder most people pick, and `$(RootDir)/Engine/...` has no
   *  root to resolve against here (RootDir is null while preprocessing). On
   *  disk both land on a file that exists; in the pick that file is usually
   *  present under a SHORTER key. So compare paths from the END, segment by
   *  segment, and accept a candidate only if every segment of the shorter
   *  path matches AND it is the single best such candidate. Ambiguity --
   *  three `PGOProperties.xml` under three platform folders -- is a miss,
   *  never a guess. Exact lookup always wins; this runs only after it has
   *  failed, and every use is recorded in `includes.matched`. */
  const matchByTail = (p) => {
    if (hasWildcard(p)) return null;             // a set of files; no one file stands in
    const want = pathSegments(p);
    if (!want.length) return null;
    let best = null, bestK = 0, tied = false;
    for (const hit of byNorm.values()) {
      const k = scoreTail(want, pathSegments(hit.path));
      if (k < MIN_TAIL_SEGMENTS) continue;       // shorter path in full, AND enough of it
      if (k > bestK) { best = hit; bestK = k; tied = false; }
      else if (k === bestK) tied = true;
    }
    if (!best || tied) return null;
    includes.matched.push({ requested: p, matched: best.path });
    return best;
  };

  const loader = (p) => {
    const hit = byNorm.get(normCase(p)) || matchByTail(p);
    if (!hit) {
      includes.missing.push(p);
      // BgError specifically, because the evaluator catches exactly that to
      // turn a missing include into a D14 finding and carry on (V47). A
      // plain Error would escape and kill the whole analysis. The wildcard
      // case says what it is: the file may well be in the pick, and "not
      // among the files you picked" would send the reader looking for it.
      throw new BgError(hasWildcard(p)
        ? `cannot read '${p}': wildcard includes are not expanded yet`
        : `cannot read '${p}': not among the files you picked`);
    }
    return loadString(hit.text, hit.path);
  };

  const rootEntry = byNorm.get(normCase(entry));
  if (!rootEntry) throw new BgError(`cannot read '${entry}'`);

  const root = loadString(rootEntry.text, rootEntry.path);
  const ev = evaluate(root, schema, overrides, loader, null);
  const [graph, modelFindings] = build(ev, schema);

  // For each missing include, the path AS WRITTEN in the script. The key the
  // loader saw has the including file's directory prepended (an entry picked
  // as `Graph/Examples/Main.xml` turns `Inc/X.xml` into
  // `Graph/Examples/Inc/X.xml`), which says nothing about where the author
  // thinks the file is. The shell's fetch and drop flows measure their
  // evidence against the written path, so pointing at a folder called `Inc`
  // satisfies `Inc/X.xml` however deep the entry sits.
  const missingSet = new Set(includes.missing);
  includes.relOf = new Map();
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Include") continue;
    for (const rel of splitList(r.attrs.get("Script") || "")) {
      const key = resolveInclude(r.elem.file, rel);
      if (missingSet.has(key) && !includes.relOf.has(key)) includes.relOf.set(key, rel);
    }
  }

  // Same-named files in the pick that the evidence bar REFUSED, best
  // agreement first. The bar is right to refuse them on paths alone (a
  // flattened copy of an engine folder and a Restricted overlay's public
  // twin look identical from here), but the refusal must be VISIBLE and the
  // user's explicit choice is the evidence the paths lack (V28). The shell
  // offers each as a one-click alias.
  includes.candidates = new Map();
  for (const key of missingSet) {
    if (hasWildcard(key)) continue;
    const want = pathSegments(key);
    const name = want.at(-1);
    if (!name) continue;
    const cands = [];
    for (const hit of byNorm.values()) {
      const have = pathSegments(hit.path);
      if (have.at(-1) !== name) continue;
      let k = 0;
      const n = Math.min(want.length, have.length);
      while (k < n && want[want.length - 1 - k] === have[have.length - 1 - k]) k++;
      cands.push({ path: hit.path, agreement: k });
    }
    cands.sort((a, b) => b.agreement - a.agreement || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    if (cands.length) includes.candidates.set(key, cands.map((c) => c.path));
  }

  // Three sources, all real defects a user must see. Dropping any one
  // silently under-reports: every D1 comes from ev.findings, not runAll.
  const findings = sortFindings([...ev.findings, ...modelFindings, ...runAll(graph, ev, schema)]);

  const counts = { info: 0, warn: 0, error: 0 };
  for (const f of findings) counts[f.severity === 30 ? "error" : f.severity === 20 ? "warn" : "info"]++;

  // The script's <Option>s as the Options panel needs them (T70). Only the
  // REGISTERED ones: an <Option> whose name already held a value is a no-op
  // in the engine (R26) and the evaluator does not register it either, so
  // offering it to set would be a control without a consumer (V28). The
  // Description rides on the resolved entry; `value` is what this run used.
  const options = [...ev.options.values()].map((o) => {
    const decl = ev.resolved.find((r) => r.elem.tag === "Option" && (r.attrs.get("Name") || "") === o.name);
    const def = o.default ?? "";
    return {
      name: o.name,
      default: def,
      restrict: o.restrict ?? null,
      description: decl ? (decl.attrs.get("Description") || "") : "",
      domain: literalDomain(o.restrict),
      value: overrides.has(o.name) ? overrides.get(o.name) : def,
    };
  });

  const result = { graph, findings, ev, entryFile: rootEntry.path, counts, includes, options, overrides };
  // Which of these nodes would run under THIS option-set -- a lens over the
  // union the walk produced, never a change to the walk (V58, V59).
  result.activity = activity(result);
  return result;
}
