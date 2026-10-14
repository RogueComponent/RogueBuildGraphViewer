/* bgview/findings.js -- shared finding/severity vocabulary.
 *
 * Port of bgview/findings.py. Sits at the bottom of the import graph and
 * imports nothing of its own, same as the Python module.
 */
"use strict";

/** Ordered so `>=` threshold comparisons just work (V16). */
export const Severity = Object.freeze({ INFO: 10, WARN: 20, ERROR: 30 });

const SEVERITY_NAME = Object.freeze({ 10: "info", 20: "warn", 30: "error" });

export function severityName(sev) {
  return SEVERITY_NAME[sev] || String(sev);
}

export function parseSeverity(s) {
  const key = String(s).trim().toUpperCase();
  if (key in Severity) return Severity[key];
  throw new Error(`unknown severity ${JSON.stringify(s)}; expected info|warn|error`);
}

/** One detector hit. Always traceable to a real source location (V15). */
export class Finding {
  constructor({ file, line, severity, detector, message, node = null, tag = null }) {
    // V15 enforced at CONSTRUCTION, exactly as the Python does, so no
    // detector can quietly emit an unlocated finding. A JS port is more
    // exposed to this than Python was, not less: `undefined` propagates
    // silently through arithmetic and string interpolation, so a missing
    // line would otherwise surface as "NaN" in the UI rather than a throw.
    if (!Number.isInteger(line) || line <= 0) {
      throw new Error(
        `Finding.line must be a 1-based line number (V15 forbids line==0); ` +
        `got ${JSON.stringify(line)} from detector=${JSON.stringify(detector)}`);
    }
    if (!file) throw new Error("Finding.file must be a non-empty path (V15)");

    this.file = file;
    this.line = line;
    this.severity = severity;
    this.detector = detector;
    this.message = message;
    this.node = node;
    this.tag = tag;
    Object.freeze(this);
  }

  /** Identity for dedup/baseline comparison.
   *
   * §B.2: this once used the file's BASENAME, which silently collapsed
   * findings from same-named files in different directories -- and the
   * pinned FP-budget set holds two files both called
   * `BuildEditorAndTools.xml`. Full normalised path, never the basename.
   */
  key() {
    return [normCase(this.file), this.detector, this.tag || this.node || this.message].join("\u0000");
  }
}

/** Windows-style path normalisation: case-insensitive, separators unified.
 *
 * The browser has no `os.path`, and paths here are virtual anyway (they come
 * from the picker, not a filesystem), but BuildGraph scripts are authored on
 * Windows and `<Include Script="../Shared.xml"/>` mixes separators freely --
 * so the same file really can arrive spelled two ways.
 */
export function normCase(p) {
  return String(p).replace(/\\/g, "/").toLowerCase();
}

/** Deterministic output order: (file, line, detector, message).
 *
 * `message` is the tiebreaker for two findings sharing file+line+detector
 * (two distinct undefined properties referenced from one attribute), so the
 * ordering is total and the output is diffable run to run.
 */
export function sortFindings(findings) {
  // Code-point comparison, NOT localeCompare. localeCompare puts 'a' before
  // 'B' and treats punctuation as ignorable, so it would order findings
  // differently from the reference implementation's sorted() -- making the
  // two outputs diff for no real reason.
  const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
  return [...findings].sort((a, b) =>
    cmp(a.file, b.file) || a.line - b.line ||
    cmp(a.detector, b.detector) || cmp(a.message, b.message));
}
