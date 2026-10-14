/* bgview/lexer.js -- tag-list and `$(...)` reference lexing.
 *
 * Port of bgview/lexer.py, kept line-for-line faithful because both halves
 * encode measured engine behaviour rather than taste.
 *
 * V1 is the load-bearing rule: tag lists split on ';' ONLY. Tag names really
 * do contain spaces -- `#First Named Output` is a real tag in Epic's shipped
 * Examples/TagsAndFiles.xml (R9) -- so a `#(\w+)`-style regex or a whitespace
 * split shreds them and invents findings. Nothing here ever splits on
 * whitespace.
 */
"use strict";

/* ---------------------------------------------------------- tag lists ---- */

/** Split a ';'-delimited list: ';' only, trim each item, drop empties.
 *  Dropping empties is what the engine's RemoveEmptyEntries does (R13/V6). */
export function splitList(value) {
  const out = [];
  for (const part of String(value ?? "").split(";")) {
    const stripped = part.trim();
    if (stripped) out.push(stripped);
  }
  return out;
}

/** True when any ';'-separated item is empty (trailing ';', or ';;').
 *  Feeds D10 at `info` only -- the engine drops these, so it is style. */
export function hadEmptyEntry(value) {
  return String(value ?? "").split(";").some((part) => part.trim() === "");
}

export function isTag(token) {
  return String(token ?? "").startsWith("#");
}

/* ------------------------------------------------------- $(...) refs ---- */

/** Find every `$(...)` in `value`, nesting-aware, in ASCENDING start order.
 *
 * Document order puts a container BEFORE the refs nested inside it, e.g.
 * "$(Outer$(Inner))" -> [Ref("Outer$(Inner)"), Ref("Inner")].
 *
 * That is deliberately the OPPOSITE of engine resolution order, and that is
 * what makes it useful: the engine scans with LastIndexOf("$(") and resolves
 * the rightmost ref first, then re-scans the mutated string. So the engine's
 * next pick is always the LAST element of this array. A caller mirroring
 * mutate-and-rescan should pop from the end and re-lex, not walk this array
 * front to back.
 */
export function iterRefs(value) {
  const text = String(value ?? "");
  const refs = [];
  scanRefs(text, 0, text.length, refs);
  refs.sort((a, b) => a.start - b.start);
  return refs;
}

function scanRefs(text, start, limit, out) {
  let i = start;
  while (i < limit) {
    if (text[i] === "$" && i + 1 < limit && text[i + 1] === "(") i = scanOneRef(text, i, limit, out);
    else i += 1;
  }
}

function scanOneRef(text, start, limit, out) {
  // An unterminated "$(" is silently dropped rather than reported: the
  // engine gives up scanning at that point too (ExpandProperties breaks
  // when IndexOf(')') returns -1).
  let i = start + 2;
  while (i < limit) {
    if (text[i] === "$" && i + 1 < limit && text[i + 1] === "(") {
      i = scanOneRef(text, i, limit, out);
      continue;
    }
    if (text[i] === ")") {
      const end = i + 1;
      out.push(buildRef(text.slice(start + 2, i), text.slice(start, end), start, end));
      return end;
    }
    i += 1;
  }
  return limit;
}

function buildRef(inner, raw, start, end) {
  // A name still holding "$(" is a SYNTACTIC PLACEHOLDER, not a lookup key
  // -- real shipped usage includes "PGOProfileCompileArgs$(Platform)".
  // Existence-checking it (D1) would be a guaranteed false positive, and a
  // ':' inside it is not reliably a slice separator either ("$(Foo:$(N))"
  // resolves fine once N is substituted). Defer rather than guess.
  if (inner.includes("$(")) {
    return { name: inner, sliceN: null, malformed: false, raw, start, end };
  }
  if (inner.includes(":")) {
    // Mirrors TryGetPropertyValue exactly: split on ALL ':', base is
    // tokens[0], slice is Int32.Parse(tokens[1]); further colons ignored,
    // because the engine never rejoins the tail.
    const tokens = inner.split(":");
    const name = tokens[0];
    const raw1 = tokens[1];
    // Deliberately stricter than Number(): Int32.Parse rejects "1.5", "1e3"
    // and "" -- all of which Number() happily accepts -- and the engine
    // THROWS on those, which V12a says we must survive as a finding.
    if (/^[+-]?\d+$/.test(raw1)) {
      return { name, sliceN: parseInt(raw1, 10), malformed: false, raw, start, end };
    }
    return { name, sliceN: null, malformed: true, raw, start, end };
  }
  return { name: inner, sliceN: null, malformed: false, raw, start, end };
}

/** R18 exactly: n>0 -> first n chars, n<0 -> last n chars, applied ONLY when
 *  value.length > abs(n). n === 0 satisfies neither engine branch, so the
 *  value is returned untouched even though the length guard passes. */
export function applySlice(value, n) {
  if (n === null || n === undefined) return value;
  if (value.length > Math.abs(n)) {
    if (n > 0) return value.slice(0, n);
    if (n < 0) return value.slice(n);
  }
  return value;
}
