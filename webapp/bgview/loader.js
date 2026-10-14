/* bgview/loader.js -- hardened XML loader with real line numbers (V7, V15).
 *
 * Port of bgview/loader.py, but the *reason* it is hand-written differs and
 * is worth stating, because "just use DOMParser" is the obvious objection:
 *
 *   DOMParser exposes no source positions. None. There is no line number on
 *   a Node, no offset, no ranges -- and V15 says every finding carries a
 *   real `file:line`, which is most of what makes this tool usable at all
 *   ("D1 at BuildEditorAndTools.xml:48" versus "D1 somewhere"). The Python
 *   hit the identical wall with ElementTree and dropped to expat for
 *   `CurrentLineNumber`. In the browser there is no expat to drop to, so the
 *   scanner below IS that layer.
 *
 * Trust boundary: the .xml being parsed is UNTRUSTED -- it is the analysis
 * subject, not something we control. Hardening, mirroring the Python:
 *
 *   - DOCTYPE is rejected outright. A blunt instrument on purpose: refusing
 *     to enter the internal/external subset at all means no <!ENTITY> can
 *     ever be declared, which kills billion-laughs and XXE together with no
 *     entity allowlist to get subtly wrong.
 *   - Only the five predefined entities and numeric character references are
 *     recognised. There is no entity table to poison, so expansion is O(1)
 *     per reference and cannot recurse.
 *   - Depth and element count are capped as a backstop against structural
 *     bloat that needs no entities at all.
 *   - Nothing here opens a socket or a URL. The only input is a string the
 *     caller already had.
 */
"use strict";

export const MAX_DEPTH = 200;
export const MAX_ELEMENT_COUNT = 200000;

export class BgError extends Error {
  constructor(message) { super(message); this.name = "BgError"; }
}

/** One XML element. Field names match the Python `Elem` dataclass. */
export class Elem {
  constructor(tag, attrib, line, file, parent) {
    this.tag = tag;             // local name, namespace STRIPPED
    this.attrib = attrib;       // { bareName: value }
    this.children = [];
    this.line = line;           // 1-based line of the start tag
    this.file = file;
    this.parent = parent || null;
    this.endLine = 0;           // 1-based line of the end tag
    this.sourceText = "";       // ROOT only: the whole document
  }

  /** Depth-first, self first (pre-order). */
  *iter() {
    yield this;
    for (const child of this.children) yield* child.iter();
  }

  /** `[start, end]` source lines, inclusive, clamped so end >= start. */
  get lineSpan() {
    return [this.line, Math.max(this.endLine, this.line)];
  }
}

/** expat yields "{uri}local" in namespace mode; XML text has "prefix:local".
 *  Both reduce to the bare local name, which is what every BuildGraph
 *  attribute already is -- only the rare xsi: hint is ever namespaced. */
function stripNs(name) {
  const colon = name.lastIndexOf(":");
  return colon < 0 ? name : name.slice(colon + 1);
}

const PREDEFINED = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

/** Resolve the ONLY entity forms we accept. An unknown `&foo;` is left
 *  verbatim rather than throwing: a stray bare '&' is common in real build
 *  scripts (paths, command lines), the engine tolerates it, and refusing the
 *  whole document over one would be a worse failure than showing it. */
function decodeEntities(text) {
  if (!text.includes("&")) return text;           // fast path; most text has none
  return text.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z][a-zA-Z0-9]*);/g, (whole, body) => {
    if (body[0] === "#") {
      const code = body[1] === "x" || body[1] === "X"
        ? parseInt(body.slice(2), 16)
        : parseInt(body.slice(1), 10);
      // Reject non-characters rather than emitting a replacement glyph that
      // would then be indistinguishable from one in the source.
      if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return whole;
      try { return String.fromCodePoint(code); } catch { return whole; }
    }
    return Object.prototype.hasOwnProperty.call(PREDEFINED, body) ? PREDEFINED[body] : whole;
  });
}

/** XML attribute-value normalisation (spec 3.3.3), which expat performs and
 *  a naive `slice()` does not.
 *
 *  Two steps, and the ORDER is the whole point:
 *
 *    1. line-end normalisation -- CRLF and lone CR both become LF
 *    2. every remaining literal tab and LF becomes a single space (#x20)
 *
 *  ...and only THEN are entities decoded, because a character reference is
 *  explicitly exempt: `&#10;` must survive as a real newline, whereas a
 *  literal newline in the source becomes a space. Decoding first would
 *  flatten the two cases together and silently rewrite the attribute.
 *
 *  This is not academic. Epic's Examples/FPSBuildGraph/BuildGame.xml wraps a
 *  long `Command/@Arguments` over several indented lines; without this the
 *  value carries embedded newlines and tabs, which is both wrong and ugly in
 *  the inspector, and it was the last of the 19 corpus files to disagree
 *  with the Python.
 */
function normalizeAttrValue(raw) {
  return decodeEntities(raw.replace(/\r\n|\r/g, "\n").replace(/[\t\n]/g, " "));
}

/**
 * Parse `text` into an `Elem` tree. Throws `BgError` on any bad input.
 *
 * @param {string} text  the document
 * @param {string} file  path used for `file:line` on findings
 */
export function loadString(text, file) {
  // A BOM would otherwise be counted as content on line 1 and push every
  // column along; expat skips it, so we do too.
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

  let i = 0;
  let line = 1;
  const n = text.length;
  const stack = [];
  let root = null;
  let depth = 0;
  let count = 0;

  const fail = (msg) => { throw new BgError(`${file}:${line}: ${msg}`); };

  // Advance the cursor to `to`, counting newlines on the way. Every position
  // change goes through here -- that single discipline is what keeps line
  // numbers honest, and is exactly what a regex-based scanner gets wrong.
  //
  // Line counting follows the XML spec's line-end handling, NOT 'count LF':
  // CRLF is ONE break, and a LONE CR is ALSO one break. That is not
  // pedantry. Epic ships Examples/FPSBuildGraph/*.xml with every line
  // ending CR CR LF -- a double LF-to-CRLF conversion -- which the spec
  // reads as TWO breaks, so those files hold 62 XML lines where an editor
  // shows 32. Counting only LF put every finding in them at half its true
  // line, and the Python (via expat, which gets this right) disagreed with
  // this parser on all 19 corpus files until it was fixed. Matching the
  // spec is also what keeps ported line numbers comparable to the pinned
  // FP-budget set.
  const advanceTo = (to) => {
    for (let k = i; k < to; k++) {
      const c = text.charCodeAt(k);
      if (c === 10) line++;                                       // LF
      else if (c === 13 && text.charCodeAt(k + 1) !== 10) line++;  // lone CR
    }
    i = to;
  };

  while (i < n) {
    const lt = text.indexOf("<", i);
    if (lt < 0) break;                       // trailing text after the root
    advanceTo(lt);

    if (text.startsWith("<!--", i)) {
      const close = text.indexOf("-->", i + 4);
      if (close < 0) fail("unterminated comment");
      advanceTo(close + 3);
      continue;
    }
    if (text.startsWith("<![CDATA[", i)) {
      const close = text.indexOf("]]>", i + 9);
      if (close < 0) fail("unterminated CDATA section");
      advanceTo(close + 3);
      continue;
    }
    if (text.startsWith("<?", i)) {          // XML declaration / processing instruction
      const close = text.indexOf("?>", i + 2);
      if (close < 0) fail("unterminated processing instruction");
      advanceTo(close + 2);
      continue;
    }
    if (text.startsWith("<!DOCTYPE", i) || text.startsWith("<!doctype", i)) {
      // Fires BEFORE any internal-subset entity is declared and before any
      // external subset is fetched. Nothing after this point is read.
      fail("DOCTYPE declarations are not permitted in BuildGraph scripts " +
           "(rejected to block external entities / DTD fetches / entity-expansion attacks)");
    }
    if (text.startsWith("<!", i)) {
      const close = text.indexOf(">", i + 2);
      if (close < 0) fail("unterminated declaration");
      advanceTo(close + 1);
      continue;
    }

    if (text.startsWith("</", i)) {          // ---------------- end tag ----
      const close = text.indexOf(">", i + 2);
      if (close < 0) fail("unterminated end tag");
      const name = stripNs(text.slice(i + 2, close).trim());
      if (!stack.length) fail(`unexpected closing tag </${name}>`);
      const open = stack[stack.length - 1];
      if (open.tag !== name) fail(`closing tag </${name}> does not match <${open.tag}>`);
      // CurrentLineNumber inside expat's EndElementHandler is the line the
      // END tag sits on, giving the element's full source range. Recorded
      // for EVERY element: an Elem that knows where it starts but not where
      // it ends is a half-truth waiting to be papered over downstream.
      open.endLine = line;
      stack.pop();
      depth--;
      advanceTo(close + 1);
      continue;
    }

    // ------------------------------------------------------ start tag ----
    const startLine = line;
    const { attrib, tag, selfClosing, next } = parseStartTag(text, i, fail);

    depth++;
    count++;
    if (depth > MAX_DEPTH) {
      fail(`element nesting exceeds ${MAX_DEPTH} levels; rejecting as a probable expansion attack`);
    }
    if (count > MAX_ELEMENT_COUNT) {
      fail(`element count exceeds ${MAX_ELEMENT_COUNT}; rejecting as a probable expansion attack`);
    }

    const parent = stack.length ? stack[stack.length - 1] : null;
    const elem = new Elem(tag, attrib, startLine, file, parent);
    if (parent) parent.children.push(elem);
    else if (root) fail("document has more than one root element");
    else root = elem;

    advanceTo(next);
    if (selfClosing) {
      // Start and end fire at the same position, giving the correct
      // single-line range rather than 0.
      elem.endLine = line;
      depth--;
    } else {
      stack.push(elem);
    }
  }

  if (stack.length) {
    throw new BgError(`${file}: unexpected end of document; <${stack[stack.length - 1].tag}> ` +
                      `opened at line ${stack[stack.length - 1].line} is never closed`);
  }
  if (!root) throw new BgError(`${file}: document has no root element`);

  // The exact text we just counted lines through, parked on the root, so
  // anything that SHOWS this file (the source view) displays what was
  // actually analysed rather than re-reading a path that may have changed --
  // a re-read pairs fresh text with stale line numbers.
  root.sourceText = text;
  return root;
}

function parseStartTag(text, start, fail) {
  const n = text.length;
  let i = start + 1;
  const nameStart = i;
  while (i < n && !/[\s/>]/.test(text[i])) i++;
  if (i >= n) fail("unterminated start tag");
  const tag = stripNs(text.slice(nameStart, i));
  if (!tag) fail("start tag has no element name");

  const attrib = Object.create(null);
  for (;;) {
    while (i < n && /\s/.test(text[i])) i++;
    if (i >= n) fail(`unterminated start tag <${tag}>`);

    if (text[i] === ">") return { attrib, tag, selfClosing: false, next: i + 1 };
    if (text[i] === "/") {
      if (text[i + 1] !== ">") fail(`malformed self-closing tag <${tag}>`);
      return { attrib, tag, selfClosing: true, next: i + 2 };
    }

    const attrStart = i;
    while (i < n && !/[\s=/>]/.test(text[i])) i++;
    const rawName = text.slice(attrStart, i);
    if (!rawName) fail(`malformed attribute in <${tag}>`);

    while (i < n && /\s/.test(text[i])) i++;
    if (text[i] !== "=") fail(`attribute '${rawName}' in <${tag}> has no value`);
    i++;
    while (i < n && /\s/.test(text[i])) i++;

    const quote = text[i];
    if (quote !== '"' && quote !== "'") fail(`attribute '${rawName}' in <${tag}> is not quoted`);
    const valueStart = ++i;
    const close = text.indexOf(quote, valueStart);
    if (close < 0) fail(`unterminated value for attribute '${rawName}' in <${tag}>`);
    // Namespace DECLARATIONS are not attributes as far as a
    // namespace-processing parser is concerned -- expat removes `xmlns` and
    // `xmlns:*` from the attribute set entirely, and every BuildGraph root
    // element carries two of them. Keeping them made our attribute tables
    // differ from the Python's on all 19 corpus files, and would eventually
    // have shown up as phantom attributes in the inspector.
    if (rawName === "xmlns" || rawName.startsWith("xmlns:")) {
      i = close + 1;
      continue;
    }
    // Namespace-processing mode mangles PREFIXED attribute keys the same way
    // it does element tags; strip those to bare local names so `attrib` is
    // uniformly "bare name -> value", which every real BuildGraph attribute
    // (Name, Value, Produces, ...) already is.
    attrib[stripNs(rawName)] = normalizeAttrValue(text.slice(valueStart, close));
    i = close + 1;
  }
}
