/* bgview/condition.js -- recursive-descent parser for `If="..."` conditions.
 *
 * Port of bgview/condition.py.
 *
 *     or-expr    ::= and-expr | or-expr "Or" and-expr
 *     and-expr   ::= comparison | and-expr "And" comparison
 *     comparison ::= scalar | scalar ("=="|"!="|"<"|"<="|">"|">=") scalar
 *     scalar     ::= "(" or-expr ")" | "!" scalar
 *                  | "Exists" "(" scalar ")"                    -- OPAQUE (V10, filesystem)
 *                  | "HasTrailingSlash" "(" scalar ")"          -- decidable (V10a)
 *                  | "Length" "(" scalar ")"                    -- INT, not bool (feeds V18)
 *                  | "Contains" "(" arg "," arg ")"
 *                  | "ContainsItem" "(" arg "," arg "," arg ")"
 *                  | string | identifier
 *
 * §B.1 is the reason this grammar is what it is: the first version was
 * transcribed from BgCondition.cs's DOC COMMENT, which is stale relative to
 * its own implementation a few hundred lines below -- it omits Contains,
 * ContainsItem and Length, all three of which Epic's own Properties.xml uses.
 * Never trust a comment over the code it documents.
 *
 * This module ONLY parses. Evaluation and satisfiability live in algebra.js.
 *
 * Property references may still be raw `$(...)` text at parse time, because
 * this tool parses conditions BEFORE expansion so it can reason about them
 * symbolically across option-sets. Such a token becomes an Ident holding the
 * raw text, nesting and all.
 */
"use strict";

export class CondParseError extends Error {
  constructor(message) { super(message); this.name = "CondParseError"; }
}

/* AST nodes. Plain tagged objects rather than classes -- they are compared
 * structurally by the algebra and dumped by the cross-validation harness. */
export const Or = (left, right) => ({ kind: "Or", left, right });
export const And = (left, right) => ({ kind: "And", left, right });
export const Cmp = (op, left, right) => ({ kind: "Cmp", op, left, right });
export const Not = (operand) => ({ kind: "Not", operand });
export const Call = (name, args) => ({ kind: "Call", name, args });
export const Str = (value) => ({ kind: "Str", value });
export const Ident = (value) => ({ kind: "Ident", value });

const END = "<EOF>";
const COMPARE_OPS = ["==", "!=", "<=", ">=", "<", ">"];

// Exists/HasTrailingSlash/Length take ONE argument obtained by recursing
// into parseScalar -- mirroring the engine calling EvaluateScalarAsync
// again, which is what lets the argument be a parenthesised or-expr.
const SINGLE_SCALAR_CALLS = new Map([
  ["exists", "Exists"], ["hastrailingslash", "HasTrailingSlash"], ["length", "Length"],
]);
// Contains/ContainsItem take a comma-separated argument LIST of fixed arity,
// scanned flat -- mirroring EvaluateArguments, which does NOT recurse.
const FLAT_ARG_CALLS = new Map([
  ["contains", ["Contains", 2]], ["containsitem", ["ContainsItem", 3]],
]);

const isDigit = (c) => c >= "0" && c <= "9";
// Deliberately ASCII-only, matching .NET's behaviour for these identifiers
// closely enough for BuildGraph names, and avoiding a Unicode-property regex
// whose idea of "letter" differs from char.IsLetter's.
const isAlpha = (c) => (c >= "a" && c <= "z") || (c >= "A" && c <= "Z");
const isAlnum = (c) => isAlpha(c) || isDigit(c);
const isSpace = (c) => c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f" || c === "\v";

/** Mirrors BgCondition.Tokenize, plus one addition: a bare `$(...)` span is
 *  scanned as a SINGLE token instead of exploding into '$','(',ident,')'.
 *  The engine never needs that -- by the time a condition reaches it, every
 *  property reference has already been textually expanded. */
function tokenize(text) {
  const tokens = [];
  const n = text.length;
  let idx = 0;
  while (idx < n) {
    const ch = text[idx];
    let end = idx + 1;
    if (!isSpace(ch)) {
      if (ch === "$" && end < n && text[end] === "(") {
        end = scanDollarParen(text, idx, n);
      } else if (isDigit(ch)) {
        while (end < n && isDigit(text[end])) end++;
      } else if (isAlpha(ch) || ch === "_") {
        while (end < n && (isAlnum(text[end]) || text[end] === "_")) end++;
      } else if (ch === "!" || ch === "<" || ch === ">" || ch === "=") {
        if (end < n && text[end] === "=") end++;
      } else if (ch === "'" || ch === '"') {
        if (end < n) {
          end++;
          while (end < n && text[end - 1] !== ch) end++;
        }
      }
      tokens.push(text.slice(idx, end));
    }
    idx = end;
  }
  tokens.push(END);
  return tokens;
}

/** `text[start..start+2] === "$("`. Index just past the matching ')',
 *  counting nesting so "$(Outer$(Inner))" is one span. An unterminated span
 *  is tolerated, not rejected: the token still starts with "$(" so it is
 *  accepted as an opaque Ident, matching lexer.js's leniency. */
function scanDollarParen(text, start, n) {
  let depth = 1;
  let end = start + 2;
  while (end < n && depth > 0) {
    if (text[end] === "$" && end + 1 < n && text[end + 1] === "(") { depth++; end += 2; continue; }
    if (text[end] === ")") depth--;
    end++;
  }
  return end;
}

export function parse(text) {
  const tokens = tokenize(text);
  const [node, pos] = parseOr(tokens, 0);
  if (tokens[pos] !== END) {
    throw new CondParseError("garbage after expression: " + tokens.slice(pos, -1).join(""));
  }
  return node;
}

function parseOr(tokens, pos) {
  let [left, p] = parseAnd(tokens, pos);
  while (tokens[p].toLowerCase() === "or") {
    const [right, p2] = parseAnd(tokens, p + 1);
    left = Or(left, right); p = p2;
  }
  return [left, p];
}

function parseAnd(tokens, pos) {
  let [left, p] = parseComparison(tokens, pos);
  while (tokens[p].toLowerCase() === "and") {
    const [right, p2] = parseComparison(tokens, p + 1);
    left = And(left, right); p = p2;
  }
  return [left, p];
}

function parseComparison(tokens, pos) {
  const [left, p] = parseScalar(tokens, pos);
  if (COMPARE_OPS.includes(tokens[p])) {
    const [right, p2] = parseScalar(tokens, p + 1);
    return [Cmp(tokens[p], left, right), p2];
  }
  return [left, p];
}

function parseScalar(tokens, pos) {
  const tok = tokens[pos];

  if (tok === "(") {
    const [node, p] = parseOr(tokens, pos + 1);
    if (tokens[p] !== ")") throw new CondParseError("expected ')', got: " + tokens[p]);
    return [node, p + 1];
  }
  if (tok === "!") {
    const [operand, p] = parseScalar(tokens, pos + 1);
    return [Not(operand), p];
  }

  const low = tok.toLowerCase();
  if (SINGLE_SCALAR_CALLS.has(low) && pos + 1 < tokens.length && tokens[pos + 1] === "(") {
    const [arg, p] = parseScalar(tokens, pos + 1);
    return [Call(SINGLE_SCALAR_CALLS.get(low), [arg]), p];
  }
  if (FLAT_ARG_CALLS.has(low) && pos + 1 < tokens.length && tokens[pos + 1] === "(") {
    const [name, arity] = FLAT_ARG_CALLS.get(low);
    const [args, p] = parseCallArguments(tokens, pos + 1, name, arity);
    return [Call(name, args), p];
  }
  return [leafFromToken(tok), pos + 1];
}

/** Mirrors EvaluateArguments exactly: a FLAT, comma-separated list of raw
 *  tokens between '(' and ')' -- not recursively-parsed sub-expressions, and
 *  (matching the engine) with no awareness of nested parens at all. */
function parseCallArguments(tokens, pos, name, arity) {
  if (tokens[pos] !== "(") {
    throw new CondParseError(`expected '(' after ${name}, got: ${JSON.stringify(tokens[pos])}`);
  }
  pos++;
  const args = [];
  let closed = false;
  while (pos < tokens.length) {
    const tok = tokens[pos];
    pos++;
    if (tok === END) break;
    if (tok === ")") { closed = true; break; }
    if (tok !== ",") args.push(leafFromToken(tok));
  }
  if (!closed) throw new CondParseError(`expected ')' in ${name}(...)`);
  if (args.length !== arity) {
    throw new CondParseError(`${name}() expects ${arity} argument(s), got ${args.length}`);
  }
  return [args, pos];
}

/** Classify a raw token as Str or Ident.
 *
 * The engine's own EvaluateArguments strips only a matched SINGLE-quote pair
 * and passes a double-quoted argument through WITH its quotes -- an
 * inconsistency with every other string production. That is deliberately NOT
 * reproduced: `Str.value` means "quotes stripped" uniformly across this AST,
 * and no real corpus usage relies on the quirk.
 */
function leafFromToken(tok) {
  if (tok.length >= 2 && (tok[0] === "'" || tok[0] === '"') && tok[tok.length - 1] === tok[0]) {
    return Str(tok.slice(1, -1));
  }
  if (tok.startsWith("$(") || isAlnum(tok[0]) || tok[0] === "_") return Ident(tok);
  throw new CondParseError(`token ${JSON.stringify(tok)} is not a valid scalar`);
}
