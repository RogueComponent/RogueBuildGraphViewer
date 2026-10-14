"""bgview.condition -- recursive-descent parser for BuildGraph `If="..."`
conditions (T7).

Grammar (R11, cross-checked against the ACTUAL implementation in the
engine's BgCondition.cs -- see B1/V25/R25: the first pass transcribed
BgCondition.cs's grammar DOC COMMENT (lines 36-62), which is stale relative
to its own implementation a few hundred lines below. Never trust a comment
over the code it documents.):

    or-expr    ::= and-expr | or-expr "Or" and-expr
    and-expr   ::= comparison | and-expr "And" comparison
    comparison ::= scalar | scalar ("=="|"!="|"<"|"<="|">"|">=") scalar
    scalar     ::= "(" or-expr ")" | "!" scalar
                 | "Exists" "(" scalar ")"                     -- 1 arg, bool, OPAQUE (V10, filesystem)
                 | "HasTrailingSlash" "(" scalar ")"           -- 1 arg, bool, syntactically decidable (V10a)
                 | "Length" "(" scalar ")"                     -- 1 arg, INT not bool (feeds V18)
                 | "Contains" "(" arg "," arg ")"               -- 2 args, bool (Haystack, Needle)
                 | "ContainsItem" "(" arg "," arg "," arg ")"   -- 3 args, bool (Haystack, Needle, Separator)
                 | string | identifier
    arg        ::= string | identifier      -- a single raw token; the engine's argument
                                              scanner (EvaluateArguments, used only by
                                              Contains/ContainsItem) does NOT recurse into
                                              sub-expressions, unlike the other three Call
                                              productions above, which each recurse via a
                                              plain "(" or-expr ")" scalar
    string     ::= any chars terminated by ' or "  -- NOT escaped (no backslash escapes)
    identifier ::= letters, digits, underscore

All five function names -- `Exists`, `HasTrailingSlash`, `Length`,
`Contains`, `ContainsItem` -- and the `Or`/`And` keywords match
case-insensitively (the engine uses StringComparison.OrdinalIgnoreCase for
all of these; the comparison operators themselves are plain symbols, not
affected by case). Wrong argument count for Contains/ContainsItem raises
CondParseError naming the function and the expected count, mirroring the
engine's own "Invalid argument count for 'X'" check.

This module ONLY parses: it builds an AST. Evaluation and satisfiability
live in algebra.py (owned by another worker) -- not implemented here.

Property references may still be present as raw "$(...)" text at parse
time (property expansion happens before evaluation, not before parsing).
Such a token is treated as an Ident whose value is the raw "$(...)" text
verbatim; nesting ("$(Outer$(Inner))") is handled the same way lexer.py
handles it -- the whole nested span becomes one token.

Dependency-free within the package: stdlib only, imports nothing from
bgview.* (in particular, nothing from bgview.lexer -- the tiny bit of
"$(...)" span-scanning needed here is reimplemented locally rather than
shared).
"""

from __future__ import annotations

import dataclasses


class CondParseError(Exception):
    """Raised on any grammar violation. The message always carries the
    offending text so a caller can report `file:line: <message>` usefully."""


# --------------------------------------------------------------------------
# AST node types
# --------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Or:
    left: object
    right: object


@dataclasses.dataclass(frozen=True)
class And:
    left: object
    right: object


@dataclasses.dataclass(frozen=True)
class Cmp:
    op: str        # one of "==" "!=" "<" "<=" ">" ">="
    left: object
    right: object


@dataclasses.dataclass(frozen=True)
class Not:
    operand: object


@dataclasses.dataclass(frozen=True)
class Call:
    name: str        # canonical casing regardless of source casing, one of:
                      # "Exists" | "HasTrailingSlash" | "Length" | "Contains" | "ContainsItem"
    args: list        # arity per `name` -- 1 for Exists/HasTrailingSlash/Length,
                       # 2 for Contains, 3 for ContainsItem (R25/V25)


@dataclasses.dataclass(frozen=True)
class Str:
    value: str     # quoted literal, quotes stripped, NOT unescaped (no escapes exist)


@dataclasses.dataclass(frozen=True)
class Ident:
    value: str     # bare identifier / already-expanded text / raw "$(...)" text


# --------------------------------------------------------------------------
# Tokenizer
# --------------------------------------------------------------------------

_END = "<EOF>"
_COMPARE_OPS = ("==", "!=", "<=", ">=", "<", ">")

# The five Call-able function names (R25/V25/B1 -- the doc comment at
# BgCondition.cs:36-62 only lists Exists/HasTrailingSlash; the actual
# EvaluateScalarAsync implementation, read directly, supports five).
# Matched case-insensitively via `.lower()` against these keys.

# Exists/HasTrailingSlash/Length: single argument, obtained by recursing
# into _parse_scalar (mirrors the engine calling EvaluateScalarAsync again,
# which is what lets the argument itself be a parenthesized or-expr).
_SINGLE_SCALAR_CALLS = {
    "exists": "Exists",
    "hastrailingslash": "HasTrailingSlash",
    "length": "Length",
}

# Contains/ContainsItem: comma-separated argument LIST with a fixed arity,
# obtained via _parse_call_arguments (mirrors the engine's EvaluateArguments
# -- a flat raw-token scanner, not a recursive scalar parse).
_FLAT_ARG_CALLS = {
    "contains": ("Contains", 2),
    "containsitem": ("ContainsItem", 3),
}


def _tokenize(text: str) -> list[str]:
    """Mirrors BgCondition.Tokenize, extended with one addition: a bare
    "$(...)" span (nesting-aware) is scanned as a SINGLE token instead of
    exploding into '$', '(', identifier, ')'. The real engine never needs
    this -- by the time a condition reaches BgCondition, BgScriptReader has
    already textually expanded every property reference. This tool parses
    conditions BEFORE expansion (so it can reason about them symbolically
    across option-sets in algebra.py), so "$(...)" can legitimately still be
    sitting in the text when we tokenize it.
    """
    tokens: list[str] = []
    n = len(text)
    idx = 0
    while idx < n:
        ch = text[idx]
        end = idx + 1
        if not ch.isspace():
            if ch == "$" and end < n and text[end] == "(":
                end = _scan_dollar_paren(text, idx, n)
            elif ch.isdigit():
                while end < n and text[end].isdigit():
                    end += 1
            elif ch.isalpha() or ch == "_":
                while end < n and (text[end].isalnum() or text[end] == "_"):
                    end += 1
            elif ch in "!<>=":
                if end < n and text[end] == "=":
                    end += 1
            elif ch in "'\"":
                if end < n:
                    end += 1
                    while end < n and text[end - 1] != ch:
                        end += 1
            tokens.append(text[idx:end])
        idx = end
    tokens.append(_END)
    return tokens


def _scan_dollar_paren(text: str, start: int, n: int) -> int:
    """`text[start:start + 2] == "$("`. Return the index just past the
    matching ')', counting nested "$(" so "$(Outer$(Inner))" scans as one
    span. Returns `n` (end of text) if unterminated.

    # ponytail: an unterminated "$(...)" (no matching ')') is tolerated,
    # not rejected -- the resulting token (raw text through end-of-input)
    # still starts with "$(" so `_parse_scalar` accepts it as an opaque
    # Ident, same as lexer.iter_refs silently dropping an unterminated ref
    # rather than raising. Real BuildGraph conditions never hit this (the
    # engine never sees "$(...)" text at all -- see module docstring), so
    # this is unreachable on real input; kept lenient for uniformity with
    # lexer.py rather than added as a distinct error path. Upgrade path: if
    # a §D detector ever wants to flag this specifically, check
    # `not tok.endswith(")")` in _parse_scalar before accepting the Ident.
    """
    depth = 1
    end = start + 2
    while end < n and depth > 0:
        if text[end] == "$" and end + 1 < n and text[end + 1] == "(":
            depth += 1
            end += 2
            continue
        if text[end] == ")":
            depth -= 1
        end += 1
    return end


# --------------------------------------------------------------------------
# Recursive-descent parser
# --------------------------------------------------------------------------


def parse(text: str) -> object:
    tokens = _tokenize(text)
    node, pos = _parse_or(tokens, 0)
    if tokens[pos] != _END:
        raise CondParseError("garbage after expression: " + "".join(tokens[pos:-1]))
    return node


def _parse_or(tokens: list[str], pos: int):
    left, pos = _parse_and(tokens, pos)
    while tokens[pos].lower() == "or":
        pos += 1
        right, pos = _parse_and(tokens, pos)
        left = Or(left, right)
    return left, pos


def _parse_and(tokens: list[str], pos: int):
    left, pos = _parse_comparison(tokens, pos)
    while tokens[pos].lower() == "and":
        pos += 1
        right, pos = _parse_comparison(tokens, pos)
        left = And(left, right)
    return left, pos


def _parse_comparison(tokens: list[str], pos: int):
    left, pos = _parse_scalar(tokens, pos)
    tok = tokens[pos]
    if tok in _COMPARE_OPS:
        pos += 1
        right, pos = _parse_scalar(tokens, pos)
        return Cmp(tok, left, right), pos
    return left, pos


def _parse_scalar(tokens: list[str], pos: int):
    tok = tokens[pos]

    if tok == "(":
        node, pos = _parse_or(tokens, pos + 1)
        if tokens[pos] != ")":
            raise CondParseError("expected ')', got: " + tokens[pos])
        return node, pos + 1

    if tok == "!":
        operand, pos = _parse_scalar(tokens, pos + 1)
        return Not(operand), pos

    low = tok.lower()
    if low in _SINGLE_SCALAR_CALLS and pos + 1 < len(tokens) and tokens[pos + 1] == "(":
        name = _SINGLE_SCALAR_CALLS[low]
        arg, pos = _parse_scalar(tokens, pos + 1)
        return Call(name, [arg]), pos
    if low in _FLAT_ARG_CALLS and pos + 1 < len(tokens) and tokens[pos + 1] == "(":
        name, arity = _FLAT_ARG_CALLS[low]
        args, pos = _parse_call_arguments(tokens, pos + 1, name, arity)
        return Call(name, args), pos

    return _leaf_from_token(tok), pos + 1


def _parse_call_arguments(tokens: list[str], pos: int, name: str, arity: int):
    """Mirrors BgCondition.EvaluateArguments exactly: a FLAT, comma-separated
    list of raw tokens between '(' and ')' -- NOT recursively-parsed
    sub-expressions, and (matching the engine) with no awareness of nested
    parens at all. Only Contains/ContainsItem use this shape; Exists,
    HasTrailingSlash and Length take a single scalar via the ordinary
    recursive-descent path instead (the engine calls EvaluateScalarAsync for
    those, not EvaluateArguments).

    `pos` points at the token expected to be '(' (i.e. the caller has
    already consumed the function name)."""
    if tokens[pos] != "(":
        raise CondParseError(f"expected '(' after {name}, got: {tokens[pos]!r}")
    pos += 1

    args: list = []
    closed = False
    while pos < len(tokens):
        tok = tokens[pos]
        pos += 1
        if tok == _END:
            break
        if tok == ")":
            closed = True
            break
        if tok != ",":
            args.append(_leaf_from_token(tok))

    if not closed:
        raise CondParseError(f"expected ')' in {name}(...)")
    if len(args) != arity:
        raise CondParseError(
            f"{name}() expects {arity} argument(s), got {len(args)}"
        )
    return args, pos


def _leaf_from_token(tok: str):
    """Classify a single raw token as a Str or Ident leaf. Used both for a
    plain scalar and for each Contains/ContainsItem argument token (the
    engine never recurses into a full scalar grammar for those -- see
    _parse_call_arguments).

    # ponytail: the engine's own EvaluateArguments only strips a matched
    # SINGLE-quote pair (`nextToken.First() == '\\''`) and passes a
    # double-quoted argument through WITH its quotes still attached -- an
    # inconsistency with every other string production in the grammar
    # (which strips both ' and "). We deliberately do NOT reproduce that
    # inconsistency: `Str.value` means "quotes stripped" uniformly
    # throughout this AST, and no real corpus usage
    # (Examples/Properties.xml:90-102) uses double quotes here anyway.
    # Upgrade path: if a real graph is ever found relying on the
    # unstripped-double-quote quirk, special-case it in
    # _parse_call_arguments specifically (not here, to keep plain-scalar
    # string parsing uniform).
    """
    if len(tok) >= 2 and tok[0] in "'\"" and tok[-1] == tok[0]:
        return Str(tok[1:-1])

    if tok.startswith("$(") or tok[0].isalnum() or tok[0] == "_":
        return Ident(tok)

    raise CondParseError(f"token {tok!r} is not a valid scalar")
