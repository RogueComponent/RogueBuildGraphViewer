"""bgview.lexer -- tag-list and `$(...)` reference lexing (T2).

Two independent surfaces, both pure/syntactic (no filesystem, no evaluation):

  * tag lists:  split_list / had_empty_entry / is_tag       (V1, V6/D10)
  * $(...) refs: iter_refs / apply_slice                    (R18, R19)

V1 is the single most important invariant here: tag lists split on ';' ONLY.
Tag names legitimately contain spaces (`#First Named Output` is a real tag in
Epic's shipped Examples/TagsAndFiles.xml, R9) -- a naive `#(\\w+)` regex or a
whitespace split shreds them. Nothing in this module ever splits on
whitespace.

Dependency-free within the package: stdlib only, imports nothing from
bgview.*.
"""

from __future__ import annotations

import dataclasses

# --------------------------------------------------------------------------
# Tag lists (V1, V6/D10, is_tag)
# --------------------------------------------------------------------------


def split_list(value: str) -> list[str]:
    """Split a ';'-delimited list. V1/V6: split on ';' ONLY -- never on
    whitespace, since tag names may contain spaces. Strip surrounding
    whitespace from each item, then drop empty items (this is what the
    engine's RemoveEmptyEntries does, R13/V6)."""
    items = []
    for part in value.split(";"):
        stripped = part.strip()
        if stripped:
            items.append(stripped)
    return items


def had_empty_entry(value: str) -> bool:
    """True when any ';'-separated item is empty/whitespace-only (trailing
    ';', or ';;'). Feeds D10 at `info` severity -- the engine drops these via
    RemoveEmptyEntries (R13/V6), so this is style-only, never a warning."""
    return any(part.strip() == "" for part in value.split(";"))


def is_tag(token: str) -> bool:
    """A token is a tag reference iff it starts with '#'."""
    return token.startswith("#")


# --------------------------------------------------------------------------
# $(...) references (R18, R19)
# --------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Ref:
    name: str          # base name, ':N' slice already stripped
    slice_n: int | None
    malformed: bool    # True when text after ':' is not an int  (R18)
    raw: str            # full original "$(...)" text
    start: int
    end: int


def iter_refs(value: str) -> list[Ref]:
    """Find every $(...) reference in `value`, nesting-aware, returned in
    ASCENDING `start` order (document order).

    Nested refs start later in the text than the ref that contains them, so
    document order puts a container BEFORE the refs nested inside it --
    innermost-last, e.g. "$(Outer$(Inner))" -> [Ref("Outer$(Inner)"),
    Ref("Inner")].

    This is deliberately the OPPOSITE of engine resolution order, and that
    is what makes it useful: the engine's own expansion
    (BgScriptReader.ExpandProperties) scans with `LastIndexOf("$(")` then
    the next ')' -- i.e. it always resolves the LAST-STARTING (rightmost)
    "$(" first, uniformly for both nesting and sibling refs, then
    substitutes and re-scans the mutated string. Concretely: the engine's
    next pick is always `refs[-1]` of THIS list. A caller mirroring the
    engine's mutate-and-rescan (T3) should do exactly that --

        while (refs := iter_refs(s)):
            r = refs[-1]
            s = s[:r.start] + resolve(r) + s[r.end:]

    -- popping from the end and re-lexing after each substitution, rather
    than consuming this list front-to-back in one pass.

    lexer.py has no evaluator/environment, so it cannot reconstruct the
    engine's dynamically-substituted outer name. A ref whose `name` still
    contains "$(" (e.g. "Outer$(Inner)", or real shipped usage like
    "PGOProfileCompileArgs$(Platform)" in Tasks/PGOProfileProject.xml) is a
    SYNTACTIC PLACEHOLDER, not a resolvable lookup key -- resolve the nested
    ref(s) first and rebuild the name, THEN look it up. Treating such a name
    as a literal property to existence-check (D1) is a guaranteed false
    positive.
    """
    refs: list[Ref] = []
    _scan_refs(value, 0, len(value), refs)
    refs.sort(key=lambda r: r.start)
    return refs


def _scan_refs(text: str, start: int, limit: int, out: list[Ref]) -> None:
    i = start
    while i < limit:
        if text[i] == "$" and i + 1 < limit and text[i + 1] == "(":
            i = _scan_one_ref(text, i, limit, out)
        else:
            i += 1


def _scan_one_ref(text: str, start: int, limit: int, out: list[Ref]) -> int:
    """`text[start:start + 2] == "$("`. Find the matching ')', recursing into
    any nested "$(...)" along the way so inner refs are appended to `out`
    before this (outer) one. Returns the index just past the matching ')',
    or `limit` if the reference is unterminated.

    # ponytail: unterminated "$(" (no matching ')') is silently dropped --
    # not reported as a distinct malformed Ref -- rather than raised as a
    # finding here; the engine itself gives up scanning at that point too
    # (ExpandProperties breaks the loop when IndexOf(')') returns -1).
    # Upgrade path: if a future §D detector needs to flag unterminated refs
    # specifically, add an `unterminated` outcome alongside `malformed`.
    """
    i = start + 2
    while i < limit:
        if text[i] == "$" and i + 1 < limit and text[i + 1] == "(":
            i = _scan_one_ref(text, i, limit, out)
            continue
        if text[i] == ")":
            end = i + 1
            raw = text[start:end]
            inner = text[start + 2 : i]
            out.append(_build_ref(inner, raw, start, end))
            return end
        i += 1
    return limit


def _build_ref(inner: str, raw: str, start: int, end: int) -> Ref:
    """Split `inner` (the text between '$(' and its matching ')') into a base
    name and an optional ':N' slice suffix (R18). Mirrors
    BgScriptReader.TryGetPropertyValue exactly: split on ALL ':' characters,
    the base name is tokens[0] and the slice length is
    `Int32.Parse(tokens[1])` -- any further colons are ignored, matching the
    real engine's `name.Split(':')` + `tokens[1]` (it never rejoins the
    tail). A non-integer tokens[1] is what the engine's Int32.Parse throws
    on; we catch that here (malformed=True) instead of raising, per V12a.

    # ponytail: when `inner` still contains an unresolved nested "$(...)",
    # a ':' in it isn't reliably a top-level slice separator -- e.g.
    # "$(Foo:$(N))" looks like a bad slice ("$(N)" isn't an int) but
    # resolves fine once N is substituted. Defer instead of guessing:
    # report unsliced rather than risk a false `malformed` finding.
    # Upgrade path: once a resolution order is available (T3), resolve the
    # nested ref first and re-derive the slice from the result.
    """
    if "$(" in inner:
        return Ref(name=inner, slice_n=None, malformed=False, raw=raw, start=start, end=end)
    if ":" in inner:
        tokens = inner.split(":")
        name = tokens[0]
        try:
            slice_n: int | None = int(tokens[1])
            malformed = False
        except ValueError:
            slice_n = None
            malformed = True
    else:
        name = inner
        slice_n = None
        malformed = False
    return Ref(name=name, slice_n=slice_n, malformed=malformed, raw=raw, start=start, end=end)


def apply_slice(value: str, n: int | None) -> str:
    """R18 exactly: n>0 -> first n chars, n<0 -> last n chars. The slice
    applies ONLY when len(value) > abs(n); otherwise (including n is None or
    n == 0) `value` is returned unchanged. Mirrors
    BgScriptReader.TryGetPropertyValue:

        if (value.Length > Math.Abs(valueLength)) {
            if (valueLength > 0) value = value.Substring(0, valueLength);
            if (valueLength < 0) value = value.Substring(value.Length + valueLength, -valueLength);
        }

    Note n == 0 satisfies neither inner `if`, so the engine leaves `value`
    untouched even when the length guard passes -- apply_slice does the
    same.
    """
    if n is None:
        return value
    if len(value) > abs(n):
        if n > 0:
            return value[:n]
        if n < 0:
            return value[n:]
    return value
