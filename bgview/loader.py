"""Hardened XML loader (V7).

Builds an `Elem` tree from a BuildGraph .xml file using `xml.parsers.expat`
directly rather than `xml.etree.ElementTree`, because ElementTree does not
expose per-element line numbers and V15 requires a real `file:line` on every
downstream finding. `expat`'s `CurrentLineNumber`, read inside the
StartElementHandler, gives the 1-based source line of each element's start
tag.

Trust boundary: the .xml file being analyzed is untrusted input (it is the
static-analysis *subject*, not something we control). Hardening applied:

  - DOCTYPE is rejected outright (`StartDoctypeDeclHandler` raises `BgError`).
    This is a deliberate blunt instrument: BuildGraph scripts never legitimately
    use a DOCTYPE, and refusing to enter the internal/external subset at all
    means no `<!ENTITY ...>` can ever be declared -- which kills both the
    billion-laughs attack (needs internal-subset entity expansion) and XXE /
    external-DTD-fetch (needs a SYSTEM/PUBLIC external subset) in one stroke,
    with no separate entity-handler allowlisting to get subtly wrong. No
    `ExternalEntityRefHandler` is registered either, so even if some other
    entity path existed, expat has nothing to call to go fetch it.
  - No network access is ever performed by this module -- nothing here opens
    a socket or URL; the only I/O is `pathlib.Path.read_bytes()` on the path
    the caller passed in.
  - Nesting depth and total element count are capped (`MAX_DEPTH`,
    `MAX_ELEMENT_COUNT`) as a backstop against pathological/adversarial
    structural bloat that doesn't require entities at all (e.g. a
    deeply-nested or extremely wide document crafted to exhaust memory).
"""

from __future__ import annotations

import dataclasses
import pathlib
from xml.parsers import expat

# Hardening caps (V7). Generous for any real BuildGraph script -- Epic's
# largest example graphs nest well under 20 levels deep and hold a few
# hundred elements -- while still bounding worst-case memory/CPU on a
# maliciously (or accidentally) huge input.
MAX_DEPTH = 200
MAX_ELEMENT_COUNT = 200_000


def _strip_ns(qualified: str) -> str:
    """expat (namespace_separator='}') yields "{uri}local"; keep just local."""
    return qualified.rsplit("}", 1)[-1]


class BgError(Exception):
    """Raised for any fatal, controlled tool error (bad input, not a bug)."""


@dataclasses.dataclass
class Elem:
    tag: str                 # local name, namespace STRIPPED
    attrib: dict[str, str]
    children: list["Elem"]
    line: int                # 1-based, from expat CurrentLineNumber
    file: str
    parent: "Elem | None" = None
    end_line: int = 0        # 1-based line of the END tag; 0 only if never closed
    source_text: str = ""    # ROOT element only -- the whole file, decoded once

    def iter(self):
        """Depth-first traversal, self first (pre-order)."""
        yield self
        for child in self.children:
            yield from child.iter()

    @property
    def line_span(self) -> tuple[int, int]:
        """`(start, end)` source lines, inclusive, clamped so `end >= start`
        even for an element whose `end_line` was never set (a truncated
        parse cannot reach here -- expat raises first -- but a hand-built
        `Elem` in a test legitimately leaves it 0)."""
        return (self.line, max(self.end_line, self.line))


def load(path: str | pathlib.Path) -> Elem:
    """Parse `path` into an `Elem` tree. Raises `BgError` on any bad input."""
    p = pathlib.Path(path)
    file_str = str(p.resolve())

    try:
        data = p.read_bytes()
    except OSError as exc:
        raise BgError(f"cannot read '{file_str}': {exc}") from exc

    parser = expat.ParserCreate(namespace_separator="}")
    parser.buffer_text = True

    def _reject_doctype(*_args):
        # Fires at "<!DOCTYPE" -- before any entity in an internal subset is
        # declared, and before any external subset is fetched. Raising here
        # aborts Parse() immediately; nothing after this point is read.
        raise BgError(
            f"{file_str}:{parser.CurrentLineNumber}: DOCTYPE declarations are "
            f"not permitted in BuildGraph scripts (rejected to block external "
            f"entities / DTD fetches / entity-expansion attacks)"
        )

    parser.StartDoctypeDeclHandler = _reject_doctype

    stack: list[Elem] = []
    root_box: list[Elem] = []
    state = {"depth": 0, "count": 0}

    def _start(name: str, attrs: dict[str, str]) -> None:
        state["depth"] += 1
        state["count"] += 1
        if state["depth"] > MAX_DEPTH:
            raise BgError(
                f"{file_str}:{parser.CurrentLineNumber}: element nesting exceeds "
                f"{MAX_DEPTH} levels; rejecting as a probable expansion attack"
            )
        if state["count"] > MAX_ELEMENT_COUNT:
            raise BgError(
                f"{file_str}:{parser.CurrentLineNumber}: element count exceeds "
                f"{MAX_ELEMENT_COUNT}; rejecting as a probable expansion attack"
            )
        local = _strip_ns(name)
        elem = Elem(
            tag=local,
            # Namespace-processing mode mangles namespace-PREFIXED attribute
            # keys (e.g. xsi:schemaLocation) into "{uri}local" too, same as
            # element tags; strip those down to plain local names so
            # Elem.attrib is uniformly "bare name -> value" like every real
            # BuildGraph attribute already is (Name, Value, Produces, ... are
            # never namespaced -- only the rare xsi: hint is).
            attrib={_strip_ns(k): v for k, v in attrs.items()},
            children=[],
            line=parser.CurrentLineNumber,
            file=file_str,
            parent=stack[-1] if stack else None,
        )
        if stack:
            stack[-1].children.append(elem)
        else:
            root_box.append(elem)
        stack.append(elem)

    def _end(_name: str) -> None:
        state["depth"] -= 1
        # CurrentLineNumber inside EndElementHandler is the line the element's
        # END tag sits on -- so `(line, end_line)` is the element's full source
        # range. A self-closing `<Node .../>` fires _start and _end at the same
        # position, giving the correct single-line range rather than 0.
        # Recorded for EVERY element, not just the ones a caller happens to
        # want a range for: an Elem that knows where it starts but not where it
        # ends is a half-truth waiting to be papered over downstream.
        stack[-1].end_line = parser.CurrentLineNumber
        stack.pop()

    parser.StartElementHandler = _start
    parser.EndElementHandler = _end

    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise BgError(f"{file_str}:{exc.lineno}: XML parse error: {exc}") from exc

    if not root_box:
        raise BgError(f"{file_str}: document has no root element")

    # The exact bytes expat just counted lines through, decoded once and
    # parked on the root, so anything that wants to SHOW this file (the HTML
    # report's source view) displays the text that was actually analysed
    # rather than re-reading a path that may have changed underneath it --
    # a re-read would silently pair fresh text with stale line numbers.
    # `utf-8-sig` drops a BOM (expat already skips it, so keeping it would
    # push a stray ﻿ onto line 1); `errors="replace"` because a decode
    # failure must degrade to a visible glyph, never abort an analysis that
    # expat itself accepted.
    root_box[0].source_text = data.decode("utf-8-sig", errors="replace")
    return root_box[0]
