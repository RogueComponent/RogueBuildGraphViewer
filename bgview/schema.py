"""Schema discovery + the tag-polarity table (R2, R3).

R2: an attribute typed `TagListType` or `TagType` in the BuildGraph schema
PRODUCES the tag(s) in its value; any other attribute whose value happens to
hold a `#Name` token CONSUMES it. This module answers the polarity question
only (`is_tag_output`); value-scanning for `#Name` consumption is a later
task's job (R3: `FileSpec` params are invisible in the xsd -- they land typed
as `BalancedStringType`, indistinguishable here from any other free-text attr).

Two sources, one interface:

  * `Schema.from_file` reads a real `Engine/Build/Graph/Schema.xsd`. It is
    parsed with `bgview.loader.load`, the same hardened, line-numbered
    expat-based loader used for BuildGraph scripts -- the xsd is read off disk
    (auto-discovered or passed via `--schema`), so it crosses the same trust
    boundary and gets the same DOCTYPE/entity hardening.

  * `Schema.from_facts_file` reads `data/schema-facts.json`, bgview's own
    derived table of the three facts anything here actually consumes: which
    elements exist, which attributes produce tags, which are required. It is
    the last-tier fallback -- R28/V29 make that tier essential, not a
    convenience -- and it exists so that bgview does not redistribute Epic's
    generated `Schema.xsd`, which is EULA-licensed. See `data/NOTICE.md`, and
    `tools/derive_schema.py` for how the table is produced.

The two are interchangeable for every caller. The only thing the xsd path
offers on top is `attr_type`, which no detector uses.
"""

from __future__ import annotations

import collections
import itertools
import json
import pathlib

from bgview.loader import BgError, Elem, load

# xs:attribute/@type and xs:extension/@base values are qualified names like
# "tns:TagListType" or "xs:string". Only the local part matters here.
# Public because tools/derive_schema.py reads it -- the derived table and the
# xsd path must agree on what "produces a tag" means, by construction.
PRODUCER_TYPES = frozenset({"TagListType", "TagType"})

# One <xs:attribute>'s schema-declared type (local name, e.g. "TagListType")
# and whether it carries use="required". Absent use= means optional -- the
# XSD default -- so `required` is only ever True on an explicit match.
_AttrInfo = collections.namedtuple("_AttrInfo", ["type", "required"])


def _local(qname: str | None) -> str | None:
    if not qname:
        return qname
    return qname.split(":", 1)[-1]


def _collect_type_attrs(complex_type: Elem) -> tuple[dict[str, _AttrInfo], str | None]:
    """Attributes declared directly on one <xs:complexType>, plus its base type name (if any).

    Deliberately shallow: only looks at xs:attribute children that are
    (a) direct children of `complex_type`, or (b) direct children of an
    <xs:extension> nested one level inside <xs:complexContent>/<xs:simpleContent>.
    It must NOT walk into nested <xs:element>/<xs:complexType> (e.g. the
    anonymous types backing inline `Do`/`Switch`/`Case`/`ForEach`), or their
    attributes would incorrectly bleed into this type's set.
    """
    # ponytail: ceiling = the two attribute-declaration shapes actually used by
    # Engine/Build/Graph/Schema.xsd today (verified by reading the whole 5.8
    # file: every xs:attribute is either a direct complexType child, or one
    # level inside complexContent/simpleContent > extension). No
    # xs:attributeGroup, no xs:attribute ref=, no xs:anySimpleType unions are
    # handled. Upgrade path: if a future engine version's schema introduces
    # those, extend `_take_attrs` below to also resolve attributeGroup refs
    # and ref= attributes -- `known_element`/`attr_type` would otherwise
    # silently under-report for whatever new task types use the new shape.
    direct: dict[str, _AttrInfo] = {}
    base: str | None = None

    def _take_attrs(container: Elem) -> None:
        for child in container.children:
            if child.tag == "attribute":
                aname = child.attrib.get("name")
                if aname:
                    direct[aname] = _AttrInfo(
                        type=_local(child.attrib.get("type")),
                        required=child.attrib.get("use") == "required",
                    )

    _take_attrs(complex_type)
    for child in complex_type.children:
        if child.tag in ("complexContent", "simpleContent"):
            for grandchild in child.children:
                if grandchild.tag == "extension":
                    base = _local(grandchild.attrib.get("base")) or base
                    _take_attrs(grandchild)

    return direct, base


def _resolve(
    name: str,
    type_direct: dict[str, dict[str, _AttrInfo]],
    type_base: dict[str, str | None],
    memo: dict[str, dict[str, _AttrInfo]],
    visiting: set[str],
) -> dict[str, _AttrInfo]:
    """Merge a named complexType's own attrs with its (recursive) base type's."""
    if name in memo:
        return memo[name]
    if name in visiting or name not in type_direct:
        return {}
    visiting.add(name)
    merged: dict[str, _AttrInfo] = {}
    base = type_base.get(name)
    if base and base in type_direct:
        merged.update(_resolve(base, type_direct, type_base, memo, visiting))
    merged.update(type_direct[name])
    visiting.discard(name)
    memo[name] = merged
    return merged


def _build_element_attrs(root: Elem) -> dict[str, dict[str, _AttrInfo]]:
    """Walk a parsed Schema.xsd, returning {element-name: {attr-name: _AttrInfo}}."""
    known: set[str] = set()
    elem_type_ref: dict[str, str] = {}
    elem_inline: dict[str, tuple[dict[str, _AttrInfo], str | None]] = {}
    type_direct: dict[str, dict[str, _AttrInfo]] = {}
    type_base: dict[str, str | None] = {}

    def walk(node: Elem) -> None:
        if node.tag == "element":
            name = node.attrib.get("name")
            if name:
                known.add(name)
                type_attr = node.attrib.get("type")
                if type_attr:
                    elem_type_ref[name] = _local(type_attr)
                else:
                    inline_ct = next((c for c in node.children if c.tag == "complexType"), None)
                    if inline_ct is not None:
                        elem_inline[name] = _collect_type_attrs(inline_ct)
        elif node.tag == "complexType":
            tname = node.attrib.get("name")
            if tname:
                type_direct[tname], type_base[tname] = _collect_type_attrs(node)
        for child in node.children:
            walk(child)

    walk(root)

    memo: dict[str, dict[str, _AttrInfo]] = {}
    elem_attrs: dict[str, dict[str, _AttrInfo]] = {}
    for name in known:
        if name in elem_inline:
            direct, base = elem_inline[name]
            merged = dict(_resolve(base, type_direct, type_base, memo, set())) if base else {}
            merged.update(direct)
            elem_attrs[name] = merged
        elif name in elem_type_ref:
            elem_attrs[name] = dict(_resolve(elem_type_ref[name], type_direct, type_base, memo, set()))
        else:
            elem_attrs[name] = {}
    return elem_attrs


class Schema:
    """The three facts every caller needs, whichever source they came from.

    Internally this is NOT the xsd's attribute table: it is the element set,
    the tag-producing attributes, and the required attributes. That is the
    whole of what the detectors ask, and it is exactly what the derived fact
    table carries -- so both sources land in the same shape and no caller can
    tell them apart.
    """

    def __init__(
        self,
        known: set[str],
        producers: dict[str, frozenset[str]],
        required: dict[str, frozenset[str]],
        attr_types: dict[str, dict[str, str | None]] | None = None,
    ):
        self._known = frozenset(known)
        self._producers = {t: frozenset(a) for t, a in producers.items() if a}
        self._required = {t: frozenset(a) for t, a in required.items() if a}
        # Only the xsd path can fill this in; the derived table does not carry
        # types because nothing consumes them. None means "not available".
        self._attr_types = attr_types
        self.source_path: str | None = None
        self.is_bundled = False

    # ----------------------------------------------------------------- build

    @classmethod
    def _from_elem_attrs(cls, elem_attrs: dict[str, dict[str, _AttrInfo]]) -> "Schema":
        return cls(
            known=set(elem_attrs),
            producers={
                tag: frozenset(a for a, info in attrs.items() if info.type in PRODUCER_TYPES)
                for tag, attrs in elem_attrs.items()
            },
            required={
                tag: frozenset(a for a, info in attrs.items() if info.required)
                for tag, attrs in elem_attrs.items()
            },
            attr_types={tag: {a: info.type for a, info in attrs.items()} for tag, attrs in elem_attrs.items()},
        )

    @classmethod
    def from_file(cls, path: str | pathlib.Path) -> "Schema":
        """Read a real `Schema.xsd` (auto-discovered, or given via --schema)."""
        obj = cls._from_elem_attrs(_build_element_attrs(load(path)))
        obj.source_path = str(path)
        obj.is_bundled = False
        return obj

    @classmethod
    def from_facts_file(cls, path: str | pathlib.Path) -> "Schema":
        """Read bgview's own derived fact table (`data/schema-facts.json`)."""
        path = pathlib.Path(path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            elements = raw["elements"]
            known = set(elements)
            producers = {tag: frozenset(entry.get("produces", ())) for tag, entry in elements.items()}
            required = {tag: frozenset(entry.get("required", ())) for tag, entry in elements.items()}
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            raise BgError(f"could not read the schema fact table '{path}': {exc}") from exc
        if not known:
            raise BgError(
                f"schema fact table '{path}' lists no elements; regenerate it with tools/derive_schema.py"
            )
        obj = cls(known=known, producers=producers, required=required)
        obj.source_path = str(path)
        return obj

    # --------------------------------------------------------------- queries

    def known_element(self, tag: str) -> bool:
        return tag in self._known

    def attr_type(self, tag: str, attr: str) -> str | None:
        """e.g. "TagListType". None if `tag` or `attr` is unknown to the schema.

        XSD-sourced schemas only -- the derived fact table carries polarity and
        requiredness, not types, so this returns None there for EVERY attr. No
        detector calls it; `is_tag_output` is the question they actually ask.
        """
        if self._attr_types is None:
            return None
        return self._attr_types.get(tag, {}).get(attr)

    def is_tag_output(self, tag: str, attr: str) -> bool:
        """R2: True only for attributes typed TagListType/TagType (incl. Node/@Produces)."""
        return attr in self._producers.get(tag, frozenset())

    def is_required(self, tag: str, attr: str) -> bool:
        """True iff the schema declares `tag`'s `attr` with use="required".

        An attr absent from the schema entirely (unknown tag or attr) is
        reported not-required, same as XSD's own default for a present-but-
        use-unspecified attribute -- there's nothing forcing it to be there
        either way.
        """
        return attr in self._required.get(tag, frozenset())

    def required_attrs(self, tag: str) -> set[str]:
        """All attribute names the schema marks use="required" for `tag`."""
        return set(self._required.get(tag, frozenset()))

    def element_names(self) -> list[str]:
        """Element names this schema knows -- used by the cross-source checks."""
        return sorted(self._known)


# bgview's own derived table (tools/derive_schema.py), NOT Epic's Schema.xsd.
# The engine's file is EULA-licensed and is deliberately not vendored here;
# see data/NOTICE.md.
BUNDLED_FACTS = pathlib.Path(__file__).parent / "data" / "schema-facts.json"


def discover(script_path: str | pathlib.Path, override: str | None = None) -> Schema:
    """Find a schema and load it. Three tiers, per SS C.

    1. `override` (`--schema`) is used verbatim.
    2. Walk up from `script_path`'s directory looking for an ancestor
       `<dir>/Engine/Build/Graph/Schema.xsd` -- the normal UE tree layout.
    3. Fall back to the bundled fact table, so a script sitting outside any UE
       tree still analyzes. The returned Schema has `is_bundled = True`, which
       the CLI surfaces, because a derived table can drift from the engine
       version that actually runs the script.
    """
    if override is not None:
        override_path = pathlib.Path(override)
        if not override_path.is_file():
            raise BgError(f"--schema path does not exist: '{override_path}'")
        return Schema.from_file(override_path)

    start = pathlib.Path(script_path).resolve()
    search_from = start if start.is_dir() else start.parent
    for ancestor in itertools.chain((search_from,), search_from.parents):
        candidate = ancestor / "Engine" / "Build" / "Graph" / "Schema.xsd"
        if candidate.is_file():
            return Schema.from_file(candidate)

    # Tier 3 (SS C): the bundled fact table, so a script living outside any UE
    # tree is still analyzable -- which is the headline use case, and what makes
    # SS C's "no UE install required" actually true. See data/NOTICE.md for
    # provenance and the version-drift caveat.
    if BUNDLED_FACTS.is_file():
        obj = Schema.from_facts_file(BUNDLED_FACTS)
        obj.is_bundled = True
        return obj

    raise BgError(
        f"could not find Engine/Build/Graph/Schema.xsd by walking up from "
        f"'{start}', and no bundled fact table is present at '{BUNDLED_FACTS}'; "
        f"pass --schema <path to Schema.xsd> explicitly"
    )
