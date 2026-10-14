"""Derive bgview's schema fact table from a real `Schema.xsd`.

bgview needs exactly three facts out of the engine's BuildGraph schema:

  1. which element names exist            -> `known_element`  (D14)
  2. which attributes PRODUCE tags (R2)   -> `is_tag_output`  (the dataflow model)
  3. which attributes are `use="required"` -> `is_required`   (D11)

Nothing else in the schema is read by any detector, so nothing else is
carried. This script reads a `Schema.xsd` and writes that three-fact table as
JSON; `bgview/schema.py` and `webapp/bgview/schema.js` both load it as the
last-tier fallback, replacing the vendored copy of Epic's file.

Why it exists is a licensing matter as much as a technical one:
`Engine/Build/Graph/Schema.xsd` is Epic Games' file, distributed under the
Unreal Engine EULA. bgview is published openly, so it must not redistribute
it. A table of element and attribute NAMES, extracted mechanically, is a
description of the interface bgview targets -- the same thing any compatible
tool has to know -- and it is bgview's own file. See `bgview/data/NOTICE.md`.

Usage:

    python tools/derive_schema.py <path to Schema.xsd> [--engine 5.8]

Regenerate the schema itself first if you do not have one:

    RunUAT.bat BuildGraph -Schema=<output path>
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bgview.loader import load
from bgview.schema import PRODUCER_TYPES, _build_element_attrs

# Written next to the package and next to the web app. Two copies of ONE
# bgview-authored file, because the web app has to be a self-contained
# directory a static host can serve as-is (V45: same-origin fetches only).
OUT_PATHS = (
    pathlib.Path("bgview") / "data" / "schema-facts.json",
    pathlib.Path("webapp") / "data" / "schema-facts.json",
)


def derive(xsd_path: pathlib.Path, engine: str) -> dict:
    elem_attrs = _build_element_attrs(load(xsd_path))
    elements: dict[str, dict[str, list[str]]] = {}
    for tag in sorted(elem_attrs):
        entry: dict[str, list[str]] = {}
        produces = sorted(a for a, info in elem_attrs[tag].items() if info.type in PRODUCER_TYPES)
        required = sorted(a for a, info in elem_attrs[tag].items() if info.required)
        if produces:
            entry["produces"] = produces
        if required:
            entry["required"] = required
        # Elements with neither still need their key: `known_element` is the
        # membership test D14 asks, and an element with no attributes at all
        # is still a real element.
        elements[tag] = entry
    return {
        "_notice": (
            "bgview's own derived fact table, not an Epic Games file. Element and "
            "attribute names extracted from a generated Engine/Build/Graph/Schema.xsd; "
            "see bgview/data/NOTICE.md. Regenerate with tools/derive_schema.py."
        ),
        "engine": engine,
        "elements": elements,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("xsd", help="path to a generated Engine/Build/Graph/Schema.xsd")
    ap.add_argument("--engine", default="5.8", help="engine version the schema came from (default: 5.8)")
    args = ap.parse_args(argv)

    xsd_path = pathlib.Path(args.xsd)
    if not xsd_path.is_file():
        ap.error(f"no such file: {xsd_path}")

    facts = derive(xsd_path, args.engine)
    # Deterministic bytes: a regeneration that changes nothing must produce no
    # diff, or the table stops being reviewable.
    text = json.dumps(facts, indent=2, sort_keys=False, ensure_ascii=True) + "\n"
    root = pathlib.Path(__file__).resolve().parent.parent
    for rel in OUT_PATHS:
        out = root / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {rel}  ({len(facts['elements'])} elements)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
