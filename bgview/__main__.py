"""bgview.__main__ -- CLI entry point (T10).

    python -m bgview <script.xml> [opts]

Wires the whole analysis pipeline together in one straight line:

    loader.load -> schema.discover -> evaluator.evaluate -> model.build
    -> detectors.run_all -> report.to_stdout (always) -> report.to_sarif /
    bgview.html.to_html (opt-in)

Findings are pooled from THREE sources, all of them real defects a user
must see (CONTRACTS.md is explicit about this): `ev.findings` (D1 undefined
property + D14 unsupported element, emitted by the evaluator itself as a
side effect of expansion/control-flow), the findings `model.build` returns
(a list per its contract, even though today's model.py always returns `[]`
-- this module never assumes that will stay true), and `detectors.run_all`'s
D2..D16. Dropping any one of the three would silently under-report -- e.g.
every D1 in ACCEPTANCE.md's own target-file table comes from `ev.findings`,
not `detectors.run_all`.

Exit codes (V16, SPEC.md SS I):
    0 -- clean (no finding >= --fail-on threshold)
    1 -- some finding >= --fail-on threshold
    2 -- tool error (bad input, bad invocation, or any unexpected failure --
         NEVER a bare Python traceback as the primary output)

`bgview.html` (T13) is a concurrent worker's file and may not exist yet (or
may still be mid-edit) at any given moment this module is imported or run.
It is therefore imported LAZILY, only inside the `--html` branch, and only
ever reached when a caller explicitly asks for `--html` output -- so this
module (and everything that imports it, including every test in this
package) works identically whether `bgview/html.py` has landed yet or not.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

from bgview import __version__, model, report
from bgview.detectors import run_all
from bgview.evaluator import evaluate
from bgview.findings import Finding, Severity
from bgview.loader import BgError, load
from bgview.schema import discover

_FAIL_ON_CHOICES = ("info", "warn", "error")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bgview",
        description="Static analysis for Unreal Engine BuildGraph scripts.",
    )
    parser.add_argument(
        "script", nargs="?",
        help="path to the BuildGraph .xml script to analyze (omit with --serve)",
    )
    parser.add_argument(
        "--serve", action="store_true",
        help="start the live picker: browse and click a .xml, re-analysed on every click",
    )
    parser.add_argument(
        "--port", type=int, default=0,
        help="port for --serve (default: let the OS choose a free one)",
    )
    parser.add_argument(
        "--set",
        dest="sets",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="override an <Option>'s value (repeatable); default is each Option's DefaultValue",
    )
    parser.add_argument(
        "--project",
        dest="project",
        metavar="<path>",
        help="uproject path; defines ProjectFile/ProjectName/ProjectDir (B5)",
    )
    parser.add_argument(
        "--target",
        dest="targets",
        action="append",
        default=[],
        metavar="NAME",
        # SS I: "graph root for display+pruning ... NB ... default target
        # does not affect severity". Accepted here for interface
        # completeness (SS I lists it as a real CLI flag); parsed and kept
        # on `args` but not read anywhere below.
        #
        # Consumed below via model.prune_to_targets (V28): the Graph is pruned
        # BEFORE it reaches to_html/to_sarif/to_stdout, so no downstream
        # signature needed a target parameter.
        help="graph root(s) for HTML display+pruning (repeatable); never affects findings or severity",
    )
    parser.add_argument("--html", metavar="PATH", help="write a self-contained HTML report to PATH")
    parser.add_argument("--sarif", metavar="PATH", help="write a SARIF 2.1.0 report to PATH")
    parser.add_argument("--schema", metavar="PATH", help="override Schema.xsd discovery")
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default="warn",
        help="exit-code severity threshold (default: warn)",
    )
    parser.add_argument("--baseline", metavar="PATH", help="suppress findings matching a baseline JSON file")
    return parser


def _parse_overrides(raw_sets: list[str]) -> dict[str, str]:
    """`--set NAME=VALUE` (repeatable) -> option overrides dict. Last `--set`
    for a given NAME wins (plain dict-assign in declaration order), same as
    any other repeated-flag CLI convention. `VALUE` may itself legally
    contain '=' (e.g. a URL query string) -- split on the FIRST '=' only."""
    overrides: dict[str, str] = {}
    for raw in raw_sets:
        if "=" not in raw:
            raise BgError(f"--set value {raw!r} is not in NAME=VALUE form")
        name, _, value = raw.partition("=")
        name = name.strip()
        if not name:
            raise BgError(f"--set value {raw!r} has an empty NAME")
        overrides[name] = value
    return overrides


def _require_input_file(raw_path: str) -> pathlib.Path:
    """Fail fast, before touching the loader, with a message that names the
    actual problem (missing vs. not-a-file) rather than surfacing whatever
    OSError text `Path.read_bytes()` happens to raise."""
    p = pathlib.Path(raw_path)
    if not p.exists():
        raise BgError(f"input file does not exist: '{p}'")
    if not p.is_file():
        raise BgError(f"input path is not a file: '{p}'")
    return p


def _load_baseline_keys(baseline_path: str, script_path: pathlib.Path) -> set[tuple]:
    """`--baseline <path>`: a JSON array of previously-accepted finding
    records, e.g.:

        [{"file": "Examples/BuildEditorAndTools.xml", "detector": "D2", "tag": "#BinaryFiles"}]

    `file` is stored RELATIVE TO THE SCRIPT'S OWN DIRECTORY -- a portable
    baseline (checked into a repo, shared across machines) cannot embed an
    absolute path, since that breaks the moment the tree is cloned
    somewhere else -- and resolved here against `script_path`'s parent.
    Each record's identity mirrors `Finding.key()` exactly (V26: normalised
    FULL path, never basename -- two files can legally share a basename in
    different directories, as V21's own pinned corpus set does) --
    (normalised full path, detector, tag-or-node-or-message). A record
    therefore needs whichever ONE of "tag"/"node"/"message" the original
    finding actually carried; the lookup here uses the exact same priority
    order `Finding.key()` does, so a baseline built from real
    `Finding.key()` tuples round-trips.

    Read-only: never writes/creates the baseline file, even when absent --
    that is an explicit product decision for SS T.10 (baselines are
    hand-curated/CI-generated artifacts, not something this tool invents on
    the fly), not an oversight.
    """
    p = pathlib.Path(baseline_path)
    if not p.is_file():
        raise BgError(f"--baseline path does not exist: '{p}'")
    try:
        raw_text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise BgError(f"cannot read --baseline '{p}': {exc}") from exc
    try:
        records = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise BgError(f"--baseline '{p}' is not valid JSON: {exc}") from exc
    if not isinstance(records, list):
        raise BgError(f"--baseline '{p}' must be a JSON array of finding records")

    script_dir = script_path.resolve().parent
    keys: set[tuple] = set()
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            raise BgError(f"--baseline '{p}' entry {i} must be a JSON object")
        file_rel = rec.get("file")
        detector = rec.get("detector")
        if not file_rel or not detector:
            raise BgError(f"--baseline '{p}' entry {i} is missing 'file' or 'detector'")
        ident = rec.get("tag") or rec.get("node") or rec.get("message")
        abs_file = str((script_dir / file_rel).resolve())
        keys.add((os.path.normcase(os.path.normpath(abs_file)), detector, ident))
    return keys


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.serve:
        # Imported lazily: nothing in the batch path should pay for http.server,
        # and every existing test keeps working whether or not serve.py is there.
        from bgview import serve as serve_mod

        return serve_mod.main(port=args.port)

    if not args.script:
        print("bgview: error: a script path is required (or use --serve)", file=sys.stderr)
        return 2

    try:
        overrides = _parse_overrides(args.sets)
        script_path = _require_input_file(args.script)

        root = load(script_path)
        schema = discover(script_path, override=args.schema)
        if getattr(schema, "is_bundled", False):
            # Say so. A snapshot can drift from the engine version that actually
            # runs this script, and silently analyzing against the wrong schema
            # is how a tool earns distrust.
            print(
                "bgview: note: no Engine/Build/Graph/Schema.xsd found by walking up from "
                "the script; using bgview's own derived schema table. Pass --schema to be "
                "explicit.",
                file=sys.stderr,
            )
        ev = evaluate(root, schema, overrides, project=args.project)
        graph, model_findings = model.build(ev, schema)
        detector_findings = run_all(graph, ev, schema)

        findings: list[Finding] = list(ev.findings) + list(model_findings) + list(detector_findings)

        if args.targets:
            # V28: --target prunes graph AND findings to the targets'
            # transitive closure, mirroring the engine's own BgGraphDef.Select.
            try:
                graph, findings, suppressed = model.prune_to_targets(
                    graph, findings, args.targets
                )
            except model.UnknownTarget as exc:
                known = sorted(graph.nodes) + sorted(graph.aggregates) + sorted(graph.agents)
                print(
                    f"bgview: error: --target {exc} matched no node, aggregate or agent. "
                    f"Known names: {', '.join(known[:12])}"
                    + (" ..." if len(known) > 12 else ""),
                    file=sys.stderr,
                )
                return 2
            if suppressed:
                # V28 forbids SILENT suppression. A hidden warn is worse than
                # an unpruned graph, so always say what was dropped.
                print(
                    f"bgview: note: --target pruned the graph to "
                    f"{len(graph.nodes)} node(s); {suppressed} finding(s) outside "
                    f"the target closure were suppressed.",
                    file=sys.stderr,
                )

        if args.baseline:
            baseline_keys = _load_baseline_keys(args.baseline, script_path)
            findings = [f for f in findings if f.key() not in baseline_keys]

        report.to_stdout(findings)

        if args.sarif:
            report.to_sarif(findings, args.sarif, tool_version=__version__)

        if args.html:
            # Lazy, deliberately: bgview.html (T13) is a concurrent worker's
            # file and may not exist (or may not be finished) yet -- see
            # module docstring. Only reached when --html is actually asked
            # for, so nothing else in this module is affected either way.
            from bgview import html

            html.to_html(graph, findings, ev, args.html)

        threshold = Severity.parse(args.fail_on)
        return report.exit_code(findings, threshold)

    except BgError as exc:
        print(f"bgview: error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 -- deliberate last-resort guard
        # V16/SS T.10: ANY unexpected failure -- anywhere in the pipeline,
        # including a concurrently-developed bgview.html that may not be
        # finished -- must become a clean exit-2 diagnostic, never a bare
        # traceback dumped as this tool's primary output.
        print(f"bgview: error: unexpected failure ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
