"""bgview.report -- stdout renderer, SARIF 2.1.0 writer, exit codes (T10).

Three independent outputs over the same `list[Finding]`:

  * to_stdout   -- §I: "<file>:<line>: <severity>: [<detector-id>] <message>"
  * to_sarif    -- SARIF 2.1.0, stdlib json only, for CI/editor ingest
  * exit_code   -- V16: 1 iff some finding's severity >= --fail-on threshold

Deliberately dependency-free within the package: imports ONLY
`bgview.findings` (plus stdlib), same discipline as findings.py itself
documents. That is what lets this module be built and tested in parallel
with detectors.py/model.py/evaluator.py -- it has no import-order
dependency on any of them, only on the shared Finding/Severity vocabulary
every other module also depends on.
"""

from __future__ import annotations

import json
import pathlib
import sys

from bgview.findings import Finding, Severity

# --------------------------------------------------------------------------
# stdout (§I)
# --------------------------------------------------------------------------


def _sort_key(finding: Finding) -> tuple:
    """Deterministic output order per §I: (file, line, detector). `message`
    is appended as a stability tiebreaker for the residual case of two
    findings sharing file+line+detector (e.g. two distinct D1 hits --
    different undefined properties -- referenced from the same attribute
    value on the same line) so that case is *also* order-independent,
    without changing the documented primary sort."""
    return (finding.file, finding.line, finding.detector, finding.message)


def to_stdout(findings: list[Finding], stream=sys.stdout) -> None:
    """§I stdout contract, one line per finding:

        <file>:<line>: <severity>: [<detector-id>] <message>

    Severity is rendered lowercase. Findings are printed in the
    deterministic `_sort_key` order, so output is identical run to run
    regardless of the order detectors happened to append findings in --
    diffable, and safe for a harness to snapshot-test.

    A trailing summary line reports per-severity counts. It is
    deliberately shaped so it can never be mistaken for a finding line by
    a harness parsing the §I format: it carries no ":<digits>: <severity>:
    [" substring anywhere (no colons at all after its first token), unlike
    every real finding line, which always has one.
    """
    ordered = sorted(findings, key=_sort_key)

    counts = {Severity.INFO: 0, Severity.WARN: 0, Severity.ERROR: 0}
    for finding in ordered:
        print(
            f"{finding.file}:{finding.line}: {finding.severity.name.lower()}:"
            f" [{finding.detector}] {finding.message}",
            file=stream,
        )
        counts[finding.severity] += 1

    print(
        f"{len(ordered)} finding(s) total -- "
        f"info={counts[Severity.INFO]} warn={counts[Severity.WARN]} error={counts[Severity.ERROR]}",
        file=stream,
    )


# --------------------------------------------------------------------------
# SARIF 2.1.0
# --------------------------------------------------------------------------

# SARIF has no "info"/"warn" level -- only note/warning/error/none exist in
# the spec. Emitting "info" or "warn" verbatim is the single most common way
# to produce a SARIF file no consumer (CI, editor) will ingest.
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.INFO: "note",
    Severity.WARN: "warning",
    Severity.ERROR: "error",
}

_SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_INFORMATION_URI = "https://github.com/bgview/bgview"


def _to_file_uri(path: str) -> str:
    """Convert a Windows filesystem path to a valid `file:///C:/...` URI:
    forward slashes, percent-encoded reserved characters (including
    spaces). A bare `C:\\Users\\...` string is not a valid URI and would
    break SARIF ingestion.

    `Finding.file` is documented (CONTRACTS.md) as always an ABSOLUTE path,
    so letting `PureWindowsPath.as_uri()` raise ValueError on a relative
    path is the correct amount of validation here -- a relative
    `Finding.file` is a contract violation upstream, not something this
    function should silently paper over.

    Deliberately `PureWindowsPath`, not `Path`: this must produce a
    correct Windows file URI regardless of the OS the process happens to
    run on (§C: "Windows-first"), not only when the interpreter itself is
    running on win32.
    """
    return pathlib.PureWindowsPath(path).as_uri()


def to_sarif(findings: list[Finding], path: str, tool_version: str) -> None:
    """Write SARIF 2.1.0 to `path` (stdlib `json` only), creating parent
    directories as needed, UTF-8 encoded.

    `runs[0].tool.driver.rules` holds exactly one entry per DISTINCT
    detector id present in `findings` (not the full D1..D16 catalog --
    this module has no access to that; see the ponytail note below).
    Every result's `ruleId` matches a declared rule id by construction,
    since both are built from the same `finding.detector` in the same
    loop.
    """
    ordered = sorted(findings, key=_sort_key)

    rules: dict[str, dict] = {}
    results = []
    for finding in ordered:
        level = _SARIF_LEVEL[finding.severity]
        if finding.detector not in rules:
            # ponytail: no static detector-id -> friendly-name/description
            # table exists at this layer -- report.py may import ONLY
            # bgview.findings (CONTRACTS.md), and findings.py itself
            # carries no such table. `name` falls back to the bare
            # detector id, and `shortDescription` is synthesized from the
            # first finding observed for that id -- the only descriptive
            # text available anywhere on this side of the import boundary.
            # Upgrade path: add a `DETECTOR_DESCRIPTIONS: dict[str, str]`
            # table to bgview.findings (shared vocabulary already imported
            # by both detectors.py and report.py) and look up `name` /
            # `shortDescription` from it here instead of a sampled message.
            rules[finding.detector] = {
                "id": finding.detector,
                "name": finding.detector,
                "shortDescription": {"text": finding.message},
                "defaultConfiguration": {"level": level},
            }
        results.append(
            {
                "ruleId": finding.detector,
                "level": level,
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _to_file_uri(finding.file)},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
            }
        )

    sarif_log = {
        "version": "2.1.0",
        "$schema": _SARIF_SCHEMA_URI,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "bgview",
                        "informationUri": _INFORMATION_URI,
                        "version": tool_version,
                        "rules": [rules[detector_id] for detector_id in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }

    out_path = pathlib.Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as stream:
        json.dump(sarif_log, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


# --------------------------------------------------------------------------
# exit code (V16)
# --------------------------------------------------------------------------


def exit_code(findings: list[Finding], fail_on: Severity) -> int:
    """V16: exit code is 1 iff some finding's severity is >= `fail_on`,
    else 0. Exit code 2 (tool error) is the CLI's (__main__.py) concern,
    not this function's -- report.py only ever returns 0 or 1."""
    return 1 if any(finding.severity >= fail_on for finding in findings) else 0
