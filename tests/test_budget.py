"""tests/test_budget.py (T11) -- the FP-budget harness. V5/V21.

"The most important test in the repo" (task brief, ACCEPTANCE.md SS B): run
`python -m bgview <script.xml> --fail-on warn` -- the REAL subprocess,
ACCEPTANCE.md SS C's own literal command -- over EVERY `.xml` file in the
19-file Epic corpus:

    c:\\UnrealEngines\\Source_5_8\\Engine\\Build\\Graph\\Examples\\*.xml
    c:\\UnrealEngines\\Source_5_8\\Engine\\Build\\Graph\\Examples\\FPSBuildGraph\\*.xml
    c:\\UnrealEngines\\Source_5_8\\Engine\\Build\\Graph\\Tests\\*.xml

and assert the complete warn-or-above result set across the WHOLE corpus is
EXACTLY the two pinned findings (ACCEPTANCE.md SS B):

    Examples/BuildEditorAndTools.xml               D2  #BinaryFiles
    Examples/FPSBuildGraph/BuildEditorAndTools.xml D2  #BinaryFiles

V21 is explicit that this is an IDENTITY assertion, not a cardinality one:
"a run that misses #BinaryFiles but emits one bogus warning has the right
count and must FAIL." A naive `len(warnings) == 2` check cannot tell those
two failure modes apart, so this file never compares counts alone -- it
always compares the actual (file, detector, tag) triples against the pinned
set, plus a per-file "exactly the pinned files have exactly one, everyone
else has zero" sweep as a second, independent check on the same data.

Identity is asserted by file path RELATIVE TO THE CORPUS ROOT, deliberately
NOT `Finding.key()` and deliberately NOT basename: both pinned files share
the identical basename `BuildEditorAndTools.xml` (one in `Examples/`, one in
`Examples/FPSBuildGraph/`) -- this is §B.2/V26's own motivating case. Reading
CLI stdout by relative path sidesteps `Finding.key()` entirely rather than
depending on it, which is the point: this harness must still catch a
regression even if `Finding.key()` itself were ever to regress back to
basename-only.

This module reads ONLY from the read-only `c:\\UnrealEngines\\...` reference
tree (via `python -m bgview`, which itself never writes there -- see
`bgview/__main__.py`); it writes nothing there and nothing anywhere else
except the ordinary `tests/__pycache__` bytecode cache.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS_ROOT = pathlib.Path(r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph")
REAL_SCHEMA = CORPUS_ROOT / "Schema.xsd"

# ACCEPTANCE.md SS I stdout contract: "<file>:<line>: <severity>: [<detector-id>] <message>"
_FINDING_LINE_RE = re.compile(r"^(?P<file>.+):(?P<line>\d+): (?P<severity>\w+): \[(?P<detector>D\d+)\] (?P<message>.*)$")

# ACCEPTANCE.md SS B's pinned set -- the ENTIRE allowed warn+ output across
# all 19 corpus files. Any other warn+ finding anywhere is a regression.
_PINNED_WARN_PLUS = {
    ("Examples/BuildEditorAndTools.xml", "D2", "#BinaryFiles"),
    ("Examples/FPSBuildGraph/BuildEditorAndTools.xml", "D2", "#BinaryFiles"),
    # B5: IncrementalValidate.xml reads $(ProjectDir) without declaring an
    # <Option> for it. ProjectFile/ProjectName/ProjectDir are set by the engine
    # ONLY when a project is supplied (BuildGraph.cs:325-333), so with no
    # --project this is precisely what the engine itself warns:
    # "Property 'ProjectDir' is not defined". A TRUE positive, not budget rot.
    ("Tests/IncrementalValidate.xml", "D1", "Property 'ProjectDir' is not defined"),
}


def _corpus_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for sub in ("Examples", "Examples/FPSBuildGraph", "Tests"):
        files.extend(sorted((CORPUS_ROOT / sub).glob("*.xml")))
    return files


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """The exact command ACCEPTANCE.md SS C pins: `python -m bgview
    <script.xml> --fail-on warn`, run as a real subprocess (same
    interpreter, same repo root) rather than re-implemented in-process --
    this harness's whole job is to prove what the ACTUAL CLI reports."""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "bgview", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=60,
    )


def _parse_finding_lines(stdout: str) -> list[dict]:
    """Every real finding line in `stdout`, per the SS I format -- the
    trailing 'N finding(s) total -- ...' summary line deliberately does not
    match `_FINDING_LINE_RE` (report.py's own documented guarantee), so it
    is naturally excluded without special-casing it here."""
    parsed = []
    for line in stdout.splitlines():
        m = _FINDING_LINE_RE.match(line)
        if m:
            parsed.append(m.groupdict())
    return parsed


class CorpusFalsePositiveBudgetTests(unittest.TestCase):
    """V5/V21 end-to-end through the real CLI."""

    @classmethod
    def setUpClass(cls):
        assert REAL_SCHEMA.is_file(), f"fixture missing: {REAL_SCHEMA}"
        cls.files = _corpus_files()

    def test_corpus_is_exactly_nineteen_files_by_the_documented_layout(self):
        # "assert the corpus really is 19 files so a broken glob cannot
        # silently pass" -- both the total AND the per-subdirectory split,
        # so a glob that e.g. silently missed the FPSBuildGraph subfolder
        # (6 files) but overcounted Tests/ by 6 some other way cannot hide
        # behind a coincidentally-correct total.
        self.assertEqual(len(self.files), 19, self.files)
        counts = {"Examples": 0, "FPSBuildGraph": 0, "Tests": 0}
        for f in self.files:
            parts = f.parts
            if "FPSBuildGraph" in parts:
                counts["FPSBuildGraph"] += 1
            elif "Tests" in parts:
                counts["Tests"] += 1
            elif "Examples" in parts:
                counts["Examples"] += 1
        self.assertEqual(counts, {"Examples": 10, "FPSBuildGraph": 6, "Tests": 3})

    def test_every_file_scans_cleanly_no_exceptions_and_warn_plus_identity_matches_pinned_set(self):
        actual: set[tuple[str, str, str]] = set()
        per_file_warn_plus: dict[str, list[dict]] = {}
        tool_errors: dict[str, subprocess.CompletedProcess] = {}

        for path in self.files:
            rel = str(path.relative_to(CORPUS_ROOT)).replace("\\", "/")
            result = _run_cli(str(path), "--schema", str(REAL_SCHEMA), "--fail-on", "warn")

            # Exit code 2 is bgview's OWN "tool error" signal (V16) -- catch
            # it explicitly by code first, since that is the unambiguous
            # channel. Exit codes 0/1 are the two "the tool ran fine"
            # outcomes; on THOSE, additionally confirm no unhandled
            # exception slipped past __main__'s catch-all and printed a
            # traceback while still (coincidentally) exiting 0 or 1 --
            # `main()`'s own tests (test_cli.py) pin exit 2 as the ONLY
            # legitimate outcome for an uncaught exception, so a traceback
            # appearing alongside exit 0/1 would itself be the regression.
            if result.returncode == 2 or "Traceback" in result.stderr:
                tool_errors[rel] = result
                continue

            self.assertIn(result.returncode, (0, 1), f"{rel}: unexpected exit code\n{result.stderr}")

            findings = _parse_finding_lines(result.stdout)
            warn_plus = [f for f in findings if f["severity"] in ("warn", "error")]
            per_file_warn_plus[rel] = warn_plus
            for f in warn_plus:
                # f["file"] is the absolute path bgview printed; recompute
                # the SAME corpus-relative form from it (not from `rel`
                # directly) so a detector that mis-anchors a finding on the
                # WRONG file (e.g. an <Include>d sibling) cannot hide behind
                # this test always trusting the file it happened to invoke.
                finding_abs = pathlib.Path(f["file"])
                finding_rel = str(finding_abs.relative_to(CORPUS_ROOT)).replace("\\", "/")
                actual.add((finding_rel, f["detector"], f["message"]))

        if tool_errors:
            details = "\n".join(f"{rel}: exit={r.returncode}\n{r.stderr}" for rel, r in tool_errors.items())
            self.fail(f"{len(tool_errors)} corpus file(s) raised a tool error instead of scanning cleanly:\n{details}")

        # Identity, not cardinality (V21): the actual set must equal the
        # pinned set exactly -- not merely have the same size. `message`
        # from stdout is compared, not a bare tag, because D2's stdout
        # message embeds the tag text ("Tag '#BinaryFiles' is consumed by
        # ...") -- substring-check it against the pinned tag below instead
        # of demanding an exact string match to the whole sentence, which
        # would make this test brittle to a pure wording change.
        actual_identity = {(rel, det, self._tag_of(msg)) for rel, det, msg in actual}
        self.assertEqual(
            actual_identity,
            _PINNED_WARN_PLUS,
            f"corpus warn+ identity set diverged from V21's pinned set.\n"
            f"actual={sorted(actual_identity)}\npinned={sorted(_PINNED_WARN_PLUS)}",
        )

        # Belt-and-suspenders per V21's own wording ("a run that misses
        # #BinaryFiles but emits one bogus warning has the right count and
        # must FAIL"): every pinned file has EXACTLY one warn+ finding, and
        # EVERY other scanned file has EXACTLY zero -- so neither a
        # duplicated pinned finding nor a silently-dropped scan can hide
        # behind the set-equality check above.
        # Occurrence counts are pinned EXACTLY, per file. V21 asserts identity
        # rather than cardinality, but a single identity can legitimately occur
        # more than once: IncrementalValidate.xml reads $(ProjectDir) on five
        # separate lines, so the engine would warn five times too. Pinning the
        # exact count keeps the belt-and-suspenders property (a duplicated
        # pinned finding or a silently-skipped scan still trips) without
        # pretending one-per-file is a rule.
        _EXPECTED_OCCURRENCES = {
            "Examples/BuildEditorAndTools.xml": 1,
            "Examples/FPSBuildGraph/BuildEditorAndTools.xml": 1,
            "Tests/IncrementalValidate.xml": 5,
        }
        for rel, warn_plus in sorted(per_file_warn_plus.items()):
            self.assertEqual(
                len(warn_plus), _EXPECTED_OCCURRENCES.get(rel, 0), (rel, warn_plus)
            )

        # And the scan actually covered all 19 -- a tool-error short-circuit
        # above would already have failed the test, but this pins it
        # independently of that path too.
        self.assertEqual(len(per_file_warn_plus), 19, per_file_warn_plus.keys())

    @staticmethod
    def _tag_of(message: str) -> str:
        """Pull the `#TagName` out of a D2 stdout message
        ("Tag '#BinaryFiles' is consumed by ..."). Falls back to the raw
        message for any non-D2 shape that reaches here (there should not be
        one, per the pinned set -- if there ever is, surfacing the full
        message rather than crashing keeps the diff above readable)."""
        m = re.search(r"'(#[^']+)'", message)
        return m.group(1) if m else message


if __name__ == "__main__":
    unittest.main()
