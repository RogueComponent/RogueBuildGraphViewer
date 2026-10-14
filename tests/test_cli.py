"""Tests for bgview.__main__ (T10): the CLI half of the pipeline.

`python -m bgview <script.xml> [opts]` wires `loader.load -> schema.discover
-> evaluator.evaluate -> model.build -> detectors.run_all -> report.to_stdout`
(always), plus `report.to_sarif` / `bgview.html.to_html` opt-in, with exit
codes 0/1/2 per V16. Every test here invokes the REAL `python -m bgview`
subprocess -- ACCEPTANCE.md SS C's own literal command form ("python -m
bgview <script.xml> --fail-on warn") -- rather than calling `main()` in
process, so a packaging/entry-point mistake (missing `__main__` guard, wrong
argv handling, an import that only breaks under real `-m` execution) would
actually be caught here. This file exists to prove the WIRING is correct;
it deliberately does not re-verify any individual stage's own behavior --
loader/schema/evaluator/model/detectors/report each already have their own
dedicated test_*.py covering that.

Required coverage (task brief):
  1. SarifOutputTests      -- --sarif writes valid SARIF 2.1.0 to a temp dir
  2. MalformedXmlTests     -- malformed XML exits 2, never 1, never a traceback
  3. FailOnThresholdTests  -- --fail-on actually moves the exit-code threshold
  4. SetOverrideTests      -- --set actually changes an <Option>'s value
  5. NonexistentInputTests -- a nonexistent input file exits 2, clear message
  6. BaselineTests         -- V26: --baseline suppresses by Finding.key()'s
     NORMALISED FULL PATH, never basename -- two same-basename files in
     different directories must not collide (the exact shape B2 fixed).

Deliberately NOT covered here: `--html`. `bgview/html.py` (T13) is a
concurrent worker's file that may not exist (or may not be finished) at any
given moment this suite runs -- see `bgview/__main__.py`'s own module
docstring for how the CLI stays robust either way. Testing that module's
behavior is its own owner's job.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
REAL_SCHEMA = pathlib.Path(r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph\Schema.xsd")

_NS = 'xmlns="http://www.epicgames.com/BuildGraph"'


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """Invoke the REAL `python -m bgview ...`: same interpreter running this
    test (`sys.executable`), same repo root on sys.path that `cd .../bgview
    && python -m unittest discover -s tests` itself runs from -- so this is
    exactly the command a human or CI would type, not a re-implementation."""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"  # deterministic decoding regardless of console codepage
    return subprocess.run(
        [sys.executable, "-m", "bgview", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=60,
    )


def _write(dir_path: str, name: str, text: str) -> pathlib.Path:
    p = pathlib.Path(dir_path) / name
    p.write_text(text, encoding="utf-8")
    return p


def _one_warn_script(dir_path: str, tag_name: str = "Alpha") -> pathlib.Path:
    """A minimal fixture with exactly one warn+ finding: D2, `#<tag_name>`
    consumed by a TASK attribute but produced nowhere. Parameterized on the
    tag name so callers can prove `--set` changes what is actually analyzed.

    Consumption goes through `Log/@Files`, not `Node/@Requires`, deliberately:
    an unresolvable tag in `Requires` is an engine HARD ERROR and is owned by
    D18 at `error` severity, while a tag consumed by a task attribute is a
    runtime file-set lookup that the engine tolerates -- which is exactly why
    Epic's own BuildEditorAndTools.xml builds despite #BinaryFiles never being
    produced. This fixture needs the `warn` shape, so it uses the task form."""
    return _write(
        dir_path,
        "script.xml",
        f"""<?xml version='1.0'?>
<BuildGraph {_NS}>
    <Option Name="Which" DefaultValue="{tag_name}"/>
    <Agent Name="A" Type="Win64">
        <Node Name="Consumer">
            <Log Message="probe" Files="#$(Which)"/>
        </Node>
    </Agent>
</BuildGraph>
""",
    )


def _info_only_script(dir_path: str) -> pathlib.Path:
    """A fixture with findings only at INFO (D3: a `@Produces` tag never
    consumed; D15: a hardcoded `Agent/@Type`) and nothing at warn/error --
    for proving `--fail-on` actually moves the exit-code threshold in both
    directions, per V16."""
    return _write(
        dir_path,
        "script.xml",
        f"""<?xml version='1.0'?>
<BuildGraph {_NS}>
    <Agent Name="A" Type="Win64">
        <Node Name="N1" Produces="#Foo"/>
    </Agent>
</BuildGraph>
""",
    )


# ---------------------------------------------------------------------------
# 1. --sarif writes valid SARIF 2.1.0 to a temp dir
# ---------------------------------------------------------------------------


class SarifOutputTests(unittest.TestCase):
    def test_sarif_writes_valid_2_1_0_to_a_temp_dir_and_matches_stdout(self):
        with tempfile.TemporaryDirectory() as d:
            script = _one_warn_script(d)
            # Nested, not-yet-existing directory: proves the CLI (via
            # report.to_sarif) creates parent dirs rather than erroring.
            sarif_path = pathlib.Path(d) / "out" / "report.sarif"

            result = _run_cli(str(script), "--schema", str(REAL_SCHEMA), "--sarif", str(sarif_path))

            self.assertEqual(result.returncode, 1, result.stderr)  # the one D2 warn -> default --fail-on warn -> 1
            self.assertTrue(sarif_path.is_file(), "bgview did not write the --sarif output file")

            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))

        self.assertEqual(sarif["version"], "2.1.0")
        results = sarif["runs"][0]["results"]

        d2_results = [r for r in results if r["ruleId"] == "D2"]
        self.assertEqual(len(d2_results), 1, results)
        self.assertEqual(d2_results[0]["level"], "warning")
        region = d2_results[0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 6)  # <Log Files="#..."/> is the fixture's 6th line

        # stdout's own trailing summary line and the SARIF results array are
        # two renderings of the SAME findings list the CLI computed once --
        # they must agree on the total.
        self.assertIn(f"{len(results)} finding(s) total", result.stdout)


# ---------------------------------------------------------------------------
# 2. malformed XML -> exit 2, never 1, never a traceback
# ---------------------------------------------------------------------------


class MalformedXmlTests(unittest.TestCase):
    def test_malformed_xml_exits_2_not_1_no_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            # Unclosed start tag -- expat hits EOF mid-element. loader.load
            # (V7) turns this into a BgError; __main__ must turn THAT into a
            # clean exit 2, never let it surface as an unhandled traceback.
            script = _write(d, "bad.xml", "<?xml version='1.0'?>\n<BuildGraph>\n<Option Name=\"X\"\n")

            result = _run_cli(str(script), "--schema", str(REAL_SCHEMA))

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stdout)
        self.assertNotIn("Traceback", result.stderr)
        self.assertTrue(result.stderr.strip(), "expected a clear diagnostic on stderr")
        # stdout is the tool's PRIMARY output channel (SS I) -- a tool error
        # must not dress itself up as a (partial/empty) findings report there.
        self.assertEqual(result.stdout, "")

    def test_doctype_rejected_via_the_cli_exits_2(self):
        # V7 hardening (billion-laughs shape), exercised end-to-end through
        # the CLI rather than loader.load directly -- proves __main__ routes
        # this specific BgError the same way as any other.
        payload = (
            "<?xml version='1.0'?>\n"
            "<!DOCTYPE lolz [\n"
            ' <!ENTITY lol "lol">\n'
            "]>\n"
            "<BuildGraph xmlns='http://www.epicgames.com/BuildGraph'>&lol;</BuildGraph>\n"
        )
        with tempfile.TemporaryDirectory() as d:
            script = _write(d, "doctype.xml", payload)
            result = _run_cli(str(script), "--schema", str(REAL_SCHEMA))

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("Traceback", result.stderr)


# ---------------------------------------------------------------------------
# 3. --fail-on moves the exit-code threshold (V16)
# ---------------------------------------------------------------------------


class FailOnThresholdTests(unittest.TestCase):
    def test_fail_on_moves_the_exit_code_threshold(self):
        with tempfile.TemporaryDirectory() as d:
            script = _info_only_script(d)  # only INFO findings, nothing warn+

            default_result = _run_cli(str(script), "--schema", str(REAL_SCHEMA))
            info_result = _run_cli(str(script), "--schema", str(REAL_SCHEMA), "--fail-on", "info")
            warn_result = _run_cli(str(script), "--schema", str(REAL_SCHEMA), "--fail-on", "warn")
            error_result = _run_cli(str(script), "--schema", str(REAL_SCHEMA), "--fail-on", "error")

        self.assertEqual(default_result.returncode, 0, default_result.stdout)  # default is warn; only info present
        self.assertEqual(info_result.returncode, 1, info_result.stdout)  # info >= info threshold
        self.assertEqual(warn_result.returncode, 0, warn_result.stdout)
        self.assertEqual(error_result.returncode, 0, error_result.stdout)

    def test_fail_on_warn_trips_on_a_warn_finding(self):
        with tempfile.TemporaryDirectory() as d:
            script = _one_warn_script(d)
            warn_result = _run_cli(str(script), "--schema", str(REAL_SCHEMA), "--fail-on", "warn")
            error_result = _run_cli(str(script), "--schema", str(REAL_SCHEMA), "--fail-on", "error")

        self.assertEqual(warn_result.returncode, 1, warn_result.stdout)
        self.assertEqual(error_result.returncode, 0, error_result.stdout)  # a warn does not trip an error-only gate


# ---------------------------------------------------------------------------
# 4. --set actually changes an <Option>'s value
# ---------------------------------------------------------------------------


class SetOverrideTests(unittest.TestCase):
    def test_set_overrides_the_option_default_and_the_change_is_visible_in_output(self):
        with tempfile.TemporaryDirectory() as d:
            script = _one_warn_script(d, tag_name="Alpha")

            default_result = _run_cli(str(script), "--schema", str(REAL_SCHEMA))
            overridden_result = _run_cli(str(script), "--schema", str(REAL_SCHEMA), "--set", "Which=Beta")

        self.assertIn("#Alpha", default_result.stdout)
        self.assertNotIn("#Beta", default_result.stdout)

        self.assertIn("#Beta", overridden_result.stdout)
        self.assertNotIn("#Alpha", overridden_result.stdout)

    def test_set_is_repeatable_and_a_malformed_entry_is_a_clean_tool_error(self):
        with tempfile.TemporaryDirectory() as d:
            script = _one_warn_script(d, tag_name="Alpha")
            # No '=' at all -- not NAME=VALUE form.
            result = _run_cli(str(script), "--schema", str(REAL_SCHEMA), "--set", "NotKeyValue")

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)


# ---------------------------------------------------------------------------
# 5. nonexistent input file -> exit 2, clear message
# ---------------------------------------------------------------------------


class NonexistentInputTests(unittest.TestCase):
    def test_nonexistent_input_file_exits_2_with_a_clear_message(self):
        missing = REPO_ROOT / "this_file_does_not_exist_anywhere.xml"
        self.assertFalse(missing.exists())  # sanity on the fixture itself

        result = _run_cli(str(missing))

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(str(missing), result.stderr)
        self.assertIn("does not exist", result.stderr.lower())

    def test_input_path_that_is_a_directory_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            result = _run_cli(d)  # a directory, not a file

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("Traceback", result.stderr)


# ---------------------------------------------------------------------------
# 6. --baseline + V26: full-path identity, never basename
# ---------------------------------------------------------------------------


class BaselineTests(unittest.TestCase):
    """--baseline suppresses findings whose `Finding.key()` matches an entry
    in a JSON baseline file, paths stored relative to the ANALYZED SCRIPT's
    own directory (portable) and resolved on load. V26/B2 is the sharp edge
    here: `Finding.key()` was fixed to key on the NORMALISED FULL PATH,
    never `os.path.basename(file)`, specifically because two files can
    legally share a basename in different directories (V21's own pinned
    corpus set has exactly this shape). A baseline implementation that
    (re)introduced a basename-keyed comparison would silently suppress the
    WRONG file's finding whenever that happens.
    """

    def test_baseline_suppresses_a_matching_finding(self):
        with tempfile.TemporaryDirectory() as d:
            script = _one_warn_script(d, tag_name="Alpha")
            baseline = _write(
                d,
                "baseline.json",
                json.dumps([{"file": "script.xml", "detector": "D2", "tag": "#Alpha"}]),
            )

            result = _run_cli(str(script), "--schema", str(REAL_SCHEMA), "--baseline", str(baseline))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)  # the only warn was baselined away
        self.assertNotIn(": warn:", result.stdout)

    def test_baseline_does_not_collide_across_same_basename_different_directory(self):
        # Two files sharing a basename ("Common.xml"), included by one
        # top-level script from two different directories, each with an
        # otherwise-identical D2 finding on the same tag -- V26/B2's exact
        # failure shape. A baseline entry naming ONLY the `a/` copy must
        # suppress THAT finding and leave the `b/` copy's identical-looking
        # finding fully reported.
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "a").mkdir()
            (pathlib.Path(d) / "b").mkdir()
            common = f"""<?xml version='1.0'?>
<BuildGraph {_NS}>
    <Agent Name="AgentA" Type="Win64">
        <Node Name="Consumer">
            <Log Message="probe" Files="#Alpha"/>
        </Node>
    </Agent>
</BuildGraph>
"""
            _write(str(pathlib.Path(d) / "a"), "Common.xml", common)
            _write(str(pathlib.Path(d) / "b"), "Common.xml", common)
            main_script = _write(
                d,
                "main.xml",
                f"""<?xml version='1.0'?>
<BuildGraph {_NS}>
    <Include Script="a/Common.xml"/>
    <Include Script="b/Common.xml"/>
</BuildGraph>
""",
            )
            baseline = _write(
                d,
                "baseline.json",
                json.dumps([{"file": "a/Common.xml", "detector": "D2", "tag": "#Alpha"}]),
            )

            result = _run_cli(str(main_script), "--schema", str(REAL_SCHEMA), "--baseline", str(baseline))

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)  # b's copy must still fire
        warn_lines = [line for line in result.stdout.splitlines() if ": warn:" in line]
        self.assertEqual(len(warn_lines), 1, warn_lines)
        self.assertIn(str(pathlib.Path("b") / "Common.xml"), warn_lines[0])
        self.assertNotIn(str(pathlib.Path("a") / "Common.xml"), warn_lines[0])

    def test_baseline_path_that_does_not_exist_is_a_clean_tool_error(self):
        # SS T.10 is explicit: --baseline is READ-ONLY -- a missing baseline
        # file must be reported as a tool error, never silently created.
        with tempfile.TemporaryDirectory() as d:
            script = _one_warn_script(d)
            missing_baseline = pathlib.Path(d) / "does_not_exist.json"

            result = _run_cli(str(script), "--schema", str(REAL_SCHEMA), "--baseline", str(missing_baseline))

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(missing_baseline.exists(), "--baseline must never invent/create the file")


if __name__ == "__main__":
    unittest.main()
