"""Tests for bgview.report (T10): stdout renderer, SARIF 2.1.0, exit codes."""

import io
import json
import random
import tempfile
import unittest
from pathlib import Path

from bgview.findings import Finding, Severity
from bgview.report import exit_code, to_sarif, to_stdout


def _finding(
    file=r"C:\fake\repo\script.xml",
    line=10,
    severity=Severity.WARN,
    detector="D1",
    message="message",
    node=None,
    tag=None,
):
    return Finding(
        file=file,
        line=line,
        severity=severity,
        detector=detector,
        message=message,
        node=node,
        tag=tag,
    )


class ToStdoutFormatTests(unittest.TestCase):
    """§I: "<file>:<line>: <severity>: [<detector-id>] <message>", severity
    rendered lowercase."""

    def test_exact_format_for_known_finding(self):
        finding = Finding(
            file=r"C:\fake\repo\script.xml",
            line=48,
            severity=Severity.WARN,
            detector="D1",
            message="property 'GameBinaries' is never defined",
        )
        stream = io.StringIO()
        to_stdout([finding], stream=stream)
        lines = stream.getvalue().splitlines()
        self.assertEqual(
            lines[0],
            r"C:\fake\repo\script.xml:48: warn: [D1] property 'GameBinaries' is never defined",
        )

    def test_severity_rendered_lowercase_for_all_three_levels(self):
        findings = [
            _finding(line=1, severity=Severity.INFO, detector="D3"),
            _finding(line=2, severity=Severity.WARN, detector="D1"),
            _finding(line=3, severity=Severity.ERROR, detector="D14"),
        ]
        stream = io.StringIO()
        to_stdout(findings, stream=stream)
        lines = stream.getvalue().splitlines()
        self.assertIn(": info: [D3]", lines[0])
        self.assertIn(": warn: [D1]", lines[1])
        self.assertIn(": error: [D14]", lines[2])
        # Never uppercase/mixed-case -- §I mandates lowercase specifically.
        for line in lines[:3]:
            self.assertNotIn("INFO", line)
            self.assertNotIn("WARN", line)
            self.assertNotIn("ERROR", line)

    def test_summary_line_present_and_does_not_match_finding_format(self):
        findings = [
            _finding(line=1, severity=Severity.INFO, detector="D3"),
            _finding(line=2, severity=Severity.WARN, detector="D1"),
        ]
        stream = io.StringIO()
        to_stdout(findings, stream=stream)
        lines = stream.getvalue().splitlines()
        # Exactly one summary line trailing the two finding lines.
        self.assertEqual(len(lines), 3)
        summary = lines[-1]
        # Every real finding line has ":<digits>: <severity>: [" somewhere
        # in it -- a harness scanning stdout for that shape must never
        # mistake the summary for a finding.
        self.assertNotRegex(summary, r":\d+: (info|warn|error): \[")
        self.assertIn("2", summary)  # total count somewhere in the summary


class ToStdoutOrderingTests(unittest.TestCase):
    """Deterministic (file, line, detector) sort -- §I: "Sort deterministically
    ... so output is diffable and testable"."""

    def test_ordering_deterministic_across_two_shuffled_runs(self):
        findings = [
            _finding(file=r"C:\a\1.xml", line=5, detector="D1", message="m1"),
            _finding(file=r"C:\a\1.xml", line=2, detector="D2", message="m2"),
            _finding(file=r"C:\a\1.xml", line=2, detector="D1", message="m3"),
            _finding(file=r"C:\b\2.xml", line=1, detector="D1", message="m4"),
        ]
        shuffled_a = findings[:]
        random.Random(1).shuffle(shuffled_a)
        shuffled_b = findings[:]
        random.Random(99).shuffle(shuffled_b)
        # Sanity: the two shuffles actually produced different input orders.
        self.assertNotEqual([f.message for f in shuffled_a], [f.message for f in shuffled_b])

        stream_a = io.StringIO()
        to_stdout(shuffled_a, stream=stream_a)
        stream_b = io.StringIO()
        to_stdout(shuffled_b, stream=stream_b)

        self.assertEqual(stream_a.getvalue(), stream_b.getvalue())

        lines = stream_a.getvalue().splitlines()
        self.assertTrue(lines[0].startswith(r"C:\a\1.xml:2: warn: [D1]"))
        self.assertTrue(lines[1].startswith(r"C:\a\1.xml:2: warn: [D2]"))
        self.assertTrue(lines[2].startswith(r"C:\a\1.xml:5: warn: [D1]"))
        self.assertTrue(lines[3].startswith(r"C:\b\2.xml:1: warn: [D1]"))

    def test_empty_findings_list_prints_only_summary_line(self):
        stream = io.StringIO()
        to_stdout([], stream=stream)
        lines = stream.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertNotRegex(lines[0], r":\d+: (info|warn|error): \[")


class ExitCodeTests(unittest.TestCase):
    """V16: exit code is 1 iff some finding's severity >= fail_on threshold."""

    def test_warn_finding_with_fail_on_warn_is_1(self):
        findings = [_finding(severity=Severity.WARN)]
        self.assertEqual(exit_code(findings, Severity.WARN), 1)

    def test_only_info_with_fail_on_warn_is_0(self):
        findings = [_finding(severity=Severity.INFO)]
        self.assertEqual(exit_code(findings, Severity.WARN), 0)

    def test_only_info_with_fail_on_info_is_1(self):
        findings = [_finding(severity=Severity.INFO)]
        self.assertEqual(exit_code(findings, Severity.INFO), 1)

    def test_error_finding_always_trips_any_threshold(self):
        findings = [_finding(severity=Severity.ERROR)]
        self.assertEqual(exit_code(findings, Severity.INFO), 1)
        self.assertEqual(exit_code(findings, Severity.WARN), 1)
        self.assertEqual(exit_code(findings, Severity.ERROR), 1)

    def test_empty_findings_is_0_regardless_of_threshold(self):
        self.assertEqual(exit_code([], Severity.INFO), 0)
        self.assertEqual(exit_code([], Severity.WARN), 0)
        self.assertEqual(exit_code([], Severity.ERROR), 0)


class ToSarifStructureTests(unittest.TestCase):
    """SARIF 2.1.0 output, written with stdlib json only."""

    def test_valid_json_with_2_1_0_version_and_no_info_or_warn_levels(self):
        findings = [
            _finding(line=1, severity=Severity.INFO, detector="D3", message="a"),
            _finding(line=2, severity=Severity.WARN, detector="D1", message="b"),
            _finding(line=3, severity=Severity.ERROR, detector="D14", message="c"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "out.sarif"
            to_sarif(findings, str(out_path), tool_version="0.1.0")
            data = json.loads(out_path.read_text(encoding="utf-8"))

        self.assertEqual(data["version"], "2.1.0")
        self.assertIn("2.1.0", data["$schema"])

        results = data["runs"][0]["results"]
        self.assertEqual(len(results), 3)
        levels = {r["level"] for r in results}
        self.assertTrue(levels.issubset({"note", "warning", "error"}))
        self.assertNotIn("info", levels)
        self.assertNotIn("warn", levels)

    def test_rules_has_one_entry_per_distinct_detector_and_ruleid_matches(self):
        findings = [
            _finding(line=1, severity=Severity.INFO, detector="D3", message="a"),
            _finding(line=2, severity=Severity.WARN, detector="D1", message="b"),
            _finding(line=3, severity=Severity.WARN, detector="D1", message="c"),
            _finding(line=4, severity=Severity.ERROR, detector="D14", message="d"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            # Nested, not-yet-existing directory: exercises "create parent
            # directories if needed".
            out_path = Path(tmp) / "nested" / "dir" / "out.sarif"
            to_sarif(findings, str(out_path), tool_version="0.1.0")
            self.assertTrue(out_path.exists())
            data = json.loads(out_path.read_text(encoding="utf-8"))

        driver = data["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "bgview")
        self.assertEqual(driver["version"], "0.1.0")
        self.assertIn("informationUri", driver)
        self.assertTrue(driver["informationUri"])

        rules = driver["rules"]
        rule_ids = {rule["id"] for rule in rules}
        # 4 findings, 3 DISTINCT detector ids (D1 appears twice) -> 3 rules.
        self.assertEqual(rule_ids, {"D3", "D1", "D14"})
        self.assertEqual(len(rules), 3)
        for rule in rules:
            self.assertIn("name", rule)
            self.assertIn("shortDescription", rule)
            self.assertIn("text", rule["shortDescription"])
            self.assertIn("level", rule["defaultConfiguration"])

        for result in data["runs"][0]["results"]:
            self.assertIn(result["ruleId"], rule_ids)

    def test_region_start_line_matches_finding_line(self):
        findings = [_finding(line=77, detector="D5", message="provably empty tag")]
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "out.sarif"
            to_sarif(findings, str(out_path), tool_version="0.1.0")
            data = json.loads(out_path.read_text(encoding="utf-8"))

        region = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 77)


class ToSarifFileUriTests(unittest.TestCase):
    """A bare Windows path string is not a valid URI -- must be converted to
    file:///C:/... with forward slashes and percent-encoded spaces."""

    def test_windows_path_with_space_produces_valid_encoded_file_uri(self):
        findings = [
            _finding(file=r"C:\Program Files\x.xml", line=7, detector="D1", message="m"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "out.sarif"
            to_sarif(findings, str(out_path), tool_version="0.1.0")
            data = json.loads(out_path.read_text(encoding="utf-8"))

        uri = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "file:///C:/Program%20Files/x.xml")
        self.assertNotIn(" ", uri)
        self.assertTrue(uri.startswith("file:///C:/"))


class ToSarifEmptyFindingsTests(unittest.TestCase):
    """Empty findings list must not crash and must still be valid SARIF."""

    def test_empty_findings_list_produces_valid_sarif_with_empty_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "out.sarif"
            to_sarif([], str(out_path), tool_version="0.1.0")
            data = json.loads(out_path.read_text(encoding="utf-8"))

        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(data["runs"][0]["results"], [])
        self.assertEqual(data["runs"][0]["tool"]["driver"]["rules"], [])
        self.assertEqual(exit_code([], Severity.INFO), 0)


if __name__ == "__main__":
    unittest.main()
