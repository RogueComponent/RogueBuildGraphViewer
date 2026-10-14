"""§T.15 -- the expansion oracle.

V11 claims bgview models the engine's parse-time, top-to-bottom, scope-stack
property expansion. That claim is only worth anything if it is pinned per
element, so this asserts the EXACT expanded value of every probe in
tests/fixtures/expansion_oracle.xml.

Every expectation was derived from the engine's C# source
(BgScriptReader.ExpandProperties / TryGetPropertyValue / SetPropertyValue),
not from observing what this implementation happens to produce. If a change
makes one of these fail, the question to ask is "does the engine agree?", not
"how do I make the test pass?".
"""

import pathlib
import unittest

from bgview import evaluator, loader, schema
from bgview.findings import Severity

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "expansion_oracle.xml"


def _probes():
    """Expand the fixture and return {probe-id: expanded Message value}."""
    sch = schema.discover(str(FIXTURE))
    ev = evaluator.evaluate(loader.load(FIXTURE), sch, {})
    out = {}
    for r in ev.resolved:
        msg = r.attrs.get("Message")
        if msg and "=" in msg:
            pid, _, val = msg.partition("=")
            out.setdefault(pid, []).append(val)
    return out, ev


class ExpansionOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probes, cls.ev = _probes()

    def one(self, pid):
        vals = self.probes.get(pid)
        self.assertIsNotNone(vals, f"probe {pid} never appeared in the resolved stream")
        self.assertEqual(len(vals), 1, f"probe {pid} appeared {len(vals)}x, expected once")
        return vals[0]

    # --- plain expansion -------------------------------------------------
    def test_p1_plain_expansion(self):
        self.assertEqual(self.one("P1"), "hello")

    def test_p2_plain_expansion_of_longer_value(self):
        self.assertEqual(self.one("P2"), "abcdefgh")

    # --- R18 slice syntax ------------------------------------------------
    def test_p3_positive_slice_takes_first_n(self):
        self.assertEqual(self.one("P3"), "abc")

    def test_p4_negative_slice_takes_last_n(self):
        self.assertEqual(self.one("P4"), "fgh")

    def test_p5_slice_is_a_noop_when_value_is_not_longer_than_n(self):
        """R18: the slice applies ONLY when len(value) > abs(N).

        'abc' is 3 chars and abs(-6) is 6, so the engine leaves it alone. An
        implementation that naively slices would return '' or raise here.
        """
        self.assertEqual(self.one("P5"), "abc")

    # --- V12: the three expansion outcomes -------------------------------
    def test_p6_undefined_expands_empty_and_warns(self):
        """V12(a): not found -> expands to '' AND emits a D1 finding."""
        self.assertEqual(self.one("P6"), "[]")
        d1 = [
            f for f in self.ev.findings
            if f.detector == "D1" and "NoSuchProperty" in f.message
        ]
        self.assertEqual(len(d1), 1, "expected exactly one D1 for NoSuchProperty")
        self.assertGreaterEqual(d1[0].severity, Severity.WARN)

    def test_p7_null_valued_builtin_keeps_literal_and_stays_silent(self):
        """V12(b) -- the subtle one.

        RootDir is a built-in that EXISTS but holds a null value. The engine's
        `if (value != null)` guard at BgScriptReader.cs:653 means the literal
        $(RootDir) text survives untouched and NO warning is emitted. Getting
        this wrong is silent corruption: you would either blank the path or
        emit a false 'not defined' warning about a property that is defined.
        """
        self.assertEqual(self.one("P7"), "$(RootDir)")
        noisy = [f for f in self.ev.findings if "RootDir" in f.message]
        self.assertEqual(noisy, [], f"RootDir must not produce a finding, got {noisy}")

    def test_p8_non_null_builtin_expands(self):
        """V22: the built-in table is loaded, so this is not a D1."""
        self.assertEqual(self.one("P8"), "false")
        self.assertEqual([f for f in self.ev.findings if "IsBuildMachine" in f.message], [])

    # --- V11 / R5: expansion order ---------------------------------------
    def test_p1_unaffected_by_later_redefinition(self):
        """The whole point of V11: a <Property> redefined AFTER an element does
        not reach back and change it. P1 read 'hello'; the redefinition to
        'REDEFINED' happens later in the document and must not touch it."""
        self.assertEqual(self.one("P1"), "hello")

    def test_p9_sees_the_redefined_value(self):
        self.assertEqual(self.one("P9"), "REDEFINED")

    # --- R20: the accumulator idiom --------------------------------------
    def test_p10_accumulator_builds_up(self):
        """Used 37x across Epic's corpus. Must expand correctly and must never
        be treated as a dead or clobbered definition (that was §B-adjacent
        unsoundness in the first cut of D13)."""
        self.assertEqual(self.one("P10"), "one;two;three")

    def test_accumulator_produces_no_dead_property_findings(self):
        bad = [
            f for f in self.ev.findings
            if f.detector in ("D8", "D13") and "Acc" in (f.message or "")
        ]
        self.assertEqual(bad, [], f"accumulator must not be flagged, got {bad}")

    # --- scope stack ------------------------------------------------------
    def test_p11_foreach_binds_loop_var_once_per_value(self):
        self.assertEqual(self.probes.get("P11"), ["alpha", "beta"])

    # --- R15 / V23: macro scoping ----------------------------------------
    def test_p12_macro_body_resolves_at_the_expansion_site(self):
        """R15: MacroProbe is defined BELOW the <Macro> but ABOVE the <Expand>.
        Resolving at the definition site would yield '' plus a bogus D1; only
        resolving at the expansion site gives the real value."""
        self.assertEqual(self.one("P12"), "seen-at-expansion-site")
        self.assertEqual([f for f in self.ev.findings if "MacroProbe" in f.message], [])

    def test_resolved_is_execution_order_not_document_order(self):
        """V23: the macro body's Log must appear in the stream AFTER the
        property it reads was defined -- i.e. at the expansion point."""
        order = [
            i for i, r in enumerate(self.ev.resolved)
            if (r.attrs.get("Message") or "").startswith("P12=")
        ]
        self.assertEqual(len(order), 1)
        defs = [i for i, (n, _e, _idx) in enumerate(self.ev.prop_defs) if n == "MacroProbe"]
        self.assertTrue(defs, "MacroProbe definition should be recorded")


if __name__ == "__main__":
    unittest.main()
