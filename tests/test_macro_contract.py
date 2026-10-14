"""D17 / V31 -- bgview must be at least as loud as the engine itself.

BgScriptReader reports five macro-contract problems that bgview previously
no-op'd in silence:

    :1080  Macro '{X}' has already been declared          LogError
    :1137  Macro '{X}' has not been declared  (Extend)    LogError
    :1748  Macro '{X}' does not exist         (Expand)    LogError
    :1765  Macro '{X}' does not take an argument '{A}'    LogWarning
    :1776  Macro '{X}' is missing argument '{A}'          LogWarning

Being silent where the ENGINE errors is a coverage hole, and a particularly
bad one for a tool whose whole pitch is that the engine under-reports. Corpus
incidence was measured at 0, so none of this can spend the V21 FP budget.
"""

import pathlib
import tempfile
import unittest

from bgview import evaluator, loader, schema
from bgview.findings import Severity

HEAD = "<?xml version='1.0' ?>\n<BuildGraph xmlns=\"http://www.epicgames.com/BuildGraph\">\n"
TAIL = "</BuildGraph>\n"


def _run(body: str):
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "s.xml"
        p.write_text(HEAD + body + TAIL, encoding="utf-8")
        sch = schema.discover(str(p))
        ev = evaluator.evaluate(loader.load(p), sch, {})
        return [f for f in ev.findings if f.detector == "D17"]


class MacroContractTests(unittest.TestCase):
    def test_expand_of_undeclared_macro_is_an_error(self):
        f = _run('<Agent Name="A" Type="W"><Node Name="N">'
                 '<Expand Name="NotDeclared"/></Node></Agent>')
        self.assertEqual(len(f), 1, f)
        self.assertEqual(f[0].severity, Severity.ERROR)
        self.assertIn("NotDeclared", f[0].message)
        self.assertGreater(f[0].line, 0)

    def test_extend_of_undeclared_macro_is_an_error(self):
        f = _run('<Extend Name="Nope"><Log Message="x"/></Extend>')
        self.assertEqual(len(f), 1, f)
        self.assertEqual(f[0].severity, Severity.ERROR)

    def test_duplicate_macro_declaration_is_an_error(self):
        f = _run('<Macro Name="M"><Log Message="a"/></Macro>'
                 '<Macro Name="M"><Log Message="b"/></Macro>')
        self.assertEqual(len(f), 1, f)
        self.assertEqual(f[0].severity, Severity.ERROR)
        self.assertIn("already been declared", f[0].message)

    def test_unknown_argument_is_a_warning(self):
        f = _run('<Macro Name="M" Arguments="Good"><Log Message="$(Good)"/></Macro>'
                 '<Agent Name="A" Type="W"><Node Name="N">'
                 '<Expand Name="M" Good="1" Typo="2"/></Node></Agent>')
        self.assertEqual(len(f), 1, f)
        self.assertEqual(f[0].severity, Severity.WARN)
        self.assertIn("Typo", f[0].message)

    def test_missing_required_argument_is_a_warning_and_body_is_skipped(self):
        f = _run('<Macro Name="M" Arguments="Needed"><Log Message="$(Needed)"/></Macro>'
                 '<Agent Name="A" Type="W"><Node Name="N">'
                 '<Expand Name="M"/></Node></Agent>')
        self.assertEqual(len(f), 1, f)
        self.assertEqual(f[0].severity, Severity.WARN)
        self.assertIn("Needed", f[0].message)
        # The dangerous part is the silence, not the skip -- say the body vanished.
        self.assertIn("skipped", f[0].message)

    def test_optional_argument_absent_is_not_a_finding(self):
        f = _run('<Macro Name="M" Arguments="A" OptionalArguments="B">'
                 '<Log Message="$(A)$(B)"/></Macro>'
                 '<Agent Name="Ag" Type="W"><Node Name="N">'
                 '<Expand Name="M" A="1"/></Node></Agent>')
        self.assertEqual(f, [])

    def test_well_formed_macro_use_is_silent(self):
        f = _run('<Macro Name="M" Arguments="A"><Log Message="$(A)"/></Macro>'
                 '<Agent Name="Ag" Type="W"><Node Name="N">'
                 '<Expand Name="M" A="1"/></Node></Agent>')
        self.assertEqual(f, [])


if __name__ == "__main__":
    unittest.main()
