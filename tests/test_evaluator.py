"""Tests for bgview.evaluator (T3: property/option/envvar engine; T4:
control flow). One test per touched invariant, per the task brief:

    1. V12(a) undefined $(Nope)            -> one D1 finding, expands to ""
    2. V12(b) $(RootDir) (null builtin)     -> no finding, literal survives
    3. V12a $(Foo:2)/$(Foo:-2)/$(Foo:bar)   -> slice correctly / finding, no raise
    4. V22   19 builtins defined            -> no D1 on Change/EscapedBranch/IsBuildMachine
    5. V11   <Property> redefined AFTER an element does not change that element
    6. R15/V23 macro body sees a property defined BETWEEN definition and Expand
    7. V9    unknown element kind           -> D14 finding
    8. <ForEach> over "a;b"                 -> body emitted twice, loop var bound
    9. Smoke: real BuildEditorAndTools.xml evaluates without raising

Plus one extra safety test (rule: "never lazy on safety") for the include-
cycle guard T4 explicitly calls for, using the injectable `loader=` seam
from the evaluate() contract so it needs no real files on disk.
"""

from __future__ import annotations

import functools
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bgview.evaluator import BUILTINS, Opt, Resolved, evaluate
from bgview.findings import Severity
from bgview.loader import Elem, load
from bgview.schema import Schema

REAL_SCHEMA = pathlib.Path(r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph\Schema.xsd")
REAL_EXAMPLE = pathlib.Path(
    r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph\Examples\BuildEditorAndTools.xml"
)
REAL_MACROS = pathlib.Path(r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph\Examples\Macros.xml")

_NS = 'xmlns="http://www.epicgames.com/BuildGraph"'


@functools.lru_cache(maxsize=None)
def _real_schema() -> Schema:
    assert REAL_SCHEMA.is_file(), f"fixture missing: {REAL_SCHEMA}"
    return Schema.from_file(REAL_SCHEMA)


def _load_fragment(body: str) -> Elem:
    """Write `body` wrapped in a <BuildGraph> root to a temp file and load it."""
    xml = f"<?xml version='1.0'?>\n<BuildGraph {_NS}>\n{body}\n</BuildGraph>\n"
    with tempfile.TemporaryDirectory() as d:
        path = pathlib.Path(d) / "fixture.xml"
        path.write_text(xml, encoding="utf-8")
        return load(path)


def _props_by_name(resolved: list[Resolved]) -> dict[str, Resolved]:
    """Last <Property> Resolved entry seen for each Name= (fixtures below
    each declare a given name once, so "last" is also "only")."""
    out: dict[str, Resolved] = {}
    for r in resolved:
        if r.elem.tag == "Property":
            out[r.attrs.get("Name", "")] = r
    return out


class ExpansionOutcomeTests(unittest.TestCase):
    """V12: the three expansion outcomes, plus V12a's slice + malformed-slice
    handling, plus V22's built-in table. One fixture covers all four
    required cases (1, 2, 3, 4) since they are all just <Property Value=...>
    expansion outcomes observed the same way."""

    @classmethod
    def setUpClass(cls):
        root = _load_fragment(
            """
            <Property Name="Foo" Value="abcdef"/>
            <Property Name="Undefined" Value="$(Nope)"/>
            <Property Name="NullBuiltin" Value="before:$(RootDir):after"/>
            <Property Name="SlicePos" Value="$(Foo:2)"/>
            <Property Name="SliceNeg" Value="$(Foo:-2)"/>
            <Property Name="SliceBad" Value="$(Foo:bar)"/>
            <Property Name="Builtins" Value="$(Change)|$(EscapedBranch)|$(IsBuildMachine)"/>
            """
        )
        cls.result = evaluate(root, _real_schema(), overrides={})
        cls.props = _props_by_name(cls.result.resolved)
        cls.d1 = [f for f in cls.result.findings if f.detector == "D1"]

    # -- test 1: V12(a) --------------------------------------------------
    def test_undefined_property_warns_once_and_expands_empty(self):
        matches = [f for f in self.d1 if "Nope" in f.message]
        self.assertEqual(len(matches), 1, self.d1)
        self.assertEqual(matches[0].severity, Severity.WARN)
        self.assertEqual(self.props["Undefined"].attrs["Value"], "")

    # -- test 2: V12(b) ----------------------------------------------------
    def test_null_valued_builtin_no_finding_literal_survives(self):
        self.assertFalse([f for f in self.d1 if "RootDir" in f.message])
        self.assertEqual(self.props["NullBuiltin"].attrs["Value"], "before:$(RootDir):after")

    # -- test 3: V12a --------------------------------------------------
    def test_slice_applied_correctly_and_malformed_survives(self):
        self.assertEqual(self.props["SlicePos"].attrs["Value"], "ab")  # first 2
        self.assertEqual(self.props["SliceNeg"].attrs["Value"], "ef")  # last 2
        # Malformed slice: must not raise (already true, since setUpClass
        # completed) and must still produce a usable (best-effort) value
        # plus exactly one finding naming the bad reference.
        self.assertEqual(self.props["SliceBad"].attrs["Value"], "abcdef")
        bad = [f for f in self.d1 if "Foo:bar" in f.message]
        self.assertEqual(len(bad), 1, self.d1)

    # -- test 4: V22 --------------------------------------------------------
    def test_builtins_defined_no_d1(self):
        # 16 UNCONDITIONAL built-ins. R17 counts 19, but ProjectFile /
        # ProjectName / ProjectDir are set only when a project is supplied
        # (BuildGraph.cs:325-333) and arrive via --project -- see B5.
        self.assertEqual(len(BUILTINS), 16)
        for conditional in ("ProjectFile", "ProjectName", "ProjectDir"):
            self.assertNotIn(conditional, BUILTINS)
        self.assertIsNone(BUILTINS["RootDir"])
        self.assertEqual(self.props["Builtins"].attrs["Value"], "0|Unknown|false")
        self.assertFalse(
            [f for f in self.d1 if any(n in f.message for n in ("Change", "EscapedBranch", "IsBuildMachine"))]
        )


class ScopeOrderTests(unittest.TestCase):
    """V11: element-read-time expansion -- a <Property> redefined AFTER an
    element does not retroactively change that element's expanded value."""

    def test_redefinition_after_read_does_not_change_earlier_expansion(self):
        root = _load_fragment(
            """
            <Property Name="X" Value="first"/>
            <Property Name="Captured" Value="seen:$(X)"/>
            <Property Name="X" Value="second"/>
            """
        )
        result = evaluate(root, _real_schema(), overrides={})
        props = _props_by_name(result.resolved)
        self.assertEqual(props["Captured"].attrs["Value"], "seen:first")


class MacroExpansionScopeTests(unittest.TestCase):
    """R15/V23, mirroring Examples/Macros.xml's `PrintThreeValues` macro: its
    body reads $(FirstValue)/$(SecondValue)/$(ThirdValue), which are defined
    lexically AFTER the macro's own <Macro> block but BEFORE the <Expand>
    that invokes it. R22 measured that a doc-order (rather than execution-
    order) analysis mistakes these for undefined -- 3 false positives on
    this exact file. Using the real, unmodified example file directly."""

    @classmethod
    def setUpClass(cls):
        assert REAL_MACROS.is_file(), f"fixture missing: {REAL_MACROS}"
        root = load(REAL_MACROS)
        cls.result = evaluate(root, _real_schema(), overrides={})

    def test_macro_body_sees_properties_defined_between_definition_and_expand(self):
        messages = {r.attrs.get("Message") for r in self.result.resolved if r.elem.tag == "Log"}
        self.assertIn("First value: 123", messages)
        self.assertIn("Second value: 456", messages)
        self.assertIn("Third value: 789", messages)

        # R22's failure mode, specifically ruled out: no false "not defined"
        # findings for the very names the macro body references.
        bad = [
            f
            for f in self.result.findings
            if f.detector == "D1" and any(n in f.message for n in ("FirstValue", "SecondValue", "ThirdValue"))
        ]
        self.assertEqual(bad, [])

    def test_resolved_ordering_is_execution_order_not_doc_order(self):
        # V23: the <Property Name="FirstValue"> definition must occupy a
        # LOWER index in `resolved` than the (later-executing, but
        # earlier-in-the-SOURCE macro body) <Log> read of it -- the def/read
        # pair must be visible to a linear lifetime scan in this order.
        def_idx = next(idx for (name, _elem, idx) in self.result.prop_defs if name == "FirstValue")
        read_idx = next(
            i for i, r in enumerate(self.result.resolved) if r.attrs.get("Message") == "First value: 123"
        )
        self.assertLess(def_idx, read_idx)


class UnknownElementTests(unittest.TestCase):
    """V9: an element kind the schema and R14 both don't know about is a
    LOUD finding (D14), never a silent skip."""

    def test_unknown_element_kind_yields_d14(self):
        root = _load_fragment('<TotallyBogusElementXYZ Foo="bar"/>')
        result = evaluate(root, _real_schema(), overrides={})
        d14 = [f for f in result.findings if f.detector == "D14"]
        self.assertEqual(len(d14), 1, result.findings)
        self.assertEqual(d14[0].severity, Severity.WARN)
        self.assertIn("TotallyBogusElementXYZ", d14[0].message)


class ForEachTests(unittest.TestCase):
    """<ForEach> emits its body once per value, with the loop variable bound
    to that value each time (this is how e.g. `Compile $(GameTarget) Win64`
    multiplies into one Resolved/Node per target)."""

    def test_foreach_emits_body_once_per_value_with_loop_var_bound(self):
        root = _load_fragment(
            """
            <ForEach Name="X" Values="a;b">
                <Property Name="Seen" Value="$(X)"/>
            </ForEach>
            """
        )
        result = evaluate(root, _real_schema(), overrides={})
        seen = [r.attrs["Value"] for r in result.resolved if r.elem.tag == "Property" and r.attrs.get("Name") == "Seen"]
        self.assertEqual(seen, ["a", "b"])


class IncludeCycleSafetyTests(unittest.TestCase):
    """T4: "guard include cycles with a visited set -> finding, not infinite
    loop." Uses the injectable `loader=` parameter from evaluate()'s own
    contract to construct a self-referential A-includes-B-includes-A cycle
    entirely in memory -- no real files needed, and no risk of actually
    hanging the test runner if the guard were ever removed by accident
    (bounded by the ancestor-stack check, not by luck)."""

    def test_include_cycle_is_caught_not_infinite_looped(self):
        a_file = "C:/fake/A.xml"
        b_file = "C:/fake/B.xml"

        root_a = Elem(tag="BuildGraph", attrib={}, children=[], line=1, file=a_file)
        include_a = Elem(
            tag="Include", attrib={"Script": "B.xml"}, children=[], line=2, file=a_file, parent=root_a
        )
        root_a.children.append(include_a)

        root_b = Elem(tag="BuildGraph", attrib={}, children=[], line=1, file=b_file)
        include_b = Elem(
            tag="Include", attrib={"Script": "A.xml"}, children=[], line=2, file=b_file, parent=root_b
        )
        root_b.children.append(include_b)

        def fake_loader(path):
            name = pathlib.Path(path).name
            if name == "A.xml":
                return root_a
            if name == "B.xml":
                return root_b
            raise AssertionError(f"unexpected include path: {path}")

        # The point of the test: this call returns at all (no RecursionError,
        # no hang) -- proving the guard, not just describing it.
        result = evaluate(root_a, _real_schema(), overrides={}, loader=fake_loader)

        cycle_findings = [f for f in result.findings if f.detector == "D14" and "cycle" in f.message.lower()]
        self.assertGreaterEqual(len(cycle_findings), 1, result.findings)


class SmokeTests(unittest.TestCase):
    """Evaluate a real, unmodified Epic-shipped BuildGraph script end to end
    without raising -- this is the "does it actually survive real input"
    check the rest of the test suite's small synthetic fixtures can't give."""

    def test_evaluates_build_editor_and_tools_without_raising(self):
        self.assertTrue(REAL_EXAMPLE.is_file(), f"fixture missing: {REAL_EXAMPLE}")
        root = load(REAL_EXAMPLE)
        result = evaluate(root, _real_schema(), overrides={})

        self.assertGreater(len(result.resolved), 50)
        # Every finding must still carry a real file:line (V15 is enforced
        # by Finding.__post_init__ itself -- this just spot-checks a few).
        for f in result.findings[:20]:
            self.assertGreater(f.line, 0)
            self.assertTrue(f.file)

        # Sanity: option-set defaults being what BuildEditorAndTools.xml
        # actually declares (EditorTarget's DefaultValue is "UnrealEditor").
        self.assertIn("EditorTarget", result.options)
        self.assertEqual(result.options["EditorTarget"].default, "UnrealEditor")
        self.assertIsInstance(result.options["EditorTarget"], Opt)

        # The EditorTarget option feeds a Node name directly
        # (Name="Compile $(EditorTarget) Win64") -- confirms expansion runs
        # on Node/@Name too, not just task attributes.
        node_names = {r.attrs.get("Name") for r in result.resolved if r.elem.tag == "Node"}
        self.assertIn("Compile UnrealEditor Win64", node_names)


if __name__ == "__main__":
    unittest.main()
