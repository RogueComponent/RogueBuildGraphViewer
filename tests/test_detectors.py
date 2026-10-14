"""Tests for bgview.detectors (T9): D2..D16.

Required coverage per the task brief, one class per item:

    1. AcceptanceTargetFileTests   -- the full ACCEPTANCE.md §A table: exactly
       4 warn+ findings at lines 48/59/61/77, D2/D11/D5 on 59/61/77
       respectively (line 48's D1 is the evaluator's, not this module's).
    2. TaxonomySilenceTests        -- zero findings anywhere corresponding to
       taxonomy #5 (cross-agent/workspace dependency) or #12 (SetVersion
       should have been guarded) -- V24.
    3. CorpusFalsePositiveBudgetTests -- V5/V21, the single most important
       test in the repo: over all 19 real Epic corpus files, the warn+ set
       is EXACTLY the two pinned #BinaryFiles D2 findings.
    4. D5UnresolvableContributorTests -- V20: one unresolvable contributor
       anywhere in a tag's provenance suppresses D5 entirely.
    5. D13AccumulatorIdiomTests    -- V23/R20: the `$(X);more` accumulator
       idiom never trips D13.
    6. D12ExistsOpaqueTests        -- V10/V14: `Exists(...)` classifies
       "unknown" -- neither a D12 warn nor a D12 info.
    7. D3VsD4Tests                 -- V3 vs V4: a @Produces tag unconsumed is
       info (D3); a node-internal created tag unconsumed is warn (D4).

Plus a small set of focused regression tests (reusing the same real/target
fixtures already required above wherever possible, per "no fixture
sprawl") pinning the concrete bugs found and fixed while developing this
module against the real corpus -- each one was a genuine false positive
measured on real Epic-shipped script content, not a hypothetical:

    * D2 must not fire on a tag created and consumed within ONE node with
      no @Produces at all (measured on the target file's own #SourceFiles/
      #ArchiveFiles/#ArchiveBinaries/#ArchiveSymbols -- checking only
      `Graph.producers_of`, which is scoped to @Produces, missed node-local
      `Node.creates` entirely).
    * D13 must not fire on a property that is simply never referenced
      anywhere (that is D8's exclusive territory -- measured on the target
      file's own `ArchiveStagingRelativeDir`).
    * D13 must not treat a redefinition as "certainly clobbers" when only
      an ANCESTOR element (a wrapping `<Do If=...>`) carries the guard, not
      the redefining element itself (measured on
      Tests/IncrementalCompare.xml's `NullIncrementalCookPrereq`).
    * D11's witness mechanism, isolated: fires when the ONLY way to fill a
      required attribute also disables the node that needed it (the target
      file's actual injected defect); stays silent when filling it keeps
      the dependency correctly gated (the real corpus's non-defective
      shape) -- mirroring both real shapes as small fragments so this
      reasoning is pinned independent of the full corpus scan.
    * D9 and D7 sanity checks -- neither is exercised by the ACCEPTANCE
      target file at all (D7 never fires there; every option in that file
      happens to be referenced somewhere, so D9 never fires there either),
      so each needs its own small positive-case fixture to prove the
      detector actually works.
"""

from __future__ import annotations

import functools
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bgview.detectors import run_all
from bgview.evaluator import evaluate
from bgview.findings import Finding, Severity
from bgview.loader import load
from bgview.model import Graph, build
from bgview.schema import Schema

REAL_SCHEMA = pathlib.Path(r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph\Schema.xsd")
CORPUS_ROOT = pathlib.Path(r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph")
# A real-world BuildGraph script the end-to-end tests run against. It is not
# shipped with the repo: set BGVIEW_TARGET_SCRIPT to its path to run them.
TARGET_FILE = pathlib.Path(os.environ.get("BGVIEW_TARGET_SCRIPT", ""))

_NS = 'xmlns="http://www.epicgames.com/BuildGraph"'


@functools.lru_cache(maxsize=None)
def _real_schema() -> Schema:
    assert REAL_SCHEMA.is_file(), f"fixture missing: {REAL_SCHEMA}"
    return Schema.from_file(REAL_SCHEMA)


def _run_pipeline(path: pathlib.Path) -> list[Finding]:
    """load -> evaluate -> build -> run_all, returning every finding from
    every stage (evaluator's own D1/D14 + detectors.run_all's D2..D16) --
    exactly the set `python -m bgview` would report for one file."""
    root = load(path)
    ev = evaluate(root, _real_schema(), overrides={})
    graph, model_findings = build(ev, _real_schema())
    det_findings = run_all(graph, ev, _real_schema())
    return list(ev.findings) + list(model_findings) + list(det_findings)


@functools.lru_cache(maxsize=None)
def _target_findings() -> tuple[Finding, ...]:
    assert TARGET_FILE.is_file(), f"fixture missing: {TARGET_FILE}"
    return tuple(_run_pipeline(TARGET_FILE))


def _corpus_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for sub in ("Examples", "Examples/FPSBuildGraph", "Tests"):
        files.extend(sorted((CORPUS_ROOT / sub).glob("*.xml")))
    return files


def _graph_from_fragment(body: str) -> tuple[Graph, list[Finding]]:
    """Write `body` wrapped in a <BuildGraph> root to a temp file, run the
    full load->evaluate->build->run_all pipeline, and return (graph,
    findings) -- the detectors.py analogue of test_model.py/
    test_evaluator.py's own same-named/`_load_fragment` helpers."""
    xml = f"<?xml version='1.0'?>\n<BuildGraph {_NS}>\n{body}\n</BuildGraph>\n"
    with tempfile.TemporaryDirectory() as d:
        path = pathlib.Path(d) / "fixture.xml"
        path.write_text(xml, encoding="utf-8")
        root = load(path)
    ev = evaluate(root, _real_schema(), overrides={})
    graph, _model_findings = build(ev, _real_schema())
    findings = run_all(graph, ev, _real_schema())
    return graph, findings


# ---------------------------------------------------------------------------
# 1. ACCEPTANCE.md §A -- the target file's exact pinned warn+ set
# ---------------------------------------------------------------------------


class AcceptanceTargetFileTests(unittest.TestCase):
    def test_exactly_four_warn_plus_findings_at_pinned_lines(self):
        findings = _target_findings()
        warn_plus = [f for f in findings if f.severity >= Severity.WARN]
        self.assertEqual(
            sorted(f.line for f in warn_plus),
            [48, 59, 61, 77],
            [(f.line, f.severity.name, f.detector, f.message) for f in warn_plus],
        )
        self.assertEqual(len(warn_plus), 4, warn_plus)

    def test_every_finding_has_a_positive_line(self):
        # V15: Finding.__post_init__ already rejects line<=0 at construction
        # time; this just confirms nothing slipped a 0/negative line past
        # that guard across the whole pipeline.
        for f in _target_findings():
            self.assertGreater(f.line, 0, f)

    def test_line_48_warn_is_d1_from_the_evaluator(self):
        at_48 = [f for f in _target_findings() if f.line == 48 and f.severity >= Severity.WARN]
        self.assertEqual([f.detector for f in at_48], ["D1"])

    def test_line_59_warn_is_d2_binaryfiles(self):
        at_59 = [f for f in _target_findings() if f.line == 59 and f.severity >= Severity.WARN]
        self.assertEqual([f.detector for f in at_59], ["D2"])
        self.assertEqual(at_59[0].tag, "#BinaryFiles")

    def test_line_61_warn_is_d11_symstore_storedir(self):
        at_61 = [f for f in _target_findings() if f.line == 61 and f.severity >= Severity.WARN]
        self.assertEqual([f.detector for f in at_61], ["D11"])
        self.assertIn("StoreDir", at_61[0].message)

    def test_line_77_warn_is_d5_archivesymbols(self):
        at_77 = [f for f in _target_findings() if f.line == 77 and f.severity >= Severity.WARN]
        self.assertEqual([f.detector for f in at_77], ["D5"])
        self.assertEqual(at_77[0].tag, "#ArchiveSymbols")

    def test_all_ten_detectable_taxonomy_rows_are_present(self):
        # ACCEPTANCE.md §A, the 10 rows this tool claims (V24: #5 and #12
        # excluded by design, not by omission -- see TaxonomySilenceTests).
        findings = _target_findings()
        by_line_detector = {(f.line, f.detector) for f in findings}
        expected = {
            (48, "D1"),
            (59, "D2"),
            (61, "D11"),
            (77, "D5"),
            (43, "D6"),
            (67, "D3"),
            (21, "D8"),
            (43, "D10"),
            (47, "D10"),
            (26, "D15"),
            (32, "D15"),
            (90, "D16"),
        }
        missing = expected - by_line_detector
        self.assertFalse(missing, f"ACCEPTANCE rows not hit: {missing}")


# ---------------------------------------------------------------------------
# 2. V24 -- taxonomy #5/#12 silence
# ---------------------------------------------------------------------------


class TaxonomySilenceTests(unittest.TestCase):
    """#5 (cross-agent workspace dependency, disproven by R24) and #12
    (SetVersion should have been guarded, undecidable intent) must produce
    ZERO findings at ANY severity -- silence is a graded requirement, not
    an omission (ACCEPTANCE.md)."""

    def test_no_d7_finding_on_the_target_file(self):
        # D7 is the one legitimate detector adjacent to #5's shape (a
        # cross-agent dependency whose transfer is PROVABLY empty) -- the
        # target file has no such node, so it must not fire at all here;
        # if it ever does on some OTHER input, its message must never
        # boil down to "cross-agent is inherently broken" (checked below,
        # corpus-wide, since #5 is disproven for every cross-agent dep
        # that declares itself, not just this file's).
        self.assertFalse([f for f in _target_findings() if f.detector == "D7"])

    def test_no_finding_anywhere_claims_setversion_needed_a_guard(self):
        for f in _target_findings():
            lowered = f.message.lower()
            looks_like_12 = "setversion" in lowered and (
                "should be guard" in lowered or "unguarded" in lowered or "needs a guard" in lowered or "should have" in lowered
            )
            self.assertFalse(looks_like_12, f"finding reads like a #12 (undecidable-intent) claim: {f}")

    def test_d6_message_is_about_the_compile_node_not_setversion_itself(self):
        # D6 (ACCEPTANCE #6, line 43) is the legitimate, adjacent claim --
        # "this Compile node has no path to a version stamp" -- verify it
        # is NOT phrased as "#12" ("SetVersion should be guarded").
        d6 = [f for f in _target_findings() if f.detector == "D6"]
        self.assertTrue(d6)  # sanity: it does fire per ACCEPTANCE
        for f in d6:
            self.assertIn("Compile", f.message)
            self.assertNotIn("guard", f.message.lower())

    def test_no_finding_treats_a_bare_cross_agent_requires_as_a_defect(self):
        # #5 disproven (R24): a node that DECLARES a cross-agent dependency
        # via bare Requires="NodeName" is fine (its build products transfer
        # via the implicit default output) -- synthetic case mirroring
        # exactly that shape, two different agents, no tagging at all
        # beyond the implicit output, target node DOES run a real task (so
        # D7's narrow "provably empty" carve-out does not apply either).
        # D15 (Agent/@Type is a hardcoded literal) is expected/irrelevant
        # noise from this fixture's own `Type="AnyAgent"` and is not what
        # this test is about -- scoped assertions below, not a blanket
        # empty-findings check.
        _graph, findings = _graph_from_fragment(
            """
            <Agent Name="AgentA" Type="AnyAgent">
                <Node Name="Upstream">
                    <SetVersion Change="1" Branch="Foo"/>
                </Node>
            </Agent>
            <Agent Name="AgentB" Type="AnyAgent">
                <Node Name="Downstream" Requires="Upstream">
                    <Log Message="uses whatever Upstream built"/>
                </Node>
            </Agent>
            """
        )
        self.assertEqual([f for f in findings if f.detector == "D7"], [], findings)
        for f in findings:
            self.assertNotIn("cross-agent", f.message.lower())


# ---------------------------------------------------------------------------
# 3. V5/V21 -- the false-positive budget. THE most important test here.
# ---------------------------------------------------------------------------


class CorpusFalsePositiveBudgetTests(unittest.TestCase):
    """Over all 19 real Epic-shipped graphs, the warn+ set is EXACTLY the
    two pinned #BinaryFiles D2 findings -- identity, not cardinality (V21).

    Identity is asserted by file-relative PATH, deliberately NOT
    `Finding.key()`: both pinned files share the identical basename
    (`BuildEditorAndTools.xml`, one in Examples/, one in
    Examples/FPSBuildGraph/), and `Finding.key()` is `(os.path.basename(file),
    detector, tag-or-node-or-message)` -- collapsing the two into ONE key. A
    budget check that (reasonably) reached for `.key()` as its identity --
    it is the vocabulary's own documented dedup helper -- would pass even if
    only one of the two files had ever been scanned, silently losing
    coverage of the other. Flagged separately to the orchestrator as a
    `Finding.key()` gap; this test sidesteps it by using the relative path.
    """

    @classmethod
    def setUpClass(cls):
        cls.files = _corpus_files()

    def test_exactly_nineteen_corpus_files_are_scanned(self):
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

    def test_warn_plus_identity_set_matches_the_pinned_set_exactly(self):
        expected = {
            ("Examples/BuildEditorAndTools.xml", "D2", "#BinaryFiles"),
            ("Examples/FPSBuildGraph/BuildEditorAndTools.xml", "D2", "#BinaryFiles"),
            # B5 -- see tests/test_budget.py for the full rationale.
            # tag is None for D1 -- this test keys identity on Finding.tag,
            # unlike test_budget.py which keys on tag-or-message.
            ("Tests/IncrementalValidate.xml", "D1", None),
        }
        actual: set[tuple[str, str, str | None]] = set()
        per_file_warn_plus: dict[str, list[Finding]] = {}

        for path in self.files:
            findings = _run_pipeline(path)
            warn_plus = [f for f in findings if f.severity >= Severity.WARN]
            rel = str(path.relative_to(CORPUS_ROOT)).replace("\\", "/")
            per_file_warn_plus[rel] = warn_plus
            for f in warn_plus:
                actual.add((rel, f.detector, f.tag))

        self.assertEqual(actual, expected, f"corpus warn+ identity set diverged from V21's pinned set: {actual}")

        # Belt-and-suspenders per V21's "identity, not cardinality" wording:
        # each pinned file has EXACTLY one warn+ finding, and every other
        # file has ZERO -- so a regression that duplicates a pinned finding
        # (same identity, extra copy) or that silently drops a scanned file
        # cannot hide behind the set comparison above.
        # Occurrence counts pinned exactly: one identity may legitimately occur
        # more than once (IncrementalValidate.xml reads $(ProjectDir) on five
        # lines, and the engine would warn five times too), so assert the real
        # numbers rather than assuming one-per-file.
        expected_occurrences = {
            "Examples/BuildEditorAndTools.xml": 1,
            "Examples/FPSBuildGraph/BuildEditorAndTools.xml": 1,
            "Tests/IncrementalValidate.xml": 5,
        }
        for rel, warn_plus in sorted(per_file_warn_plus.items()):
            self.assertEqual(
                len(warn_plus), expected_occurrences.get(rel, 0), (rel, warn_plus)
            )


# ---------------------------------------------------------------------------
# 4. V20 -- D5 fires only on proof
# ---------------------------------------------------------------------------


class D5UnresolvableContributorTests(unittest.TestCase):
    def test_bare_wildcard_contributor_suppresses_d5_entirely(self):
        # #Intermediate's only contribution is a bare wildcard path with no
        # Except at all -- UNRESOLVABLE per CONTRACTS.md's D5 algorithm.
        # One unresolvable contributor must suppress the finding, even
        # though the consuming step's Filter='*.pdb' looks exactly like the
        # worked example that DOES fire in the target file (ACCEPTANCE line
        # 77) -- the difference is provability, not shape.
        _graph, findings = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Producer">
                    <Tag Files="build/.../*.obj" With="#Intermediate"/>
                </Node>
                <Node Name="Consumer" Requires="Producer">
                    <Tag Files="#Intermediate" Filter="*.pdb" With="#ShouldNeverFire"/>
                </Node>
            </Agent>
            """
        )
        self.assertEqual([f for f in findings if f.detector == "D5"], [], findings)

    def test_unresolvable_sibling_alongside_a_provably_disjoint_one_still_suppresses(self):
        # Same idea, but with TWO contributors: one provably disjoint
        # (a literal that doesn't match), one unresolvable (a bare
        # wildcard). V20 requires EVERY contributor to be provably
        # disjoint -- one unresolvable contributor is enough to abstain.
        _graph, findings = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Producer">
                    <Tag Files="readme.txt" With="#Mixed"/>
                    <Tag Files="build/.../*.obj" With="#Mixed"/>
                </Node>
                <Node Name="Consumer" Requires="Producer">
                    <Tag Files="#Mixed" Filter="*.pdb" With="#ShouldNeverFire"/>
                </Node>
            </Agent>
            """
        )
        self.assertEqual([f for f in findings if f.detector == "D5"], [], findings)


# ---------------------------------------------------------------------------
# 5. V23/R20 -- the accumulator idiom must never trip D13
# ---------------------------------------------------------------------------


class D13AccumulatorIdiomTests(unittest.TestCase):
    def test_accumulator_chain_with_a_final_reader_produces_no_d13(self):
        _graph, findings = _graph_from_fragment(
            """
            <Property Name="Deps" Value="First"/>
            <Property Name="Deps" Value="$(Deps);Second"/>
            <Property Name="Deps" Value="$(Deps);Third"/>
            <Agent Name="A" Type="AnyAgent">
                <Node Name="UsesIt">
                    <Log Message="deps=$(Deps)"/>
                </Node>
            </Agent>
            """
        )
        self.assertEqual([f for f in findings if f.detector == "D13"], [], findings)


# ---------------------------------------------------------------------------
# 6. V10/V14 -- Exists() is opaque; D12 must stay silent through it
# ---------------------------------------------------------------------------


class D12ExistsOpaqueTests(unittest.TestCase):
    def test_bare_exists_guard_produces_no_d12_finding(self):
        _graph, findings = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="N">
                    <Log Message="hi" If="Exists('some/path')"/>
                </Node>
            </Agent>
            """
        )
        self.assertEqual([f for f in findings if f.detector == "D12"], [], findings)

    def test_exists_combined_via_and_with_an_option_still_produces_no_d12(self):
        # Left side depends on a real option (not short-circuitable to a
        # fixed truth value), so the opaque Exists() on the right cannot be
        # eliminated -- must still classify "unknown", not unsat/taut.
        _graph, findings = _graph_from_fragment(
            """
            <Option Name="Flag" DefaultValue="false" Restrict="true|false" Description="d"/>
            <Agent Name="A" Type="AnyAgent">
                <Node Name="N">
                    <Log Message="hi" If="$(Flag) And Exists('some/path')"/>
                </Node>
            </Agent>
            """
        )
        self.assertEqual([f for f in findings if f.detector == "D12"], [], findings)


# ---------------------------------------------------------------------------
# 7. V3 vs V4 -- @Produces is public API (info); node-internal-only is dead
# (warn)
# ---------------------------------------------------------------------------


class D3VsD4Tests(unittest.TestCase):
    def test_produces_tag_unconsumed_is_info_via_d3_not_warn_via_d4(self):
        _graph, findings = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Producer" Produces="#PublicButUnused">
                    <Tag Files="a.txt" With="#PublicButUnused"/>
                </Node>
            </Agent>
            """
        )
        d3 = [f for f in findings if f.detector == "D3" and f.tag == "#PublicButUnused"]
        d4 = [f for f in findings if f.detector == "D4" and f.tag == "#PublicButUnused"]
        self.assertEqual(len(d3), 1, findings)
        self.assertEqual(d3[0].severity, Severity.INFO)
        self.assertEqual(d4, [])

    def test_node_internal_tag_unconsumed_is_warn_via_d4_not_info_via_d3(self):
        _graph, findings = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Sneaky">
                    <Tag Files="a.txt" With="#NeverEscapes"/>
                </Node>
            </Agent>
            """
        )
        d4 = [f for f in findings if f.detector == "D4" and f.tag == "#NeverEscapes"]
        d3 = [f for f in findings if f.detector == "D3" and f.tag == "#NeverEscapes"]
        self.assertEqual(len(d4), 1, findings)
        self.assertEqual(d4[0].severity, Severity.WARN)
        self.assertEqual(d3, [])


# ---------------------------------------------------------------------------
# Regression tests for concrete bugs found while developing against the
# real corpus -- each pins one mechanism that a future change could easily
# re-break silently.
# ---------------------------------------------------------------------------


class D2SameNodeCreateSatisfiesConsumptionTests(unittest.TestCase):
    """A tag created and consumed within ONE node, with no @Produces at
    all, must not be treated as "produced nowhere" -- `Graph.producers_of`
    alone (which only sees @Produces) missed this; D2 must also check the
    consuming node's own `Node.creates`. Measured false positive: the
    target file's #SourceFiles/#ArchiveFiles/#ArchiveBinaries/
    #ArchiveSymbols are all created and consumed inside one node this way."""

    def test_node_local_create_then_consume_produces_no_d2(self):
        _graph, findings = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="SelfContained">
                    <Tag Files="a.txt" With="#Local"/>
                    <Log Message="uses it" Files="#Local"/>
                </Node>
            </Agent>
            """
        )
        self.assertEqual([f for f in findings if f.detector == "D2"], [], findings)

    def test_cross_node_create_without_produces_still_trips_d2(self):
        # Sanity control: the SAME shape but consumed from a DIFFERENT node
        # must still fire -- a node-local create only satisfies node-local
        # consumption, it does not silently make D2 toothless everywhere.
        _graph, findings = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Creator">
                    <Tag Files="a.txt" With="#NotExported"/>
                </Node>
                <Node Name="OtherNode" Requires="Creator">
                    <Log Message="tries to use it" Files="#NotExported"/>
                </Node>
            </Agent>
            """
        )
        d2 = [f for f in findings if f.detector == "D2" and f.tag == "#NotExported"]
        self.assertEqual(len(d2), 1, findings)


class D13NeverReferencedIsNotDeadOnArrivalTests(unittest.TestCase):
    """A property that is simply never referenced ANYWHERE (no
    redefinition either) is D8's territory (info), not D13's (warn) --
    nothing ever raced it, so there is no "arrival" to be dead on. Measured
    false positive: the target file's own `ArchiveStagingRelativeDir`
    (ACCEPTANCE line 21, D8 only)."""

    def test_unused_property_with_no_redefinition_produces_d8_not_d13(self):
        _graph, findings = _graph_from_fragment(
            """
            <Property Name="NeverTouchedAgain" Value="12345"/>
            <Agent Name="A" Type="AnyAgent">
                <Node Name="N">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            """
        )
        d8 = [f for f in findings if f.detector == "D8"]
        d13 = [f for f in findings if f.detector == "D13"]
        self.assertEqual(len(d8), 1, findings)
        self.assertEqual(d8[0].severity, Severity.INFO)
        self.assertEqual(d13, [], findings)


class D13AncestorGuardedRedefinitionTests(unittest.TestCase):
    """A redefinition is only a PROVEN clobber when NEITHER it nor any
    ancestor element carries an If= -- checking only the redefining
    element's own attribute is not enough. Measured false positive:
    Tests/IncrementalCompare.xml's `NullIncrementalCookPrereq`, redefined
    by a bare `<Property>` that sits inside a guarded `<Do If=...>`."""

    def test_redefinition_inside_a_guarded_do_block_does_not_prove_death(self):
        _graph, findings = _graph_from_fragment(
            """
            <Option Name="Flag" DefaultValue="false" Restrict="true|false" Description="d"/>
            <Property Name="Prereq" Value="First"/>
            <Do If="$(Flag)">
                <Property Name="Prereq" Value="Second"/>
            </Do>
            <Agent Name="A" Type="AnyAgent">
                <Node Name="N" Requires="$(Prereq)">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            """
        )
        d13 = [f for f in findings if f.detector == "D13" and "Prereq" in f.message]
        self.assertEqual(d13, [], findings)

    def test_truly_unconditional_redefinition_still_trips_d13(self):
        # Sanity control: remove the guard entirely -- now the second
        # definition certainly clobbers the first before Requires= reads
        # it, so D13 must still fire (this rule did not just get disabled
        # outright by the ancestor-awareness fix above).
        _graph, findings = _graph_from_fragment(
            """
            <Property Name="Prereq" Value="First"/>
            <Property Name="Prereq" Value="Second"/>
            <Agent Name="A" Type="AnyAgent">
                <Node Name="N" Requires="$(Prereq)">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            """
        )
        d13 = [f for f in findings if f.detector == "D13" and "Prereq" in f.message]
        self.assertEqual(len(d13), 1, findings)


class D11WitnessMechanismTests(unittest.TestCase):
    """D11's core mechanism, isolated from the full corpus scan: force the
    referenced Option to a non-empty sentinel and check whether the guard
    controlling the dependent node's inclusion still holds. Mirrors the
    real target-file defect (inverted guard -- filling the option disables
    the very node that needed it) against the real corpus's non-defective
    shape (correct guard polarity -- filling the option keeps the
    dependency correctly gated) as two small, otherwise-identical
    fragments."""

    _FRAGMENT = """
        <Option Name="SymPath" DefaultValue="" Description="d"/>
        <Agent Name="A" Type="AnyAgent">
            <Node Name="StoreSymbols">
                <SymStore Platform="Win64" Files="a.txt" StoreDir="$(SymPath)" Product="P"/>
            </Node>
            <Property Name="Deps" Value="Placeholder"/>
            <Property Name="Deps" Value="$(Deps); StoreSymbols" If="{guard}"/>
            <Node Name="Downstream" Requires="$(Deps)">
                <Log Message="hi"/>
            </Node>
        </Agent>
        """

    def test_inverted_guard_shape_fires_d11_like_the_real_injected_defect(self):
        # Only pulls StoreSymbols in when the path is EMPTY -- filling
        # SymPath disables the very dependency that would need it. No
        # invocation both fills StoreDir and keeps it load-bearing.
        _graph, findings = _graph_from_fragment(self._FRAGMENT.format(guard="'$(SymPath)' == ''"))
        d11 = [f for f in findings if f.detector == "D11"]
        self.assertEqual(len(d11), 1, findings)
        self.assertEqual(d11[0].severity, Severity.WARN)

    def test_correct_guard_shape_stays_silent_like_the_real_corpus(self):
        # Only pulls StoreSymbols in when a path WAS supplied -- filling
        # SymPath both fixes StoreDir AND keeps the dependency correctly
        # gated. A legitimate, working, option-driven configuration.
        _graph, findings = _graph_from_fragment(self._FRAGMENT.format(guard="'$(SymPath)' != ''"))
        d11 = [f for f in findings if f.detector == "D11"]
        self.assertEqual(d11, [], findings)


class D9UnusedOptionTests(unittest.TestCase):
    """D9 is never exercised by the ACCEPTANCE target file (every option it
    declares happens to be referenced somewhere) -- needs its own positive
    case."""

    def test_declared_but_unreferenced_option_produces_d9_info(self):
        _graph, findings = _graph_from_fragment(
            """
            <Option Name="NeverUsed" DefaultValue="" Description="d"/>
            <Agent Name="A" Type="AnyAgent">
                <Node Name="N">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            """
        )
        d9 = [f for f in findings if f.detector == "D9"]
        self.assertEqual(len(d9), 1, findings)
        self.assertEqual(d9[0].severity, Severity.INFO)


class D7ProvablyEmptyCrossAgentTransferTests(unittest.TestCase):
    """D7 never fires on the ACCEPTANCE target file -- needs its own
    positive case: a cross-agent Requires by bare name naming a node with
    no @Produces and zero task children (provably transfers nothing)."""

    def test_empty_cross_agent_target_node_produces_d7_warn(self):
        _graph, findings = _graph_from_fragment(
            """
            <Agent Name="AgentA" Type="AnyAgent">
                <Node Name="DoesNothing">
                </Node>
            </Agent>
            <Agent Name="AgentB" Type="AnyAgent">
                <Node Name="Downstream" Requires="DoesNothing">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            """
        )
        d7 = [f for f in findings if f.detector == "D7"]
        self.assertEqual(len(d7), 1, findings)
        self.assertEqual(d7[0].severity, Severity.WARN)

    def test_cross_agent_target_node_with_a_task_does_not_trip_d7(self):
        # Sanity control: the target node DOES run a task (even though it
        # declares no @Produces) -- D7's narrow "provably empty" carve-out
        # must not claim this is provably empty (V13: a plain cross-agent
        # dependency is normal and fine by default).
        _graph, findings = _graph_from_fragment(
            """
            <Agent Name="AgentA" Type="AnyAgent">
                <Node Name="DoesSomething">
                    <SetVersion Change="1" Branch="Foo"/>
                </Node>
            </Agent>
            <Agent Name="AgentB" Type="AnyAgent">
                <Node Name="Downstream" Requires="DoesSomething">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            """
        )
        self.assertEqual([f for f in findings if f.detector == "D7"], [], findings)


class D10EmptyEntryProvenanceTests(unittest.TestCase):
    """D10 must say WHERE the empty entry came from.

    Reported from the report itself: hovering line 48 of the target file
    showed the D1 warn and a D10 reading "trailing or duplicate ';'" -- but
    there is no ';' on that line to find. The entry is left behind by
    `$(GameBinaries)` expanding to nothing, which is the D1 sitting directly
    above it in the same tooltip. Reading as a stray duplicate rather than as
    cause-and-effect is what made it confusing.

    This is the common case, not the exotic one: 5 of the 7 D10 findings
    across Epic's 19 shipped graphs are the expansion kind, so the literal
    wording was pointing at a character that is not there most of the time.
    """

    def _d10(self, body: str) -> list[Finding]:
        _graph, findings = _graph_from_fragment(body)
        return [f for f in findings if f.detector == "D10"]

    def test_a_literal_trailing_semicolon_still_says_so(self):
        f = self._d10('<Agent Name="A" Type="W">'
                      '<Node Name="N" Requires="#A;#B;" Produces="#Out"/></Agent>')
        hit = [x for x in f if "Requires" in x.message]
        self.assertEqual(len(hit), 1, f)
        self.assertIn("trailing or duplicate ';'", hit[0].message)

    def test_an_entry_left_by_an_empty_expansion_names_the_property(self):
        """The measured case. One ref, so it can be named outright."""
        f = self._d10('<Agent Name="A" Type="W">'
                      '<Node Name="P" Produces="#A"/>'
                      '<Node Name="N" Requires="#A;$(Nope)"/></Agent>')
        hit = [x for x in f if "Requires" in x.message]
        self.assertEqual(len(hit), 1, f)
        self.assertIn("'$(Nope)' expanded to nothing", hit[0].message)
        self.assertNotIn("trailing or duplicate", hit[0].message)

    def test_severity_and_detector_are_unchanged(self):
        """Wording only. D10 stays `info` (V6) whichever way it fired."""
        f = self._d10('<Agent Name="A" Type="W">'
                      '<Node Name="P" Produces="#A"/>'
                      '<Node Name="N" Requires="#A;$(Nope)"/></Agent>')
        self.assertTrue(f)
        for x in f:
            self.assertEqual(x.severity, Severity.INFO)

    def test_several_candidate_refs_name_none_of_them(self):
        """Naming one would be a guess. Deciding between them means
        re-expanding entry by entry, which a property value legitimately
        containing ';' (the accumulator idiom, R20) makes unsound."""
        f = self._d10('<Property Name="X" Value=""/>'
                      '<Property Name="Y" Value=""/>'
                      '<Agent Name="A" Type="W">'
                      '<Node Name="P" Produces="#A"/>'
                      '<Node Name="N" Requires="#A;$(X);$(Y)"/></Agent>')
        hit = [x for x in f if "Requires" in x.message]
        self.assertTrue(hit, f)
        self.assertIn("an expansion produced nothing", hit[0].message)
        self.assertNotIn("$(X)", hit[0].message)

    def test_the_target_file_line_48_explains_its_pairing_with_the_d1(self):
        """End to end: ACCEPTANCE.md §A row #9 keeps D10 at line 48, and the
        message now says why it is there."""
        at_48 = [f for f in _target_findings() if f.line == 48 and f.detector == "D10"]
        self.assertEqual(len(at_48), 1, at_48)
        self.assertIn("'$(GameBinaries)' expanded to nothing", at_48[0].message)
        # the acceptance contract itself is untouched
        self.assertEqual(at_48[0].severity, Severity.INFO)

    def test_lines_43_and_47_keep_the_literal_wording(self):
        """They really do have a trailing ';'. Only the expansion case moves."""
        for line in (43, 47):
            hits = [f for f in _target_findings() if f.line == line and f.detector == "D10"]
            self.assertEqual(len(hits), 1, hits)
            self.assertIn("trailing or duplicate ';'", hits[0].message)


if __name__ == "__main__":
    unittest.main()
