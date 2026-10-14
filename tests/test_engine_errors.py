"""D18 / V31 -- conditions the engine treats as HARD ERRORS.

Found by auditing all 46 LogError call sites in BgScriptReader.cs and checking
which ones bgview was silent about. These are not style opinions: each one makes
the engine refuse to build the graph, so bgview reports them at `error`.

The interesting constraint is the opposite one. D18 must NOT fire on Epic's own
corpus, and getting there required two real corrections:

  * §B.5 -- ProjectFile/ProjectName/ProjectDir were being defined
    unconditionally, but the engine sets them only when a project is supplied.
    Combined with R26 (an <Option> whose name already holds a non-null value is
    silently not registered), that made a script's own
    `<Option Name="ProjectName" DefaultValue="_Unknown_"/>` a no-op, so node
    names built from $(ProjectName) diverged from what the engine produces --
    manufacturing four phantom "unresolvable reference" errors.

  * Union evaluation -- bgview walks every branch, so a reference and the node
    satisfying it can share a guard yet look inconsistent once unioned. Only
    UNCONDITIONAL references can be proven unresolvable.
"""

import pathlib
import tempfile
import unittest

from bgview import detectors, evaluator, loader, model, schema
from bgview.findings import Severity

HEAD = "<?xml version='1.0' ?>\n<BuildGraph xmlns=\"http://www.epicgames.com/BuildGraph\">\n"
TAIL = "</BuildGraph>\n"


def _d18(body: str):
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "s.xml"
        p.write_text(HEAD + body + TAIL, encoding="utf-8")
        sch = schema.discover(str(p))
        ev = evaluator.evaluate(loader.load(p), sch, {})
        graph, mf = model.build(ev, sch)
        allf = list(ev.findings) + list(mf) + list(detectors.run_all(graph, ev, sch))
        return [f for f in allf if f.detector == "D18"]


class UnresolvableReferenceTests(unittest.TestCase):
    def test_reference_to_nonexistent_node_is_an_error(self):
        f = _d18('<Agent Name="A" Type="W"><Node Name="N" Requires="NoSuchNode"/></Agent>')
        self.assertEqual(len(f), 1, f)
        self.assertEqual(f[0].severity, Severity.ERROR)
        self.assertGreater(f[0].line, 0)

    def test_missing_hash_prefix_offers_a_did_you_mean(self):
        """The single most common BuildGraph typo: writing `Requires="Out"`
        when the tag is `#Out`. The engine has a dedicated message for it."""
        f = _d18('<Agent Name="A" Type="W">'
                 '<Node Name="P" Produces="#Out"/>'
                 '<Node Name="C" Requires="Out"/></Agent>')
        self.assertEqual(len(f), 1, f)
        self.assertIn("did you mean '#Out'?", f[0].message)

    def test_resolvable_references_are_silent(self):
        for token in ("P", "#Out"):
            with self.subTest(token=token):
                self.assertEqual(
                    _d18(f'<Agent Name="A" Type="W">'
                         f'<Node Name="P" Produces="#Out"/>'
                         f'<Node Name="C" Requires="{token}"/></Agent>'), [])

    def test_a_guarded_reference_is_never_reported(self):
        """bgview unions all branches, so a guarded reference cannot be PROVEN
        unresolvable. Measured real case: IncrementalCompare.xml's 'Alternate
        Platform Cook'. D18 emits `error`, so it must only speak when certain."""
        f = _d18('<Agent Name="A" Type="W">'
                 '<Do If="\'$(Nope)\' != \'\'">'
                 '<Node Name="N" Requires="GhostNode"/>'
                 '</Do></Agent>')
        self.assertEqual(f, [])

    def test_reference_by_agent_name_resolves(self):
        """R8: a bare name resolves node -> aggregate -> agent, in that order."""
        self.assertEqual(
            _d18('<Agent Name="Builder" Type="W"><Node Name="N"/></Agent>'
                 '<Agent Name="B2" Type="W"><Node Name="M" Requires="Builder"/></Agent>'), [])


class DuplicateOutputTests(unittest.TestCase):
    def test_two_nodes_producing_one_tag_is_an_error(self):
        f = _d18('<Agent Name="A" Type="W">'
                 '<Node Name="P1" Produces="#Dup"/>'
                 '<Node Name="P2" Produces="#Dup"/></Agent>')
        self.assertEqual(len(f), 1, f)
        self.assertEqual(f[0].severity, Severity.ERROR)
        self.assertIn("#Dup", f[0].message)

    def test_distinct_tags_are_silent(self):
        self.assertEqual(
            _d18('<Agent Name="A" Type="W">'
                 '<Node Name="P1" Produces="#One"/>'
                 '<Node Name="P2" Produces="#Two"/></Agent>'), [])


class OptionRestrictTests(unittest.TestCase):
    def test_default_value_violating_its_own_restrict_is_an_error(self):
        f = _d18('<Option Name="B" Restrict="true|false" DefaultValue="banana"/>'
                 '<Agent Name="A" Type="W"><Node Name="N"/></Agent>')
        self.assertEqual(len(f), 1, f)
        self.assertIn("banana", f[0].message)

    def test_valid_default_is_silent(self):
        self.assertEqual(
            _d18('<Option Name="B" Restrict="true|false" DefaultValue="true"/>'
                 '<Agent Name="A" Type="W"><Node Name="N"/></Agent>'), [])

    def test_uncompilable_dotnet_regex_stays_silent_rather_than_guessing(self):
        """A .NET regex Python cannot compile must produce NO finding. D18 is
        error-severity; guessing there would be worse than saying nothing."""
        self.assertEqual(
            _d18('<Option Name="B" Restrict="(?&lt;name&gt;a)(?&#39;x&#39;b)" DefaultValue="zz"/>'
                 '<Agent Name="A" Type="W"><Node Name="N"/></Agent>'), [])


class ProjectPropertiesTests(unittest.TestCase):
    def test_project_properties_are_undefined_without_the_flag(self):
        """§B.5: matching BuildGraph.cs:325-333, which sets these only when a
        project is supplied. Without --project, $(ProjectDir) is genuinely
        undefined and the engine warns -- so bgview must too."""
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "s.xml"
            p.write_text(HEAD + '<Agent Name="A" Type="W"><Node Name="N">'
                                '<Log Message="$(ProjectDir)"/></Node></Agent>' + TAIL,
                         encoding="utf-8")
            sch = schema.discover(str(p))
            ev = evaluator.evaluate(loader.load(p), sch, {})
            self.assertTrue([f for f in ev.findings
                             if f.detector == "D1" and "ProjectDir" in f.message])

    def test_project_flag_defines_them(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "s.xml"
            p.write_text(HEAD + '<Agent Name="A" Type="W"><Node Name="N">'
                                '<Log Message="$(ProjectName)|$(ProjectDir)"/></Node></Agent>' + TAIL,
                         encoding="utf-8")
            sch = schema.discover(str(p))
            ev = evaluator.evaluate(loader.load(p), sch, {},
                                    project=r"C:\Games\MyGame\MyGame.uproject")
            self.assertEqual([f for f in ev.findings if f.detector == "D1"], [])
            msgs = [r.attrs.get("Message", "") for r in ev.resolved if r.elem.tag == "Log"]
            self.assertTrue(any("MyGame" in m for m in msgs), msgs)



class DuplicateNameTests(unittest.TestCase):
    """CheckNameIsUnique (BgScriptReader.cs:2114) errors on a duplicate name.

    The namespace is exactly what BgGraphDef.ContainsName checks --
    NameToNode | NameToReport | NameToAggregate. Agents and labels are NOT in
    it, which is not a detail we can hand-wave: Epic's
    BuildWorldPartitionHLODs.xml deliberately names an <Agent> and its <Node>
    both "HLOD Setup", and AllExamples.xml pulls in two files that each declare
    <Agent Name="Properties Agent">. Including agents here produced three
    measured false positives on Epic's own corpus.
    """

    def test_duplicate_node_name_is_an_error(self):
        f = _d18('<Agent Name="A" Type="W">\n<Node Name="Dup"/>\n<Node Name="Dup"/>\n</Agent>')
        dup = [x for x in f if "declared more than once" in x.message]
        self.assertEqual(len(dup), 1, f)
        self.assertEqual(dup[0].severity, Severity.ERROR)

    def test_node_and_aggregate_collision_is_an_error(self):
        f = _d18('<Agent Name="A" Type="W">\n<Node Name="X"/>\n</Agent>\n'
                 '<Aggregate Name="X" Requires="X"/>')
        self.assertTrue([x for x in f if "declared more than once" in x.message], f)

    def test_agent_and_node_sharing_a_name_is_legal(self):
        """Epic does this on purpose in BuildWorldPartitionHLODs.xml."""
        f = _d18('<Agent Name="HLOD Setup" Type="W">\n<Node Name="HLOD Setup"/>\n</Agent>')
        self.assertEqual([x for x in f if "declared more than once" in x.message], [])

    def test_two_agents_with_the_same_name_are_legal(self):
        """Duplicate agents merge; only a TYPE mismatch is an engine error."""
        f = _d18('<Agent Name="Same" Type="W">\n<Node Name="N1"/>\n</Agent>\n'
                 '<Agent Name="Same" Type="W">\n<Node Name="N2"/>\n</Agent>')
        self.assertEqual([x for x in f if "declared more than once" in x.message], [])

class OutputTagShapeTests(unittest.TestCase):
    """D18(e)/(f) -- BgScriptReader.cs:1533 and :1593."""

    def test_produces_entry_without_a_hash_is_an_error(self):
        f = _d18('<Agent Name="A" Type="W"><Node Name="N" Produces="NoHash"/></Agent>')
        hit = [x for x in f if "does not begin with '#'" in x.message]
        self.assertEqual(len(hit), 1, f)
        self.assertEqual(hit[0].severity, Severity.ERROR)

    def test_hashed_produces_entry_is_fine(self):
        f = _d18('<Agent Name="A" Type="W"><Node Name="N" Produces="#Ok"/></Agent>')
        self.assertEqual([x for x in f if "begin with" in x.message], [])

    def test_same_tag_listed_twice_in_one_produces_is_an_error(self):
        f = _d18('<Agent Name="A" Type="W"><Node Name="N" Produces="#Dup;#Dup"/></Agent>')
        hit = [x for x in f if "listed more than once" in x.message]
        self.assertEqual(len(hit), 1, f)
        self.assertEqual(hit[0].severity, Severity.ERROR)

    def test_producing_the_nodes_own_implicit_output_is_an_error(self):
        """BgNodeDef.cs:198-203 builds Outputs as ['#'+Name] ++ outputNames
        filtered by `x != Name` -- against the BARE name. Since :1531 has
        already rejected every entry that does not start with '#', that filter
        can never match, so '#Foo' on node 'Foo' duplicates the implicit output
        and hits :1593. Reading R7's "de-duped" as covering this spelling is
        the trap; model.build DOES fold it away, which is exactly why D18(b)
        cannot see it and this clause reads raw @Produces."""
        f = _d18('<Agent Name="A" Type="W"><Node Name="Foo" Produces="#Foo"/></Agent>')
        hit = [x for x in f if "implicit default output" in x.message]
        self.assertEqual(len(hit), 1, f)
        self.assertEqual(hit[0].severity, Severity.ERROR)


class ObjectNameValidationTests(unittest.TestCase):
    """D18(g) -- BgScriptReader.cs:2182-2206 (ValidateName)."""

    def test_consecutive_spaces_in_a_node_name_is_an_error(self):
        f = _d18('<Agent Name="A" Type="W"><Node Name="Bad  Name"/></Agent>')
        hit = [x for x in f if "consecutive spaces" in x.message]
        self.assertEqual(len(hit), 1, f)
        self.assertEqual(hit[0].severity, Severity.ERROR)

    def test_illegal_character_in_a_name_is_an_error(self):
        """BgSchema.cs:203 -- IllegalNameCharacters = "^<>:\\"/\\\\|?*".
        `<`, `>` and `"` must be written as entities to survive XML parsing at
        all; the NAME the engine validates still holds the raw character."""
        for literal, escaped in (("A|B", "A|B"), ("A<B", "A&lt;B"), ('A"B', "A&quot;B"),
                                 ("A>B", "A&gt;B"), ("A?B", "A?B"), ("A*B", "A*B"),
                                 ("A^B", "A^B"), ("A:B", "A:B"), ("A/B", "A/B"),
                                 ("A\\B", "A\\B")):
            with self.subTest(name=literal):
                f = _d18(f'<Agent Name="A" Type="W"><Node Name="{escaped}"/></Agent>')
                self.assertTrue([x for x in f if "illegal character" in x.message], f"{literal}: {f}")

    def test_single_trailing_space_is_LEGAL_and_must_not_fire(self):
        """R33: ValidateName never trims and permits a single trailing space.
        That is what makes such a node genuinely unreferenceable, but it is not
        an error, and reporting it would be a false positive."""
        f = _d18('<Agent Name="A" Type="W"><Node Name="Trailing "/></Agent>')
        self.assertEqual([x for x in f if "is invalid" in x.message], [], f)

    def test_ordinary_names_with_single_spaces_do_not_fire(self):
        f = _d18('<Agent Name="Build Agent" Type="W"><Node Name="Compile Editor Win64"/></Agent>')
        self.assertEqual([x for x in f if "is invalid" in x.message], [], f)


class ArtifactTagTests(unittest.TestCase):
    """D18(h) -- BgScriptReader.cs:1337-1344. <Artifact> was absent from
    `_ref_tokens_with_location`, so D18(a) never reached it."""

    def test_artifact_naming_an_unproduced_tag_is_an_error(self):
        f = _d18('<Agent Name="A" Type="W"><Node Name="N"/></Agent>'
                 '<Artifact Name="Art" Type="Zen" Tag="#Nope"/>')
        hit = [x for x in f if "which no node produces" in x.message]
        self.assertEqual(len(hit), 1, f)
        self.assertEqual(hit[0].severity, Severity.ERROR)

    def test_artifact_tag_defaults_to_hash_name_and_is_still_checked(self):
        """With @Tag absent the engine substitutes '#<Name>' and validates
        that, so an <Artifact> with no @Tag is still a checked reference."""
        f = _d18('<Agent Name="A" Type="W"><Node Name="N"/></Agent>'
                 '<Artifact Name="Missing" Type="Zen"/>')
        hit = [x for x in f if "defaulted from its @Name" in x.message]
        self.assertEqual(len(hit), 1, f)

    def test_artifact_pointing_at_a_produced_tag_is_silent(self):
        f = _d18('<Agent Name="A" Type="W"><Node Name="N" Produces="#Good"/></Agent>'
                 '<Artifact Name="Art" Type="Zen" Tag="#Good"/>')
        self.assertEqual([x for x in f if "no node produces" in x.message], [], f)

    def test_artifact_defaulting_onto_a_real_node_output_is_silent(self):
        """<Artifact Name="N"> defaults to '#N', which the node named N
        implicitly produces -- the ordinary way this element is used."""
        f = _d18('<Agent Name="A" Type="W"><Node Name="N"/></Agent>'
                 '<Artifact Name="N" Type="Zen"/>')
        self.assertEqual([x for x in f if "no node produces" in x.message], [], f)


def _detector(body: str, detector_id: str):
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "s.xml"
        p.write_text(HEAD + body + TAIL, encoding="utf-8")
        sch = schema.discover(str(p))
        ev = evaluator.evaluate(loader.load(p), sch, {})
        graph, mf = model.build(ev, sch)
        allf = list(ev.findings) + list(mf) + list(detectors.run_all(graph, ev, sch))
        return [f for f in allf if f.detector == detector_id]


class CrossAgentOrderingTests(unittest.TestCase):
    """D19 -- BgScriptReader.cs:1552-1558.

    Reachable only by REOPENING an agent: references resolve against the graph
    built so far (:1471 runs before the node is registered at :1563), so inside
    one agent block every dependency is necessarily at or before it.
    """

    REOPENED = ('<Agent Name="A" Type="W"><Node Name="A1"/></Agent>'
                '<Agent Name="B" Type="W"><Node Name="B1"/></Agent>'
                '<Agent Name="A" Type="W"><Node Name="A2" Requires="B1"/></Agent>')

    def test_reopened_agent_depending_on_a_later_agent_is_an_error(self):
        f = _detector(self.REOPENED, "D19")
        self.assertEqual(len(f), 1, f)
        self.assertEqual(f[0].severity, Severity.ERROR)
        self.assertIn("A2", f[0].message)
        self.assertIn("B1", f[0].message)
        self.assertGreater(f[0].line, 0)  # V15

    def test_forward_dependency_is_found_through_an_intermediate(self):
        """The engine closes orderDependencies transitively (:1546-1550), so a
        two-hop path is equally an error -- and is the shape a reviewer misses."""
        body = ('<Agent Name="A" Type="W"><Node Name="A1"/></Agent>'
                '<Agent Name="B" Type="W"><Node Name="B1"/></Agent>'
                '<Agent Name="C" Type="W"><Node Name="C1" Requires="B1"/></Agent>'
                '<Agent Name="A" Type="W"><Node Name="A2" Requires="C1"/></Agent>')
        f = _detector(body, "D19")
        self.assertTrue(f, "transitive forward dependency went unreported")
        self.assertTrue(any("B1" in x.message for x in f), f)

    def test_after_attribute_counts_as_an_ordering_dependency(self):
        body = ('<Agent Name="A" Type="W"><Node Name="A1"/></Agent>'
                '<Agent Name="B" Type="W"><Node Name="B1"/></Agent>'
                '<Agent Name="A" Type="W"><Node Name="A2" After="B1"/></Agent>')
        self.assertTrue(_detector(body, "D19"))

    def test_ordinary_forward_declaration_order_is_silent(self):
        """The overwhelmingly common shape: agents declared once, each node
        depending on earlier work. Must never fire."""
        body = ('<Agent Name="A" Type="W"><Node Name="A1" Produces="#T"/></Agent>'
                '<Agent Name="B" Type="W"><Node Name="B1" Requires="#T"/></Agent>')
        self.assertEqual(_detector(body, "D19"), [])

    def test_dependency_within_one_agent_is_silent(self):
        body = ('<Agent Name="A" Type="W">'
                '<Node Name="A1"/><Node Name="A2" Requires="A1"/></Agent>')
        self.assertEqual(_detector(body, "D19"), [])

    def test_reopened_agent_depending_only_backwards_is_silent(self):
        """Reopening an agent is perfectly legal in itself (R34) -- only
        reaching FORWARD out of the reopened block is the error."""
        body = ('<Agent Name="A" Type="W"><Node Name="A1"/></Agent>'
                '<Agent Name="B" Type="W"><Node Name="B1"/></Agent>'
                '<Agent Name="A" Type="W"><Node Name="A2" Requires="A1"/></Agent>')
        self.assertEqual(_detector(body, "D19"), [])

    def test_guarded_node_is_exempt(self):
        """V33: bgview unions every branch, so a guarded dependency is never
        PROVABLY mis-ordered and an `error` detector must stay silent."""
        body = ('<Option Name="Opt" DefaultValue="false" Restrict="true|false"/>'
                '<Agent Name="A" Type="W"><Node Name="A1"/></Agent>'
                '<Agent Name="B" Type="W"><Node Name="B1"/></Agent>'
                '<Agent Name="A" Type="W">'
                '<Node Name="A2" Requires="B1" If="$(Opt)"/></Agent>')
        self.assertEqual(_detector(body, "D19"), [])


class EngineWarningTests(unittest.TestCase):
    """D20 -- the LogWarning half of V31, which R31/R32 never cashed in."""

    def test_input_listed_as_both_required_and_optional_is_a_warning(self):
        body = ('<Agent Name="A" Type="W">'
                '<Node Name="P" Produces="#T"/>'
                '<Node Name="N" Requires="#T" OptionalRequires="#T"/></Agent>')
        f = _detector(body, "D20")
        self.assertEqual(len(f), 1, f)
        self.assertEqual(f[0].severity, Severity.WARN)
        self.assertIn("#T", f[0].message)

    def test_distinct_required_and_optional_inputs_are_silent(self):
        body = ('<Agent Name="A" Type="W">'
                '<Node Name="P" Produces="#T;#U"/>'
                '<Node Name="N" Requires="#T" OptionalRequires="#U"/></Agent>')
        self.assertEqual(_detector(body, "D20"), [])

    def test_macro_argument_listed_twice_is_a_warning(self):
        f = _detector('<Macro Name="M" Arguments="A;A"><Property Name="X" Value="$(A)"/></Macro>', "D20")
        self.assertEqual(len(f), 1, f)
        self.assertEqual(f[0].severity, Severity.WARN)

    def test_argument_repeated_across_required_and_optional_is_a_warning(self):
        f = _detector('<Macro Name="M" Arguments="A" OptionalArguments="A">'
                      '<Property Name="X" Value="$(A)"/></Macro>', "D20")
        self.assertEqual(len(f), 1, f)

    def test_distinct_macro_arguments_are_silent(self):
        f = _detector('<Macro Name="M" Arguments="A;B"><Property Name="X" Value="$(A)$(B)"/></Macro>', "D20")
        self.assertEqual(f, [])

    def test_multi_character_foreach_separator_is_a_warning(self):
        """The engine does not split on what the author wrote -- it falls back
        to ';', so the loop iterates over something else entirely."""
        f = _detector('<ForEach Name="V" Values="a,,b" Separator=",,">'
                      '<Property Name="X" Value="$(V)"/></ForEach>', "D20")
        self.assertEqual(len(f), 1, f)
        self.assertEqual(f[0].severity, Severity.WARN)

    def test_single_character_separator_is_silent(self):
        f = _detector('<ForEach Name="V" Values="a,b" Separator=",">'
                      '<Property Name="X" Value="$(V)"/></ForEach>', "D20")
        self.assertEqual(f, [])


class ShadowPropertyTests(unittest.TestCase):
    """D21 -- BgScriptReader.cs:612-625, emitted by the evaluator where the
    scope stack lives.

    Writing a property inside an inner scope marks that name in every OUTER
    scope (:619-623). Writing the name again at one of those outer levels is
    then a hard engine error (:615). Scopes are opened for exactly four things
    -- agent body, node body, <ForEach>, macro <Expand> (:1191, :1618, :1698,
    :1784) -- notably NOT <Do> or <Switch>.

    The non-firing cases matter far more than the firing one: the outer-first
    ordering below is the ubiquitous accumulator idiom (R20, 37 uses in Epic's
    corpus), and getting the scope-targeting backwards would fire on all of it.
    """

    def test_inner_write_then_outer_write_is_an_error(self):
        f = _detector('<Agent Name="A" Type="W"><Node Name="N">\n'
                      '<Property Name="X" Value="1"/>\n'
                      '</Node></Agent>\n'
                      '<Property Name="X" Value="2"/>', "D21")
        self.assertEqual(len(f), 1, f)
        self.assertEqual(f[0].severity, Severity.ERROR)
        self.assertIn("already used in a child scope", f[0].message)
        self.assertGreater(f[0].line, 0)  # V15

    def test_inner_write_then_write_in_the_enclosing_agent_is_an_error(self):
        f = _detector('<Agent Name="A" Type="W"><Node Name="N">\n'
                      '<Property Name="X" Value="1"/>\n'
                      '</Node>\n'
                      '<Property Name="X" Value="2"/>\n'
                      '</Agent>', "D21")
        self.assertEqual(len(f), 1, f)

    def test_outer_first_then_inner_write_is_LEGAL(self):
        """The accumulator idiom. `_assign` targets the OUTERMOST scope that
        already holds the name, so the inner write lands back in the global
        scope and marks nothing. R20: 37 uses in Epic's corpus -- getting this
        backwards would fire on every one of them."""
        f = _detector('<Property Name="X" Value="1"/>\n'
                      '<Agent Name="A" Type="W"><Node Name="N">\n'
                      '<Property Name="X" Value="$(X);2"/>\n'
                      '</Node></Agent>', "D21")
        self.assertEqual(f, [], f)

    def test_two_sibling_nodes_each_defining_the_name_locally_is_LEGAL(self):
        f = _detector('<Agent Name="A" Type="W">\n'
                      '<Node Name="N1"><Property Name="X" Value="1"/></Node>\n'
                      '<Node Name="N2"><Property Name="X" Value="2"/></Node>\n'
                      '</Agent>', "D21")
        self.assertEqual(f, [], f)

    def test_nodes_in_different_agents_defining_the_name_locally_is_LEGAL(self):
        f = _detector('<Agent Name="A" Type="W">\n'
                      '<Node Name="N1"><Property Name="X" Value="1"/></Node></Agent>\n'
                      '<Agent Name="B" Type="W">\n'
                      '<Node Name="N2"><Property Name="X" Value="2"/></Node></Agent>', "D21")
        self.assertEqual(f, [], f)

    def test_the_check_is_case_insensitive_like_the_engine(self):
        """:566 -- the shadow sets are built with StringComparer.OrdinalIgnoreCase."""
        f = _detector('<Agent Name="A" Type="W"><Node Name="N">\n'
                      '<Property Name="MyProp" Value="1"/>\n'
                      '</Node></Agent>\n'
                      '<Property Name="myprop" Value="2"/>', "D21")
        self.assertEqual(len(f), 1, f)

    def test_builtin_seeding_never_trips_the_check(self):
        """The engine seeds built-ins through SetPropertyValue with a null
        element (:391); nothing there may produce a finding."""
        f = _detector('<Agent Name="A" Type="W"><Node Name="N"/></Agent>', "D21")
        self.assertEqual(f, [], f)


if __name__ == "__main__":
    unittest.main()
