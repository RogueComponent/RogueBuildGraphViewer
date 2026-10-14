"""Tests for bgview.model (T5: graph model; T6: tag dataflow).

One test per touched invariant, per the task brief:

    1. V2/R7  a node implicitly produces #<NodeName>; an explicit Produces=
              of that SAME tag does not duplicate it.
    2. V2/R8  resolve_ref precedence: node -> aggregate -> agent, node wins
              even when all three share a name.
    3. V1     Files="#First Named Output;#Second Named Output" -> exactly
              those two tags consumed, spaces intact (';'-only split).
    4. R2     <Copy Files="#In" Tag="#Out"/> -> #Out created, #In consumed,
              driven through schema.is_tag_output (no hardcoded "Copy").
    5. real corpus: Examples/TagsAndFiles.xml -- #Create Three Named Outputs
       (a node's implicit default output, never declared via @Produces) has
       a producer. This is the exact shape that caused measured false
       positives before V2/R7 (R9).
    6. real corpus: Examples/BuildEditorAndTools.xml -- #BinaryFiles has NO
       producer. Epic's own genuine latent bug (R16/V21); must not be
       papered over by the graph model.
    7. tag_provenance populated for a tag written by two different <Tag>
       tasks -- the exact D5 worked example from CONTRACTS.md
       (#ArchiveFiles: a literal-file contributor and a #OutputFiles-with-
       Except contributor).

Plus a handful of cheap supporting checks for the rest of T5's pinned
surface (Graph.aggregates/labels/agents population, After carrying no
consumption, resolve_ref's other precedence tiers) -- reusing the same two
real corpus files and small inline fragments rather than growing new
fixtures.
"""

from __future__ import annotations

import functools
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bgview.evaluator import evaluate
from bgview.loader import load
from bgview.model import Graph, build
from bgview.schema import Schema

REAL_SCHEMA = pathlib.Path(r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph\Schema.xsd")
REAL_TAGS_AND_FILES = pathlib.Path(
    r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph\Examples\TagsAndFiles.xml"
)
REAL_BUILD_EDITOR_AND_TOOLS = pathlib.Path(
    r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph\Examples\BuildEditorAndTools.xml"
)

_NS = 'xmlns="http://www.epicgames.com/BuildGraph"'


@functools.lru_cache(maxsize=None)
def _real_schema() -> Schema:
    assert REAL_SCHEMA.is_file(), f"fixture missing: {REAL_SCHEMA}"
    return Schema.from_file(REAL_SCHEMA)


def _graph_from_fragment(body: str) -> Graph:
    """Write `body` wrapped in a <BuildGraph> root to a temp file, load,
    evaluate, and build a Graph from it -- the model.py analogue of
    test_evaluator.py's `_load_fragment`."""
    xml = f"<?xml version='1.0'?>\n<BuildGraph {_NS}>\n{body}\n</BuildGraph>\n"
    with tempfile.TemporaryDirectory() as d:
        path = pathlib.Path(d) / "fixture.xml"
        path.write_text(xml, encoding="utf-8")
        root = load(path)
    ev = evaluate(root, _real_schema(), overrides={})
    graph, _findings = build(ev, _real_schema())
    return graph


@functools.lru_cache(maxsize=None)
def _real_graph(path: pathlib.Path) -> Graph:
    assert path.is_file(), f"fixture missing: {path}"
    root = load(path)
    ev = evaluate(root, _real_schema(), overrides={})
    graph, _findings = build(ev, _real_schema())
    return graph


class ImplicitOutputTests(unittest.TestCase):
    """V2/R7: every node implicitly produces '#'+its own name; an explicit
    @Produces entry equal to that is de-duplicated, not doubled up."""

    def test_implicit_output_present_and_not_duplicated_by_explicit_produces(self):
        graph = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Foo Bar" Produces="#Foo Bar">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            """
        )
        node = graph.nodes["Foo Bar"]
        self.assertEqual(node.produces, {"#Foo Bar"})  # one entry, not two

    def test_implicit_output_present_when_no_explicit_produces_at_all(self):
        graph = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Plain Node">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            """
        )
        self.assertEqual(graph.nodes["Plain Node"].produces, {"#Plain Node"})


class ResolveRefPrecedenceTests(unittest.TestCase):
    """V2/R8: bare-name resolution is node -> aggregate -> agent, in that
    exact order -- the node wins even when a same-named aggregate AND agent
    would otherwise also match."""

    def test_node_wins_over_same_named_aggregate_and_agent(self):
        graph = _graph_from_fragment(
            """
            <Agent Name="X" Type="AnyAgent">
                <Node Name="NodeInAgentX">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            <Agent Name="AgentY" Type="AnyAgent">
                <Node Name="X">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            <Aggregate Name="X" Requires="NodeInAgentX"/>
            """
        )
        # The same-named Agent "X" and Aggregate "X" both resolve to
        # ["NodeInAgentX"] if consulted -- only ["X"] (the node itself)
        # proves node-first precedence rather than an accidental pass
        # through either of the other two tiers.
        self.assertEqual(graph.resolve_ref("X"), ["X"])

    def test_aggregate_wins_over_same_named_agent_when_no_node_matches(self):
        graph = _graph_from_fragment(
            """
            <Agent Name="Y" Type="AnyAgent">
                <Node Name="NodeInY">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            <Aggregate Name="Y" Requires="NodeInY"/>
            """
        )
        self.assertEqual(graph.resolve_ref("Y"), ["NodeInY"])

    def test_hash_prefixed_name_resolves_to_tag_producers_not_a_bare_name(self):
        graph = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Producer" Produces="#Shared">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            """
        )
        self.assertEqual(graph.resolve_ref("#Shared"), ["Producer"])

    def test_unresolvable_bare_name_returns_empty_list_not_a_crash(self):
        graph = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="OnlyNode">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            """
        )
        self.assertEqual(graph.resolve_ref("NoSuchThing"), [])


class WhitespaceIsNotNormalizedTests(unittest.TestCase):
    """resolve_ref/producers_of fold CASE only -- they must never strip
    whitespace, because a name's whitespace can be load-bearing. Measured
    real case: Tests/DDCVerify.xml declares
    `Node Name="Compile $(EditorPlatform) $(ProjectName)"`, and
    `ProjectName` collides with one of the 19 R17 built-ins (pre-seeded
    into scope 0 as ""); its own `<Option Name="ProjectName"
    DefaultValue="_Unknown_">` therefore silently no-ops (V22: an Option
    whose name is already defined does not reassign), leaving `$(ProjectName)`
    as "". The real node name is "Compile Win64 " -- trailing space and
    all. An asymmetric `.strip()` on only one side of a name comparison
    (caught here before it shipped, via a full-corpus smoke run) makes
    that exact real node permanently unresolvable."""

    def test_trailing_space_in_node_name_still_resolves(self):
        graph = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Compile Win64 ">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            """
        )
        self.assertIn("Compile Win64 ", graph.nodes)
        self.assertEqual(graph.resolve_ref("Compile Win64 "), ["Compile Win64 "])
        self.assertEqual(graph.producers_of("#Compile Win64 "), ["Compile Win64 "])


class TagListSplitTests(unittest.TestCase):
    """V1: tag lists split on ';' ONLY -- spaces inside a tag name survive,
    and each item lands as its own consumed tag."""

    def test_semicolon_list_yields_exactly_those_tags_spaces_intact(self):
        graph = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Consumer">
                    <Tag Files="#First Named Output;#Second Named Output" With="#Out"/>
                </Node>
            </Agent>
            """
        )
        self.assertEqual(
            graph.nodes["Consumer"].consumes,
            {"#First Named Output", "#Second Named Output"},
        )


class TagPolarityDrivenByCopyTests(unittest.TestCase):
    """R2: <Copy Files="#In" Tag="#Out"/> -- #Out produced, #In consumed,
    with polarity decided purely by schema.is_tag_output (Copy/@Tag is
    TagListType, Copy/@Files is not) -- never a hardcoded "Copy" case."""

    def test_copy_tag_produces_and_files_consumes(self):
        graph = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Copier">
                    <Copy Files="#In" From="Engine/Build" To="Engine/Out" Tag="#Out"/>
                </Node>
            </Agent>
            """
        )
        node = graph.nodes["Copier"]
        self.assertIn("#Out", node.creates)
        self.assertIn("#In", node.consumes)
        self.assertNotIn("#Out", node.consumes)
        self.assertNotIn("#In", node.creates)


class RealCorpusTagsAndFilesTests(unittest.TestCase):
    """Examples/TagsAndFiles.xml is the exact real-world shape that caused
    measured false positives before V2/R7: '#Create Three Named Outputs' is
    ONLY ever referenced as a plain tag (a <Log Files=.../>), never declared
    via @Produces -- it exists solely as the node's own implicit default
    output. A graph model missing V2/R7 would see it as unproduced."""

    def test_node_default_output_has_a_producer(self):
        graph = _real_graph(REAL_TAGS_AND_FILES)
        self.assertEqual(graph.producers_of("#Create Three Named Outputs"), ["Create Three Named Outputs"])

    def test_explicit_multi_tag_produces_parsed_with_spaces_intact(self):
        node = _real_graph(REAL_TAGS_AND_FILES).nodes["Create Three Named Outputs"]
        self.assertEqual(
            node.produces,
            {
                "#Create Three Named Outputs",
                "#First Named Output",
                "#Second Named Output",
                "#Third Named Output",
            },
        )

    def test_aggregate_populated_from_aggregate_element(self):
        graph = _real_graph(REAL_TAGS_AND_FILES)
        self.assertEqual(
            graph.aggregates.get("Tag and File Examples"),
            ["Print all Output Folders", "Consume a Single Named Output", "List Named Outputs"],
        )


class RealCorpusBuildEditorAndToolsTests(unittest.TestCase):
    """Examples/BuildEditorAndTools.xml: '#BinaryFiles' is consumed by
    SrcSrv/@BinaryFiles but produced nowhere in the file -- Epic's own
    genuine latent bug (R16/V21, the sole pinned FP-budget true positive).
    The graph model must report NO producer for it, not paper over the gap."""

    def test_binary_files_tag_has_no_producer(self):
        graph = _real_graph(REAL_BUILD_EDITOR_AND_TOOLS)
        self.assertEqual(graph.producers_of("#BinaryFiles"), [])

    def test_output_files_tag_does_have_a_producer(self):
        # Sanity control alongside the empty result above: #OutputFiles IS
        # produced -- "Tag Output Files" declares Produces="#OutputFiles" AND
        # creates it via a <Tag ... With="#OutputFiles"/> task -- proving
        # producers_of() isn't just vacuously always-empty.
        graph = _real_graph(REAL_BUILD_EDITOR_AND_TOOLS)
        self.assertEqual(graph.producers_of("#OutputFiles"), ["Tag Output Files"])

    def test_task_created_tag_absent_from_node_produces_has_no_producer(self):
        # V4's premise, seen in real data: #SourceFiles IS created by a task
        # inside "Store Symbols" (<Tag ... With="#SourceFiles"/>, consumed two
        # lines later by SrcSrv/@SourceFiles) but "Store Symbols" declares NO
        # @Produces at all -- so #SourceFiles is node-LOCAL only and must NOT
        # show up as having a producer. producers_of() answers "which nodes
        # make this tag available to the rest of the graph" (Node.produces),
        # which is deliberately NOT the same question as "which nodes create
        # this tag somewhere in their body" (Node.creates, checked below).
        graph = _real_graph(REAL_BUILD_EDITOR_AND_TOOLS)
        store_symbols = graph.nodes["Store Symbols"]
        self.assertIn("#SourceFiles", store_symbols.creates)
        self.assertNotIn("#SourceFiles", store_symbols.produces)
        self.assertEqual(graph.producers_of("#SourceFiles"), [])


class AfterIsOrderOnlyTests(unittest.TestCase):
    """T5/CONTRACTS: Node.after is order-only -- unlike Requires, a #tag
    sitting in @After must NOT be added to Node.consumes (no file transfer)."""

    def test_after_attribute_carries_no_consumption(self):
        graph = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Upstream" Produces="#Marker">
                    <Log Message="hi"/>
                </Node>
                <Node Name="Downstream" After="#Marker">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            """
        )
        downstream = graph.nodes["Downstream"]
        self.assertEqual(downstream.after, ["#Marker"])
        self.assertNotIn("#Marker", downstream.consumes)


class AggregatesAgentsLabelsPopulationTests(unittest.TestCase):
    """T5: <Aggregate>/<Label> populate Graph.aggregates/labels; every
    <Agent> (even one holding zero nodes) is inventoried in Graph.agents."""

    def test_labels_populated_from_label_element(self):
        graph = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Win64 Node">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            <Label Category="Editors" Name="Win64" Requires="Win64 Node"/>
            """
        )
        self.assertEqual(graph.labels.get("Win64"), ["Win64 Node"])

    def test_same_named_label_declarations_merge_requires(self):
        # Multiple <Label> elements sharing a Name arise legitimately from
        # mutually-exclusive <Do If=.../<Switch> branches, which this tool
        # walks as the union of all possible executions (evaluator.py's own
        # documented design) rather than one concrete run -- so same-named
        # declarations must MERGE their requires tokens, not silently
        # overwrite one another (measured real case: Examples/
        # BuildEditorAndTools.xml declares Label Name="Win64" twice).
        graph = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="NodeOne">
                    <Log Message="hi"/>
                </Node>
                <Node Name="NodeTwo">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            <Label Category="Cat1" Name="Shared" Requires="NodeOne"/>
            <Label Category="Cat2" Name="Shared" Requires="NodeTwo"/>
            """
        )
        self.assertEqual(graph.labels.get("Shared"), ["NodeOne", "NodeTwo"])

    def test_empty_agent_is_still_inventoried(self):
        graph = _graph_from_fragment('<Agent Name="EmptyAgent" Type="AnyAgent"></Agent>')
        self.assertEqual(graph.agents.get("EmptyAgent"), [])


class TagProvenanceTests(unittest.TestCase):
    """D5 evidence: tag_provenance records one Contribution per producing
    task, keyed by tag -- this is the exact worked example from
    CONTRACTS.md's D5 algorithm section. #ArchiveFiles gets two
    contributors in the real file: a literal-file <Tag> (L169) and a
    #OutputFiles-with-Except <Tag> (L172)."""

    def test_provenance_populated_for_tag_written_by_two_tag_tasks(self):
        graph = _real_graph(REAL_BUILD_EDITOR_AND_TOOLS)
        contributions = graph.tag_provenance["#ArchiveFiles"]
        self.assertEqual(len(contributions), 2)

        by_spec = {c.source_spec: c for c in contributions}
        # RootDir is a null-valued builtin (V12b): the literal "$(RootDir)"
        # text survives expansion verbatim rather than being substituted.
        self.assertIn("$(RootDir)/Engine/Build/PrecompiledBinaries.txt", by_spec)
        self.assertIn("#OutputFiles", by_spec)

        literal_contribution = by_spec["$(RootDir)/Engine/Build/PrecompiledBinaries.txt"]
        self.assertEqual(literal_contribution.filter, "")
        self.assertEqual(literal_contribution.except_, "")
        self.assertGreater(literal_contribution.line, 0)

        output_files_contribution = by_spec["#OutputFiles"]
        self.assertEqual(output_files_contribution.except_, ".../Intermediate/...")
        self.assertGreater(output_files_contribution.line, 0)

    def test_provenance_has_no_entry_for_a_tag_nobody_writes(self):
        graph = _graph_from_fragment(
            """
            <Agent Name="A" Type="AnyAgent">
                <Node Name="Lonely">
                    <Log Message="hi"/>
                </Node>
            </Agent>
            """
        )
        self.assertNotIn("#NeverWritten", graph.tag_provenance)


if __name__ == "__main__":
    unittest.main()
