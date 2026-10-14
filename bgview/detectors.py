"""bgview.detectors -- the D2..D16 + D18..D20 static-analysis detectors (T9, T21, T39).

`evaluator.py` already emits D1 (undefined property / malformed `:N` slice)
and D14 (unsupported element, include cycle, `<Expand>` depth cap) as a
side effect of the property-expansion/control-flow walk -- this module does
not re-emit either. Everything else in SPEC.md's §D table lives here, one
`_dN(graph, ev, schema)` function per detector, collected by `run_all`.
D17 (macro contract) and D21 (shadow property) live in evaluator.py, where
macro scope and the scope stack are.

Ground truth for the three detectors with real false-positive risk (D5, D6,
D11) is CONTRACTS.md's "Detector algorithms" section -- read that first if
modifying any of the three. The single most important constraint governing
every detector in this file is V5/V21: across all 19 Epic-shipped graphs
under `Engine/Build/Graph/{Examples,Examples/FPSBuildGraph,Tests}`, the
ENTIRE allowed `warn`-or-above output is three identities: D2 `#BinaryFiles`
in Examples/BuildEditorAndTools.xml and its FPSBuildGraph copy, plus D1
`Property 'ProjectDir' is not defined` x5 in Tests/IncrementalValidate.xml
(B5 -- what the engine itself warns with no --project). Every `warn`-capable detector below (D2, D4, D5, D6 is `info` not
`warn`, D7, D11, D12-unsat, D13) was hand-verified against that corpus
during development for exactly this reason -- see test_detectors.py's
`CorpusFalsePositiveBudgetTests`. `info`-severity detectors (D3, D6, D8,
D9, D10, D12-taut, D15, D16) are unbounded per V5 and reasoned about only
for genuine usefulness, not budget.

V24: there is deliberately NO detector for taxonomy #5 (cross-agent
workspace dependency -- disproven by R24: `SetVersion` registers its
version files as build products, and `Requires="NodeName"` transfers a
node's build products via its implicit default output, R23) or #12
(`SetVersion` should have been guarded -- undecidable intent). Do not
invent either.

Case-folding convention, matching model.py: tag/node names are compared
case-insensitively (`.lower()`) but never whitespace-stripped -- a name's
whitespace can be load-bearing (see model.py's `_resolve_bare` docstring
for the measured real case).
"""

from __future__ import annotations

import fnmatch
import re

from bgview import algebra
from bgview.condition import CondParseError
from bgview.condition import parse as parse_condition
from bgview.evaluator import BUILTINS, EvalResult
from bgview.findings import Finding, Severity
from bgview.lexer import apply_slice, had_empty_entry, is_tag, iter_refs, split_list
from bgview.model import Contribution, Graph
from bgview.schema import Schema

# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------


def run_all(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    """Run every D2..D16 + D18..D20 detector and return the combined finding list.

    De-duplicated by exact `Finding` equality (frozen dataclass -> hashable)
    before returning: a `<ForEach>`/`<Expand>`-repeated element produces one
    `Resolved` entry per iteration (V23), and several detectors below key
    directly off those per-occurrence entries -- a defect on a repeated
    source line would otherwise surface as N byte-identical findings. This
    is a pure textual/positional de-dup only (same file+line+severity+
    detector+message+node+tag); it never collapses genuinely distinct
    occurrences at different lines. `Finding.key()` (basename/detector/
    tag-or-node-or-message) is the coarser identity used by the FP-budget
    harness (V21: "identity, not cardinality") -- that is a harness-level
    concern, not this function's.
    """
    findings: list[Finding] = []
    findings.extend(_d18(graph, ev, schema))
    findings.extend(_d19(graph, ev, schema))
    findings.extend(_d20(graph, ev, schema))
    findings.extend(_d2(graph, ev, schema))
    findings.extend(_d3(graph, ev, schema))
    findings.extend(_d4(graph, ev, schema))
    findings.extend(_d5(graph, ev, schema))
    findings.extend(_d6(graph, ev, schema))
    findings.extend(_d7(graph, ev, schema))
    findings.extend(_d8(graph, ev, schema))
    findings.extend(_d9(graph, ev, schema))
    findings.extend(_d10(graph, ev, schema))
    findings.extend(_d11(graph, ev, schema))
    findings.extend(_d12(graph, ev, schema))
    findings.extend(_d13(graph, ev, schema))
    findings.extend(_d15(graph, ev, schema))
    findings.extend(_d16(graph, ev, schema))
    findings.extend(_d22(graph, ev, schema))
    return list(dict.fromkeys(findings))


# ---------------------------------------------------------------------------
# shared tag-dataflow site harvesting (D2/D3/D4) -- mirrors model.build()'s
# own produce/consume rule (R2/R3) exactly, but keeps the per-occurrence
# element+attr location that Node.creates/consumes (bare sets) discard, so
# these detectors can point at a real file:line (V15) instead of just the
# owning node.
# ---------------------------------------------------------------------------


def _consumption_sites(ev: EvalResult, schema: Schema):
    """Yield (tag, node_name, elem, attr) for every place a `#tag` is
    CONSUMED: `Node/@Requires` itself (R23: Requires consumes its own
    `#tags`), or any non-producer attribute of a task inside a node body.
    `@After` is explicitly excluded -- order-only, R23: no file transfer,
    matching model.py's Node.consumes precisely (After never contributes to
    it)."""
    sites = []
    for r in ev.resolved:
        tag = r.elem.tag
        if tag == "Node":
            node_name = r.attrs.get("Name", "")
            for token in split_list(r.attrs.get("Requires", "")):
                if is_tag(token):
                    sites.append((token, node_name, r.elem, "Requires"))
        elif r.node:
            for attr, value in r.attrs.items():
                if attr == "After":
                    continue
                if schema.is_tag_output(tag, attr):
                    continue
                for token in split_list(value):
                    if is_tag(token):
                        sites.append((token, r.node, r.elem, attr))
    return sites


def _creation_sites(ev: EvalResult, schema: Schema):
    """Yield (tag, node_name, elem, attr) for every place a `#tag` is
    CREATED inside a node body: any TagListType/TagType attribute occurrence
    (R2). `Node/@Produces` itself is never included here -- a Node's own
    `Resolved` entry has `node=None` (it names the nearest *enclosing*
    node), so it structurally cannot match `r.node` truthy; Produces is the
    node's declared interface, not something created *within* it."""
    sites = []
    for r in ev.resolved:
        if not r.node:
            continue
        for attr, value in r.attrs.items():
            if not schema.is_tag_output(r.elem.tag, attr):
                continue
            for token in split_list(value):
                sites.append((token, r.node, r.elem, attr))
    return sites


# ---------------------------------------------------------------------------
# D2 -- tag consumed, never produced anywhere (warn) -- #2
#
# "Produced" here must count BOTH ways a tag can exist: exported globally
# via some node's @Produces (`Graph.producers_of`), OR created by a task
# purely node-locally (`Node.creates`) and consumed within that SAME node --
# the latter never needs to "escape" the node at all, so it is not a defect
# (measured false positive during development: #SourceFiles/#ArchiveFiles/
# #ArchiveBinaries/#ArchiveSymbols in the target file are all created and
# consumed within one node, with no @Produces -- checking `producers_of`
# alone misclassified all four as "produced nowhere").
# ---------------------------------------------------------------------------


def _d2(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    findings = []
    for tag, node_name, elem, attr in _consumption_sites(ev, schema):
        if elem.tag == "Node" and attr == "Requires":
            # D18 owns this site, at `error`. The distinction is real and
            # observable: an unresolvable tag in Node/@Requires is a HARD
            # engine error (ResolveInputReferences -> LogError, the graph
            # refuses to build), whereas a tag consumed by a task attribute
            # such as SrcSrv/@BinaryFiles is only a runtime file-set lookup --
            # which is exactly why Epic's own BuildEditorAndTools.xml builds
            # successfully despite #BinaryFiles never being produced. Same
            # defect shape, genuinely different severity; reporting it twice
            # at two severities would be noise.
            continue
        node = graph.nodes.get(node_name)
        folded = tag.lower()
        created_locally = node is not None and folded in {c.lower() for c in node.creates}
        if created_locally or graph.producers_of(tag):
            continue
        findings.append(
            Finding(
                file=elem.file,
                line=elem.line,
                severity=Severity.WARN,
                detector="D2",
                message=f"Tag '{tag}' is consumed by {elem.tag}/@{attr} but produced nowhere in the graph",
                node=node_name,
                tag=tag,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# D3 -- tag in @Produces, unconsumed in-graph (info) -- #7
# ---------------------------------------------------------------------------


def _d3(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    # V3 vs V4: only the EXPLICITLY-authored `@Produces` text counts as
    # "public API" here -- re-derived from each Node's own raw attribute
    # rather than `Node.produces` (which also folds in the ALWAYS-present
    # implicit `#<NodeName>` output, V2/R7). Flagging every node's implicit
    # default output as "unconsumed public API" would flood real graphs with
    # noise for something that was never a deliberate declaration.
    consumed_anywhere = {c.lower() for node in graph.nodes.values() for c in node.consumes}
    findings = []
    for r in ev.resolved:
        if r.elem.tag != "Node":
            continue
        node_name = r.attrs.get("Name", "")
        for produced_tag in split_list(r.attrs.get("Produces", "")):
            if produced_tag.lower() in consumed_anywhere:
                continue
            findings.append(
                Finding(
                    file=r.elem.file,
                    line=r.elem.line,
                    severity=Severity.INFO,
                    detector="D3",
                    message=f"Tag '{produced_tag}' is declared in Node/@Produces but never consumed anywhere in the graph",
                    node=node_name,
                    tag=produced_tag,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# D4 -- tag created in node, not in @Produces, unconsumed within the node
# (warn) -- provably dead, it cannot escape the node
# ---------------------------------------------------------------------------


def _d4(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    findings = []
    for tag, node_name, elem, attr in _creation_sites(ev, schema):
        node = graph.nodes.get(node_name)
        if node is None:
            continue
        folded = tag.lower()
        if folded in {p.lower() for p in node.produces}:
            continue  # declared (or is the implicit default output) -- V3 territory
        if folded in {c.lower() for c in node.consumes}:
            continue  # consumed somewhere within this same node -- not dead
        findings.append(
            Finding(
                file=elem.file,
                line=elem.line,
                severity=Severity.WARN,
                detector="D4",
                message=(
                    f"Tag '{tag}' is created by {elem.tag}/@{attr} but is not in Node/@Produces "
                    f"and is never consumed within node '{node_name}' -- cannot escape the node, provably dead"
                ),
                node=node_name,
                tag=tag,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# D5 -- provably-empty tag (warn, V20) -- #4
#
# Algorithm per CONTRACTS.md exactly: for a consuming `<Tag Files="..."
# Filter="F" With="U">`, fire only when EVERY contributor to the Files spec
# is provably disjoint from F:
#   - a literal filename (no wildcard) that does not match F -> disjoint
#   - a tag #S all of whose OWN contributions carry an Except that
#     (syntactically) subsumes F -> disjoint
#   - anything else (wildcard path, no known provenance, blank spec) ->
#     UNRESOLVABLE -> the whole detector abstains (V20: one unresolvable
#     contributor emits NOTHING; never guess)
# ---------------------------------------------------------------------------


def _has_wildcard(spec: str) -> bool:
    return "*" in spec or "?" in spec or "..." in spec


def _matches_pattern(literal: str, filter_patterns: str) -> bool:
    """Does a wildcard-free literal path match ANY pattern in a Filter-style
    ';'-list ("*.c;*.h")? fnmatch's '*' matches any run of characters
    including path separators (unlike glob.glob), which is what a
    BuildGraph Filter needs; checked against the full spec and its trailing
    filename component since "*.pdb" conventionally matches an extension
    anywhere in the path."""
    norm = literal.replace("\\", "/")
    basename = norm.rsplit("/", 1)[-1]
    for pattern in split_list(filter_patterns):
        if fnmatch.fnmatch(norm, pattern) or fnmatch.fnmatch(basename, pattern):
            return True
    return False


def _pattern_subsumes(filter_patterns: str, except_value: str) -> bool:
    """CONTRACTS/D5: syntactic subsumption only -- every pattern in
    `filter_patterns` appears verbatim among `except_value`'s ';'-split
    entries (F subset-of E as literal strings). No fuzzy/semantic pattern
    reasoning (V20 is a hard gate: syntactic, not clever)."""
    filter_items = split_list(filter_patterns)
    if not filter_items:
        return False
    except_items = split_list(except_value)
    return all(f in except_items for f in filter_items)


def _item_disjoint_from_filter(
    item: str, filter_pattern: str, tag_provenance: dict[str, list[Contribution]], visiting: frozenset[str]
) -> bool:
    if is_tag(item):
        return _tag_disjoint_from_filter(item, filter_pattern, tag_provenance, visiting)
    if _has_wildcard(item):
        return False  # bare wildcard path -- unresolvable (V20)
    return not _matches_pattern(item, filter_pattern)


def _tag_disjoint_from_filter(
    tag: str, filter_pattern: str, tag_provenance: dict[str, list[Contribution]], visiting: frozenset[str]
) -> bool:
    if tag in visiting:
        return False  # cycle guard -- never assume disjoint through a cycle
    contributions = tag_provenance.get(tag)
    if not contributions:
        return False  # no known provenance at all -- unresolvable (V20)
    visiting = visiting | {tag}
    for c in contributions:
        if _pattern_subsumes(filter_pattern, c.except_):
            continue  # this contribution proven disjoint via its own Except
        items = split_list(c.source_spec)
        if not items:
            return False  # blank Files/FileLists on a TagList-producing task -- unresolvable
        for item in items:
            if not _item_disjoint_from_filter(item, filter_pattern, tag_provenance, visiting):
                return False
    return True


def _d5(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    findings = []
    for r in ev.resolved:
        # R29 established that exactly two task types carry both a tag output
        # and filter semantics: Tag (Filter/Except) and Copy (Exclude). D5
        # nonetheless handles ONLY Tag, deliberately -- see §B.4.
        #
        # The two are OPPOSITE polarity. Tag/@Filter SELECTS (keep only what
        # matches); Copy/@Exclude REMOVES (drop what matches). The proof below
        # fires when every contributor is DISJOINT from the pattern, which for
        # Tag means nothing was selected => empty. For Copy, disjoint means
        # nothing was removed => everything copied => decidedly NOT empty.
        # Reusing this predicate for Copy would false-positive on nearly every
        # Copy that has an Exclude.
        #
        # Proving a Copy tag empty needs the opposite predicate -- every
        # contributor fully SUBSUMED by Exclude -- which we do not implement,
        # because Epic's 19-graph corpus contains zero Copy/@Exclude and V20
        # forbids shipping an unexercised proof. Upgrade path: add
        # `_item_subsumed_by(item, pattern)` and a Copy branch, with fixtures.
        if r.elem.tag != "Tag":
            continue
        filter_pattern = r.attrs.get("Filter", "")
        with_value = r.attrs.get("With", "")
        if not filter_pattern or not with_value:
            continue  # nothing restrictive is being applied -- nothing to prove empty
        files_value = r.attrs.get("Files") or r.attrs.get("FileLists") or ""
        items = split_list(files_value)
        if not items:
            continue
        if not all(_item_disjoint_from_filter(item, filter_pattern, graph.tag_provenance, frozenset()) for item in items):
            continue
        for target_tag in split_list(with_value):
            findings.append(
                Finding(
                    file=r.elem.file,
                    line=r.elem.line,
                    severity=Severity.WARN,
                    detector="D5",
                    message=(
                        f"Tag '{target_tag}' is provably empty -- every contributor to "
                        f"'{files_value}' is disjoint from Filter='{filter_pattern}'"
                    ),
                    node=r.node,
                    tag=target_tag,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# D6 -- SetVersion-bearing node is not an ancestor of a Compile-bearing node
# (info, anchored on the offending Compile node) -- #6
# ---------------------------------------------------------------------------


def _has_path_to_any(graph: Graph, start: str, targets: set[str]) -> bool:
    """BFS over the Requires dependency graph (via `Graph.resolve_ref`,
    which folds bare names through node -> aggregate -> agent precedence,
    V2/R8) from `start`, true iff any node in `targets` is reachable --
    including `start` itself (a node that is BOTH Compile- and
    SetVersion-bearing trivially satisfies its own dependency). Only
    `Node.requires` is followed, never `.after` -- R23/R24: only Requires
    transfers a node's build products across the agent boundary; After is
    order-only and carries no file transfer."""
    if start in targets:
        return True
    visited = {start}
    queue = [start]
    while queue:
        current = queue.pop()
        node = graph.nodes.get(current)
        if node is None:
            continue
        for token in node.requires:
            for resolved_name in graph.resolve_ref(token):
                if resolved_name in targets:
                    return True
                if resolved_name not in visited:
                    visited.add(resolved_name)
                    queue.append(resolved_name)
    return False


def _d6(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    compile_nodes: set[str] = set()
    setversion_nodes: set[str] = set()
    for r in ev.resolved:
        if not r.node:
            continue
        if r.elem.tag == "Compile":
            compile_nodes.add(r.node)
        elif r.elem.tag == "SetVersion":
            setversion_nodes.add(r.node)

    findings = []
    for node_name in sorted(compile_nodes):
        if _has_path_to_any(graph, node_name, setversion_nodes):
            continue
        node = graph.nodes[node_name]
        if setversion_nodes:
            target_desc = " or ".join(f"'{n}'" for n in sorted(setversion_nodes))
            message = (
                f"Node '{node_name}' contains a Compile task but has no dependency path (via Requires) "
                f"to a SetVersion-bearing node ({target_desc}); may stamp a stale version"
            )
        else:
            message = (
                f"Node '{node_name}' contains a Compile task but the graph has no SetVersion-bearing "
                f"node at all; may stamp a stale version"
            )
        findings.append(
            Finding(
                file=node.file,
                line=node.line,
                severity=Severity.INFO,
                detector="D6",
                message=message,
                node=node_name,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# D7 -- declared cross-agent dependency whose transferred set is provably
# empty (warn) -- no taxonomy item
#
# V13: a cross-agent Requires is normal and fine by default (R23/R24:
# Requires="NodeName" DOES transfer the target's build products via its
# implicit default output) -- flag ONLY when the target's output is
# PROVABLY empty. Deliberately narrow: fires only when the target node has
# no explicit @Produces AND zero task children at all, so it provably ran
# nothing and produced nothing (no tag content, no build products of any
# kind). This is the one shape provable without a task-type table of "which
# tasks register build products" (only SetVersion is documented, R24) --
# see the module-level ponytail note.
# ---------------------------------------------------------------------------


def _d7(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    # ponytail: ceiling = only the "target node is entirely empty" shape is
    # provable here (no @Produces, zero task children -- so it can neither
    # tag anything nor register any implicit build product). A target node
    # that DOES run tasks but whose only tag output is provably empty (the
    # same D5-style reasoning, extended across the agent boundary) is not
    # attempted: that would additionally require knowing which non-Tag task
    # types (Compile? Zip? arbitrary future tasks?) register build products
    # outside of tagging, and only SetVersion's build-product behavior is
    # documented (R24) -- guessing beyond that risks a false "provably
    # empty" on a node that actually does produce real build products.
    # Upgrade path: once a table of build-product-registering task types
    # exists, extend the eligibility check below to also cover nodes with
    # tasks but a D5-provably-empty tag set and no such task type present.
    explicit_produces: dict[str, list[str]] = {}
    node_has_no_children: dict[str, bool] = {}
    for r in ev.resolved:
        if r.elem.tag == "Node":
            name = r.attrs.get("Name", "")
            explicit_produces[name] = split_list(r.attrs.get("Produces", ""))
            node_has_no_children[name] = len(r.elem.children) == 0

    findings = []
    for a_name, a_node in graph.nodes.items():
        for token in a_node.requires:
            if is_tag(token):
                continue  # an explicit #tag Requires names its own producer directly -- not this narrow case
            resolved = graph.resolve_ref(token)
            if len(resolved) != 1:
                continue  # ambiguous/aggregate resolution -- abstain rather than guess
            b_name = resolved[0]
            b_node = graph.nodes.get(b_name)
            if b_node is None or b_node.agent == a_node.agent:
                continue  # not cross-agent
            if explicit_produces.get(b_name) or not node_has_no_children.get(b_name, False):
                continue  # has a declared interface, or ran at least one task -- cannot prove empty
            findings.append(
                Finding(
                    file=a_node.file,
                    line=a_node.line,
                    severity=Severity.WARN,
                    detector="D7",
                    message=(
                        f"Node '{a_name}' declares a cross-agent dependency on '{b_name}' "
                        f"(agent '{b_node.agent}'), whose transferred output is provably empty "
                        f"(no @Produces, no tasks in its body)"
                    ),
                    node=a_name,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# D8 -- property defined, never referenced (info) -- #8
#
# V23: uses ev.prop_reads/prop_defs directly, which are already computed
# during the POST-Expand execution-order walk -- a name is "referenced" iff
# it appears anywhere in prop_reads, with no separate doc-order re-scan of
# our own (R22 measured that a doc-order scan gives 3 false positives on
# Examples/Macros.xml; reusing the evaluator's own post-expansion trace
# sidesteps that class of bug entirely rather than re-deriving it).
# ---------------------------------------------------------------------------


def _d8(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    read_names = {name for name, _elem, _idx in ev.prop_reads}
    findings = []
    for name, elem, idx in ev.prop_defs:
        if name in read_names:
            continue
        findings.append(
            Finding(
                file=elem.file,
                line=elem.line,
                severity=Severity.INFO,
                detector="D8",
                message=f"Property '{name}' is defined but never referenced",
                node=ev.resolved[idx].node,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# D9 -- option declared, never referenced (info) -- no taxonomy item
# ---------------------------------------------------------------------------


def _d9(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    read_names = {name for name, _elem, _idx in ev.prop_reads}
    findings = []
    for r in ev.resolved:
        if r.elem.tag != "Option":
            continue
        name = r.attrs.get("Name", "")
        if not name or name in read_names:
            continue
        findings.append(
            Finding(
                file=r.elem.file,
                line=r.elem.line,
                severity=Severity.INFO,
                detector="D9",
                message=f"Option '{name}' is declared but never referenced",
                node=r.node,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# D22 -- boolean-looking <Option> without a Restrict (info) -- hygiene
# ---------------------------------------------------------------------------
# An <Option> whose DefaultValue is "true" or "false" is a switch, and a
# switch with no Restrict accepts ANY string on a manual run:
# `-set:WithDDC=ture` is not an error to the engine, it is a value -- and
# engine truthiness ("true", case-insensitive, nothing else) reads it as
# FALSE, so the typo silently flips the switch off. Restrict="true|false"
# turns that into a hard parse-time error instead. Info, never warn: the
# script is correct as written and the engine is silent; this is hygiene
# for the run somebody types by hand. Matched case-insensitively (the
# engine's own rule), quoted as written.
_BOOL_DEFAULTS = frozenset({"true", "false"})


def _d22(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    findings = []
    for r in ev.resolved:
        if r.elem.tag != "Option":
            continue
        name = r.attrs.get("Name", "")
        default = r.attrs.get("DefaultValue", "")
        if not name or default.strip().lower() not in _BOOL_DEFAULTS:
            continue
        if (r.attrs.get("Restrict") or "").strip():
            continue
        findings.append(
            Finding(
                file=r.elem.file,
                line=r.elem.line,
                severity=Severity.INFO,
                detector="D22",
                message=(
                    f"Option '{name}' defaults to '{default}' but has no Restrict; add "
                    f"Restrict=\"true|false\" so a mistyped value on a manual run "
                    f"(-set:{name}=ture) is rejected instead of being read as false"
                ),
                node=r.node,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# D10 -- trailing ';' / empty list entry (info, never warn per V6) -- #9
# ---------------------------------------------------------------------------

# ponytail: ceiling = attributes this tool already treats as ';'-lists
# elsewhere (schema-declared TagListType/TagType producer attrs, plus
# Node's own Requires/OptionalRequires/After, plus the well-established
# FileSpec-list attrs R2/R3/model.py's own `_source_spec` already name:
# Files/FileLists/Filter/Except). Deliberately NOT every attribute
# indiscriminately -- most BalancedStringType attrs (Message, Description,
# Arguments, Target, ...) are free text, never ';'-split by the engine at
# all, and flagging a stray ';' inside prose would be pure noise rather
# than "harmless list styling" (R13). Upgrade path: extend this name set if
# a future corpus is found using another genuine ';'-list attribute.
_LIST_ATTR_NAMES = frozenset({"Requires", "OptionalRequires", "After", "Files", "FileLists", "Filter", "Except"})


def _d10(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    findings = []
    for r in ev.resolved:
        tag = r.elem.tag
        for attr, value in r.attrs.items():
            if not value:
                continue
            if not (schema.is_tag_output(tag, attr) or attr in _LIST_ATTR_NAMES):
                continue
            if not had_empty_entry(value):
                continue
            # WHERE the empty entry came from, because the two sources read
            # identically in a message and only one of them is visible.
            #
            # A literal trailing ';' you can point at. An entry left behind by
            # an expansion that produced nothing you cannot: the measured case
            # is line 48 of the target file,
            #     Files="#ToolBinaries;#EditorBinaries;$(GameBinaries)"
            # where GameBinaries is undefined (D1, reported on the SAME line),
            # expands to "", and leaves a trailing empty entry. Saying
            # "trailing or duplicate ';'" there sends the reader hunting for a
            # character that is not in the source, and makes the pair of
            # findings on that line look like a duplicate rather than the
            # cause-and-effect it is.
            raw = r.elem.attrib.get(attr, "")
            if had_empty_entry(raw):
                why = "trailing or duplicate ';'"
            else:
                # Only refs can have introduced it: no refs would mean raw and
                # expanded agree, which the branch above already handled.
                names = list(dict.fromkeys(ref.name for ref in iter_refs(raw)))
                if len(names) == 1:
                    why = f"'$({names[0]})' expanded to nothing"
                else:
                    # Several candidates. Naming one would be a guess, and
                    # deciding between them means re-expanding entry by entry
                    # -- which a property value legitimately containing ';'
                    # (the accumulator idiom, R20) makes unsound anyway.
                    why = "an expansion produced nothing; no literal ';' in the source"
            findings.append(
                Finding(
                    file=r.elem.file,
                    line=r.elem.line,
                    severity=Severity.INFO,
                    detector="D10",
                    message=f"{tag}/@{attr} has an empty list entry ({why})",
                    node=r.node,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# D11 -- schema-required attribute resolves to "" on EVERY reachable
# option-set (warn) -- #3
#
# CONTRACTS.md's literal algorithm ("fire whenever the expanded value is ''
# under the evaluated option-set") is under-quantified and was measured,
# during development, to blow the V21 FP budget two different ways:
#
#   1. Scope: applied to every element indiscriminately, it fires on
#      Option/@DefaultValue="" and Option/@Description="" (and similar
#      "required to be WRITTEN, not required to be non-empty" declaration
#      attributes) dozens of times across the corpus -- completely normal,
#      intentional BuildGraph usage (an option whose whole point is "extra
#      args, none by default"), never a defect. Fixed by scoping to genuine
#      TASK elements: skip R14's 22 structural/declaration kinds, and
#      require `schema.known_element` (excludes synthetic Switch
#      Case/Default branches, which bypass schema classification entirely).
#
#   2. Even task-scoped, `SymStore/@StoreDir="$(SymbolStorePath)"` with
#      `SymbolStorePath` defaulting to "" is IDENTICAL in the target file
#      (must fire, ACCEPTANCE.md line 61) and in the real
#      Examples/BuildEditorAndTools.xml + its FPSBuildGraph copy (must stay
#      silent, V21) -- UNLESS you look 4-8 lines further: the target file
#      gates `Store Symbols`'s inclusion in `SubmissionDependencies` on
#      `'$(SymbolStorePath)' == ''` (backwards -- pulls the node in exactly
#      when the path is EMPTY), while both real files gate it on `!= ''`
#      (correct -- only when a path was actually supplied). That inversion
#      IS the injected defect: in the target file, the only way to make
#      StoreDir non-empty (supply a path) also disables the very node that
#      needs it, so the empty default can never be meaningfully fixed by
#      any invocation. In the real files, supplying a path both fills
#      StoreDir AND keeps the node correctly required -- a legitimate,
#      working, option-driven configuration, not a defect. Two more real
#      corpus sites (FPSBuildGraph/DeployToEpicGames.xml Spawn/@Exe,
#      FPSBuildGraph/ValidateContent.xml Cook/@Project) are empty-by-default
#      required attrs with NO such contradiction -- R27's own precedent
#      ("invocation-dependent, not a script defect") -- and must also stay
#      silent.
#
# The fix (per cavepony-advisor ruling): fire only when NO possible
# invocation can BOTH fill the attribute AND keep it load-bearing. Force
# every <Option>-declared name referenced in the attribute's raw text to a
# non-empty sentinel (a real `--set` can always do that), then check the
# result is non-empty AND every guard that could gate the element (or the
# node it lives in) out of relevance -- If= on the element/its ancestor
# chain, plus any accumulator-style "$(X);ThisNodeName" inclusion gate
# indexed elsewhere in the script -- still evaluates to non-False under
# that same forced env (V10: UNKNOWN counts as holding; only a provable
# False blocks). This is intentionally a HYPOTHETICAL reasoning pass
# (a possible invocation, not the actual script), so unlike every other
# detector in this file it never emits a Finding or a D1-style warning of
# its own on a bad/unresolvable reference -- it only answers yes/no.
#
# NOTE for the orchestrator: this exposed two upstream inaccuracies,
# reported here per the escalation protocol rather than corrected directly
# (this worker does not own SPEC.md/CONTRACTS.md):
#   - CONTRACTS.md's D11 algorithm section (and SPEC.md's D11 row, "under
#     some option-set", an existential) should read "empty under EVERY
#     option-set that reaches the element" (a universal) -- ACCEPTANCE.md's
#     own rows (§A line 61, §B's pinned set) are correct as written and
#     needed no change; the algorithm text is what under-specified it.
#   - findings.py's `Finding.key()` uses `os.path.basename(file)`, which
#     collapses V21's two pinned entries -- both literally named
#     `BuildEditorAndTools.xml` -- into ONE key. Any FP-budget harness that
#     compares via `.key()` (a natural thing to reach for, since it is the
#     documented dedup/identity helper) will silently pass even if only one
#     of the two files was ever scanned. test_detectors.py's corpus test
#     below therefore asserts identity via relative *path*, not `.key()`.
# ---------------------------------------------------------------------------

_R14_STRUCTURAL = frozenset(
    {
        "Include",
        "Option",
        "Property",
        "Regex",
        "StringOp",
        "EnvVar",
        "Macro",
        "Extend",
        "Agent",
        "Aggregate",
        "Artifact",
        "Report",
        "Badge",
        "Label",
        "Trace",
        "Warning",
        "Error",
        "Do",
        "Switch",
        "ForEach",
        "Expand",
        "Node",
    }
)

# Deliberately using the same textual shape as algebra.py's own
# nonempty-sample sentinel (a leading control char no real XML attribute
# value can contain) -- not imported from there since it is a private
# module constant, but the same reasoning applies.
_WITNESS_SENTINEL = "\x01nonempty"


def _base_env(ev: EvalResult) -> dict[str, str | None]:
    """A best-effort 'typical value' for every name the script ever binds:
    the 19 builtins (R17), every <Option>'s own DefaultValue, and every
    <Property>/<EnvVar>'s LAST-assigned value across the whole script. Used
    only as the starting point for the D11 witness test below -- resolving
    whatever OTHER names happen to sit alongside the Option reference under
    test, not a precise point-in-time lookup."""
    env: dict[str, str | None] = dict(BUILTINS)
    for name, opt in ev.options.items():
        env[name] = opt.default
    for name, _elem, idx in ev.prop_defs:
        env[name] = ev.resolved[idx].attrs.get("Value", "")
    return env


def _inclusion_gates(ev: EvalResult) -> dict[str, list[str]]:
    """casefolded name -> raw If= guard texts of every <Property> whose
    accumulator Value= list (';'-split, V1) includes that name as one of
    its items -- the "$(X);NodeName" idiom used to conditionally pull a
    node into a Requires-style aggregation, e.g. `<Property
    Name="SubmissionDependencies" Value="$(SubmissionDependencies); Store
    Symbols" If="..."/>`. The D11 witness test treats each as an
    additional gate on whether the named node's work is ever load-bearing."""
    gates: dict[str, list[str]] = {}
    for r in ev.resolved:
        if r.elem.tag == "Property" and r.raw_if:
            for item in split_list(r.attrs.get("Value", "")):
                gates.setdefault(item.casefold(), []).append(r.raw_if)
    return gates


def _witness_substitute(text: str, env: dict[str, str | None]) -> str:
    """Minimal $(...) resolver for the D11 witness test only: the same
    right-to-left mutate-and-rescan order as evaluator._expand (R18/V12),
    but purely hypothetical -- a name absent from `env` silently resolves
    to "" (this reasons about a POSSIBLE invocation, never the actual
    script, so it must not emit a finding or raise) -- and a null-valued
    entry (V12b) is left inert exactly like the real expander, so it can
    never re-select the same reference forever."""
    result = text
    search_end = len(result)
    inert: set[str] = set()
    while True:
        refs = [r for r in iter_refs(result) if r.start < search_end and r.raw not in inert]
        if not refs:
            return result
        ref = refs[-1]
        if "$(" in ref.name:
            search_end = ref.start
            continue
        value = env.get(ref.name, "")
        if value is None:
            inert.add(ref.raw)
            search_end = ref.start
            continue
        replacement = value if ref.malformed else apply_slice(value, ref.slice_n)
        result = result[: ref.start] + replacement + result[ref.end :]
        search_end = len(result)


def _gate_texts_for(elem, node_name: str | None, inclusion_gates: dict[str, list[str]]) -> list[str]:
    """Every guard that could make `elem` (or the node containing it)
    irrelevant: If= on the element itself and every ancestor (a Do/Switch
    branch wrapping it), plus any accumulator-inclusion gate indexed under
    the enclosing node's own name (`_inclusion_gates`)."""
    texts = []
    walk = elem
    while walk is not None:
        raw_if = walk.attrib.get("If")
        if raw_if:
            texts.append(raw_if)
        walk = walk.parent
    if node_name:
        texts.extend(inclusion_gates.get(node_name.casefold(), []))
    return texts


def _some_invocation_fills(raw_value: str, gate_texts: list[str], base_env: dict[str, str | None], options: dict) -> bool:
    """True iff some option-set exists under which `raw_value` resolves
    non-empty AND every gate in `gate_texts` still holds (V10: an
    unparseable or opaque/UNKNOWN gate counts as holding -- only a
    *provable* False blocks). Every <Option>-declared name referenced by
    `raw_value` is forced to a non-empty sentinel (a real `--set` can
    always do this); any other referenced name (a plain Property, a
    builtin) keeps its typical value from `base_env` -- forcing those too
    would manufacture invocations that can never actually happen."""
    referenced = {ref.name for ref in iter_refs(raw_value)}
    env = dict(base_env)
    for name in referenced:
        if name in options:
            env[name] = _WITNESS_SENTINEL

    if not _witness_substitute(raw_value, env):
        return False

    for gate_text in gate_texts:
        try:
            ast = parse_condition(gate_text)
        except CondParseError:
            continue  # can't even parse it -- never let an uncertain gate prove anything
        if algebra.evaluate(ast, env) is False:
            return False
    return True


def _d11(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    base_env = _base_env(ev)
    inclusion_gates = _inclusion_gates(ev)

    findings = []
    for r in ev.resolved:
        tag = r.elem.tag
        if tag in _R14_STRUCTURAL or not schema.known_element(tag):
            continue
        for attr in schema.required_attrs(tag):
            if r.attrs.get(attr) != "":
                continue
            raw_val = r.elem.attrib.get(attr, "")
            gate_texts = _gate_texts_for(r.elem, r.node, inclusion_gates)
            if _some_invocation_fills(raw_val, gate_texts, base_env, ev.options):
                continue  # some real --set makes this both non-empty AND load-bearing
            message = f"{tag}/@{attr} is required but resolves to an empty string on every reachable option-set"
            if raw_val:
                message += f" (source: '{raw_val}')"
            findings.append(
                Finding(
                    file=r.elem.file,
                    line=r.elem.line,
                    severity=Severity.WARN,
                    detector="D11",
                    message=message,
                    node=r.node,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# D12 -- guard unsat -> warn; tautological -> info (warn+info) -- #3
#
# V10/V14: algebra.classify's "unknown" verdict (an opaque Exists(), or a
# leaf that fails to resolve) produces NEITHER severity -- never guess
# through an opaque guard.
#
# Two corpus-measured refinements on top of a direct algebra.classify call,
# both in the direction of MORE caution (can only turn a false unsat/taut
# into a correct "contingent"/"unknown", never the reverse):
#
#   1. base_env excludes the 19 R17 builtins entirely (unlike D11, which
#      needs *a* concrete stand-in to reason about ordinary property text).
#      A builtin's real runtime value is fundamentally unknowable to static
#      analysis (evaluator.py's own docstring: "there is no real P4
#      branch/changelist/host to query") -- e.g. `If="$(IsBuildMachine)"`
#      guards (a common, legitimate "only on CI" pattern, corpus-measured
#      in Examples/BuildWorldPartitionHLODs.xml) would otherwise
#      unconditionally see IsBuildMachine="false" and misclassify as
#      "unsat" every time, regardless of what any *option* is set to.
#      Leaving a builtin reference unresolved makes algebra.evaluate return
#      UNKNOWN for it, correctly classifying as "unknown".
#   2. Every referenced Option's domain is widened with "true"/"false" on
#      top of whatever `Opt.domain()` already samples. R21 measured 30/136
#      (22%) of real If= conditions are bare-boolean option checks
#      (`If="$(SomeFlag)"`); `Opt.domain()`'s fallback for an unrestricted
#      option -- {default, "", one nonempty sentinel} -- has no reason to
#      ever equal the literal "true" (corpus-measured case:
#      Examples/BuildEditorAndTools.xml's `Horde` option defaults to the
#      compound STRING "$(IsBuildMachine) And $(IsHordeEnv)", not "true";
#      `If="$(Horde)"` was misclassified "unsat" because none of the 3
#      sampled values happen to equal "true", even though `--set
#      Horde=true` obviously satisfies it). `_D12Opt` below is a thin
#      subclass overriding only `domain()`; `algebra.classify` calls
#      `.domain()` polymorphically and does no isinstance/type checking,
#      so this needs no changes to algebra.py itself.
# ---------------------------------------------------------------------------


class _D12Opt(algebra.Opt):
    """`algebra.Opt` widened for D12's satisfiability check only -- see the
    module note above. No new fields; overrides `domain()` alone."""

    def domain(self) -> list[str]:
        base = super().domain()
        return base + [s for s in ("true", "false") if s not in base]


def _d12(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    # CONTRACTS/Opt bridge: evaluator.Opt and algebra.Opt are deliberate
    # structural twins (name/default/restrict); bridge exactly as pinned,
    # never make either module import the other.
    algebra_opts = {name: _D12Opt(o.name, o.default, o.restrict) for name, o in ev.options.items()}
    base_env: dict[str, str | None] = {}

    findings = []
    for r in ev.resolved:
        raw_if = r.raw_if
        if not raw_if or not raw_if.strip():
            continue
        if not iter_refs(raw_if):
            # A condition with ZERO "$(...)" references anywhere (a pure
            # literal, e.g. "2 < 1") has no config-dependent ambiguity at
            # all -- classify() would still call it correctly (a
            # zero-option enumeration is exact, not a sampling gap), but
            # it is trivially visible on inspection and has no static-
            # analysis value-add; corpus-measured, this exact shape is how
            # Examples/Properties.xml deliberately demonstrates each
            # comparison operator ("2 < 1" alongside "1 < 2" etc.) --
            # tutorial content, not a defect. Skip rather than flag.
            continue
        try:
            ast = parse_condition(raw_if)
        except CondParseError:
            continue  # cannot even parse it -- never guess (mirrors V20's spirit)
        verdict = algebra.classify(ast, algebra_opts, base_env)
        if verdict == "unsat":
            findings.append(
                Finding(
                    file=r.elem.file,
                    line=r.elem.line,
                    severity=Severity.WARN,
                    detector="D12",
                    message=f"Guard If=\"{raw_if}\" is unsatisfiable -- this branch can never run",
                    node=r.node,
                )
            )
        elif verdict == "taut":
            findings.append(
                Finding(
                    file=r.elem.file,
                    line=r.elem.line,
                    severity=Severity.INFO,
                    detector="D12",
                    message=f"Guard If=\"{raw_if}\" is tautological -- always true, the condition is redundant",
                    node=r.node,
                )
            )
        # "contingent"/"unknown" -> neither finding (V10/V14).
    return findings


# ---------------------------------------------------------------------------
# D13 -- dead-on-arrival property definition (warn) -- no taxonomy item
#
# V23: computed on ev.prop_defs/prop_reads (post-Expand execution order),
# never source doc order (R22).
#
# D13 is deliberately narrower than "this name is never read anywhere" --
# that degenerate case (nothing ever happens to the name again, ever) is
# D8's job (info) and must NOT also trip D13 (measured false positive
# during development: a property that is simply unused, with no
# subsequent redefinition either, was being flagged as "dead on arrival"
# by an earlier version of this rule -- but nothing ever raced it, so
# there was no "arrival" to be dead on). D13 fires ONLY when a definition
# is provably CLOBBERED: scanning forward from resolved-index i, the very
# next event touching the name (merging reads and defs, sorted by index,
# reads before defs at an equal index -- see the tie-break note below) is
# an UNCONDITIONAL redefinition -- one with no `If=` guard at all, so it
# is certain to run before any reader could see this value. A read
# anywhere later proves the definition WAS observed (live). A
# CONDITIONALLY-guarded redefinition proves nothing either way on its own
# (it might not execute) -- V20's "never guess" spirit extended here: skip
# past it and keep looking, rather than assuming it wins the race. If
# nothing certain turns up (no read, and no unconditional redefinition)
# before the events run out, the definition is not PROVABLY dead --
# whatever happens to it is either genuinely nothing (D8's case) or
# depends on a guard this detector cannot be sure about, and V20's
# posture is to abstain rather than guess.
#
# "Unconditional" means neither the redefining element ITSELF nor any of
# its ANCESTORS (a wrapping `<Do If=...>`/`<Switch>` branch) carries an
# `If=` -- checking only the element's own attribute is not enough
# (corpus-measured false positive: Tests/IncrementalCompare.xml defines
# `NullIncrementalCookPrereq`, then redefines it with a bare `<Property
# .../>` -- no If= of its own -- but that Property sits inside `<Do
# If="'$(NullCookInterleaveAlternatePlatform)' != ''">`; the ancestor's
# guard is what actually decides whether the redefinition runs, and a
# later `Node/@Requires="$(NullIncrementalCookPrereq)"` does observe the
# FIRST definition whenever that guard is false).
#
# (Measured real case, also from the target file: `<Property
# Name="SubmitClient" Value="..."/>` immediately followed by a SECOND
# `<Property Name="SubmitClient" .../>` guarded by `If="'$(P4CLIENT)' !=
# ''"`. A naive "any later redefinition clobbers it" rule flags the FIRST
# definition as dead -- but in the real engine, when P4CLIENT is empty the
# second assignment never runs, and a later task reading $(SubmitClient)
# DOES observe the first definition's value in that execution. Only an
# unconditional next redefinition can prove the earlier value unobservable
# in every execution.)
#
# The equal-index tie-break is not arbitrary: for the SAME element (e.g. a
# `<Property Name="X" Value="$(X);more"/>` accumulator step), evaluator.py
# always expands the Value attribute (recording any self-referential read
# of the OLD value in prop_reads) strictly BEFORE recording that element's
# own prop_defs entry -- both land at the same resolved-index, but the read
# is causally first. Sorting reads before defs at equal index reproduces
# that real order, which is exactly what makes an accumulator step's
# PREVIOUS definition register as observed (R20: the 37 real accumulator
# occurrences must never trip this).
# ---------------------------------------------------------------------------


def _has_any_guard(elem) -> bool:
    """True if `elem` or any ancestor up to the document root carries a
    non-empty If= attribute -- used by D13 to decide whether a
    redefinition is PROVABLY unconditional or merely might-not-happen."""
    walk = elem
    while walk is not None:
        if walk.attrib.get("If"):
            return True
        walk = walk.parent
    return False


def _d13(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    READ, DEF = 0, 1
    events_by_name: dict[str, list[tuple[int, int]]] = {}
    defs_by_name: dict[str, list[int]] = {}
    for name, _elem, idx in ev.prop_defs:
        events_by_name.setdefault(name, []).append((idx, DEF))
        defs_by_name.setdefault(name, []).append(idx)
    for name, _elem, idx in ev.prop_reads:
        events_by_name.setdefault(name, []).append((idx, READ))

    findings = []
    for name, def_indices in defs_by_name.items():
        events = sorted(events_by_name[name])  # (index, kind); READ(0) sorts before DEF(1) at equal index
        pos_of_def = {idx: pos for pos, (idx, kind) in enumerate(events) if kind == DEF}
        for idx in def_indices:
            pos = pos_of_def[idx]
            is_dead = False
            for nxt_idx, nxt_kind in events[pos + 1 :]:
                if nxt_kind == READ:
                    break  # observed -- live
                if not _has_any_guard(ev.resolved[nxt_idx].elem):
                    is_dead = True  # unconditional redefinition -- certainly clobbered first
                    break
                # conditionally-guarded redefinition: can't prove it runs -- keep scanning past it
            if not is_dead:
                continue
            elem = ev.resolved[idx].elem
            findings.append(
                Finding(
                    file=elem.file,
                    line=elem.line,
                    severity=Severity.WARN,
                    detector="D13",
                    message=(
                        f"Property '{name}' is dead on arrival -- it is unconditionally redefined "
                        f"before this value is ever read"
                    ),
                    node=ev.resolved[idx].node,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# D15 -- Agent/@Type is a literal, not option-driven (info) -- #10
# ---------------------------------------------------------------------------


def _d15(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    findings = []
    for r in ev.resolved:
        if r.elem.tag != "Agent":
            continue
        # RAW source text, not the expanded r.attrs value: an option-driven
        # Type ("$(AgentType)") expands to something with zero "$(...)"
        # refs left in it, which would look indistinguishable from a
        # hardcoded literal if checked post-expansion.
        raw_type = r.elem.attrib.get("Type", "")
        if not raw_type:
            continue
        if iter_refs(raw_type):
            continue  # references a property/option somewhere -- IS option-driven
        findings.append(
            Finding(
                file=r.elem.file,
                line=r.elem.line,
                severity=Severity.INFO,
                detector="D15",
                message=f"Agent/@Type=\"{raw_type}\" is a hardcoded literal, not option-driven",
                node=None,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# D16 -- task consumes a dir path written by another node with no tag flow
# (info) -- #11
# ---------------------------------------------------------------------------

# ponytail: ceiling = a CURATED read/write attribute allowlist (expanded in
# loop 1 to Move and Unzip, Strip/@BaseDir and Tag/@BaseDir) -- R30 shows this
# is irreducible rather than lazy: BuildGraph.cs:434-435 registers both
# FileReference and DirectoryReference as BalancedString, and Copy/@From,
# Copy/@To and Zip/@FromDir are plain `string` in the C# anyway -- there is no CONTRACTS-specified algorithm for
# D16, and schema.py exposes no "this attr denotes an output directory"
# signal to derive the set generically. Upgrade path: extend both frozensets
# below if a future corpus shows another directory-write/read task shape.
# R30: this allowlist is IRREDUCIBLE, not a shortcut. BuildGraph.cs:434-435
# registers both FileReference and DirectoryReference as BalancedString, so the
# XSD erases the distinction; and the C# type does not help either, since
# Copy/@From, Copy/@To and Zip/@FromDir are plain `string`, not
# DirectoryReference. Identifying "this attribute names a directory another
# node fills" is a semantic judgement no machine-readable source encodes.
_DIR_WRITE_ATTRS = frozenset({
    ("Copy", "To"), ("Move", "To"), ("Strip", "OutputDir"), ("Unzip", "ToDir"),
})
_DIR_READ_ATTRS = frozenset({
    ("Copy", "From"), ("Move", "From"), ("Zip", "FromDir"),
    ("Strip", "BaseDir"), ("Tag", "BaseDir"),
})


def _norm_path(value: str) -> str:
    """Windows-first path comparison (§C: case-insensitive, '\\' and '/'
    both) -- normalize separators, fold case, drop a trailing separator."""
    return value.strip().replace("\\", "/").rstrip("/").lower()


def _d16(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    writers: dict[str, set[str]] = {}
    for r in ev.resolved:
        if not r.node:
            continue
        for task_tag, attr in _DIR_WRITE_ATTRS:
            if r.elem.tag != task_tag:
                continue
            value = r.attrs.get(attr, "")
            if value:
                writers.setdefault(_norm_path(value), set()).add(r.node)

    findings = []
    for r in ev.resolved:
        if not r.node:
            continue
        for task_tag, attr in _DIR_READ_ATTRS:
            if r.elem.tag != task_tag:
                continue
            value = r.attrs.get(attr, "")
            if not value:
                continue
            other_writers = writers.get(_norm_path(value), set()) - {r.node}
            if not other_writers:
                continue
            findings.append(
                Finding(
                    file=r.elem.file,
                    line=r.elem.line,
                    severity=Severity.INFO,
                    detector="D16",
                    message=(
                        f"{r.elem.tag}/@{attr} reads directory '{value}', written by node(s) "
                        f"{sorted(other_writers)} with no tag flow connecting them (breaks if agents split)"
                    ),
                    node=r.node,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# D18 -- engine HARD-ERROR conditions (V31: be at least as loud as the engine)
#
# BgScriptReader LogErrors on all of these, meaning the script does not build
# at all. bgview was silent on every one, which is the worst kind of gap for a
# tool whose pitch is that the engine under-reports. Sourced by auditing all
# 46 LogError call sites in BgScriptReader.cs, not by guesswork.
# ---------------------------------------------------------------------------


def _under_a_guard(elem) -> bool:
    """True if `elem` or any ancestor carries an `If=` attribute.

    Deliberately conservative: it does not try to evaluate the guard. A
    reference that only exists on some branch cannot be *proven* unresolvable
    under union evaluation, and D18 emits `error`, so it must only speak when
    it is certain (same discipline as V20 for D5)."""
    node = elem
    while node is not None:
        if node.attrib.get("If"):
            return True
        node = getattr(node, "parent", None)
    return False


def _ref_tokens_with_location(graph: Graph, ev: EvalResult):
    """Yield (token, elem, kind) for every name reference the engine resolves.

    Driven off `ev.resolved` rather than `Graph`, so every finding carries the
    exact source element (V15 forbids a finding without a location).
    """
    for r in ev.resolved:
        tag = r.elem.tag
        if _under_a_guard(r.elem):
            # bgview walks EVERY branch (union semantics), so a reference and
            # the node that satisfies it can both be guarded by the same
            # condition yet appear inconsistent once unioned. Measured real
            # case: IncrementalCompare.xml's "Alternate Platform Cook" node
            # and the property naming it share a guard; under the union they
            # look unresolvable, but no real engine run ever sees that state.
            # Only UNCONDITIONAL references can be proven unresolvable.
            continue
        if tag == "Node":
            for attr in ("Requires", "After", "OptionalRequires"):
                for token in split_list(r.attrs.get(attr, "")):
                    yield token, r.elem, f"Node/@{attr}"
        elif tag in ("Aggregate", "Label", "Report", "Badge"):
            for attr in ("Requires", "Include", "Exclude", "Nodes", "Targets"):
                for token in split_list(r.attrs.get(attr, "")):
                    yield token, r.elem, f"{tag}/@{attr}"


# Elements whose @Name goes through the engine's ValidateName (:2182).
_NAMED_OBJECT_TAGS = frozenset({
    "Node", "Agent", "Aggregate", "Report", "Label", "Artifact", "Badge",
})

# BgSchema.cs:203. Kept as a literal rather than derived from the XSD: it is a
# C# `const` the schema generator embeds into a name regex, not an attribute
# the schema exposes, so there is nothing in Schema.xsd to read it back out of.
_ILLEGAL_NAME_CHARS = frozenset('^<>:"/\\|?*')


def _invalid_object_name_reason(name: str) -> str | None:
    """Why the engine's ValidateName would reject `name`, or None if it accepts.

    Mirrors BgScriptReader.cs:2182-2206 exactly, including the place where it
    is more permissive than a casual reading suggests (R33): it never trims, so
    a single leading or trailing space is ACCEPTED -- which is precisely how a
    node name ends up genuinely unreferenceable while still being legal. Only
    CONSECUTIVE spaces are an error, so this must never test `.strip()`."""
    if name == "":
        return "the name is empty"
    for idx, char in enumerate(name):
        if idx > 0 and char == " " and name[idx - 1] == " ":
            return "it contains consecutive spaces"
        if ord(char) < 32 or char in _ILLEGAL_NAME_CHARS:
            shown = repr(char) if ord(char) < 32 else f"'{char}'"
            return f"it contains the illegal character {shown}"
    return None


def _d18(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    findings: list[Finding] = []

    # (a) Unresolvable reference. Engine: "Reference to '{Name}' cannot be
    #     resolved; check it has been defined." (BgScriptReader.cs:2170) and
    #     the did-you-mean variant at :2166 for a missing '#'.
    seen: set[tuple] = set()
    for token, elem, where in _ref_tokens_with_location(graph, ev):
        if graph.resolve_ref(token):
            continue
        # A '$(...)' that survived expansion is already reported by D1; do not
        # double-report it as an unresolvable reference.
        if "$(" in token:
            continue
        hint = ""
        if not token.startswith("#") and graph.resolve_ref("#" + token):
            hint = f"; did you mean '#{token}'?"
        key = (elem.file, elem.line, token)
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            file=elem.file, line=elem.line, severity=Severity.ERROR, detector="D18",
            message=(f"{where} references '{token}', which resolves to no node, "
                     f"aggregate, agent or tag{hint} (engine reports an error)"),
        ))

    # (b) Two nodes generating the same output tag. Engine: "Output tag '{Tag}'
    #     is already generated by node '{Name}'". Silent data hazard: which
    #     producer wins is not something the script author controls.
    for tag in sorted({t for n in graph.nodes.values() for t in n.produces}):
        producers = graph.producers_of(tag)
        if len(producers) > 1:
            node = graph.nodes[producers[1]]
            findings.append(Finding(
                file=node.file, line=node.line, severity=Severity.ERROR, detector="D18",
                message=(f"Output tag '{tag}' is generated by more than one node "
                         f"({', '.join(sorted(producers))}) (engine reports an error)"),
                node=producers[1], tag=tag,
            ))

    # (d) Duplicate object name. Engine: CheckNameIsUnique ->
    #     "'{Name}' is already defined; cannot add a second time"
    #     (BgScriptReader.cs:2114). The namespace is EXACTLY what
    #     BgGraphDef.ContainsName checks: NameToNode | NameToReport |
    #     NameToAggregate -- agents and labels are NOT in it. That matters:
    #     Epic's BuildWorldPartitionHLODs.xml deliberately names an <Agent> and
    #     its <Node> both "HLOD Setup", and AllExamples.xml pulls in two files
    #     each declaring an <Agent Name="Properties Agent"> (duplicate agents
    #     merge; only a TYPE mismatch is an error). Including agents/labels here
    #     produced 3 measured false positives.
    #     Guarded declarations are exempt per V33.
    declared: dict[str, list] = {}
    for r in ev.resolved:
        if r.elem.tag not in ("Node", "Aggregate", "Report"):
            continue
        name = r.attrs.get("Name", "")
        if not name or _under_a_guard(r.elem):
            continue
        declared.setdefault(name.lower(), []).append((name, r.elem, r.elem.tag))
    for _folded, decls in sorted(declared.items()):
        # De-dup by source position: a <ForEach> body re-emits the same element
        # once per value, which is one declaration, not N.
        positions = {(e.file, e.line) for _n, e, _k in decls}
        if len(positions) > 1:
            name, elem, kind = decls[-1]
            kinds = ", ".join(sorted({k for _n, _e, k in decls}))
            findings.append(Finding(
                file=elem.file, line=elem.line, severity=Severity.ERROR, detector="D18",
                message=(f"'{name}' is declared more than once ({kinds}); node, report "
                         f"and aggregate names share one namespace "
                         f"(engine reports an error)"),
            ))

    # (c) An <Option>'s own DefaultValue violating its own Restrict. Engine:
    #     "Default value '{DefaultValue}' is not valid for '{Name}'". Trivially
    #     checkable and always a genuine authoring bug.
    for r in ev.resolved:
        if r.elem.tag != "Option":
            continue
        restrict = r.attrs.get("Restrict", "")
        if not restrict:
            continue
        default = r.attrs.get("DefaultValue", "")
        if "$(" in restrict or "$(" in default:
            continue  # unresolved expansion -- D1's business, not ours
        try:
            ok = re.fullmatch(restrict, default, re.IGNORECASE) is not None
        except re.error:
            continue  # .NET regex bgview cannot compile: stay silent, never guess
        if not ok:
            findings.append(Finding(
                file=r.elem.file, line=r.elem.line, severity=Severity.ERROR, detector="D18",
                message=(f"Option '{r.attrs.get('Name','')}' has DefaultValue "
                         f"'{default}', which does not match its own Restrict "
                         f"'{restrict}' (engine reports an error)"),
            ))

    # (e) An output tag that does not begin with '#'. Engine: "Output tag names
    #     must begin with a '#' character ('{Name}')" (BgScriptReader.cs:1533).
    #     Purely syntactic, so nothing here can be wrong about it. Note the
    #     engine drops such an entry from the node's outputs entirely, so the
    #     tag silently never exists -- which is exactly why it is worth saying.
    for r in ev.resolved:
        if r.elem.tag != "Node":
            continue
        for token in split_list(r.attrs.get("Produces", "")):
            if token.startswith("#") or "$(" in token:
                continue
            if _under_a_guard(r.elem):
                continue
            findings.append(Finding(
                file=r.elem.file, line=r.elem.line, severity=Severity.ERROR, detector="D18",
                message=(f"Node/@Produces entry '{token}' does not begin with '#'; "
                         f"the engine rejects it and the tag is never produced "
                         f"(engine reports an error)"),
                node=r.attrs.get("Name") or None,
            ))

    # (f) A node declaring the same output twice. Engine: "Node '{NodeName}'
    #     already has an output called '{TagName}'" (BgScriptReader.cs:1593),
    #     raised while registering `BgNodeDef.Outputs` into the global tag
    #     table. Two distinct shapes reach it, and BOTH are errors:
    #       * a literal duplicate inside one @Produces list;
    #       * @Produces naming the node's OWN implicit '#<NodeName>' output.
    #     The second is easy to get wrong. BgNodeDef.cs:198-203 builds Outputs
    #     as ['#'+Name] ++ outputNames.Where(x => x != Name) -- the filter
    #     compares against the BARE name, but :1531 has already rejected every
    #     entry not starting with '#', so no surviving entry can ever equal it.
    #     The filter is effectively dead and '#Foo' on a node named 'Foo'
    #     duplicates the implicit output rather than collapsing into it. This
    #     sharpens R7: "explicit output == node name de-duped" holds for the
    #     unhashed spelling only, which :1531 rejects anyway.
    #
    #     D18(b) cannot see either shape: model.build de-duplicates
    #     `Node.produces` into a set (via `_add_deduped`) before D18(b) ever
    #     runs, so both collapse to one producer. This must read raw @Produces.
    for r in ev.resolved:
        if r.elem.tag != "Node":
            continue
        if _under_a_guard(r.elem):
            continue
        node_name = r.attrs.get("Name", "")
        implicit = f"#{node_name}".lower()
        seen_outputs: set[str] = set()
        for token in split_list(r.attrs.get("Produces", "")):
            if "$(" in token or not token.startswith("#"):
                continue  # (e) owns the unhashed case; D1 owns the unexpanded one
            folded = token.lower()
            if folded in seen_outputs or folded == implicit:
                why = ("duplicates the node's own implicit default output"
                       if folded == implicit and folded not in seen_outputs
                       else "is listed more than once")
                findings.append(Finding(
                    file=r.elem.file, line=r.elem.line, severity=Severity.ERROR, detector="D18",
                    message=(f"Node '{node_name}' output '{token}' {why} "
                             f"(engine reports an error)"),
                    node=node_name or None, tag=token,
                ))
            seen_outputs.add(folded)

    # (g) An object name the engine's ValidateName rejects: empty, containing
    #     CONSECUTIVE spaces, or containing a control/illegal character
    #     (BgScriptReader.cs:2187,2196,2201). The illegal set is
    #     BgSchema.cs:203 `IllegalNameCharacters = "^<>:\"/\\|?*"`.
    #     R33 is precise about the boundary and it is not the obvious one:
    #     ValidateName does NOT trim, and a SINGLE trailing space is legal --
    #     which is how a node name can end up genuinely unreferenceable. Only
    #     consecutive spaces are an error, so this must not test `.strip()`.
    for r in ev.resolved:
        if r.elem.tag not in _NAMED_OBJECT_TAGS:
            continue
        name = r.attrs.get("Name")
        if name is None or "$(" in name or _under_a_guard(r.elem):
            continue
        reason = _invalid_object_name_reason(name)
        if reason:
            findings.append(Finding(
                file=r.elem.file, line=r.elem.line, severity=Severity.ERROR, detector="D18",
                message=(f"<{r.elem.tag}> name '{name}' is invalid: {reason} "
                         f"(engine reports an error)"),
            ))

    # (h) An <Artifact> naming a tag no node produces. Engine: "Artifact
    #     '{Name}' references non-existent tag '{Tag}'" (BgScriptReader.cs:1344).
    #     <Artifact> is NOT in `_ref_tokens_with_location`'s element list, so
    #     D18(a) never saw it. The subtlety is the DEFAULT: when @Tag is absent
    #     or empty the engine substitutes '#<Name>' (:1337-1341) and validates
    #     THAT, so an <Artifact> with no @Tag is still a checked reference.
    produced_tags = {t.lower() for n in graph.nodes.values() for t in n.produces}
    for r in ev.resolved:
        if r.elem.tag != "Artifact" or _under_a_guard(r.elem):
            continue
        art_name = r.attrs.get("Name", "")
        tag = r.attrs.get("Tag", "") or (f"#{art_name}" if art_name else "")
        if not tag or "$(" in tag:
            continue
        if tag.lower() in produced_tags:
            continue
        how = "" if r.attrs.get("Tag", "") else " (defaulted from its @Name)"
        findings.append(Finding(
            file=r.elem.file, line=r.elem.line, severity=Severity.ERROR, detector="D18",
            message=(f"Artifact '{art_name}' references tag '{tag}'{how}, which no "
                     f"node produces (engine reports an error)"),
            tag=tag,
        ))
    return findings


# ---------------------------------------------------------------------------
# D19 -- cross-agent ordering error (BgScriptReader.cs:1552-1558)
# ---------------------------------------------------------------------------

def _agent_declaration_order(ev: EvalResult) -> dict[str, int]:
    """agent name (folded) -> index of its FIRST <Agent> declaration.

    Duplicate <Agent> blocks MERGE rather than conflict (R34), and the engine
    keeps one `BgGraphDef.Agents` entry per agent at the position it was first
    seen. `dict` preserves insertion order, so first-seen order is just
    insertion order here -- the same thing `model.build`'s `agents.setdefault`
    relies on."""
    order: dict[str, int] = {}
    for r in ev.resolved:
        if r.elem.tag != "Agent":
            continue
        name = r.attrs.get("Name", "").lower()
        if name and name not in order:
            order[name] = len(order)
    return order


def _d19(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    """A node ordered after a node belonging to a LATER-declared agent.

    Engine (BgScriptReader.cs:1552-1558, LogError):

        "Node '{Name}' has a dependency on '{OtherName}', which was declared
         after the initial definition of '{AgentName}'."

    V31 makes this an `error`. What makes it worth a detector of its own rather
    than another D18 clause is that it is the only diagnostic in the engine
    that is purely about the AGENT BOUNDARY -- one of the three invisible
    semantics SS G exists to expose -- and it is invisible in the source: every
    name involved resolves fine, so nothing looks wrong at any single site.

    It is reachable ONLY when an agent is REOPENED. References resolve against
    the graph built so far (`ResolveInputReferences` at :1471 runs before the
    node is registered at :1563), so within a single agent block every
    dependency necessarily lives in an agent at or before the current one. Only
    a second <Agent Name="A"> block appearing after some <Agent Name="B"> can
    put a B-node into an A-node's dependency set:

        <Agent Name="A"> <Node Name="A1"/>                 </Agent>
        <Agent Name="B"> <Node Name="B1"/>                 </Agent>
        <Agent Name="A"> <Node Name="A2" Requires="B1"/>   </Agent>   <- error

    The engine compares against `orderDependencies`, which it has already
    closed transitively (:1546-1550) over Requires, OptionalRequires and After,
    so the closure below is transitive too -- a two-hop path through an
    innocent-looking intermediate is the shape a human reviewer misses.

    Measured: 0 hits across the 19-graph Epic corpus (V5/V21), which is what
    lets it ship at `error`.
    """
    agent_order = _agent_declaration_order(ev)
    if len(agent_order) < 2:
        return []  # a single agent can never be reopened around another one

    # folded -> as-written, so messages quote the name the author actually typed
    agent_display: dict[str, str] = {}
    for r in ev.resolved:
        if r.elem.tag == "Agent":
            written = r.attrs.get("Name", "")
            if written:
                agent_display.setdefault(written.lower(), written)

    direct: dict[str, set[str]] = {}
    node_agent: dict[str, str] = {}
    node_site: dict[str, tuple] = {}
    for r in ev.resolved:
        if r.elem.tag != "Node":
            continue
        raw_name = r.attrs.get("Name", "")
        if not raw_name:
            continue
        folded = raw_name.lower()
        node_agent[folded] = (r.agent or "").lower()
        node_site.setdefault(folded, (raw_name, r.elem))
        targets = direct.setdefault(folded, set())
        for attr in ("Requires", "OptionalRequires", "After"):
            for token in split_list(r.attrs.get(attr, "")):
                for resolved_name in graph.resolve_ref(token):
                    targets.add(resolved_name.lower())

    def closure(start: str) -> set[str]:
        seen: set[str] = set()
        stack = list(direct.get(start, ()))
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(direct.get(current, ()))
        return seen

    findings: list[Finding] = []
    for folded, (raw_name, elem) in sorted(node_site.items()):
        # V33: bgview unions every branch, so a dependency that only exists on
        # one branch is not PROVABLY ordered wrongly. `error` stays silent.
        if _under_a_guard(elem):
            continue
        own_agent = node_agent.get(folded, "")
        own_idx = agent_order.get(own_agent)
        if own_idx is None:
            continue
        for dep in sorted(closure(folded)):
            dep_agent = node_agent.get(dep)
            if dep_agent is None:
                continue
            dep_idx = agent_order.get(dep_agent)
            if dep_idx is None or dep_idx <= own_idx:
                continue
            dep_name = node_site.get(dep, (dep, None))[0]
            dep_agent_name = agent_display.get(dep_agent, dep_agent)
            own_agent_name = agent_display.get(own_agent, own_agent)
            findings.append(Finding(
                file=elem.file, line=elem.line, severity=Severity.ERROR, detector="D19",
                message=(f"Node '{raw_name}' depends on '{dep_name}', which belongs to "
                         f"agent '{dep_agent_name}' -- declared after the first definition of "
                         f"agent '{own_agent_name}'. Reopening an agent cannot pull in "
                         f"work scheduled later (engine reports an error)"),
                node=raw_name,
            ))
    return findings


# ---------------------------------------------------------------------------
# D20 -- engine WARNINGS bgview was silent on (V31, second half)
# ---------------------------------------------------------------------------


def _d20(graph: Graph, ev: EvalResult, schema: Schema) -> list[Finding]:
    """Conditions the engine `LogWarning`s that nothing else here reports.

    V31 has two halves, and R31/R32 only ever cashed in the `LogError` one.
    These are the remaining `LogWarning` sites in BgScriptReader.cs that
    describe a SCRIPT defect (as opposed to a host/invocation condition like
    :431 "Unknown argument for script", which is about the command line, not
    the file, and so has no source location to attach to -- V15).

    All three are intra-element: each compares attributes of a single element
    against each other, never one element against another. That is why none of
    them needs V33's guard exemption -- there is no cross-branch union that
    could make a guarded case look broken (contrast D18(a), D18(h), D19).

    Measured: 0 hits across the 19-graph corpus.
    """
    findings: list[Finding] = []

    for r in ev.resolved:
        tag = r.elem.tag

        # (a) Engine :1488 -- "Optional input '{Tag}' is also a required input.
        #     The required input takes precedence". Harmless at runtime, but it
        #     always means the author believed one of the two declarations was
        #     doing something, and it is not.
        if tag == "Node":
            required = {t.lower(): t for t in split_list(r.attrs.get("Requires", ""))}
            optional = {t.lower() for t in split_list(r.attrs.get("OptionalRequires", ""))}
            for folded in sorted(required.keys() & optional):
                findings.append(Finding(
                    file=r.elem.file, line=r.elem.line, severity=Severity.WARN, detector="D20",
                    message=(f"Node '{r.attrs.get('Name','')}' lists '{required[folded]}' in both "
                             f"@Requires and @OptionalRequires; the required one wins and the "
                             f"optional declaration has no effect (engine reports a warning)"),
                    node=r.attrs.get("Name") or None,
                ))

        # (b) Engine :1110 -- "Argument '{Name}' is listed multiple times".
        elif tag == "Macro":
            seen_args: set[str] = set()
            for attr in ("Arguments", "OptionalArguments"):
                for arg in split_list(r.attrs.get(attr, "")):
                    folded = arg.lower()
                    if folded in seen_args:
                        findings.append(Finding(
                            file=r.elem.file, line=r.elem.line, severity=Severity.WARN, detector="D20",
                            message=(f"Macro '{r.attrs.get('Name','')}' lists argument '{arg}' "
                                     f"more than once (engine reports a warning)"),
                        ))
                    seen_args.add(folded)

        # (c) Engine :1705 -- "Node {Name}'s Separator attribute is more than
        #     one character ({Separator}). Defaulting to ;". The engine does
        #     NOT split on the string the author wrote; it silently falls back
        #     to ';', so the loop iterates over something other than what the
        #     script says.
        elif tag == "ForEach":
            separator = r.attrs.get("Separator", "")
            if len(separator) > 1 and "$(" not in separator:
                findings.append(Finding(
                    file=r.elem.file, line=r.elem.line, severity=Severity.WARN, detector="D20",
                    message=(f"<ForEach> Separator '{separator}' is more than one character; "
                             f"the engine ignores it and splits on ';' instead "
                             f"(engine reports a warning)"),
                ))

    return findings
