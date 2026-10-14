"""bgview.model -- graph model (T5) + tag dataflow (T6).

Builds `Graph`/`Node` from the evaluator's flat, post-Expand/ForEach/Include
execution-order trace (`EvalResult.resolved`, V23). Two things this module
must get exactly right, per measured ground truth (R7/R8, R2/R3):

  * V2/R7: every node IMPLICITLY produces `#<NodeName>` -- the engine's
    `BgNodeDef.DefaultOutput => Outputs[0]` is built from the node's own
    Name, and an explicit `@Produces` entry equal to the node name is
    de-duplicated rather than doubled up. Missing this is "the single
    largest false-positive source in the whole tool": a plain reference to
    a node's default output (e.g. `#Create Three Named Outputs` in
    Examples/TagsAndFiles.xml, which is never declared via `@Produces` --
    it exists ONLY as that node's implicit output) would otherwise look
    like a dangling, unproduced tag.
  * R2/R3 tag polarity: `schema.is_tag_output(elem.tag, attr)` decides
    PRODUCES (TagListType/TagType attrs -- e.g. `Tag/@With`, `Copy/@Tag`,
    `Node/@Produces`); every other attribute is scanned for `#Name` tokens
    (V1: split on ';' ONLY, via `lexer.split_list` -- tag names legitimately
    hold spaces), each of which is CONSUMED. This is applied uniformly,
    element by element and attribute by attribute, with no per-task-name
    table anywhere in this module -- `schema.py` (T1) already resolved the
    polarity question generically straight from Schema.xsd.

`Node/@Requires` is the one attribute that does double duty: it both
declares a node-level dependency (raw tokens, resolved later via
`Graph.resolve_ref`) AND consumes any `#tag` tokens found in it (R23: a
`Requires="NodeName"` dependency DOES carry that node's tagged/implicit
output across the agent boundary via `TryResolveInputReference`, so a
`#tag` sitting in `Requires` alongside plain node names is a real
consumption, not noise -- do not model cross-agent Requires as "broken",
R24 disproves that entirely). `Node/@After` is ordering-only and
contributes to neither `consumes` nor any other dataflow -- it explicitly
carries NO file transfer, unlike `Requires`.

Names (node/tag/aggregate/agent) are matched case-insensitively throughout
(the engine uses .NET's InvariantCultureIgnoreCase/OrdinalIgnoreCase for
these lookups), but STORED using whatever casing the source script used --
so every lookup in this module folds case at compare time rather than
normalizing storage up front.
"""

from __future__ import annotations

import dataclasses

from bgview.evaluator import EvalResult
from bgview.findings import Finding
from bgview.lexer import is_tag, split_list
from bgview.schema import Schema


@dataclasses.dataclass
class Node:
    name: str
    agent: str
    line: int
    file: str
    produces: set[str]     # explicit @Produces + implicit '#'+name  (V2)
    creates: set[str]      # tags made by task TagList attrs inside this node
    consumes: set[str]     # '#tags' referenced by non-TagList attrs
    requires: list[str]    # raw @Requires tokens
    after: list[str]       # raw @After tokens -- order-only, R23: no file transfer
    # Last line of the `<Node>` element, i.e. the `</Node>` (or the same line
    # as `line` for a self-closing node). Threaded from `Elem.end_line` so the
    # HTML report's source view can highlight the node's WHOLE element rather
    # than re-parsing the .xml behind the model's back. Defaults to 0 = "not
    # known", which `line_span` reads as a single-line range.
    end_line: int = 0

    @property
    def line_span(self) -> tuple[int, int]:
        """`(start, end)` source lines, inclusive, `end >= start` always."""
        return (self.line, max(self.end_line, self.line))


@dataclasses.dataclass(frozen=True)
class Contribution:
    """One task's contribution to a tag's contents -- the evidence D5 (a
    later task, T9) needs to decide whether a tag is provably empty. See
    CONTRACTS.md "Detector algorithms" / D5 for how this gets consumed.

    `except_` (trailing underscore) because `except` is a Python keyword;
    it otherwise mirrors the XML attribute name `Except` exactly, same as
    `filter` mirrors `Filter`.
    """

    source_spec: str   # raw (expanded) Files value, or FileLists if Files absent/empty; "" if neither present
    filter: str        # raw Filter value; "" if absent
    except_: str        # raw Except value; "" if absent
    line: int


@dataclasses.dataclass
class Graph:
    nodes: dict[str, Node]
    agents: dict[str, list[str]]                    # agent name -> node names declared in it
    aggregates: dict[str, list[str]]                 # aggregate name -> raw @Requires tokens
    labels: dict[str, list[str]]                     # label name -> raw @Requires tokens
    tag_provenance: dict[str, list[Contribution]]    # tag -> contributing tasks (D5 evidence)

    def resolve_ref(self, name: str) -> list[str]:
        """V2/R8: resolve a bare `Requires`/`After`/`Aggregate-Requires`-
        style token to the node name(s) it denotes.

        A `#`-prefixed name resolves to that tag's producer node(s)
        (counting implicit default outputs, R7 -- already folded into
        every `Node.produces` set, so `producers_of` needs no separate
        implicit/explicit special-casing).

        A bare name resolves node -> aggregate -> agent, in that EXACT
        precedence (BgGraphDef.cs:144): the first kind that matches wins
        outright, even if a later kind would also match under the same
        name (a node and an aggregate and an agent may legally share a
        display name -- they are separate identifier spaces in the real
        engine).
        """
        if is_tag(name):
            return self.producers_of(name)
        return self._resolve_bare(name, frozenset())

    def _resolve_bare(self, name: str, seen: frozenset[str]) -> list[str]:
        # No .strip() here: names are matched case-insensitively (folded)
        # but otherwise EXACTLY -- whitespace is not normalized away.
        # Measured real case, Tests/DDCVerify.xml: Node Name="Compile
        # $(EditorPlatform) $(ProjectName)" expands to "Compile Win64 "
        # (trailing space and all) because ProjectName collides with one of
        # the 19 R17 built-ins (BUILTINS["ProjectName"] == "", pre-seeded
        # into scope 0) -- the script's own <Option Name="ProjectName"
        # DefaultValue="_Unknown_"> silently no-ops (V22/R17: an Option
        # whose name is already defined does not reassign). That trailing
        # space is a real part of the node's identity, not incidental
        # formatting -- stripping it here would make this name unresolvable.
        folded = name.lower()
        if not folded or folded in seen:
            # Empty/blank token, or an aggregate-requires-aggregate cycle:
            # never guess, never recurse forever -- just denote nothing.
            return []
        seen = seen | {folded}

        for node_name in self.nodes:
            if node_name.lower() == folded:
                return [node_name]

        for agg_name, tokens in self.aggregates.items():
            if agg_name.lower() == folded:
                out: list[str] = []
                for token in tokens:
                    for resolved_name in self._resolve_token(token, seen):
                        if resolved_name not in out:
                            out.append(resolved_name)
                return out

        for agent_name, node_names in self.agents.items():
            if agent_name.lower() == folded:
                return list(node_names)

        return []

    def _resolve_token(self, token: str, seen: frozenset[str]) -> list[str]:
        """One token from an aggregate's own (raw) Requires list: either a
        `#tag` or another bare node/aggregate/agent name, resolved with the
        same node -> aggregate -> agent precedence, sharing the path-scoped
        `seen` set so a real cycle (not a legitimate diamond -- two
        siblings independently reaching the same aggregate) is still
        caught."""
        if is_tag(token):
            return self.producers_of(token)
        return self._resolve_bare(token, seen)

    def producers_of(self, tag: str) -> list[str]:
        """Node names producing `tag`, counting implicit default outputs
        (V2/R7). Case-folded, not whitespace-normalized -- see
        `_resolve_bare`'s comment for why a stray `.strip()` is unsafe."""
        folded = tag.lower()
        return [name for name, node in self.nodes.items() if any(p.lower() == folded for p in node.produces)]


def _add_deduped(target: set[str], folded_seen: set[str], candidate: str) -> None:
    """Add `candidate` to `target` unless a case-insensitive duplicate is
    already present -- V2's "explicit @Produces entry equal to the node
    name is de-duplicated". Whichever spelling is offered FIRST wins;
    callers control priority via call order (the implicit `#`+node-name
    output is always added before explicit `@Produces` tokens, so the
    node's own `Name=` casing wins any collision)."""
    folded = candidate.lower()
    if folded not in folded_seen:
        folded_seen.add(folded)
        target.add(candidate)


def _merge_requires(bucket: dict[str, list[str]], name: str, tokens: list[str]) -> None:
    """Add `tokens` to `bucket[name]`, deduped, preserving first-seen order.

    Aggregate/Label declarations sharing a `Name` legitimately recur across
    mutually-exclusive `<Do If=.../>`/`<Switch>` branches -- this tool walks
    EVERY branch unconditionally (evaluator.py's own documented design:
    analyse the union of possible executions, not one concrete run), so a
    second same-named declaration must MERGE into the first rather than
    silently replacing it. Measured real case: Examples/BuildEditorAndTools.xml
    declares `<Label Name="Win64">` twice -- once unconditionally
    (`Category="Editors"`) and once inside a `<Do If="...GameTargetNodes...">`
    guarding a `Category="Target Platforms"` label whose `$(TargetPlatform)`
    also happens to be "Win64" by default. A plain dict-assign would let the
    second (here, incidentally empty) declaration silently truncate
    `Graph.labels["Win64"]`'s Requires down to nothing.
    """
    existing = bucket.setdefault(name, [])
    for token in tokens:
        if token not in existing:
            existing.append(token)


def _source_spec(attrs: dict[str, str]) -> str:
    """D5 evidence: the raw Files/FileLists value a producing task read
    from. `Files` takes priority (`FileLists` is unused anywhere in the
    19-file Epic corpus or the target assessment file, per a full-corpus
    grep -- but CONTRACTS.md names both, so an empty/absent Files falls
    back to FileLists rather than silently dropping it)."""
    return attrs.get("Files") or attrs.get("FileLists") or ""


def build(ev: EvalResult, schema: Schema) -> tuple[Graph, list[Finding]]:
    """Build the graph model + tag dataflow from `ev.resolved` (V23:
    post-Expand/ForEach/Include execution order) in one linear pass.

    A `<Node>` element's own `Resolved` entry always precedes every
    `Resolved` for elements inside its body (the evaluator emits the Node's
    own leaf entry, via `_emit_leaf`, before walking its children -- see
    `evaluator._handle_node`), so `nodes` always already holds the owning
    Node by the time a body element inside it is reached in this same pass.
    """
    nodes: dict[str, Node] = {}
    agents: dict[str, list[str]] = {}
    aggregates: dict[str, list[str]] = {}
    labels: dict[str, list[str]] = {}
    tag_provenance: dict[str, list[Contribution]] = {}

    for r in ev.resolved:
        tag = r.elem.tag

        if tag == "Agent":
            # Seed even a node-less agent -- an empty swimlane is still a
            # real (if unusual) agent, and resolve_ref's agent precedence
            # tier should find it (returning [], same as "not found" would,
            # but Graph.agents itself stays a complete/honest inventory).
            agents.setdefault(r.attrs.get("Name", ""), [])

        elif tag == "Aggregate":
            _merge_requires(aggregates, r.attrs.get("Name", ""), split_list(r.attrs.get("Requires", "")))

        elif tag == "Label":
            name = r.attrs.get("Name", "")
            if name:
                # Label/@Name is optional (Schema.xsd) -- a nameless label
                # can never be the target of a bare-name reference, so
                # there is nothing meaningful to key it under.
                _merge_requires(labels, name, split_list(r.attrs.get("Requires", "")))

        elif tag == "Node":
            node_name = r.attrs.get("Name", "")
            produces: set[str] = set()
            folded_seen: set[str] = set()
            _add_deduped(produces, folded_seen, "#" + node_name)  # V2/R7: implicit default output, added first
            for produced in split_list(r.attrs.get("Produces", "")):
                _add_deduped(produces, folded_seen, produced)

            requires = split_list(r.attrs.get("Requires", ""))
            after = split_list(r.attrs.get("After", ""))

            node = Node(
                name=node_name,
                agent=r.agent or "",
                line=r.elem.line,
                file=r.elem.file,
                produces=produces,
                creates=set(),
                consumes={token for token in requires if is_tag(token)},  # R23: Requires consumes its own #tags
                requires=requires,
                after=after,  # order-only (R23) -- deliberately NOT scanned for consumption
                end_line=r.elem.end_line,
            )
            # ponytail: ceiling = last-declaration-wins on a duplicate Node
            # Name (ForEach-substituted names are what keep real scripts
            # collision-free; a genuine duplicate is invalid input -- the
            # real engine requires unique node identities to schedule
            # builds at all -- unlike Aggregate/Label, which legitimately
            # reuse a display Name across mutually-exclusive branches, see
            # _merge_requires). Upgrade path: if a future corpus exercises
            # a real same-name-different-branch Node, merge produces/
            # requires/after here the same way _merge_requires does,
            # keyed on node_name, instead of overwriting outright.
            nodes[node_name] = node
            agents.setdefault(r.agent or "", []).append(node_name)

        elif r.node:
            # A task (or any other element -- Do/Switch/Case/ForEach
            # wrappers included, deliberately not filtered by tag name so
            # no per-task table ever creeps in here) inside a Node body.
            node = nodes[r.node]
            for attr, value in r.attrs.items():
                if schema.is_tag_output(tag, attr):
                    produced_tags = split_list(value)
                    if not produced_tags:
                        continue
                    contribution = Contribution(
                        source_spec=_source_spec(r.attrs),
                        filter=r.attrs.get("Filter", ""),
                        except_=r.attrs.get("Except", ""),
                        line=r.elem.line,
                    )
                    for produced_tag in produced_tags:
                        node.creates.add(produced_tag)
                        tag_provenance.setdefault(produced_tag, []).append(contribution)
                else:
                    for token in split_list(value):
                        if is_tag(token):
                            node.consumes.add(token)
        # else: outside any <Node> body entirely (top-level <Property>,
        # <Artifact>, ...) -- R2/R3's produce/consume rule is about a
        # node's OWN tag dataflow; nothing here to attribute it to.

    graph = Graph(
        nodes=nodes,
        agents=agents,
        aggregates=aggregates,
        labels=labels,
        tag_provenance=tag_provenance,
    )
    return graph, []


class UnknownTarget(Exception):
    """A `--target` name matched no node, aggregate, agent or tag."""


def closure(graph: "Graph", targets: list[str]) -> set[str]:
    """Node names reachable from `targets`, following Requires and After.

    Mirrors the engine's own `BgGraphDef.Select`, which retains a target's
    transitive dependencies and drops everything else. Resolution of each
    target token goes through `resolve_ref`, so a target may name a node, an
    aggregate, an agent or a tag (V2/R8).

    Raises UnknownTarget rather than returning an empty set -- V28: a typo'd
    target must not silently produce an empty graph that looks like success.
    """
    seen: set[str] = set()
    stack: list[str] = []
    for t in targets:
        resolved = graph.resolve_ref(t)
        if not resolved:
            raise UnknownTarget(t)
        stack.extend(resolved)
    while stack:
        name = stack.pop()
        if name in seen or name not in graph.nodes:
            continue
        seen.add(name)
        node = graph.nodes[name]
        for token in list(node.requires) + list(node.after):
            stack.extend(graph.resolve_ref(token))
    return seen


def prune_to_targets(graph: "Graph", findings: list, targets: list[str]):
    """Restrict `graph` and `findings` to the targets' transitive closure.

    Returns `(pruned_graph, kept_findings, suppressed_count)`.

    V28 forbids SILENT suppression: the caller must report `suppressed_count`.
    A hidden `warn` is worse than an unpruned graph, so findings that are not
    anchored to any node (file-level ones such as a dead <Option>) are always
    KEPT -- pruning removes graph scope, never whole classes of finding.
    """
    keep = closure(graph, targets)
    pruned = Graph(
        nodes={n: v for n, v in graph.nodes.items() if n in keep},
        agents={a: [n for n in ns if n in keep] for a, ns in graph.agents.items()},
        aggregates=dict(graph.aggregates),
        labels=dict(graph.labels),
        tag_provenance=dict(graph.tag_provenance),
    )
    pruned.agents = {a: ns for a, ns in pruned.agents.items() if ns}
    kept = [f for f in findings if not f.node or f.node in keep]
    return pruned, kept, len(findings) - len(kept)
