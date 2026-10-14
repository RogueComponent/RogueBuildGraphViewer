"""Tests for bgview.html (T13): the self-contained HTML report.

Required coverage per the task brief:

    1. XssEscapingTests          -- V8: a malicious node name/tag/finding
       message (`<script>alert(1)</script>` + `" onload="x`, an
       attribute-breakout attempt) never appears as its raw substring
       anywhere in the output; the html.escape'd form does.
    2. NoInnerHtmlOrInlineHandlersTests -- V8: no `innerHTML` anywhere in
       the generated file, no inline `on<event>=` handler attribute.
    3. NoNetworkReferencesTests   -- V17/§C: no `http://`/`https://`/
       `//cdn` reference anywhere except the SVG XML namespace URI, which
       is an identifier, not a fetch.
    4. TargetFileEndToEndTests    -- the full loader->evaluator->model->
       detectors->to_html pipeline on the real assessment target file:
       output is written, is well-formed/balanced markup, names both real
       agents, and carries exactly the 4 pinned warn+ findings
       (ACCEPTANCE.md §A: lines 48/59/61/77).
    5. ScaleTests                 -- ~500 nodes / ~20 agents: to_html
       completes promptly and every lane defaults to collapsed (§T13:
       "usable from ~10 nodes up to thousands").
    6. EdgeKindTests              -- the two edge kinds (Requires-derived
       "dataflow" vs After-derived "order") are distinguishable via
       distinct CSS classes in the markup, and a legend is present.

Fixtures are built two ways, deliberately kept to just two shapes (no
fixture sprawl):

  * `_hand_built_graph(...)` constructs `Graph`/`Node`/`Finding`/
    `EvalResult` objects directly (no XML involved at all) -- used for the
    XSS/innerHTML/network/edge-kind checks, which only care about what
    `to_html` does with arbitrary data, not about real BuildGraph parsing.
  * the real pipeline (`bgview.loader`/`evaluator`/`model`/`detectors`),
    reused verbatim from test_detectors.py's own `_run_pipeline` shape --
    used only for the end-to-end acceptance test, which specifically needs
    real findings at real lines.
"""

from __future__ import annotations

import functools
import html
import json
import os
import pathlib
import re
import sys
import tempfile
import time
import unittest
from html.parser import HTMLParser

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bgview.detectors import run_all
from bgview.evaluator import EvalResult, evaluate
from bgview.findings import Finding, Severity
from bgview.html import to_html
from bgview.loader import load
from bgview.model import Graph, Node, build
from bgview.schema import Schema

REAL_SCHEMA = pathlib.Path(r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph\Schema.xsd")
# A real-world BuildGraph script the end-to-end tests run against. It is not
# shipped with the repo: set BGVIEW_TARGET_SCRIPT to its path to run them.
TARGET_FILE = pathlib.Path(os.environ.get("BGVIEW_TARGET_SCRIPT", ""))

_EMPTY_EV = EvalResult(resolved=[], findings=[], options={}, prop_defs=[], prop_reads=[])


def _node(name, agent="Agent A", line=1, file=r"C:\fake\s.xml", produces=None, consumes=None, requires=None, after=None):
    return Node(
        name=name,
        agent=agent,
        line=line,
        file=file,
        produces=set(produces or set()),
        creates=set(),
        consumes=set(consumes or set()),
        requires=list(requires or []),
        after=list(after or []),
    )


def _render_to_tempfile(graph: Graph, findings: list[Finding], ev: EvalResult) -> str:
    with tempfile.TemporaryDirectory() as d:
        out = pathlib.Path(d) / "report.html"
        to_html(graph, findings, ev, str(out))
        assert out.is_file(), "to_html did not write the output file"
        return out.read_text(encoding="utf-8")


def _extract_payload(text: str) -> dict:
    m = re.search(r'<script type="application/json" id="bgview-data">(.*?)</script>', text, re.S)
    assert m is not None, "bgview-data JSON script block not found in output"
    return json.loads(m.group(1))


# ---------------------------------------------------------------------------
# small hand-built fixture -- two agents, one dataflow edge (Requires), one
# order-only edge (After). Reused by the innerHTML/network/edge-kind tests.
# ---------------------------------------------------------------------------


def _hand_built_graph():
    build_node = _node("Build", agent="Agent A", line=10, produces={"#Build", "#BuildOut"})
    test_node = _node("Test", agent="Agent B", line=20, consumes={"#BuildOut"}, requires=["#BuildOut"])
    package_node = _node("Package", agent="Agent B", line=30, produces={"#Package"}, after=["Test"])
    graph = Graph(
        nodes={"Build": build_node, "Test": test_node, "Package": package_node},
        agents={"Agent A": ["Build"], "Agent B": ["Test", "Package"]},
        aggregates={},
        labels={},
        tag_provenance={},
    )
    findings = [
        Finding(file=r"C:\fake\s.xml", line=20, severity=Severity.WARN, detector="D2", message="warn here", node="Test", tag="#BuildOut"),
        Finding(file=r"C:\fake\s.xml", line=10, severity=Severity.INFO, detector="D3", message="info here", node="Build", tag="#Build"),
    ]
    return graph, findings, _EMPTY_EV


# ---------------------------------------------------------------------------
# 1. V8 -- XSS escaping
# ---------------------------------------------------------------------------


class XssEscapingTests(unittest.TestCase):
    """A BuildGraph script is a file from another team's repo -- untrusted
    input. A malicious node/tag/finding-message string must render as
    inert text everywhere, never as markup or an attribute breakout."""

    PAYLOAD = '<script>alert(1)</script>" onload="x'

    def _render(self):
        node = _node(self.PAYLOAD, agent="Agent A", line=5, produces={"#" + self.PAYLOAD})
        graph = Graph(
            nodes={self.PAYLOAD: node},
            agents={"Agent A": [self.PAYLOAD]},
            aggregates={},
            labels={},
            tag_provenance={},
        )
        findings = [
            Finding(
                file=r"C:\fake\evil.xml",
                line=5,
                severity=Severity.WARN,
                detector="D2",
                message=self.PAYLOAD,
                node=self.PAYLOAD,
                tag="#" + self.PAYLOAD,
            )
        ]
        return _render_to_tempfile(graph, findings, _EMPTY_EV)

    def test_raw_script_tag_substring_never_appears(self):
        text = self._render()
        self.assertNotIn("<script>alert(1)</script>", text)

    def test_raw_attribute_breakout_substring_never_appears(self):
        text = self._render()
        # A literal `="` right after "onload" would break out of whatever
        # attribute it landed in -- html.escape(quote=True) turns the `"`
        # into `&quot;`, so this exact 3-char sequence must be gone.
        self.assertNotIn('onload="x', text)

    def test_escaped_form_is_present(self):
        text = self._render()
        self.assertIn(html.escape("<script>alert(1)</script>", quote=True), text)
        self.assertIn(html.escape(self.PAYLOAD, quote=True), text)

    def test_json_data_block_also_never_contains_the_raw_substring(self):
        # V17/script-breakout hardening: a `</script` substring inside the
        # JSON payload would prematurely close the <script> element
        # regardless of its type= attribute. Confirm the mitigation (\u003c
        # etc.) actually landed, by checking the isolated data block too,
        # not just the whole document.
        text = self._render()
        m = re.search(r'<script type="application/json" id="bgview-data">(.*?)</script>', text, re.S)
        self.assertIsNotNone(m)
        self.assertNotIn("<script>alert(1)</script>", m.group(1))
        self.assertNotIn("</script", m.group(1))
        # ... and it still round-trips to the original raw string via JSON.
        data = json.loads(m.group(1))
        self.assertEqual(data["nodes"][0]["name"], self.PAYLOAD)


# ---------------------------------------------------------------------------
# 2. V8 -- no innerHTML, no inline event handlers
# ---------------------------------------------------------------------------


class NoInnerHtmlOrInlineHandlersTests(unittest.TestCase):
    def test_no_innerhtml_outerhtml_or_documentwrite_anywhere(self):
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        self.assertNotIn("innerHTML", text)
        self.assertNotIn("outerHTML", text)
        self.assertNotIn("insertAdjacentHTML", text)
        self.assertNotIn("document.write", text)

    def test_no_inline_on_event_handler_attributes(self):
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        # Matches e.g. `onclick="..."` / `onload='...'` sitting inside a
        # tag (i.e. actually in attribute position, not incidental text).
        matches = re.findall(r"<[^>]*\son[a-zA-Z]+\s*=", text)
        self.assertEqual(matches, [])

    def test_all_event_wiring_uses_addeventlistener(self):
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        self.assertIn("addEventListener", text)


# ---------------------------------------------------------------------------
# 3. V17/§C -- zero network references
# ---------------------------------------------------------------------------


class NoNetworkReferencesTests(unittest.TestCase):
    def test_no_http_https_or_cdn_reference_except_svg_namespace(self):
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        urls = re.findall(r'(?:https?:)?//[^\s"\'<>]+', text)
        offenders = [u for u in urls if "www.w3.org/2000/svg" not in u]
        self.assertEqual(offenders, [], f"unexpected network-looking reference(s): {offenders}")
        self.assertIn("http://www.w3.org/2000/svg", text)  # the SVG xmlns IS expected

    def test_no_link_or_external_script_src_tags(self):
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        self.assertNotRegex(text, r"<link\b")
        self.assertNotRegex(text, r"<script[^>]+\bsrc=")


# ---------------------------------------------------------------------------
# 4. end-to-end on the real target file
# ---------------------------------------------------------------------------


class _TagBalanceParser(HTMLParser):
    """Confirms the document is well-formed, balanced markup (every open
    tag has a matching close, void elements excepted) -- a meaningfully
    strong "is this valid parseable HTML" check using only the stdlib.
    `HTMLParser` already special-cases <script>/<style> content as raw
    text (CDATA_CONTENT_ELEMENTS), so JS operators like `&&`/`<` inside
    the inline <script> do not confuse it."""

    _VOID = frozenset(
        {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
    )

    def __init__(self):
        super().__init__()
        self.stack: list[str] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag not in self._VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self._VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"</{tag}> does not match open stack {self.stack}")
            return
        self.stack.pop()


@functools.lru_cache(maxsize=None)
def _real_schema() -> Schema:
    assert REAL_SCHEMA.is_file(), f"fixture missing: {REAL_SCHEMA}"
    return Schema.from_file(REAL_SCHEMA)


@functools.lru_cache(maxsize=None)
def _target_pipeline():
    assert TARGET_FILE.is_file(), f"fixture missing: {TARGET_FILE}"
    schema = _real_schema()
    root = load(TARGET_FILE)
    ev = evaluate(root, schema, overrides={})
    graph, model_findings = build(ev, schema)
    det_findings = run_all(graph, ev, schema)
    findings = list(ev.findings) + list(model_findings) + list(det_findings)
    return graph, findings, ev


@functools.lru_cache(maxsize=None)
def _target_report_text() -> str:
    graph, findings, ev = _target_pipeline()
    return _render_to_tempfile(graph, findings, ev)


class TargetFileEndToEndTests(unittest.TestCase):
    def test_file_is_written_and_nonempty(self):
        text = _target_report_text()
        self.assertGreater(len(text), 0)

    def test_output_is_well_formed_balanced_markup(self):
        text = _target_report_text()
        parser = _TagBalanceParser()
        parser.feed(text)
        parser.close()
        self.assertEqual(parser.errors, [])
        self.assertEqual(parser.stack, [], f"unclosed tag(s) at end of document: {parser.stack}")

    def test_json_data_block_itself_is_valid_json(self):
        text = _target_report_text()
        data = _extract_payload(text)  # raises on invalid JSON
        self.assertIn("nodes", data)
        self.assertIn("findings", data)

    def test_contains_both_real_agent_names(self):
        text = _target_report_text()
        self.assertIn("Update Version Agent", text)
        self.assertIn("Compile Agent", text)

    def test_contains_all_four_pinned_warn_plus_findings(self):
        # ACCEPTANCE.md §A hard gate: exactly 4 findings at warn+, at
        # lines 48/59/61/77 -- verified here via the report's own emitted
        # JSON data (i.e. what actually reached the page), not just the
        # Python-side findings list that was fed into to_html.
        data = _extract_payload(_target_report_text())
        warn_plus_lines = sorted(f["line"] for f in data["findings"] if f["severity"] in ("warn", "error"))
        self.assertEqual(warn_plus_lines, [48, 59, 61, 77])

    def test_every_pinned_finding_line_appears_in_the_findings_panel_markup(self):
        """The row renders the location as `line N` in its own <span>.

        It used to render the full filename plus `:N`, which was what collapsed
        the panel at narrow widths: a nowrap filename consumed the whole row and
        squeezed the message to near-zero width, so it wrapped one character per
        line. The filename is redundant anyway -- the report covers one file and
        names it in the header -- and it survives as the span's title attribute.
        """
        text = _target_report_text()
        for line in (48, 59, 61, 77):
            self.assertIn(f">line {line}<", text, f"line {line} not found in a finding-loc span")

    def test_finding_row_can_shrink_without_collapsing(self):
        """Regression guard for the narrow-viewport collapse. The shrinkable
        column needs min-width:0 (a flex item otherwise refuses to go below its
        content size) and the badge must never wrap."""
        text = _target_report_text()
        self.assertIn(".finding-body", text)
        body_rule = text.split(".finding-body {", 1)[1].split("}", 1)[0]
        self.assertIn("min-width: 0", body_rule)
        badge_rule = text.split(".sev-badge {", 1)[1].split("}", 1)[0]
        self.assertIn("white-space: nowrap", badge_rule)
        self.assertIn("flex: 0 0 auto", badge_rule)

    def test_inspector_hides_scrollbar_chrome_but_stays_scrollable(self):
        """Requested: no visible scrollbar in the inspector. It must still
        scroll -- clipping a long produces/consumes list would lose findings
        off the bottom of the panel, which is worse than a scrollbar."""
        text = _target_report_text()
        rule = text.split("#inspector {", 1)[1].split("}", 1)[0]
        self.assertIn("overflow-y: auto", rule)
        self.assertNotIn("overflow-y: hidden", rule)
        self.assertIn("scrollbar-width: none", rule)
        self.assertIn("#inspector::-webkit-scrollbar", text)

    def test_inspector_text_adapts_to_the_panel_width(self):
        """Text scales off the inspector's own width via container queries, not
        the viewport -- the panel is itself clamp()ed, so vw units would drift
        out of step with it. Every fluid size is clamp()ed so it stays legible
        at the 240px floor and stops growing at the 340px ceiling."""
        text = _target_report_text()
        rule = text.split("#inspector {", 1)[1].split("}", 1)[0]
        self.assertIn("container-type: inline-size", rule)
        for sel in ("#insp-name", "#inspector li", "#insp-meta"):
            block = text.split(sel + " {", 1)[1].split("}", 1)[0]
            self.assertIn("cqi", block, f"{sel} should scale with the container")
            self.assertIn("clamp(", block, f"{sel} needs clamp bounds, not raw cqi")

    def test_inspector_never_overflows_horizontally(self):
        """A long tag name must wrap inside the panel rather than push it wide."""
        text = _target_report_text()
        block = text.split("#inspector li {", 1)[1].split("}", 1)[0]
        self.assertIn("overflow-wrap: anywhere", block)

    def test_narrow_viewports_stack_instead_of_crushing(self):
        text = _target_report_text()
        self.assertIn("@media (max-width: 900px)", text)
        narrow = text.split("@media (max-width: 900px) {", 1)[1]
        self.assertIn("flex-direction: column", narrow)


# ---------------------------------------------------------------------------
# 5. scale -- ~500 nodes / ~20 agents
# ---------------------------------------------------------------------------


def _big_graph(num_nodes=500, num_agents=20):
    agent_names = [f"Agent {i}" for i in range(num_agents)]
    agents: dict[str, list[str]] = {name: [] for name in agent_names}
    nodes: dict[str, Node] = {}
    for i in range(num_nodes):
        name = f"Node {i}"
        agent = agent_names[i % num_agents]
        # Every third node resets to no dependency; the others require
        # their immediate predecessor -- enough real (mostly cross-agent,
        # since consecutive indices round-robin across agents) edges to
        # exercise layout/edge rendering at scale without a fragile
        # hand-maintained global topology.
        requires = [f"Node {i - 1}"] if i > 0 and i % 3 != 0 else []
        nodes[name] = _node(name, agent=agent, line=i + 1, file=r"C:\fake\big.xml", produces={f"#{name}"}, requires=requires)
        agents[agent].append(name)
    graph = Graph(nodes=nodes, agents=agents, aggregates={}, labels={}, tag_provenance={})
    return graph, [], _EMPTY_EV


class BlueprintSplineTests(unittest.TestCase):
    """Edges are drawn with Unreal's own connection-spline formula, not an
    approximation of the look: FConnectionDrawingPolicy::ComputeSplineTangent
    with the Kismet graph defaults, converted Hermite -> cubic Bezier."""

    def test_edges_are_cubic_bezier_paths_not_straight_lines(self):
        text = _target_report_text()
        self.assertNotIn('<line id="edge-', text)
        edges = re.findall(r'<path id="edge-\d+"[^>]*\sd="([^"]+)"', text)
        self.assertTrue(edges, "no edge paths found")
        for d in edges:
            self.assertRegex(d, r"^M[\d.,-]+ C[\d.,-]+ [\d.,-]+ [\d.,-]+$", d)

    def test_tangent_matches_unreals_formula(self):
        from bgview.html import _spline_tangent

        # forward: min(|dx|,1000)*1.0 + min(|dy|,1000)*1.0
        self.assertAlmostEqual(_spline_tangent(100, 0), 100.0)
        self.assertAlmostEqual(_spline_tangent(100, 90), 190.0)
        self.assertAlmostEqual(_spline_tangent(5000, 0), 1000.0)   # clamped
        # backward: min(|dx|,200)*2.0 + min(|dy|,200)*1.5
        self.assertAlmostEqual(_spline_tangent(-100, 0), 200.0)
        self.assertAlmostEqual(_spline_tangent(-100, 100), 350.0)
        self.assertAlmostEqual(_spline_tangent(-5000, 5000), 200 * 2.0 + 200 * 1.5)

    def test_control_points_are_horizontal_from_each_pin(self):
        """Both of UE's tangent vectors are purely horizontal -- that flat
        entry/exit at the pin is what makes a Blueprint wire look like one."""
        from bgview.html import _spline_path

        d = _spline_path(0, 10, 200, 90)
        m = re.match(r"^M0\.0,10\.0 C([\d.]+),([\d.]+) ([\d.]+),([\d.]+) 200\.0,90\.0$", d)
        self.assertIsNotNone(m, d)
        self.assertEqual(float(m.group(2)), 10.0)   # leaves at the source's y
        self.assertEqual(float(m.group(4)), 90.0)   # arrives at the target's y

    def test_js_mirror_uses_the_same_constants_as_python(self):
        """The inline script re-runs this formula on lane collapse. If the two
        copies drift, edges snap to different curves after a toggle."""
        from bgview import html as H

        text = _target_report_text()
        js = text.split("function splineTangent(", 1)[1].split("}", 1)[0]
        for value in (H._SPLINE_FWD_RANGE, H._SPLINE_BACK_RANGE,
                      H._SPLINE_FWD_H, H._SPLINE_BACK_H, H._SPLINE_BACK_V):
            self.assertIn(str(value), js, f"{value} missing from the JS mirror")
        self.assertIn("function splinePath(", text)
        self.assertIn('setAttribute("d", splinePath(', text)


class PaintOrderTests(unittest.TestCase):
    def test_edges_are_inside_the_svg(self):
        """The obvious half, and the half the first version of this test
        missed: ordering was asserted with raw string indices, which stayed
        happily true when the edge layer was emitted AFTER </svg>. Outside the
        SVG the paths are not part of the drawing and render as nothing -- the
        graph came up with no wires at all and every ordering assertion still
        passed. Assert containment, not position."""
        text = _target_report_text()
        svg = text[text.index("<svg"): text.index("</svg>") + len("</svg>")]
        self.assertIn('<g id="edge-layer">', svg)
        self.assertEqual(len(re.findall(r'<path id="edge-\d+"', svg)),
                         len(_extract_payload(text)["edges"]),
                         "every edge must be drawn inside the svg")

    def test_edges_paint_on_top_of_lane_headers(self):
        """SVG has no z-index: painting order IS document order. With the edge
        layer emitted first, every lane-header-bg rect painted over any wire
        crossing it, so cross-lane connections vanished behind the header of
        the lane they passed through. Checked WITHIN the svg, so this can
        never again be satisfied by putting the layer outside it."""
        text = _target_report_text()
        svg = text[text.index("<svg"): text.index("</svg>") + len("</svg>")]
        self.assertGreater(
            svg.index('<g id="edge-layer">'), svg.rindex("lane-header-bg"),
            "edge-layer must come after every lane header to paint above it",
        )

    def test_every_edge_still_reachable_by_id_after_the_move(self):
        """relayout() looks edges up by id; document order must not matter."""
        text = _target_report_text()
        data = _extract_payload(text)
        for i in range(len(data["edges"])):
            self.assertIn(f'id="edge-{i}"', text)


def _lane_layout(xml_text: str):
    """Run a small script through the real pipeline and return
    (graph, lanes, node_pos)."""
    import tempfile

    from bgview.detectors import run_all
    from bgview.evaluator import evaluate
    from bgview.loader import load
    from bgview.model import build
    from bgview.schema import BUNDLED_FACTS, Schema
    from bgview import html as H

    schema = Schema.from_facts_file(BUNDLED_FACTS)
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "s.xml"
        p.write_text(xml_text, encoding="utf-8")
        ev = evaluate(load(p), schema, {})
        graph, _ = build(ev, schema)
    lanes, pos, _w = H._assign_positions(graph, set())
    return graph, lanes, pos


def _wires_through_boxes(graph, lanes, pos):
    """Every (from, to, blocked_box) where a drawn spline passes through a
    node box that is not one of its own endpoints.

    Samples the SAME cubic the renderer emits, so this measures the picture
    rather than a proxy for it."""
    from bgview import html as H

    def bez(p0, c1, c2, p1, t):
        u = 1 - t
        return (u * u * u * p0[0] + 3 * u * u * t * c1[0] + 3 * u * t * t * c2[0] + t * t * t * p1[0],
                u * u * u * p0[1] + 3 * u * u * t * c1[1] + 3 * u * t * t * c2[1] + t * t * t * p1[1])

    lane_y, y = {}, H._MARGIN_TOP
    for lane in lanes:
        lane_y[lane["index"]] = y
        y += H._LANE_HEADER_H + lane["rows"] * H._ROW_H + H._LANE_PAD

    def centre(p):
        return (p["x"], lane_y[p["lane"]] + H._LANE_HEADER_H + p["row"] * H._ROW_H)

    boxes = {}
    for name, p in pos.items():
        bx, by = centre(p)
        boxes[name] = (bx, by, bx + p["w"], by + H._NODE_H)

    hits = []
    for frm, to, _kind in H._build_edges(graph):
        a, b = pos[frm], pos[to]
        ax0, ay0 = centre(a)
        bx0, by0 = centre(b)
        ax, ay = ax0 + a["w"], ay0 + H._NODE_H / 2
        bx, by = bx0, by0 + H._NODE_H / 2
        t = H._spline_tangent(bx - ax, by - ay) / 3.0
        pts = ((ax, ay), (ax + t, ay), (bx - t, by), (bx, by))
        for i in range(1, 400):
            x, yy = bez(*pts, i / 400.0)
            blocked = [
                n for n, (x0, y0, x1, y1) in boxes.items()
                if n not in (frm, to) and x0 <= x <= x1 and y0 <= yy <= y1
            ]
            if blocked:
                hits.append((frm, to, blocked[0]))
                break
    return hits


_FAN = """<?xml version="1.0" encoding="utf-8"?>
<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">
\t<Agent Name="A" Type="Win64">
\t\t<Node Name="a" Produces="#a"><Log Message="a"/></Node>
\t\t<Node Name="b" Requires="#a" Produces="#b"><Log Message="b"/></Node>
\t\t<Node Name="c" Requires="#a;#b"><Log Message="c"/></Node>
\t\t<Node Name="e" Requires="#a;#b"><Log Message="e"/></Node>
\t\t<Node Name="d" Requires="#a"><Log Message="d"/></Node>
\t</Agent>
</BuildGraph>
"""


class RowAllocationTests(unittest.TestCase):
    """Rows come from the dependency structure, not from declaration order.

    The reported shape: `a` feeds `b`, `c`, `e`, `d`, and `c`/`e` are also
    behind `b`. All four dependents must land on their own rows, and no wire
    may run through a box.

    Measured across Epic's shipped graphs, this took in-lane wires that pass
    through a box from 6 to 2 (over 96 in-lane edges). The remaining 140 of
    the corpus's 142 are CROSS-lane and out of reach of any row policy --
    see the class docstring on CrossLaneHonestyTests."""

    def test_every_dependent_gets_its_own_row(self):
        graph, _lanes, pos = _lane_layout(_FAN)
        rows = [pos[n]["row"] for n in ("b", "c", "e", "d")]
        self.assertEqual(len(set(rows)), 4, f"b/c/e/d share rows: {rows}")

    def test_no_wire_runs_through_a_box(self):
        graph, lanes, pos = _lane_layout(_FAN)
        self.assertEqual(_wires_through_boxes(graph, lanes, pos), [])

    def test_a_parent_is_centred_on_its_dependents(self):
        """Centring is what makes a fan read as a fan. Asserted on a shape
        with no rank-skipping edge, because a reserved wire corridor
        outranks it -- see the next test."""
        xml = """<?xml version="1.0" encoding="utf-8"?>
<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">
\t<Agent Name="A" Type="Win64">
\t\t<Node Name="a" Produces="#a"><Log Message="a"/></Node>
\t\t<Node Name="b" Requires="#a" Produces="#b"><Log Message="b"/></Node>
\t\t<Node Name="c" Requires="#b"><Log Message="c"/></Node>
\t\t<Node Name="e" Requires="#b"><Log Message="e"/></Node>
\t</Agent>
</BuildGraph>
"""
        _graph, _lanes, pos = _lane_layout(xml)
        kids = [pos[n]["row"] for n in ("c", "e")]
        self.assertAlmostEqual(pos["b"]["row"], (min(kids) + max(kids)) / 2, places=6)

    def test_a_reserved_corridor_outranks_centring(self):
        """When a rank-skipping wire needs the row a centred parent wants,
        the BOX moves and the corridor stays. Getting this backwards is
        silent: the reservation is still made, just somewhere the wire does
        not go, and the box stays exactly where the wire crosses it. That is
        what the earlier single-sweep version did, and the only thing that
        caught it was measuring the picture."""
        graph, lanes, pos = _lane_layout(_FAN)
        kids = [pos[n]["row"] for n in ("c", "e")]
        self.assertNotAlmostEqual(pos["b"]["row"], (min(kids) + max(kids)) / 2, places=6)
        self.assertEqual(_wires_through_boxes(graph, lanes, pos), [])

    def test_two_nodes_at_one_rank_never_share_a_row(self):
        graph, _lanes, pos = _lane_layout(_FAN)
        seen = set()
        for name, p in pos.items():
            key = (p["lane"], p["col"], p["row"])
            self.assertNotIn(key, seen, f"{name} collides at {key}")
            seen.add(key)

    def test_siblings_are_ordered_by_requires_then_consumes(self):
        """Fewest Requires on top; ties broken by fewest Consumes; then, and
        only then, declaration order. The fixture declares them in exactly
        the wrong order so passing cannot be an accident."""
        xml = """<?xml version="1.0" encoding="utf-8"?>
<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">
\t<Agent Name="A" Type="Win64">
\t\t<Node Name="root" Produces="#root;#e1;#e2"><Tag Files="x.txt" With="#root;#e1;#e2"/></Node>
\t\t<Node Name="s1" Produces="#s1"><Log Message="s"/></Node>
\t\t<Node Name="three" Requires="#root;#s1;#e1"><Log Message="3"/></Node>
\t\t<Node Name="greedy" Requires="#root"><Tag Files="#e1;#e2" With="#g"/></Node>
\t\t<Node Name="plain" Requires="#root"><Log Message="p"/></Node>
\t</Agent>
</BuildGraph>
"""
        graph, _lanes, pos = _lane_layout(xml)
        rank1 = sorted(
            (n for n in graph.nodes if pos[n]["col"] == 1), key=lambda n: pos[n]["row"]
        )
        weights = [(len(graph.nodes[n].requires), len(graph.nodes[n].consumes)) for n in rank1]
        self.assertEqual(weights, sorted(weights), f"{rank1} -> {weights} is not least-entangled-first")
        self.assertLess(pos["plain"]["row"], pos["greedy"]["row"], "consumes tiebreak did not apply")

    def test_same_lane_consumption_outranks_total_consumption(self):
        """Between two siblings tied on Requires and on TOTAL Consumes, the
        one reading fewer tags produced in its OWN lane goes on top -- those
        are the only reads that become a wire drawn in this lane, and so the
        only ones the row allocation can do anything about. `reads_far` is
        declared first only to prove the order is not incidental."""
        xml = """<?xml version="1.0" encoding="utf-8"?>
<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">
\t<Agent Name="Other" Type="Win64">
\t\t<Node Name="far" Produces="#far1;#far2"><Tag Files="x.txt" With="#far1;#far2"/></Node>
\t</Agent>
\t<Agent Name="A" Type="Win64">
\t\t<Node Name="root" Produces="#root;#near1;#near2"><Tag Files="x.txt" With="#root;#near1;#near2"/></Node>
\t\t<Node Name="reads_far" Requires="#root"><Tag Files="#far1;#far2" With="#rf"/></Node>
\t\t<Node Name="reads_near" Requires="#root"><Tag Files="#near1;#near2" With="#rn"/></Node>
\t</Agent>
</BuildGraph>
"""
        graph, _lanes, pos = _lane_layout(xml)
        far, near = graph.nodes["reads_far"], graph.nodes["reads_near"]
        self.assertEqual(len(far.requires), len(near.requires), "fixture must tie on Requires")
        self.assertEqual(len(far.consumes), len(near.consumes), "fixture must tie on total Consumes")
        self.assertLess(pos["reads_far"]["row"], pos["reads_near"]["row"])

    def test_in_lane_counts_beat_global_counts_outright(self):
        """The ordering is (in-lane Requires, in-lane Consumes, global
        Requires, global Consumes) -- in-lane first, global only as a
        tiebreak.

        `global_heavy` has MORE global Requires than `local_heavy` (4 vs 3)
        but only one that lands in this lane, so it belongs on top: as far
        as this lane's picture is concerned it is the simpler node, and its
        other wires are drawn somewhere else entirely. A fixture where the
        two orderings agree could not tell the rules apart, so this one is
        built so they disagree, and declares `local_heavy` first."""
        xml = """<?xml version="1.0" encoding="utf-8"?>
<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">
\t<Agent Name="Other" Type="Win64">
\t\t<Node Name="f1" Produces="#f1"><Log Message="f"/></Node>
\t\t<Node Name="f2" Produces="#f2"><Log Message="f"/></Node>
\t\t<Node Name="f3" Produces="#f3"><Log Message="f"/></Node>
\t</Agent>
\t<Agent Name="A" Type="Win64">
\t\t<Node Name="root" Produces="#root;#loc1;#loc2"><Tag Files="x.txt" With="#root;#loc1;#loc2"/></Node>
\t\t<Node Name="local_heavy" Requires="#root;#loc1;#loc2"><Log Message="lh"/></Node>
\t\t<Node Name="global_heavy" Requires="#root;#f1;#f2;#f3"><Log Message="gh"/></Node>
\t</Agent>
</BuildGraph>
"""
        graph, _lanes, pos = _lane_layout(xml)
        lane = set(graph.agents["A"])
        local_req = {
            n: sum(1 for tok in graph.nodes[n].requires
                   if any(r in lane for r in graph.resolve_ref(tok)))
            for n in ("local_heavy", "global_heavy")
        }
        self.assertEqual(local_req, {"local_heavy": 3, "global_heavy": 1})
        self.assertGreater(
            len(graph.nodes["global_heavy"].requires),
            len(graph.nodes["local_heavy"].requires),
            "fixture must have the global order DISAGREE with the in-lane one",
        )
        self.assertLess(
            pos["global_heavy"]["row"], pos["local_heavy"]["row"],
            "global counts overrode the in-lane ones",
        )

    def test_the_longest_reach_wins_a_tie(self):
        """Last ordering term: when two nodes are equally simple by all four
        counts, the one whose furthest dependent is more columns away goes on
        top. A wire that skips columns is the one most likely to cross
        something -- everything between its ends is in its way -- so running
        it along the lane's top edge keeps it clear.

        Modelled on `Examples/BuildEditorAndTools.xml`, where
        `Update Version Files` and `Compile UnrealEditor Win64` are both
        0/0/0/0 and only their reach (1 column vs 2) separates them. `near`
        is declared first so declaration order would give the other answer."""
        xml = """<?xml version="1.0" encoding="utf-8"?>
<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">
\t<Agent Name="A" Type="Win64">
\t\t<Node Name="near" Produces="#near"><Log Message="n"/></Node>
\t\t<Node Name="far" Produces="#far"><Log Message="f"/></Node>
\t\t<Node Name="mid" Requires="#near" Produces="#mid"><Log Message="m"/></Node>
\t\t<Node Name="sink" Requires="#far;#mid"><Log Message="s"/></Node>
\t</Agent>
</BuildGraph>
"""
        graph, _lanes, pos = _lane_layout(xml)
        for n in ("near", "far"):
            self.assertEqual(len(graph.nodes[n].requires), 0, "fixture must tie on Requires")
            self.assertEqual(len(graph.nodes[n].consumes), 0, "fixture must tie on Consumes")
        self.assertEqual(pos["near"]["col"], pos["far"]["col"], "fixture must put both at one rank")
        # `far` reaches `sink` two columns away; `near` reaches `mid`, one.
        self.assertEqual(pos["sink"]["col"] - pos["far"]["col"], 2)
        self.assertEqual(pos["mid"]["col"] - pos["near"]["col"], 1)
        self.assertLess(pos["far"]["row"], pos["near"]["row"])

    def test_a_dependency_cycle_does_not_hang_the_layout(self):
        """No §V row claims to detect a cycle; this only asserts the renderer
        survives one, same guarantee `_compute_ranks` gives."""
        xml = """<?xml version="1.0" encoding="utf-8"?>
<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">
\t<Agent Name="A" Type="Win64">
\t\t<Node Name="x" Requires="y" Produces="#x"><Log Message="x"/></Node>
\t\t<Node Name="y" Requires="x" Produces="#y"><Log Message="y"/></Node>
\t</Agent>
</BuildGraph>
"""
        graph, _lanes, pos = _lane_layout(xml)
        self.assertEqual(len(pos), 2)
        for p in pos.values():
            self.assertIsInstance(p["row"], float)


class CorpusCrossingTests(unittest.TestCase):
    """The property, measured on real graphs rather than on a fixture.

    NO in-lane wire may pass through a box it does not belong to, across
    every graph Epic ships. This started at 6 (over 96 in-lane edges) and
    the whole row-allocation change exists to drive it to 0 -- so assert 0,
    not "fewer than before", which would quietly accept a regression back
    to 5."""

    CORPUS_ROOT = pathlib.Path(r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph")

    def _corpus(self):
        files = []
        for sub in ("Examples", "Examples/FPSBuildGraph", "Tests"):
            d = self.CORPUS_ROOT / sub
            if d.is_dir():
                files.extend(sorted(d.glob("*.xml")))
        return files

    def test_no_in_lane_wire_passes_through_a_box_anywhere_in_the_corpus(self):
        from bgview.evaluator import evaluate
        from bgview.loader import load
        from bgview.model import build
        from bgview.schema import BUNDLED_FACTS, Schema
        from bgview import html as H

        files = self._corpus()
        if not files:
            self.skipTest(f"corpus not present at {self.CORPUS_ROOT}")
        schema = Schema.from_facts_file(BUNDLED_FACTS)

        offenders, in_lane_edges = [], 0
        for f in files:
            ev = evaluate(load(f), schema, {})
            graph, _ = build(ev, schema)
            lanes, pos, _w = H._assign_positions(graph, set())
            in_lane_edges += sum(
                1 for a, b, _k in H._build_edges(graph) if pos[a]["lane"] == pos[b]["lane"]
            )
            for frm, to, blocker in _wires_through_boxes(graph, lanes, pos):
                if pos[frm]["lane"] == pos[to]["lane"]:
                    offenders.append(f"{f.name}: {frm} -> {to} crosses {blocker}")
        self.assertGreater(in_lane_edges, 50, "corpus should exercise plenty of in-lane edges")
        self.assertEqual(offenders, [], "\n".join(offenders))


class CrossLaneHonestyTests(unittest.TestCase):
    """What the row policy does NOT fix, asserted so nobody re-measures it.

    Lanes are stacked vertically, so a wire from the first lane to the
    fortieth must cross every lane in between and whatever boxes are there.
    `_assign_rows` only ever sees ONE lane's nodes, so it cannot help. On
    Epic's `BuildWorldPartitionHLODs.xml` -- 105 nodes across 53 agent lanes
    -- 153 of 204 edges are cross-lane and account for 136 of its crossings,
    unchanged by any of this. Fixing that means changing the swimlane layout
    itself, not the rows inside a lane."""

    def test_assign_rows_only_considers_nodes_in_its_own_lane(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">
\t<Agent Name="A" Type="Win64">
\t\t<Node Name="up" Produces="#up"><Log Message="u"/></Node>
\t</Agent>
\t<Agent Name="B" Type="Win64">
\t\t<Node Name="down" Requires="#up"><Log Message="d"/></Node>
\t</Agent>
</BuildGraph>
"""
        graph, lanes, pos = _lane_layout(xml)
        self.assertEqual(len(lanes), 2)
        self.assertNotEqual(pos["up"]["lane"], pos["down"]["lane"])
        # Each lane is laid out on its own, so both sit at the top of theirs.
        self.assertEqual(pos["up"]["row"], 0.0)
        self.assertEqual(pos["down"]["row"], 0.0)


class SpacingTests(unittest.TestCase):
    """Boxes are sized to their own labels now, so there is no single node
    width to compare a column stride against. These assert the property that
    actually mattered -- boxes never collide, wires have room -- against the
    real packed geometry rather than against two constants."""

    def test_rows_are_spaced_clear_of_the_box(self):
        from bgview import html as H

        self.assertGreater(H._ROW_H, H._NODE_H + 24, "rows too tight")

    def test_no_two_boxes_can_overlap_and_every_wire_has_room(self):
        graph, findings, ev = _big_graph(120, 6)
        data = _extract_payload(_render_to_tempfile(graph, findings, ev))

        # Column packing is GLOBAL: one x per column shared by every lane, so
        # a column still lines up across lanes -- that alignment is the
        # "same rank, therefore parallel" signal the layout exists to show.
        by_col: dict[int, set[int]] = {}
        for n in data["nodes"]:
            by_col.setdefault(n["col"], set()).add(n["x"])
        for col, xs in by_col.items():
            self.assertEqual(len(xs), 1, f"column {col} was placed at more than one x")

        right_edge: dict[int, int] = {}
        for n in data["nodes"]:
            right_edge[n["col"]] = max(right_edge.get(n["col"], 0), n["x"] + n["w"])
        cols = sorted(by_col)
        for prev, nxt in zip(cols, cols[1:]):
            gap = next(iter(by_col[nxt])) - right_edge[prev]
            self.assertGreaterEqual(
                gap, 60, f"only {gap}px between column {prev}'s widest box and column {nxt}"
            )

    def test_a_box_is_at_least_as_wide_as_its_own_label(self):
        from bgview import html as H

        for name in ("x", "Compile", "Compile UnrealEditor Win64", "z" * 40):
            w = H._node_width(name, False)
            self.assertGreaterEqual(w, H._NODE_MIN_W)
            self.assertLessEqual(w, H._NODE_MAX_W)
            needed = len(name) * H._NODE_CHAR_W + H._NODE_PAD_X * 2
            if needed <= H._NODE_MAX_W:
                self.assertGreaterEqual(w + 1, needed, f"{name!r} does not fit its own box")

    def test_a_longer_name_gets_a_wider_box(self):
        from bgview import html as H

        short = H._node_width("Compile", False)
        longer = H._node_width("Compile UnrealEditor Win64 Shipping", False)
        self.assertGreater(longer, short)

    def test_a_warn_badge_does_not_sit_on_top_of_the_name(self):
        """The badge is drawn inside the box's top-right corner, so without
        reserved room it covers the tail of the name on exactly the nodes a
        reader most needs to identify."""
        from bgview import html as H

        name = "Compile UnrealEditor Win64"
        self.assertGreaterEqual(
            H._node_width(name, True) - H._node_width(name, False), H._NODE_BADGE_W - 1
        )


class ScaleTests(unittest.TestCase):
    def test_five_hundred_nodes_twenty_agents_completes_and_collapses_by_default(self):
        graph, findings, ev = _big_graph(500, 20)
        start = time.time()
        text = _render_to_tempfile(graph, findings, ev)
        elapsed = time.time() - start
        self.assertLess(elapsed, 15.0, f"to_html took {elapsed:.2f}s on a 500-node graph -- too slow")

        data = _extract_payload(text)
        self.assertEqual(len(data["nodes"]), 500)
        self.assertEqual(len(data["lanes"]), 20)
        self.assertTrue(
            all(lane["collapsedDefault"] for lane in data["lanes"]),
            "large graph must default every lane to collapsed (\u00a7T13)",
        )


# ---------------------------------------------------------------------------
# 6. two edge kinds distinguishable + legend present
# ---------------------------------------------------------------------------


class EdgeKindTests(unittest.TestCase):
    def test_dataflow_and_order_edges_use_distinct_css_classes(self):
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        # _hand_built_graph has exactly one Requires-derived edge (Build ->
        # Test, via #BuildOut) and one After-derived edge (Test -> Package).
        self.assertIn('class="edge edge-dataflow"', text)
        self.assertIn('class="edge edge-order"', text)
        # And they are genuinely styled differently, not just labelled
        # differently -- distinct colour/dash CSS rules exist for each.
        self.assertIn(".edge-dataflow {", text)
        self.assertIn(".edge-order {", text)

    def test_legend_present_and_names_both_kinds(self):
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        self.assertIn('id="legend"', text)
        # T40: the legend moved into #report-header and gained per-tab groups,
        # so it is no longer a flat <div>...</div>. Scope to the graph group,
        # which is what names the edge kinds.
        legend = re.search(r'<span class="legend-group" id="legend-graph".*?</span>\s*<span class="legend-group" id="legend-source"',
                           text, re.S).group(0)
        self.assertIn("Dataflow", legend)
        self.assertIn("Order only", legend)

    def test_legend_lives_in_the_header_not_in_the_graph_pane(self):
        """T40. Parked inside `#graph-area` the legend was hidden wholesale
        whenever the Source tab came up -- exactly when a key for the gutter
        marks is needed. It has to sit somewhere that never gets hidden."""
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        header = re.search(r'<header id="report-header">(.*?)</header>', text, re.S).group(1)
        self.assertIn('id="legend"', header)
        graph_area = re.search(r'<main id="graph-area".*?</main>', text, re.S).group(0)
        self.assertNotIn('id="legend"', graph_area)

    def test_graph_legend_shows_first_and_source_legend_is_hidden(self):
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        graph_group = re.search(r'<span class="legend-group" id="legend-graph"[^>]*>', text).group(0)
        source_group = re.search(r'<span class="legend-group" id="legend-source"[^>]*>', text).group(0)
        # First paint is the Graph tab, so its key is up and the other is not.
        self.assertNotIn("hidden", graph_group)
        self.assertIn('hidden="hidden"', source_group)

    def test_setTab_toggles_the_two_legend_groups(self):
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        set_tab = re.search(r'function setTab\(name\) \{(.*?)\n  \}', text, re.S).group(1)
        self.assertIn('document.getElementById("legend-" + t)', set_tab)
        self.assertIn("group.hidden = t !== name", set_tab)

    def test_header_carries_no_severity_counts(self):
        """The findings panel's All / Warn+ / Info chips already count them.
        A second tally in the header is the same number in two places, free to
        disagree -- and after a severity filter one of them is always wrong."""
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        header = re.search(r'<header id="report-header">(.*?)</header>', text, re.S).group(1)
        self.assertNotIn("sev-badge", header)
        self.assertNotRegex(header, r"\d+\s+(error|warn|info)")
        # the counts are still available where they belong
        panel = re.search(r'id="findings-panel".*?</aside>', text, re.S)
        self.assertIsNotNone(panel, "findings panel missing")

    def test_source_legend_carries_the_severity_colour_key(self):
        """T35 stashes the findings panel on the Source tab, so the severity
        badges in the findings list are off screen exactly when the gutter
        tints need explaining. The mapping rides inside the finding item as
        three tinted words -- a key, not a count."""
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        source_group = re.search(
            r'<span class="legend-group" id="legend-source".*?\n\s*</span>', text, re.S).group(0)
        for word in ("error", "warn", "info"):
            self.assertIn(f'<span class="legend-sev sev-{word}">{word}</span>', source_group)
        # named, never counted
        self.assertNotRegex(source_group, r"\d+\s+(error|warn|info)")
        self.assertIn("Selected", source_group)

    def test_severity_key_mirrors_the_gutter_dot_not_a_badge(self):
        """A filled badge is what the removed counts looked like; the gutter
        mark is a dot in the severity colour, so the key wears the same dot."""
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        self.assertIn('.legend-sev::before { content: "\\25CF"', text)
        for word in ("error", "warn", "info"):
            self.assertIn(f".legend-sev.sev-{word} {{ color: var(--{word}); }}", text)

    def test_graph_legend_needs_no_severity_key(self):
        """Its one severity-coloured thing -- the warn+ node border -- is
        named outright, so repeating the key there would be noise."""
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        graph_group = re.search(
            r'<span class="legend-group" id="legend-graph".*?\n\s*</span>', text, re.S).group(0)
        self.assertNotIn("legend-sev", graph_group)
        self.assertIn("warn+ finding", graph_group)

    def test_legend_group_hidden_rule_beats_the_display_rule(self):
        """`.legend-group` sets a display value, and `[hidden]` only wins if
        something restores display:none. Without the explicit rule the
        "hidden" group stays visible and both keys show at once."""
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        self.assertIn(".legend-group[hidden] { display: none; }", text)

    def test_node_state_swatches_mirror_a_stroke_not_a_dot(self):
        """On the canvas what varies is the node's STROKE. The old swatch was
        a filled circle, which matched nothing actually drawn -- and ochre is
        shared by `--edge-order` and `--warn`, so a shapeless amber blob was
        actively ambiguous."""
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        self.assertIn(".legend-node-warn { border-color: var(--warn); }", text)
        self.assertNotIn("legend-warn-dot", text)

    def test_payload_edges_carry_the_correct_kind(self):
        graph, findings, ev = _hand_built_graph()
        text = _render_to_tempfile(graph, findings, ev)
        data = _extract_payload(text)
        kinds_by_pair = {(e["from"], e["to"]): e["kind"] for e in data["edges"]}
        self.assertEqual(kinds_by_pair.get(("n0", "n1")), "dataflow")  # Build -> Test
        self.assertEqual(kinds_by_pair.get(("n1", "n2")), "order")  # Test -> Package


if __name__ == "__main__":
    unittest.main()
