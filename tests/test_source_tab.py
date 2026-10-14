"""Tests for the XML source tab, and for the viewport controls beside it.

Two lessons from this codebase are load-bearing in how these are written:

  1. **Assert the property that makes it visible, not a proxy for it.** An
     earlier test here asserted the SVG edge layer came "after the last lane
     header" by comparing raw string indices; it passed while the edge layer
     sat OUTSIDE the `<svg>` entirely and the graph drew zero wires. So the
     source-tab tests assert CONTAINMENT (`#source-area` really encloses the
     `.src-line` rows) and CONTENT (the rows really carry the script's text
     at the right line numbers), never mere ordering.
  2. **Run it in a real browser before believing it works.** These tests
     cannot click anything, so they deliberately do not pretend to: they
     assert the wiring EXISTS and that the data it needs is present and
     correct. The behavioural pass -- double-click, wheel-zoom, right-drag
     pan, drag-resize -- was verified by driving the generated report in
     headless Chrome, which is where the `Fit` rounding bug was actually
     caught.

Coverage, in the order the classes appear:

    SourceRangeTests        -- loader.Elem.end_line / model.Node.end_line:
                               every element gets a range, `end >= start`,
                               and the target file's real node ranges match.
    SourceCaptureTests      -- EvalResult.sources holds the exact analysed
                               text, includes and all, and is never re-read
                               from disk.
    LineNumberingTests      -- display lines are numbered exactly as expat
                               numbered them (CRLF, lone CR, and the form
                               feed that `str.splitlines()` would break on).
    SourceTabMarkupTests    -- the tab exists, contains the real source, and
                               marks findings in the gutter by severity.
    SourceTabXssTests       -- V8: a payload in a node NAME and a payload in
                               the SOURCE BODY both render inert.
    ViewportControlTests    -- zoom/pan/resize/hide wiring, and the Unreal
                               zoom table reproduced stop for stop.
    NoRegressionTests       -- V8/V17/V38 still hold with source embedded.
"""

from __future__ import annotations

import html as html_mod
import json
import os
import pathlib
import re
import sys
import tempfile
import unittest
from html.parser import HTMLParser

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bgview import html as bghtml
from bgview.detectors import run_all
from bgview.evaluator import evaluate
from bgview.findings import Finding, Severity
from bgview.html import render_html
from bgview.loader import load
from bgview.model import build
from bgview.schema import Schema

# A real-world BuildGraph script the end-to-end tests run against. It is not
# shipped with the repo: set BGVIEW_TARGET_SCRIPT to its path to run them.
TARGET_FILE = pathlib.Path(os.environ.get("BGVIEW_TARGET_SCRIPT", ""))

# Node ranges measured off the target file. `Update Version Files` is the
# smallest, `Stage for Submission` the longest and the one with findings
# inside it -- the two the handoff brief calls out for the highlight.
EXPECTED_SPANS = {
    "Update Version Files": (27, 29),
    "Compile Tools Win64": (33, 41),
    "Compile UnrealEditor Win64": (43, 45),
    "Tag Output Files": (47, 49),
    "Copy To Staging Directory": (51, 54),
    "Store Symbols": (56, 62),
    "Stage for Submission": (67, 85),
    "Submit To Perforce": (87, 95),
}


def _bundled() -> pathlib.Path:
    from bgview.schema import BUNDLED_FACTS

    return BUNDLED_FACTS


def _pipeline(path: pathlib.Path):
    schema = Schema.from_facts_file(_bundled())
    root = load(path)
    ev = evaluate(root, schema, {})
    graph, model_findings = build(ev, schema)
    findings = list(ev.findings) + list(model_findings) + list(run_all(graph, ev, schema))
    findings.sort(key=lambda f: (f.file, f.line))
    return root, ev, graph, findings


def _render(path: pathlib.Path) -> str:
    _root, ev, graph, findings = _pipeline(path)
    return render_html(graph, findings, ev)


class _Collector(HTMLParser):
    """Records, for every element, its tag/attrs plus the id of the nearest
    enclosing ancestor that had one -- enough to assert real CONTAINMENT
    rather than document-order proximity."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, str | None]] = []
        self.rows: list[dict] = []
        self._text_target: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        ancestor_id = next((i for _t, i in reversed(self.stack) if i), None)
        self.rows.append({"tag": tag, "attrs": a, "under": ancestor_id, "text": []})
        self._text_target = self.rows[-1]["text"]
        if tag not in ("br", "img", "input", "meta", "link"):
            self.stack.append((tag, a.get("id")))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break
        self._text_target = None

    def handle_data(self, data):
        if self._text_target is not None:
            self._text_target.append(data)

    def ancestor_ids_of(self, predicate) -> set[str | None]:
        return {r["under"] for r in self.rows if predicate(r)}


def _parse(doc: str) -> _Collector:
    c = _Collector()
    c.feed(doc)
    return c


def _script_body(doc: str) -> str:
    """Just the inline behaviour script -- NOT the JSON payload and NOT the
    embedded source text. Assertions about what the CODE does must not be
    satisfiable (or broken) by a string that happens to sit in the analysed
    .xml file."""
    blocks = re.findall(r"<script>(.*?)</script>", doc, re.S)
    assert blocks, "no inline script found"
    return max(blocks, key=len)


# ---------------------------------------------------------------------------


class SourceRangeTests(unittest.TestCase):
    def test_every_element_gets_an_end_line_and_it_never_precedes_the_start(self):
        root = load(TARGET_FILE)
        elems = list(root.iter())
        self.assertGreater(len(elems), 20)
        for e in elems:
            self.assertGreater(e.end_line, 0, f"<{e.tag}> at line {e.line} has no end_line")
            self.assertGreaterEqual(
                e.end_line, e.line, f"<{e.tag}> ends at {e.end_line} before it starts at {e.line}"
            )
            self.assertEqual(e.line_span, (e.line, e.end_line))

    def test_a_self_closing_element_starts_and_ends_on_its_own_line(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "s.xml"
            p.write_text(
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">\n'
                '\t<Option Name="A" DefaultValue="x"/>\n'
                "</BuildGraph>\n",
                encoding="utf-8",
            )
            root = load(p)
            opt = next(e for e in root.iter() if e.tag == "Option")
            self.assertEqual(opt.line_span, (3, 3))

    def test_node_end_line_is_threaded_into_the_model(self):
        _root, _ev, graph, _f = _pipeline(TARGET_FILE)
        actual = {name: node.line_span for name, node in graph.nodes.items()}
        self.assertEqual(actual, EXPECTED_SPANS)

    def test_line_span_survives_a_node_that_never_learned_its_end(self):
        """A hand-built Node (tests, and any future non-loader producer)
        leaves end_line at 0. That must read as a one-line range, not as a
        range ending before it begins."""
        from bgview.model import Node

        n = Node(
            name="n", agent="a", line=7, file="f.xml",
            produces=set(), creates=set(), consumes=set(), requires=[], after=[],
        )
        self.assertEqual(n.end_line, 0)
        self.assertEqual(n.line_span, (7, 7))


class SourceCaptureTests(unittest.TestCase):
    def test_sources_holds_the_analysed_text_verbatim(self):
        _root, ev, _g, _f = _pipeline(TARGET_FILE)
        self.assertEqual(list(ev.sources), [str(TARGET_FILE.resolve())])
        on_disk = TARGET_FILE.read_bytes().decode("utf-8-sig")
        self.assertEqual(ev.sources[str(TARGET_FILE.resolve())], on_disk)

    def test_included_files_are_captured_too(self):
        with tempfile.TemporaryDirectory() as d:
            root_dir = pathlib.Path(d)
            (root_dir / "inc.xml").write_text(
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">\n'
                '\t<Agent Name="B" Type="Win64"><Node Name="Included Node"/></Agent>\n'
                "</BuildGraph>\n",
                encoding="utf-8",
            )
            main = root_dir / "main.xml"
            main.write_text(
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">\n'
                '\t<Include Script="inc.xml"/>\n'
                '\t<Agent Name="A" Type="Win64"><Node Name="Main Node"/></Agent>\n'
                "</BuildGraph>\n",
                encoding="utf-8",
            )
            _root, ev, graph, findings = _pipeline(main)
            self.assertEqual(len(ev.sources), 2, "entry script + include")
            self.assertIn("Included Node", ev.sources[str((root_dir / "inc.xml").resolve())])

            doc = render_html(graph, findings, ev)
            payload = json.loads(
                re.search(r'id="bgview-data">(.*?)</script>', doc, re.S).group(1)
                .replace("\\u003c", "<").replace("\\u003e", ">").replace("\\u0026", "&")
            )
            self.assertEqual(len(payload["sources"]), 2)
            # The node declared in the INCLUDE must point at the include's
            # own source index, not at the entry script's.
            by_name = {n["name"]: n for n in payload["nodes"]}
            self.assertNotEqual(by_name["Main Node"]["src"], by_name["Included Node"]["src"])
            # ...and a picker must exist to reach it.
            self.assertIn('id="source-file-select"', doc)
            self.assertEqual(doc.count("<option value="), 2)


class LineNumberingTests(unittest.TestCase):
    """`_split_source_lines` must number lines exactly as expat did: XML
    folds CRLF and lone CR to one break and treats NOTHING else as one."""

    def test_crlf_counts_as_one_line_break(self):
        self.assertEqual(bghtml._split_source_lines("a\r\nb\r\nc"), ["a", "b", "c"])

    def test_lone_cr_counts_as_one_line_break(self):
        self.assertEqual(bghtml._split_source_lines("a\rb\rc"), ["a", "b", "c"])

    def test_a_trailing_newline_does_not_invent_a_final_line(self):
        self.assertEqual(bghtml._split_source_lines("a\nb\n"), ["a", "b"])

    def test_form_feed_is_not_a_line_break(self):
        """The bug this exists to prevent: `str.splitlines()` breaks on \\x0c
        (and \\x0b, \\u2028, \\u0085) while XML does not, so one form feed in
        a comment would shift every line below it by one and point every
        highlight at the wrong place."""
        text = "a\n\x0cstill line 2\nc"
        self.assertEqual(len(text.splitlines()), 4, "precondition: splitlines would over-count")
        self.assertEqual(bghtml._split_source_lines(text), ["a", "\x0cstill line 2", "c"])

    def test_rendered_line_count_matches_the_file(self):
        doc = _render(TARGET_FILE)
        expected = len(bghtml._split_source_lines(TARGET_FILE.read_text(encoding="utf-8-sig")))
        self.assertEqual(doc.count('<div class="src-line'), expected)
        self.assertEqual(expected, 98, "the target file is 98 lines")


class SourceTabMarkupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = _render(TARGET_FILE)
        cls.parsed = _parse(cls.doc)
        cls.raw = TARGET_FILE.read_text(encoding="utf-8-sig")
        cls.lines = bghtml._split_source_lines(cls.raw)

    def test_there_is_a_tab_strip_with_both_tabs(self):
        ids = {r["attrs"].get("id") for r in self.parsed.rows}
        self.assertIn("tab-btn-graph", ids)
        self.assertIn("tab-btn-source", ids)
        graph_tab = next(r for r in self.parsed.rows if r["attrs"].get("id") == "tab-btn-graph")
        source_tab = next(r for r in self.parsed.rows if r["attrs"].get("id") == "tab-btn-source")
        self.assertEqual(graph_tab["attrs"].get("role"), "tab")
        self.assertEqual(graph_tab["attrs"].get("aria-selected"), "true", "graph is the initial view")
        self.assertEqual(source_tab["attrs"].get("aria-selected"), "false")

    def test_source_lines_are_CONTAINED_by_the_source_panel(self):
        """Containment, not ordering. The lesson from the edge-layer bug: a
        row that merely appears after `<section id="source-area">` in the
        byte stream can still be outside it."""
        parents = self.parsed.ancestor_ids_of(lambda r: "src-line" in r["attrs"].get("class", ""))
        self.assertEqual(parents - {None}, {"srcfile-0"}, "every source row sits inside a .src-file")
        file_parents = self.parsed.ancestor_ids_of(lambda r: r["attrs"].get("id") == "srcfile-0")
        self.assertEqual(file_parents, {"source-area"}, "the file wrapper sits inside #source-area")

    def test_the_source_panel_holds_the_REAL_text_at_the_RIGHT_line_numbers(self):
        """Content, not just presence -- and checked per line id, so an
        off-by-one in the numbering cannot slip through."""
        for number in (1, 27, 43, 48, 85, 98):
            row = re.search(
                r'<div class="src-line[^"]*" id="s0-%d">.*?<code class="src-text">(.*?)</code>' % number,
                self.doc,
                re.S,
            )
            self.assertIsNotNone(row, f"no source row for line {number}")
            self.assertEqual(html_mod.unescape(row.group(1)), self.lines[number - 1])

    def test_node_ranges_reach_the_client_as_data(self):
        payload = json.loads(
            re.search(r'id="bgview-data">(.*?)</script>', self.doc, re.S).group(1)
            .replace("\\u003c", "<").replace("\\u003e", ">").replace("\\u0026", "&")
        )
        by_name = {n["name"]: (n["line"], n["endLine"]) for n in payload["nodes"]}
        self.assertEqual(by_name, EXPECTED_SPANS)
        for n in payload["nodes"]:
            self.assertEqual(n["src"], 0, "single-file script: every node points at source 0")

    def test_findings_are_marked_in_the_gutter_at_their_own_lines(self):
        _root, _ev, _g, findings = _pipeline(TARGET_FILE)
        warn_lines = {f.line for f in findings if f.severity >= Severity.WARN}
        self.assertEqual(warn_lines, {48, 59, 61, 77}, "ACCEPTANCE.md's pinned warn+ set")
        for line in warn_lines:
            self.assertRegex(self.doc, r'<div class="src-line src-sev-warn" id="s0-%d">' % line)
        # A line carrying BOTH an info and a warn must read as the warn:
        # line 48 has D1 (warn) and D10 (info).
        self.assertNotIn('class="src-line src-sev-info" id="s0-48"', self.doc)

    def test_every_finding_can_be_resolved_to_a_source_line(self):
        payload = json.loads(
            re.search(r'id="bgview-data">(.*?)</script>', self.doc, re.S).group(1)
            .replace("\\u003c", "<").replace("\\u003e", ">").replace("\\u0026", "&")
        )
        for f in payload["findings"]:
            self.assertEqual(f["src"], 0)
            self.assertRegex(self.doc, r'id="s0-%d"' % f["line"])

    def test_the_interaction_wiring_exists(self):
        js = _script_body(self.doc)
        self.assertIn('addEventListener("dblclick"', js)
        self.assertIn("revealNodeSource", js)
        self.assertIn("revealFindingSource", js)
        self.assertIn('"s" + srcIndex + "-" + ln', js, "line ids are built from integers only")

    def test_the_reveal_scroll_is_instant_not_animated(self):
        """Regression guard, measured in a browser rather than reasoned about.

        The reveal originally used `behavior: "smooth"`, matching the graph's
        node selection. Driving the real report in headless Chrome showed the
        scroll never happened at all -- scrollTop stayed 0 a full 1.5s after
        the double-click, with the correct lines highlighted ~1750px below
        the fold -- while `behavior: "auto"` landed immediately. A smooth
        scroll started in the same task that un-hides the panel is not
        reliable, and animating across a 5000-line file to a line the user
        explicitly asked for is wrong even when it does work.

        This asserts the code contract; the behaviour itself is only
        observable in a browser, which is exactly where the bug was found."""
        js = _script_body(self.doc)
        scroll = re.search(r"function scrollToMarked\(\).*?\n  \}", js, re.S).group(0)
        self.assertIn('scrollIntoView({ behavior: "auto", block: "center" })', scroll)
        # The word itself appears in the comment explaining why it is gone --
        # match the SETTING, not the string.
        self.assertNotIn('behavior: "smooth"', scroll)

    def test_a_second_mark_clears_the_first_highlight(self):
        js = _script_body(self.doc)
        self.assertIn("clearSourceHighlight();", js)
        mark = re.search(r"function markSource\(.*?\n  \}", js, re.S).group(0)
        self.assertLess(
            mark.index("clearSourceHighlight()"),
            mark.index('classList.add("src-hit")'),
            "the old highlight must be cleared before the new one is applied",
        )

    def test_single_click_selection_still_works(self):
        """The handoff's explicit non-regression: double-click is additive."""
        js = _script_body(self.doc)
        self.assertIn('svgRoot.addEventListener("click"', js)
        self.assertIn("selectTarget(nodeEl.getAttribute(\"data-node-id\"))", js)
        self.assertIn("showNodeDetail", js)
        # and the findings-panel click still selects a graph target
        self.assertIn('row.getAttribute("data-target")', js)

    def test_a_single_file_script_gets_no_file_picker(self):
        self.assertNotIn('id="source-file-select"', self.doc)
        self.assertNotIn('id="source-toolbar"', self.doc, "the toolbar row was removed for good")


class TabAndPanelTests(unittest.TestCase):
    """Selecting marks; only double-click travels. And the Source tab owns
    the window while it is up.

    Driven in headless Chrome on the target file, all of it: single click
    marked lines 67-85 and stayed on the graph; switching to Source hid both
    side panels and performed the scroll it owed; returning restored both;
    with the inspector closed beforehand only the findings list came back;
    reopening the findings list while on Source kept it open after the
    return; and double-click switched."""

    @classmethod
    def setUpClass(cls):
        cls.js = _script_body(_render(TARGET_FILE))

    def test_selection_marks_the_source_without_switching_tabs(self):
        """Yanking the view to another tab on a plain selection would make
        the graph unusable for its main purpose -- clicking around to read
        structure."""
        self.assertIn("markNodeSource(id)", self.js)
        mark = re.search(r"function markSource\(.*?\n  \}", self.js, re.S).group(0)
        self.assertNotIn("setTab(", mark)
        select = re.search(r"function selectTarget\(.*?\n  \}", self.js, re.S).group(0)
        self.assertIn("markNodeSource", select)
        self.assertNotIn('setTab("source")', select)

    def test_only_reveal_switches_and_double_click_is_what_calls_it(self):
        reveal = re.search(r"function revealSource\(.*?\n  \}", self.js, re.S).group(0)
        self.assertIn('setTab("source")', reveal)
        self.assertIn("markSource(", reveal)
        # dblclick -> revealNodeSource -> revealSource
        self.assertIn('addEventListener("dblclick"', self.js)
        self.assertIn("revealNodeSource(nodeEl.getAttribute(\"data-node-id\"))", self.js)

    def test_a_scroll_owed_while_hidden_is_paid_when_the_tab_opens(self):
        """`scrollIntoView` does nothing inside a `display:none` ancestor, so
        marking while the source panel is down cannot scroll. The scroll is
        owed until the panel is actually up, or the view sits at line 1 with
        the right lines highlighted far below the fold."""
        mark = re.search(r"function markSource\(.*?\n  \}", self.js, re.S).group(0)
        self.assertIn('if (activeTab === "source") { scrollToMarked(); }', mark)
        settab = re.search(r"function setTab\(.*?\n  \}\n", self.js, re.S).group(0)
        self.assertIn("if (showSrc) { scrollToMarked(); }", settab)

    def test_the_source_tab_stashes_both_side_panels(self):
        settab = re.search(r"function setTab\(.*?\n  \}\n", self.js, re.S).group(0)
        self.assertIn('setPanelShown("findings", false)', settab)
        self.assertIn('setPanelShown("inspector", false)', settab)
        self.assertIn("stashedPanels", settab)

    def test_each_panel_is_restored_INDEPENDENTLY(self):
        """Someone who had already closed the inspector must not find it
        reopened by a round trip through the source, so the two are stashed
        and restored as separate booleans rather than one flag."""
        settab = re.search(r"function setTab\(.*?\n  \}\n", self.js, re.S).group(0)
        self.assertIn("setPanelShown(\"findings\", stashedPanels.findings)", settab)
        self.assertIn("setPanelShown(\"inspector\", stashedPanels.inspector)", settab)

    def test_a_manual_toggle_while_on_source_outranks_the_stash(self):
        """Otherwise reopening the findings list over the source and then
        going back to the graph would silently undo it."""
        toggle = re.search(r"function togglePanel\(.*?\n  \}", self.js, re.S).group(0)
        self.assertIn("if (stashedPanels) { stashedPanels[name] = shown; }", toggle)

    def test_clicking_empty_canvas_deselects_everything(self):
        """Selection is reachable but was previously inescapable: nothing
        dropped it. Blank canvas now clears the box, its lit wires, the
        details panel AND the source highlight -- leaving the highlight
        behind would point at a node that is no longer selected.

        Driven in headless Chrome: selecting `Stage for Submission` lit 3
        wires and marked its lines; a click on blank canvas took selection
        1 -> 0, lit wires 3 -> 0, the highlight to empty and the inspector
        back to its empty state."""
        self.assertIn("function deselectAll()", self.js)
        fn = re.search(r"function deselectAll\(\).*?\n  \}", self.js, re.S).group(0)
        for expected in ("clearSelection()", "clearSourceHighlight()", "markedAnchor = null"):
            self.assertIn(expected, fn)
        self.assertIn('document.getElementById("inspector-empty").hidden = false', fn)
        self.assertIn('document.getElementById("inspector-content").hidden = true', fn)

    def test_deselect_is_reachable_from_canvas_padding_and_from_the_keyboard(self):
        """The SVG only covers as much of the pane as the graph needs, so a
        click in the padding below it never reaches the SVG handler at all."""
        self.assertIn("if (e.target === graphArea) { deselectAll(); }", self.js)
        self.assertIn('e.key === "Escape"', self.js)

    def test_selecting_a_node_does_NOT_deselect(self):
        """`deselectAll` is the fall-through of the canvas click handler, so
        the node and lane-header branches must return before reaching it."""
        handler = re.search(
            r'svgRoot\.addEventListener\("click".*?\n  \}\);', self.js, re.S
        ).group(0)
        self.assertLess(handler.index("selectTarget("), handler.index("deselectAll()"))
        self.assertLess(handler.index("toggleLane("), handler.index("deselectAll()"))
        self.assertIn("if (hdr) { toggleLane(hdr.getAttribute(\"data-lane-id\")); return; }", handler)

    def test_selecting_a_node_emphasises_its_own_findings(self):
        """Driven in headless Chrome on the target file: selecting
        `Stage for Submission` marked exactly its two findings (lines 67 and
        77) as related; `Tag Output Files` moved the mark to its three
        (47, 48, 48) rather than accumulating; deselecting cleared it.

        Note for whoever tests this next: assert the CLASSES, not the
        computed opacity. CSS transitions do not advance under headless
        Chrome's virtual clock, so `getComputedStyle(...).opacity` reads the
        pre-transition value and every row looks undimmed -- the same class
        of headless-clock trap as the `behavior: "smooth"` scroll. The
        dimming itself was confirmed from a screenshot."""
        self.assertIn("function markRelatedFindings(", self.js)
        fn = re.search(r"function markRelatedFindings\(.*?\n  \}", self.js, re.S).group(0)
        self.assertIn("clearRelatedFindings()", fn)
        self.assertIn('classList.add("has-selection")', fn)
        self.assertIn('row.parentNode.classList.add("related")', fn)
        select = re.search(r"function selectTarget\(.*?\n  \}", self.js, re.S).group(0)
        self.assertIn("markRelatedFindings(id)", select)

    def test_a_node_with_no_findings_greys_the_whole_list(self):
        """`has-selection` goes on regardless, and `related` simply lands on
        nothing -- so "this node has no findings" reads as a list with
        nothing lit in it rather than as an empty screen. That falls out of
        the CSS; it is not a special case in the JS, and it should not
        become one."""
        css = bghtml._CSS
        self.assertIn("#findings-list.has-selection > li { opacity:", css)
        self.assertIn("#findings-list.has-selection > li.related { opacity: 1; }", css)
        fn = re.search(r"function markRelatedFindings\(.*?\n  \}", self.js, re.S).group(0)
        # the class is added BEFORE the (possibly empty) findingIds loop
        self.assertLess(fn.index('classList.add("has-selection")'), fn.index("findingIds"))

    def test_related_findings_are_lifted_to_the_top_and_the_list_scrolls_up(self):
        """Emphasis alone is not enough when the matching rows are below the
        fold -- lifting them is pointless if the pane is still scrolled to
        where they used to be, so the reorder and the scroll reset are one
        operation.

        Browser-verified on the target file: with the list scrolled to 400px,
        selecting `Tag Output Files` put its three findings (48/D1 warn,
        47/D10 info, 48/D10 info) in the first three slots and scrollTop back
        to 0; selecting `Stage for Submission` moved the lift to its two."""
        self.assertIn("function reorderFindings(", self.js)
        fn = re.search(r"function reorderFindings\(.*?\n  \}", self.js, re.S).group(0)
        self.assertIn('li.classList.contains("related") ? head : tail', fn)
        self.assertIn("head.concat(tail)", fn)
        self.assertIn("list.scrollTop = 0", fn)
        mark = re.search(r"function markRelatedFindings\(.*?\n  \}", self.js, re.S).group(0)
        self.assertIn("reorderFindings(true)", mark)

    def test_every_severity_of_the_selected_node_is_lifted(self):
        """The question being answered is 'what is wrong with THIS node', so
        an info of its own outranks someone else's error in this ordering.
        The severity filter is still there for the other question."""
        fn = re.search(r"function reorderFindings\(.*?\n  \}", self.js, re.S).group(0)
        for sev in ("sev-info", "sev-warn", "sev-error", "severity"):
            self.assertNotIn(sev, fn)

    def test_the_original_order_is_kept_so_it_can_be_restored(self):
        """Rows are MOVED, not rebuilt -- each keeps its id, its listeners and
        its tag chip -- which is exactly why the original sequence has to be
        captured up front: nothing else records it."""
        self.assertIn("var findingOrder = Array.prototype.slice.call(", self.js)
        clear = re.search(r"function clearRelatedFindings\(\).*?\n  \}", self.js, re.S).group(0)
        self.assertIn("reorderFindings(false)", clear)

    def test_the_emphasis_dims_and_never_removes(self):
        """The severity filter and the tag lens both remove rows outright
        (`display:none`). A third mechanism that also removed them would
        make it impossible to tell which one had, and dimmed rows stay
        clickable so the list remains a way to move around."""
        css = bghtml._CSS
        block = css[css.index("#findings-list.has-selection > li {"):]
        block = block[: block.index("}") + 1]
        self.assertNotIn("display", block)
        self.assertNotIn("pointer-events", block)

    def test_deselecting_restores_the_findings_list(self):
        fn = re.search(r"function deselectAll\(\).*?\n  \}", self.js, re.S).group(0)
        self.assertIn("clearRelatedFindings()", fn)
        clear = re.search(r"function clearRelatedFindings\(\).*?\n  \}", self.js, re.S).group(0)
        self.assertIn('classList.remove("has-selection")', clear)
        self.assertIn('li.classList.remove("related")', clear)

    def test_a_finding_click_marks_its_line_and_double_click_travels(self):
        """Same contract as a node: click marks, double-click switches. A
        finding names ONE line, which is more precise than the node range
        `selectTarget` marks on the way past, so it is marked afterwards.

        Browser-checked including the case most likely to be missed: a
        finding with no graph target at all (D8 on a dead property, line 21)
        still marks its line."""
        click = re.search(
            r'findingsList\.addEventListener\("click".*?\n  \}\);', self.js, re.S
        ).group(0)
        self.assertIn("markFindingSource(", click)
        self.assertNotIn("revealFindingSource(", click)
        self.assertLess(click.index("selectTarget("), click.index("markFindingSource("))
        dbl = re.search(
            r'findingsList\.addEventListener\("dblclick".*?\n  \}\);', self.js, re.S
        ).group(0)
        self.assertIn("revealFindingSource(", dbl)

    def test_the_stash_is_cleared_on_the_way_out(self):
        """`stashedPanels` doubles as 'are we on source', so leaving it set
        after a return to the graph would make the next entry stash the
        already-hidden state and lose the real one."""
        settab = re.search(r"function setTab\(.*?\n  \}\n", self.js, re.S).group(0)
        self.assertIn("stashedPanels = null;", settab)
        self.assertIn('showSrc && was !== "source"', settab)


class SourceTabXssTests(unittest.TestCase):
    """V8. Embedding raw source text is the most dangerous thing this
    renderer does, so the payload is planted in BOTH places it can enter:
    a node NAME (which reaches the graph, the inspector and the JSON) and
    the SOURCE BODY itself (which reaches the new panel)."""

    PAYLOADS = [
        "<script>alert(1)</script>",
        '" onload="alert(2)',
        "</script><script>alert(3)</script>",
        "<img src=x onerror=alert(4)>",
    ]

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        p = pathlib.Path(cls.tmp.name) / "evil.xml"
        p.write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">\n'
            "\t<!-- </script><script>alert(3)</script> -->\n"
            '\t<Agent Name="&lt;img src=x onerror=alert(4)&gt;" Type="Win64">\n'
            '\t\t<Node Name="&lt;script&gt;alert(1)&lt;/script&gt;">\n'
            '\t\t\t<Log Message="&quot; onload=&quot;alert(2)"/>\n'
            "\t\t</Node>\n"
            "\t</Agent>\n"
            "</BuildGraph>\n",
            encoding="utf-8",
        )
        cls.path = p
        cls.doc = _render(p)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_no_payload_survives_as_live_markup(self):
        for payload in self.PAYLOADS:
            self.assertNotIn(payload, self.doc, f"raw payload {payload!r} reached the document")

    def test_every_source_line_unescapes_back_to_the_exact_file_text(self):
        """Inert is not the same as absent. The source view's whole job is to
        show this text, so assert the round trip line by line: what the
        `<code>` renders must unescape to exactly what is on disk -- which is
        simultaneously proof that nothing was dropped and proof that nothing
        was left live."""
        lines = bghtml._split_source_lines(self.path.read_text(encoding="utf-8-sig"))
        # Deliberately does NOT pin the gutter's internals: a marked line now
        # nests one <span class="src-dot"> per severity inside .src-mark
        # (T43), and this test is about the <code> round trip, not about how
        # many dots sit to its left.
        rendered = re.findall(
            r'<div class="src-line[^"]*" id="s0-(\d+)"><span class="src-ln"[^>]*>\d+</span>'
            r'.*?<code class="src-text">(.*?)</code></div>',
            self.doc,
            re.S,
        )
        self.assertEqual(len(rendered), len(lines))
        for number, body in rendered:
            expected = lines[int(number) - 1]
            self.assertEqual(html_mod.unescape(body), expected or "​")

    def test_the_payloads_are_visible_as_text_somewhere_on_the_page(self):
        """Every payload reaches the page in SOME escaped form -- once via
        the model (a node/agent name is escaped once) or, for the ones expat
        drops or resolves (an XML comment; an entity-encoded attribute), via
        the source body, where the file's own literal characters are escaped
        on top of whatever encoding the file already used."""
        for payload in self.PAYLOADS:
            once = html_mod.escape(payload, quote=True)
            twice = html_mod.escape(once, quote=True)
            self.assertTrue(
                once in self.doc or twice in self.doc,
                f"payload {payload!r} is not visible anywhere, escaped or double-escaped",
            )

    def test_no_element_was_conjured_out_of_the_payloads(self):
        """If any payload had been parsed as markup rather than escaped, the
        document would contain an element the renderer never emits. The only
        `<script>`s here are this module's own two (the JSON payload block
        and the behaviour script), and there is no `<img>`/`<iframe>` at
        all -- this renderer emits neither, so one appearing could only have
        come from the analysed file."""
        parsed = _parse(self.doc)
        self.assertEqual([r["tag"] for r in parsed.rows if r["tag"] == "script"].__len__(), 2)
        for forbidden in ("img", "iframe", "object", "embed", "svg script"):
            self.assertEqual(
                [r for r in parsed.rows if r["tag"] == forbidden], [],
                f"a <{forbidden}> appeared; a payload was parsed as markup",
            )

    def test_element_ids_are_never_derived_from_file_content(self):
        for match in re.finditer(r'\sid="([^"]*)"', self.doc):
            ident = match.group(1)
            self.assertRegex(
                ident,
                r"^[A-Za-z][A-Za-z0-9_:.-]*$",
                f"id {ident!r} is not a plain synthetic token",
            )

    def test_a_payload_in_a_findings_message_is_escaped_too(self):
        _r, _e, _g, findings = _pipeline(self.path)
        self.assertTrue(findings, "the evil fixture should produce findings")


class ViewportControlTests(unittest.TestCase):
    """Zoom, pan, panel resize and panel hide/show.

    The zoom table is asserted stop for stop against
    `Engine/Source/Editor/GraphEditor/Private/SNodePanel.cpp`
    (FGraphEditorZoomLevelsContainer:59-78, GetDefaultZoomLevel:111-114).
    Reproducing Unreal's feel is the point; drifting off its numbers by a
    stop would be invisible in a screenshot and wrong in the hand."""

    UNREAL_ZOOM_TABLE = [
        (0.100, "-12"), (0.125, "-11"), (0.150, "-10"), (0.175, "-9"), (0.200, "-8"),
        (0.225, "-7"), (0.250, "-6"), (0.375, "-5"), (0.500, "-4"), (0.675, "-3"),
        (0.750, "-2"), (0.875, "-1"), (1.000, "1:1"), (1.250, "+1"), (1.375, "+2"),
        (1.500, "+3"), (1.675, "+4"), (1.750, "+5"), (1.875, "+6"), (2.000, "+7"),
    ]

    @classmethod
    def setUpClass(cls):
        cls.doc = _render(TARGET_FILE)
        cls.js = _script_body(cls.doc)
        cls.parsed = _parse(cls.doc)

    def test_the_zoom_table_matches_unreals_stop_for_stop(self):
        block = re.search(r"var ZOOM_LEVELS = \[(.*?)\];", self.js, re.S).group(1)
        pairs = [
            (float(a), b) for a, b in re.findall(r"\[([0-9.]+),\s*\"([^\"]+)\"\]", block)
        ]
        self.assertEqual(pairs, self.UNREAL_ZOOM_TABLE)

    def test_the_default_stop_is_unreals_index_12_which_is_1_to_1(self):
        level = int(re.search(r"var ZOOM_DEFAULT_LEVEL = (\d+)", self.js).group(1))
        self.assertEqual(level, 12)
        self.assertEqual(self.UNREAL_ZOOM_TABLE[level], (1.000, "1:1"))

    def test_the_wheel_zooms_and_ctrl_is_the_limit_break_past_1_to_1(self):
        self.assertIn('addEventListener("wheel"', self.js)
        self.assertIn("passive: false", self.js)
        # ChangeZoomLevel's bAllowFullZoomRange, transcribed.
        self.assertRegex(
            self.js,
            r"zoomLevel === ZOOM_DEFAULT_LEVEL && delta > 0 && breakLimit",
        )
        self.assertRegex(self.js, r"zoomLevel > ZOOM_DEFAULT_LEVEL")

    def test_zoom_is_cursor_anchored(self):
        self.assertIn("area.scrollLeft + ax) * ratio - ax", self.js)
        self.assertIn("area.scrollTop + ay) * ratio - ay", self.js)

    def test_zoom_scales_the_svg_box_and_never_the_viewBox(self):
        """The viewBox is the natural layout size at every stop; only the
        painted width/height change. That is what keeps the wires crisp and
        leaves relayout()'s coordinates alone."""
        self.assertIn('svg.setAttribute("width", (TOTAL_WIDTH * zoom)', self.js)
        self.assertRegex(self.js, r'setAttribute\("viewBox", "0 0 " \+ TOTAL_WIDTH \+ " " \+ y\)')
        self.assertNotRegex(self.js, r'setAttribute\("viewBox"[^)]*zoom')

    def test_pan_is_right_or_middle_drag_and_never_left(self):
        self.assertRegex(self.js, r"if \(e\.button !== 1 && e\.button !== 2\) \{ return; \}")
        self.assertIn("graphArea.scrollLeft -= dx", self.js)
        self.assertIn("graphArea.scrollTop -= dy", self.js)

    def test_a_right_click_that_never_moved_keeps_its_context_menu(self):
        self.assertIn("panning.moved", self.js)
        self.assertIn('addEventListener("contextmenu"', self.js)

    def test_both_panels_have_a_hide_show_toggle(self):
        ids = {r["attrs"].get("id") for r in self.parsed.rows}
        self.assertIn("toggle-findings", ids)
        self.assertIn("toggle-inspector", ids)
        for tid in ("toggle-findings", "toggle-inspector"):
            btn = next(r for r in self.parsed.rows if r["attrs"].get("id") == tid)
            self.assertEqual(btn["attrs"].get("aria-pressed"), "true", "both panels start shown")
        self.assertIn("togglePanel", self.js)

    def test_both_panels_have_a_resizer_with_a_floor_and_a_ceiling(self):
        for rid, panel in (("resize-findings", "findings"), ("resize-inspector", "inspector")):
            sep = next(r for r in self.parsed.rows if r["attrs"].get("id") == rid)
            self.assertEqual(sep["attrs"].get("role"), "separator")
            self.assertEqual(sep["attrs"].get("data-panel"), panel)
            self.assertEqual(sep["attrs"].get("tabindex"), "0", "resizing must not be pointer-only")
        self.assertIn("var PANEL_MIN = 180", self.js)
        self.assertIn("function panelMax()", self.js)
        self.assertIn("Math.min(panelMax(), Math.max(PANEL_MIN, px))", self.js)

    def test_the_inspector_resizer_is_mirrored(self):
        """It sits on the far side of the centre pane, so dragging LEFT must
        widen it. A shared sign would make one of the two handles run the
        wrong way -- and both would still 'work'."""
        self.assertIn('var sign = name === "findings" ? 1 : -1', self.js)

    def test_each_tabs_controls_travel_with_it(self):
        self.assertIn('document.getElementById("zoom-controls").hidden = showSrc', self.js)
        zoom = next(r for r in self.parsed.rows if r["attrs"].get("id") == "zoom-controls")
        self.assertEqual(zoom["attrs"].get("role"), "group")


class IncidentEdgeTests(unittest.TestCase):
    """Selecting a node lights the wires that touch it.

    Driven in headless Chrome on the target file: selecting `Tag Output
    Files` lit 2 incoming and 3 outgoing of the 8 edges, leaving 3
    untouched; selecting another node MOVED the marks rather than
    accumulating them."""

    @classmethod
    def setUpClass(cls):
        cls.js = _script_body(_render(TARGET_FILE))

    def test_selection_marks_incident_edges_in_both_directions(self):
        self.assertIn("markIncidentEdges", self.js)
        self.assertIn('e.to === nodeId ? "edge-in"', self.js)
        self.assertIn('e.from === nodeId ? "edge-out"', self.js)

    def test_the_marks_are_cleared_before_the_next_selection(self):
        """Otherwise every click adds another lit bundle and the graph ends
        up entirely 'related to' whatever was clicked."""
        self.assertIn("clearIncidentEdges", self.js)
        clear_sel = re.search(r"function clearSelection\(\).*?\n  \}", self.js, re.S).group(0)
        self.assertIn("clearIncidentEdges()", clear_sel)
        mark = re.search(r"function markIncidentEdges\(.*?\n  \}", self.js, re.S).group(0)
        self.assertLess(mark.index("clearIncidentEdges()"), mark.index('classList.add(dir)'))

    def test_incident_styling_does_not_erase_the_edge_KIND(self):
        """The dataflow/order distinction is the point of the graph. An
        earlier version cleared `stroke-dasharray` on outgoing edges, which
        made every outgoing After edge look like proven dataflow."""
        css = bghtml._CSS
        block = css[css.index(".edge.edge-in, .edge.edge-out"):]
        block = block[: block.index("}") + 1]
        self.assertNotIn("stroke-dasharray", block)
        self.assertNotIn("stroke:", block)


class TagLensTests(unittest.TestCase):
    """The Highlight and Filter fields, and the draggable tag chips.

    Driven in headless Chrome on the target file: dropping `#OutputFiles`
    into Highlight accented 4 nodes and hid nothing; dragging it into
    Filter dimmed the other 4 nodes, dimmed 4 edges and hid 6 findings with
    a visible count."""

    @classmethod
    def setUpClass(cls):
        cls.doc = _render(TARGET_FILE)
        cls.js = _script_body(cls.doc)
        cls.parsed = _parse(cls.doc)

    def test_both_fields_are_in_the_report_header(self):
        header_ids = {r["attrs"].get("id") for r in self.parsed.rows if r["under"] == "report-header"}
        self.assertIn("lenses", header_ids)
        for lens in ("lens-highlight", "lens-filter"):
            row = next(r for r in self.parsed.rows if r["attrs"].get("id") == lens)
            self.assertEqual(row["under"], "lenses")
            self.assertIn("aria-label", row["attrs"])

    def test_tag_chips_are_draggable_AND_clickable(self):
        """Drag is the discoverable gesture, not the only one -- a drag-only
        control does not exist at all for a keyboard user."""
        self.assertIn("chip.draggable = true", self.js)
        self.assertIn('chip.addEventListener("dragstart"', self.js)
        self.assertIn('e.dataTransfer.setData("text/plain", tag)', self.js)
        self.assertIn('addToLens(e.shiftKey ? "filter" : "highlight", tag)', self.js)

    def test_a_tag_is_draggable_WHEREVER_it_appears(self):
        """Not just the two lists that happen to be pure tags. Every place a
        tag can surface offers the same object with the same gestures."""
        for section in ("produces", "creates", "consumes"):
            self.assertIn('setTagList("insp-%s"' % section, self.js)
        # Mixed raw-token lists: the tags in them are draggable too.
        self.assertIn('setTokenList("insp-requires"', self.js)
        self.assertIn('setTokenList("insp-after"', self.js)
        # Findings on the node, and the findings panel itself.
        self.assertIn('setFindingList("insp-findings"', self.js)
        self.assertIn("finding-tag", self.doc)

    def test_ONE_wiring_path_for_every_chip(self):
        """Runtime-built chips and the statically-rendered findings-panel
        chips share `wireTagChip`. Two copies of 'what a tag chip does' is
        how a gesture ends up working in one list and not another."""
        self.assertIn("function wireTagChip(", self.js)
        self.assertIn("return wireTagChip(chip, tag);", self.js)
        self.assertIn('querySelectorAll(".finding-tag")', self.js)
        self.assertIn('wireTagChip(chip, chip.getAttribute("data-tag"))', self.js)

    def test_node_references_are_chips_but_NOT_draggable(self):
        """A node name dropped into a tag lens would match nothing and look
        broken, so Requires/After entries that are not tags get an inert
        chip."""
        self.assertIn("function plainChip(", self.js)
        plain = re.search(r"function plainChip\(.*?\n  \}", self.js, re.S).group(0)
        # Match the ASSIGNMENT, not the word -- it appears in the comment
        # explaining why it is absent.
        self.assertNotIn("chip.draggable", plain)
        self.assertNotIn("wireTagChip", plain)
        self.assertNotIn("addToLens", plain)
        self.assertIn('isTag(token) ? tagChip(token) : plainChip(token)', self.js)
        # ...and it has to LOOK undraggable at rest. A difference that only
        # shows on hover is not a difference for someone deciding what to
        # reach for.
        self.assertIn(".chip-inert {", bghtml._CSS)

    def test_the_creates_section_exists_at_all(self):
        """It did not before. D4 fires on tags created in a node and absent
        from @Produces, and a reader had no way to see the set the finding
        was about."""
        self.assertIn('id="insp-creates"', self.doc)

    def test_a_finding_about_a_lensed_tag_survives_its_own_filter(self):
        """D2 says 'consumed but produced nowhere' -- no node matches, by
        definition. Filtering on that tag must not hide the finding the user
        dragged the tag out of."""
        apply_fn = re.search(r"function applyLenses\(\).*?\n  \}\n", self.js, re.S).group(0)
        self.assertIn("aboutTag", apply_fn)
        self.assertIn("keep = aboutTag ||", apply_fn)

    def test_hiding_a_finding_hides_its_chip_too(self):
        """The chip is a SIBLING of the row (nesting a button inside a button
        is invalid and unreachable by keyboard), so both filters have to hide
        the whole <li> or the chip is orphaned."""
        css = bghtml._CSS
        self.assertIn('#findings-list[data-filter="warnplus"] > li.sev-info', css)
        self.assertIn("#findings-list > li.lens-hidden { display: none; }", css)
        self.assertIn('row.parentNode.classList.toggle("lens-hidden"', self.js)
        # every row still carries its severity on the <li> for those selectors
        items = re.findall(r'<li class="finding-item sev-(\w+)">', self.doc)
        self.assertEqual(len(items), 13, "the target file's 13 findings")

    def test_the_chip_is_not_nested_inside_the_row_button(self):
        parsed = _parse(self.doc)
        for row in parsed.rows:
            if "finding-tag" in row["attrs"].get("class", ""):
                self.assertNotIn(
                    "finding-", str(row["under"]),
                    "a tag chip is nested inside a finding-row button",
                )

    def test_a_lens_matches_produced_consumed_AND_created_tags(self):
        """`creates` is in the payload for exactly this: a tag made by a
        `<Tag With=...>` inside a node is produced there whether or not it
        was hoisted into `@Produces`. Ignoring it would make the lens
        contradict D4, which is reported in the same page."""
        self.assertIn("n.produces, n.consumes, n.creates", self.js)
        payload = json.loads(
            re.search(r'id="bgview-data">(.*?)</script>', self.doc, re.S).group(1)
            .replace("\\u003c", "<").replace("\\u003e", ">").replace("\\u0026", "&")
        )
        for n in payload["nodes"]:
            self.assertIn("creates", n)
        created = {t for n in payload["nodes"] for t in n["creates"]}
        self.assertIn("#ArchiveSymbols", created, "the target file creates this inside a node")

    def test_matching_is_case_insensitive(self):
        self.assertIn("toLowerCase()", self.js)
        fn = re.search(r"function nodeTouchesTag\(.*?\n  \}", self.js, re.S).group(0)
        self.assertIn(".toLowerCase() === folded", fn)

    def test_highlight_adds_and_filter_takes_away(self):
        css = bghtml._CSS
        self.assertIn(".node.lens-hit .node-box", css)
        self.assertIn(".node.lens-dim", css)
        self.assertIn(".finding-row.lens-hidden { display: none; }", css)
        # Highlight must not touch the findings list at all.
        apply_fn = re.search(r"function applyLenses\(\).*?\n  \}\n", self.js, re.S).group(0)
        findings_part = apply_fn[apply_fn.index("DATA.findings.forEach"):]
        self.assertNotIn('"highlight"', findings_part)

    def test_a_filtered_edge_needs_BOTH_ends_to_survive(self):
        """A wire with one end suppressed points into blank space."""
        self.assertIn("!(hitIds[e.from] && hitIds[e.to])", self.js)

    def test_filtering_reports_what_it_hid(self):
        """V28's rule -- no silent suppression -- applied to a UI control.
        A hidden warn is worse than a cluttered list."""
        self.assertIn('id="lens-note"', self.doc)
        self.assertIn("finding(s) hidden by the filter", self.js)

    def test_a_tag_cannot_be_added_to_the_same_lens_twice(self):
        fn = re.search(r"function addToLens\(.*?\n  \}", self.js, re.S).group(0)
        self.assertIn("already", fn)

    def test_runtime_chips_never_reach_a_markup_sink(self):
        """Tag names are attacker-influenced (V8). Chips built at runtime go
        through .textContent, and no tag ever reaches an id or a selector."""
        for fn_name in ("renderLens", "tagChip", "plainChip"):
            fn = re.search(r"function %s\(.*?\n  \}\n" % fn_name, self.js, re.S).group(0)
            self.assertRegex(fn, r"\.textContent = (tag|text)")
            self.assertNotIn("getElementById(tag", fn)
            self.assertNotIn("querySelector(tag", fn)

    def test_the_static_findings_chips_are_escaped_once_in_python(self):
        """These are rendered server-side, so `_esc` is what makes them
        inert -- both the visible text and the `data-tag` the JS reads back."""
        payload = '#<script>alert(1)</script>'
        from bgview.findings import Finding

        f = Finding(
            file=r"C:\x\s.xml", line=1, severity=Severity.WARN,
            detector="D2", message="m", tag=payload,
        )
        markup = bghtml._render_findings_panel([f], [None], {})
        self.assertNotIn(payload, markup)
        self.assertIn(html_mod.escape(payload, quote=True), markup)
        self.assertIn('data-tag="%s"' % html_mod.escape(payload, quote=True), markup)

    def test_a_finding_without_a_tag_gets_no_chip(self):
        from bgview.findings import Finding

        f = Finding(file=r"C:\x\s.xml", line=1, severity=Severity.INFO, detector="D8", message="m")
        self.assertNotIn("finding-tag", bghtml._render_findings_panel([f], [None], {}))


class NoRegressionTests(unittest.TestCase):
    """The invariants the handoff calls load-bearing, re-checked with the
    source now embedded in the page."""

    @classmethod
    def setUpClass(cls):
        cls.doc = _render(TARGET_FILE)

    def test_V8_no_markup_parsing_sinks_and_no_inline_handlers(self):
        js = _script_body(self.doc)
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(sink, js, f"{sink} appears in the behaviour script")
        # No inline on*= attributes -- checked on the MARKUP, with the
        # embedded source text excluded, since the analysed file may legally
        # contain such a string as inert data.
        markup = re.sub(r'<code class="src-text">.*?</code>', "", self.doc, flags=re.S)
        self.assertEqual(re.findall(r"\son[a-z]+\s*=\s*[\"']", markup), [])

    def test_V17_no_network_references(self):
        # Namespace URIs are IDENTIFIERS, never fetched -- and the source
        # body legitimately shows the analysed script's own xmlns=, so match
        # on the PREFIX rather than the exact token (the escaped `&quot;`
        # that closes the attribute in the displayed source would otherwise
        # be swallowed into the match).
        allowed = (
            "http://www.w3.org/2000/svg",
            "http://www.epicgames.com/BuildGraph",
            "http://www.w3.org/2001/XMLSchema-instance",
        )
        for match in re.finditer(r"https?://[^\s\"'<>]+", self.doc):
            url = match.group(0)
            self.assertTrue(
                any(url.startswith(prefix) for prefix in allowed),
                f"{url!r} is not one of the permitted XML namespace identifiers",
            )
        self.assertNotIn("<link", self.doc)
        self.assertNotIn("<script src", self.doc)
        self.assertNotIn("@import", self.doc)

    def test_V38_serve_and_html_share_one_renderer(self):
        """`to_html` must stay a thin wrapper -- a second render path is how
        the live view and the written file drift apart."""
        _root, ev, graph, findings = _pipeline(TARGET_FILE)
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "r.html"
            bghtml.to_html(graph, findings, ev, str(out))
            self.assertEqual(out.read_text(encoding="utf-8"), render_html(graph, findings, ev))

    def test_the_report_stays_one_self_contained_file_of_sane_size(self):
        self.assertLess(len(self.doc), 400_000, "98-line script should not produce a huge report")

    def test_embedding_is_capped(self):
        self.assertEqual(bghtml._MAX_SOURCE_LINES, 20_000)
        self.assertEqual(bghtml._MAX_SOURCE_CHARS, 4_000_000)

    def test_a_file_over_the_cap_is_truncated_LOUDLY(self):
        """Over the cap the text is cut, but the file stays in the picker and
        the view SAYS it was cut. A silently dropped file reads as 'no such
        source'; a silently short one reads as a shorter script."""

        class _Ev:
            sources = {r"C:\x\big.xml": "\n".join(f"<!-- line {i} -->" for i in range(bghtml._MAX_SOURCE_LINES + 50))}

        out = bghtml._source_files(None, _Ev())
        self.assertTrue(out[0]["truncated"])
        self.assertEqual(len(out[0]["lines"]), bghtml._MAX_SOURCE_LINES)
        markup = bghtml._render_source_area(out, {})
        self.assertIn("src-truncated", markup)
        self.assertIn("truncated:", markup)


class RelatedSourceMarkTests(unittest.TestCase):
    """T41 -- with a node selected, the gutter says which marks are ITS.

    Before this, selecting a node left the source marking every finding in the
    whole file. That is a question nobody asked, and T35 stashes the findings
    panel on the Source tab, so nothing else on screen narrowed it either.

    Measured in headless Chrome on Examples/BuildEditorAndTools.xml (6 marked
    lines), reading COMPUTED background -- a paint fact, not a transition, so
    it is not the headless-clock trap that caught the T37 probe:

        no selection                     related=0  tinted=6  flat=0
        select node owning 1 finding     related=1  tinted=1  flat=5
        select node owning 2 findings    related=2  tinted=2  flat=4
        Escape                           related=0  tinted=6  flat=0

    Re-selecting swaps the set rather than accumulating, and deselect restores
    every mark.
    """

    @classmethod
    def setUpClass(cls):
        cls.doc = _render(TARGET_FILE)

    def test_the_gutter_is_driven_by_the_same_list_as_the_findings_panel(self):
        """Both projections read `n.findingIds`, from inside the same pair of
        functions. If the gutter grew its own notion of 'related' the two
        views could disagree about the same finding."""
        marker = re.search(r"function markRelatedFindings\(nodeId\) \{(.*?)\n  \}", self.doc, re.S).group(1)
        self.assertIn("markRelatedSourceMarks(n.findingIds || [])", marker)
        clearer = re.search(r"function clearRelatedFindings\(\) \{(.*?)\n  \}", self.doc, re.S).group(1)
        self.assertIn("clearRelatedSourceMarks()", clearer)

    def test_lane_selection_clears_the_gutter_emphasis_too(self):
        """An agent lane owns no findings, so the lane branch of selectTarget
        calls clearRelatedFindings -- which now also clears the source marks.
        Emphasis is dropped rather than a wrong set invented (T37)."""
        lane_branch = re.search(r'\} else if \(id\.charAt\(0\) === "l"\) \{(.*?)\n    \}', self.doc, re.S).group(1)
        self.assertIn("clearRelatedFindings()", lane_branch)

    def test_unrelated_marks_lose_their_tint_but_related_ones_keep_it(self):
        for sev in ("error", "warn", "info"):
            self.assertIn(
                f"#source-area.has-selection .src-sev-{sev}:not(.src-related):not(.src-hit)",
                self.doc,
            )

    def test_de_emphasis_never_touches_the_code_text(self):
        """Readability is the source view's whole job. Dimming a row with
        `opacity` would take the code with it, so only the row TINT and the
        gutter DOT step back."""
        rule = re.search(
            r"#source-area\.has-selection \.src-line:not\(\.src-related\) \.src-dot::before \{([^}]*)\}",
            self.doc).group(1)
        self.assertIn("color: var(--muted)", rule)
        self.assertNotIn(
            "#source-area.has-selection .src-line:not(.src-related) { opacity",
            self.doc,
        )
        self.assertNotIn(".src-related .src-text", self.doc)

    def test_the_selected_span_keeps_its_accent_even_on_an_unattributed_finding(self):
        """A finding with no owning node is in nobody's findingIds. If such a
        line falls inside the selected node's range it must still read as part
        of that range -- the span highlight is about the SELECTION, not about
        the finding -- hence the `:not(.src-hit)` guard."""
        for sev in ("error", "warn", "info"):
            self.assertIn(f".src-sev-{sev}:not(.src-related):not(.src-hit)", self.doc)

    def test_marks_are_dimmed_never_removed(self):
        """Same discipline as T37: the line really does carry a finding, and
        hiding that would be a lie. Nothing here may set display:none."""
        self.assertNotIn("#source-area.has-selection .src-line:not(.src-related) { display: none", self.doc)
        self.assertNotIn(".src-sev-error:not(.src-related) { display", self.doc)


class GutterTooltipTests(unittest.TestCase):
    """T42 -- hovering a gutter mark says what the finding IS.

    It used to produce the file path, inherited from the `title` on the
    enclosing `.src-file`. That is the right answer for the code area and a
    useless one for a mark whose whole job is to point at one finding.

    Measured in headless Chrome: the mark's box is 9.0 x 18.6 against a row
    height of 18.6 (it stretches, so the target is the full line height rather
    than a ~12px dot), `elementFromPoint` at its centre returns the mark
    itself, and `cursor` is `help` on a marked mark against `auto` on a
    decorative one.
    """

    @classmethod
    def setUpClass(cls):
        cls.doc = _render(TARGET_FILE)

    def _mark(self, severity, detector, message, line=7):
        return Finding(file=r"C:\x\s.xml", line=line, severity=severity,
                       detector=detector, message=message)

    def test_a_marked_line_carries_the_finding_text_not_the_path(self):
        marks = {(0, 1): [self._mark(Severity.WARN, "D2", "Tag '#X' is produced nowhere", line=1)]}
        files = [{"index": 0, "path": r"C:\x\s.xml", "lines": ["<BuildGraph/>"], "truncated": False}]
        markup = bghtml._render_source_area(files, marks)
        self.assertIn("warn: [D2] Tag &#x27;#X&#x27; is produced nowhere", markup)
        # and the file path is still the tooltip for the code area itself
        self.assertIn(f'title="{bghtml._esc(r"C:\x\s.xml")}"', markup)

    def test_an_unmarked_mark_stays_decoration(self):
        """No finding, no tooltip and no affordance -- an empty mark that
        advertised a tooltip would be a promise it cannot keep."""
        files = [{"index": 0, "path": r"C:\x\s.xml", "lines": ["<BuildGraph/>"], "truncated": False}]
        markup = bghtml._render_source_area(files, {})
        self.assertIn('<span class="src-mark" aria-hidden="true"></span>', markup)
        self.assertNotIn('role="img"', markup)

    def test_a_line_with_two_severities_gets_two_dots_each_owning_its_own(self):
        """T43. The reported case: line 48 carries a D1 warn and a D10 info.
        One amber dot said so only in the tooltip, which made the info look
        like a stray duplicate. Now each severity has its own dot, and each
        dot's tooltip holds ONLY its own findings."""
        marks = {(0, 1): [self._mark(Severity.WARN, "D1", "GameBinaries not defined", line=1),
                          self._mark(Severity.INFO, "D10", "empty list entry", line=1)]}
        files = [{"index": 0, "path": "s.xml", "lines": ["<BuildGraph/>"], "truncated": False}]
        markup = bghtml._render_source_area(files, marks)
        self.assertEqual(markup.count('class="src-dot '), 2)
        warn_dot = re.search(r'<span class="src-dot src-dot-warn"[^>]*title="([^"]*)"', markup).group(1)
        info_dot = re.search(r'<span class="src-dot src-dot-info"[^>]*title="([^"]*)"', markup).group(1)
        self.assertIn("GameBinaries", warn_dot)
        self.assertNotIn("empty list entry", warn_dot)
        self.assertIn("empty list entry", info_dot)
        self.assertNotIn("GameBinaries", info_dot)

    def test_many_findings_of_one_severity_collapse_into_a_single_dot(self):
        """Grouped by COLOUR: three infos on a line are one info dot whose
        tooltip lists all three, not three identical blue dots."""
        marks = {(0, 1): [self._mark(Severity.INFO, "D10", f"thing {i}", line=1) for i in range(3)]}
        files = [{"index": 0, "path": "s.xml", "lines": ["<BuildGraph/>"], "truncated": False}]
        markup = bghtml._render_source_area(files, marks)
        self.assertEqual(markup.count('class="src-dot '), 1)
        tip = re.search(r'<span class="src-dot src-dot-info"[^>]*title="([^"]*)"', markup).group(1)
        for i in range(3):
            self.assertIn(f"thing {i}", tip)

    def test_dots_are_ordered_most_severe_first(self):
        marks = {(0, 1): [self._mark(Severity.INFO, "D10", "i", line=1),
                          self._mark(Severity.ERROR, "D18", "e", line=1),
                          self._mark(Severity.WARN, "D1", "w", line=1)]}
        files = [{"index": 0, "path": "s.xml", "lines": ["<BuildGraph/>"], "truncated": False}]
        markup = bghtml._render_source_area(files, marks)
        order = re.findall(r'class="src-dot src-dot-(\w+)"', markup)
        self.assertEqual(order, ["error", "warn", "info"])

    def test_the_row_tint_is_still_the_single_highest_severity(self):
        """One row cannot have three background colours; the dots already say
        which severities are present."""
        marks = {(0, 1): [self._mark(Severity.INFO, "D10", "i", line=1),
                          self._mark(Severity.WARN, "D1", "w", line=1)]}
        files = [{"index": 0, "path": "s.xml", "lines": ["<BuildGraph/>"], "truncated": False}]
        markup = bghtml._render_source_area(files, marks)
        self.assertIn('class="src-line src-sev-warn"', markup)
        self.assertNotIn("src-sev-info", markup)

    def test_two_findings_on_one_line_are_both_named(self):
        """`_source_marks` keeps the whole list precisely so this can happen;
        collapsing to the top severity would silently drop the other one."""
        both = [self._mark(Severity.INFO, "D10", "trailing ';'"),
                self._mark(Severity.WARN, "D2", "produced nowhere")]
        tip = bghtml._mark_tooltip(both)
        self.assertIn("info: [D10] trailing ';'", tip)
        self.assertIn("warn: [D2] produced nowhere", tip)
        self.assertEqual(tip.count("\n"), 1, "one line per finding")

    def test_the_mark_colour_is_the_highest_severity_on_the_line(self):
        """A line carrying both an info and a warn must read as the warn."""
        both = [self._mark(Severity.INFO, "D10", "a"), self._mark(Severity.WARN, "D2", "b")]
        self.assertEqual(bghtml._mark_severity(both), Severity.WARN)
        self.assertEqual(bghtml._mark_severity(list(reversed(both))), Severity.WARN,
                         "highest, not last")

    def test_the_tooltip_is_reachable_without_a_pointer(self):
        """A `title` reaches pointer users only. `role="img"` plus an
        aria-label is what makes an empty span announceable at all."""
        marks = {(0, 1): [self._mark(Severity.ERROR, "D18", "already defined", line=1)]}
        files = [{"index": 0, "path": "s.xml", "lines": ["<BuildGraph/>"], "truncated": False}]
        markup = bghtml._render_source_area(files, marks)
        self.assertIn('role="img"', markup)
        self.assertIn('aria-label="error: [D18] already defined"', markup)
        self.assertNotIn('<span class="src-mark" aria-hidden="true"></span>', markup)

    def test_only_a_dot_advertises_itself_as_hoverable(self):
        rule = re.search(r"\n\.src-dot \{([^}]*)\}", self.doc).group(1)
        self.assertIn("cursor: help", rule)
        # the empty container itself must not claim to be hoverable
        self.assertNotIn('.src-mark { cursor: help', self.doc)

    def test_a_dot_stretches_to_the_row_so_it_can_be_hit(self):
        rule = re.search(r"\n\.src-dot \{([^}]*)\}", self.doc).group(1)
        self.assertIn("align-self: stretch", rule)

    def test_the_gutter_is_sized_for_the_worst_case_of_three(self):
        """Fixed width, not content width: the code column has to start at the
        same x on every row or the file stops being readable as code."""
        rule = re.search(r"\n\.src-mark \{([^}]*)\}", self.doc).group(1)
        self.assertIn("width: 21px", rule)

    def test_the_real_report_emits_one_dot_per_severity_per_line(self):
        """End to end on the target file: a dot for every (line, severity)
        pair -- NOT one per finding, and not one per line."""
        _root, _ev, _graph, findings = _pipeline(TARGET_FILE)
        pairs = {(f.file, f.line, f.severity) for f in findings}
        self.assertEqual(self.doc.count('class="src-dot '), len(pairs))
        # and strictly fewer dots than findings only if some line doubles up
        self.assertLess(len(pairs), len(findings), "target file should have a doubled line")


if __name__ == "__main__":
    unittest.main()
