/* bgview/render.js -- builds the report DOM.
 *
 * The Python renders a self-contained HTML STRING, which is why html.py is
 * 3000 lines: every attacker-influenced value has to be escaped by hand on
 * the way into that string (V8), and the interactive layer has to be written
 * as JavaScript inside a Python string literal.
 *
 * Rendering into a live DOM removes that whole category of work AND the
 * whole category of bug. Nothing here concatenates markup. Every value off
 * the analysed script -- node names, log messages, paths, option values --
 * reaches the page through textContent or setAttribute, both of which treat
 * it as data by construction. There is no innerHTML in this file, so there
 * is no escaping to get wrong.
 */
"use strict";

import { severityName, Severity, normCase } from "./findings.js";
import { rank, matchPositions } from "./fuzzy.js";
import { resolveInclude } from "./evaluator.js";
import { splitList } from "./lexer.js";
import { layout, edgePath, ZOOM_LEVELS, ZOOM_DEFAULT_LEVEL,
         fitZoomLevel, LARGE_NODE_THRESHOLD, LARGE_LANE_THRESHOLD } from "./layout.js";

const SVG_NS = "http://www.w3.org/2000/svg";
const LANE_HEADER_BAND = 34;   // matches layout.js LANE_HEADER_H

const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
};
const svg = (tag, attrs) => {
  const n = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, String(v));
  return n;
};

/** Split source text into lines the same way the loader counted them.
 *  A lone CR is a line break in XML, and Epic ships files whose lines end
 *  CR CR LF -- splitting on \n alone would put the gutter marks on
 *  different lines than the findings refer to. */
export function splitSourceLines(text) {
  return text.split(/\r\n|\r|\n/);
}

/**
 * Render the whole report into `root`.
 * @returns {{selectNode:Function, clearSelection:Function}} controls the shell uses
 */
export function renderReport(root, { graph, findings, ev, entryFile, activity, includes }) {
  root.replaceChildren();
  root.classList.remove("show-inactive");   // a re-render starts from the dimmed view

  // Guard activity under the option-set (T71/T73). Absent (an older caller),
  // everything is active and the lens draws nothing.
  const act = activity || { nodes: new Map(), agents: new Map(), counts: { active: graph.nodes.size, inactive: 0, unknown: 0 } };
  const nodeState = (name) => (act.nodes.get(name) || { state: "active" }).state;
  const agentState = (name) => (act.agents.get(name) || { state: "active" }).state;
  const lensHasEffect = act.counts.inactive + act.counts.unknown > 0;

  // Worst severity per node, not merely "has a warn+". An error and a warning
  // should not look identical on the canvas, and the palette already
  // distinguishes them everywhere else.
  const worstByNode = new Map();
  for (const f of findings) {
    if (f.severity < Severity.WARN || !f.node) continue;
    const cur = worstByNode.get(f.node);
    if (cur === undefined || f.severity > cur) worstByNode.set(f.node, f.severity);
  }
  const warnNodes = new Set(worstByNode.keys());

  // Nodes declared in a file other than the one dropped -- an <Include>d
  // fragment. They get a small link glyph before the name, their lanes get
  // the same glyph with the file named, and the legend explains it. The
  // glyph is a MARK, not a colour: colour is already spoken for by severity
  // and selection, and a mark reads the same in every theme.
  const linkedNodes = new Set();
  const laneLinkedFiles = new Map();   // agent name -> Set of included files its nodes come from
  for (const [name, node] of graph.nodes) {
    if (node.file === entryFile) continue;
    linkedNodes.add(name);
    const laneName = node.agent || "";
    if (!laneLinkedFiles.has(laneName)) laneLinkedFiles.set(laneName, new Set());
    laneLinkedFiles.get(laneName).add(node.file);
  }
  /** The link glyph (two chain links), as a nested <svg> so it can sit at an
   *  x/y inside the canvas or inline in HTML alike. Stroke comes from CSS. */
  const fileMark = (x, y, cls) => {
    const s = svg("svg", { class: cls, x, y, width: 12, height: 12, viewBox: "0 0 24 24", "aria-hidden": "true" });
    s.append(
      svg("path", { d: "M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" }),
      svg("path", { d: "M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" }),
    );
    return s;
  };
  const legendFileItem = () => {
    const item = el("span", "legend-item");
    item.append(fileMark(0, 0, "legend-filemark"));
    item.append(el("span", null, "from an included file"));
    return item;
  };
  // §C wants this usable from 10 nodes to thousands, so a large graph opens
  // FOLDED rather than as one uninterrupted canvas. BuildWorldPartitionHLODs
  // is 105 nodes across 53 lanes -- expanded, that is not a view of anything.
  const collapsed = new Set();
  if (graph.nodes.size > LARGE_NODE_THRESHOLD || graph.agents.size > LARGE_LANE_THRESHOLD) {
    for (const a of graph.agents.keys()) collapsed.add(a);
  }
  let L = layout(graph, warnNodes, collapsed, linkedNodes);

  // Findings are attributed to nodes so a selection can narrow both panels
  // from ONE list -- the two projections cannot drift if they read the same
  // map (the Python learned this the hard way in T41).
  const byNode = new Map();
  findings.forEach((f, i) => {
    if (!f.node) return;
    if (!byNode.has(f.node)) byNode.set(f.node, []);
    byNode.get(f.node).push(i);
  });

  /* Every raw If= in the script, split node-attached vs node-less. A guard
   * outside any <Node> (a top-level <Property> under an <Agent>) belongs to
   * the lane, not to a box -- that is where the target file's own
   * SubmissionDependencies accumulator guard lives. */
  const VERDICT_HELP = {
    unsat: "unsatisfiable -- this branch can never run",
    taut: "tautological -- always true, the condition is redundant",
    contingent: "depends on the option-set",
    unknown: "cannot be decided statically (an opaque Exists(), or an unresolved name)",
  };
  const conditionsByNode = new Map();
  const conditionsByAgent = new Map();
  {
    // D12 already classified every guard it could; reuse its verdicts rather
    // than re-deriving them, so the panel and the findings cannot disagree.
    const verdictAt = new Map();
    for (const f of findings) {
      if (f.detector !== "D12") continue;
      verdictAt.set(`${f.file}:${f.line}`, /unsatisfiable/.test(f.message) ? "unsat" : "taut");
    }
    const seen = new Set();
    for (const r of ev.resolved) {
      if (!r.rawIf) continue;
      // A <Node>'s own If= is the NODE's guard and an <Agent>'s is its
      // lane's: the stacks are pushed AFTER the element's own entry is
      // emitted, so r.node / r.agent name the ENCLOSING scope, not the
      // element itself. (Measured: a node's own guard used to land in the
      // lane tooltip as "outside any node", and its card said "none".)
      const isNodeElem = r.elem.tag === "Node";
      const isAgentElem = r.elem.tag === "Agent";
      const owner = (isNodeElem || isAgentElem) ? (r.attrs.get("Name") || "") : (r.node || r.agent || "");
      const key = `${isNodeElem ? "n" : "s"}${owner}|${r.elem.file}:${r.elem.line}|${r.rawIf}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const entry = {
        text: r.rawIf,
        verdict: verdictAt.get(`${r.elem.file}:${r.elem.line}`) || "contingent",
        line: r.elem.line,
        file: r.elem.file,
        tag: r.elem.tag,
        own: isNodeElem,            // the node's own guard, vs one on a task inside it
      };
      const bucket = (isNodeElem || r.node) ? conditionsByNode : conditionsByAgent;
      if (!bucket.has(owner)) bucket.set(owner, []);
      bucket.get(owner).push(entry);
    }
  }

  const counts = { info: 0, warn: 0, error: 0 };
  for (const f of findings) counts[severityName(f.severity)]++;

  /* ---------------------------------------------------------- header ---- */
  const header = el("header", "report-header");
  const title = el("div", "report-title");
  title.append(el("h2", null, entryFile.split("/").pop()));
  title.append(el("div", "title-meta",
    `${graph.nodes.size} nodes · ${graph.agents.size} agents · ` +
    `${new Set([...graph.nodes.values()].flatMap((n) => [...n.produces])).size} tags`));
  // V60: every dim the lens applies is counted, right under the title.
  if (lensHasEffect) {
    title.append(el("div", "title-activity",
      `${act.counts.active} of ${graph.nodes.size} nodes active under these options` +
      (act.counts.unknown ? ` · ${act.counts.unknown} undecidable` : "")));
  }
  header.append(title);

  const legend = el("div", "legend");
  // Shared: the severity key, which both tabs need -- the findings list and
  // the source gutter use the same three colours.
  const legendShared = el("span", "legend-group");
  for (const [cls, label] of [["sev-error", "error"], ["sev-warn", "warn"], ["sev-info", "info"]]) {
    const item = el("span", "legend-item");
    item.append(el("span", `legend-dot ${cls}`));
    // Colour key ONLY -- the counts live on the findings panel's filter
    // chips. The same number in two places is free to disagree, and after a
    // severity filter one of them always does.
    item.append(el("span", null, label));
    legendShared.append(item);
  }
  // Graph-only: the two edge kinds. Worth naming outright because dataflow
  // and order-only differ by DASH, and a dashed amber wire next to an amber
  // warn border is exactly the pair a reader confuses.
  const legendGraph = el("span", "legend-group");
  for (const [cls, label] of [["dataflow", "dataflow (Requires)"], ["order", "order only (After)"]]) {
    const item = el("span", "legend-item");
    item.append(el("span", `legend-wire ${cls}`));
    item.append(el("span", null, label));
    legendGraph.append(item);
  }
  // Only when there is something to explain: a one-file graph has no glyphs.
  if (linkedNodes.size) legendGraph.append(legendFileItem());
  // Source-only: what a gutter dot means.
  const legendSource = el("span", "legend-group");
  const gutterKey = el("span", "legend-item");
  gutterKey.append(el("span", "legend-dot sev-warn"));
  gutterKey.append(el("span", null, "gutter dot = a finding on that line"));
  legendSource.append(gutterKey);
  if (linkedNodes.size) legendSource.append(legendFileItem());
  legendSource.hidden = true;
  legend.append(legendShared, legendGraph, legendSource);
  header.append(legend);

  // Panel toggles. Both panels are real estate the reader may not want at a
  // given moment -- a wide graph wants the whole window -- so each can be
  // dismissed and brought back. `aria-pressed` rather than a class alone,
  // because "is this panel showing" is state a screen reader needs too.
  const toggles = el("div", "panel-toggles");
  const mkToggle = (label, title) => {
    const b = el("button", "toggle on", label);
    b.type = "button";
    b.title = title;
    b.setAttribute("aria-pressed", "true");
    toggles.append(b);
    return b;
  };
  /* ---- tag lens (T31) -------------------------------------------------
   * Two lenses, and the difference between them is the whole point:
   *   Highlight ACCENTS matches and hides NOTHING.
   *   Filter    DIMS non-matches and prunes the findings list.
   * A node matches if the tag appears in produces ∪ creates ∪ consumes,
   * case-insensitively -- the same union the graph draws from, so what the
   * lens selects and what the wires show cannot disagree. */
  const lenses = { highlight: [], filter: [] };
  // Suggestion candidates: every tag the graph actually has. Sorted so the
  // list is stable, and deduped case-insensitively while keeping the source
  // spelling, which is what gets inserted.
  const allTags = (() => {
    const seen = new Map();
    for (const n of graph.nodes.values()) {
      for (const set of [n.produces, n.creates, n.consumes]) {
        for (const t of set) if (!seen.has(t.toLowerCase())) seen.set(t.toLowerCase(), t);
      }
    }
    return [...seen.values()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  })();
  const lensBar = el("div", "lens-bar");
  const lensChips = {};
  for (const which of ["highlight", "filter"]) {
    const box = el("div", "lens");
    box.dataset.lens = which;
    const label = el("label", "lens-label", which === "highlight" ? "Highlight" : "Filter");
    const input = el("input", "lens-input");
    input.type = "search";
    input.placeholder = "#tag";
    input.setAttribute("aria-label", `${which} by tag`);
    const id = `lens-input-${which}`;
    input.id = id;
    label.htmlFor = id;
    /* Typo-tolerant suggestions. Tag names are identifiers people retype
     * from memory, so the input is a combobox over the tags this graph
     * actually has, ranked by fuzzy.js. Enter takes the highlighted
     * SUGGESTION when there is one -- that is the "self-correcting" part --
     * and otherwise takes the literal text, because filtering on a tag this
     * graph does not contain is a legitimate thing to do (it is how you
     * confirm it is absent). */
    const listId = `lens-list-${which}`;
    const list = el("ul", "lens-suggest");
    list.id = listId;
    list.setAttribute("role", "listbox");
    list.hidden = true;
    let active = -1;
    let shown = [];

    input.setAttribute("role", "combobox");
    input.setAttribute("aria-expanded", "false");
    input.setAttribute("aria-controls", listId);
    input.setAttribute("aria-autocomplete", "list");
    input.autocomplete = "off";

    const closeList = () => {
      list.hidden = true;
      list.replaceChildren();
      input.setAttribute("aria-expanded", "false");
      input.removeAttribute("aria-activedescendant");
      active = -1;
      shown = [];
    };

    const setActive = (i) => {
      active = i;
      [...list.children].forEach((li, k) => {
        const on = k === i;
        li.classList.toggle("active", on);
        li.setAttribute("aria-selected", String(on));
      });
      if (i >= 0 && list.children[i]) {
        input.setAttribute("aria-activedescendant", list.children[i].id);
        list.children[i].scrollIntoView({ block: "nearest" });
      } else input.removeAttribute("aria-activedescendant");
    };

    const openList = (query) => {
      shown = rank(query, allTags, 8);
      if (!shown.length) { closeList(); return; }
      list.replaceChildren();
      shown.forEach((hit, i) => {
        const li = el("li", "lens-option");
        li.id = `${listId}-opt-${i}`;
        li.setAttribute("role", "option");
        li.setAttribute("aria-selected", "false");
        // Emphasise the characters that actually matched. Built with
        // createElement, never innerHTML -- a tag name is untrusted text.
        const positions = new Set(matchPositions(query, hit.value));
        if (positions.size) {
          for (let k = 0; k < hit.value.length; k++) {
            const ch = hit.value[k];
            if (positions.has(k)) li.append(el("mark", null, ch));
            else li.append(document.createTextNode(ch));
          }
        } else {
          // A typo correction has no honest per-character alignment, so it
          // is labelled instead of pretending to one.
          li.append(document.createTextNode(hit.value));
          li.append(el("span", "lens-option-why", "did you mean"));
        }
        li.addEventListener("mousedown", (e) => { e.preventDefault(); accept(hit.value); });
        list.append(li);
      });
      list.hidden = false;
      input.setAttribute("aria-expanded", "true");
      // Preselect the best match: Enter then corrects the spelling, which is
      // the whole point. Arrow keys move away from it, and Escape dismisses.
      setActive(0);
    };

    const accept = (value) => {
      if (value && !lenses[which].some((t) => t.toLowerCase() === value.toLowerCase())) {
        lenses[which].push(value);
      }
      input.value = "";
      closeList();
      renderLens(which);
      applyLenses();
    };

    const addFromInput = () => {
      const v = input.value.trim();
      if (!v) { closeList(); return; }
      // The highlighted suggestion wins; falling back to the literal text
      // keeps "filter on a tag that is not here" possible.
      accept(active >= 0 && shown[active] ? shown[active].value : v);
    };

    input.addEventListener("input", () => {
      const v = input.value.trim();
      if (v) openList(v); else closeList();
    });
    input.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown" && !list.hidden) { e.preventDefault(); setActive((active + 1) % shown.length); }
      else if (e.key === "ArrowUp" && !list.hidden) { e.preventDefault(); setActive((active - 1 + shown.length) % shown.length); }
      else if (e.key === "Enter") { e.preventDefault(); addFromInput(); }
      else if (e.key === "Escape" && !list.hidden) { e.preventDefault(); e.stopPropagation(); closeList(); }
    });
    // Commit on blur, but only a literal -- silently applying a CORRECTION
    // the user never looked at is how an autocomplete earns distrust.
    input.addEventListener("blur", () => {
      const v = input.value.trim();
      closeList();
      if (v) accept(v);
    });
    // Drop target: chips drag out of the inspector into a lens. Click and
    // Shift+click do the same thing, so this is never pointer-only.
    box.addEventListener("dragover", (e) => { e.preventDefault(); box.classList.add("drop"); });
    box.addEventListener("dragleave", () => box.classList.remove("drop"));
    box.addEventListener("drop", (e) => {
      e.preventDefault();
      box.classList.remove("drop");
      const tag = e.dataTransfer.getData("text/plain");
      if (!tag) return;
      if (!lenses[which].some((t) => t.toLowerCase() === tag.toLowerCase())) lenses[which].push(tag);
      renderLens(which);
      applyLenses();
    });
    const chips = el("div", "lens-chips");
    lensChips[which] = chips;
    box.append(label, input, list, chips);
    lensBar.append(box);
  }
  const lensNote = el("div", "lens-note");
  lensNote.hidden = true;
  lensBar.append(lensNote);
  // Everything that ACTS on the report (lenses, panel toggles, Share) sits
  // in one right-aligned group, so the header reads title | key | controls
  // and wraps as a unit on a narrow window.
  const tools = el("div", "report-tools");
  tools.append(lensBar);

  function renderLens(which) {
    const box = lensChips[which];
    box.replaceChildren();
    lenses[which].forEach((tag, i) => {
      const chip = el("span", "chip-in-lens");
      chip.append(el("span", "chip-label", tag));   // untrusted text -- never markup
      const x = el("button", "chip-x", "✕");
      x.type = "button";
      x.title = `Remove ${tag}`;
      x.setAttribute("aria-label", `Remove ${tag} from ${which}`);
      x.addEventListener("click", () => { lenses[which].splice(i, 1); renderLens(which); applyLenses(); });
      chip.append(x);
      box.append(chip);
    });
  }

  const nodeTouchesTag = (name, folded) => {
    const n = graph.nodes.get(name);
    if (!n) return false;
    for (const set of [n.produces, n.creates, n.consumes]) {
      for (const t of set) if (t.toLowerCase() === folded) return true;
    }
    return false;
  };
  /** null = this lens is empty, so it has no opinion. */
  const nodeMatchesLens = (name, which) => {
    const tags = lenses[which];
    if (!tags.length) return null;
    return tags.some((t) => nodeTouchesTag(name, t.toLowerCase()));
  };

  function applyLenses() {
    const surviving = new Set();
    for (const [name, g] of nodeEls) {
      const hl = nodeMatchesLens(name, "highlight");
      const fl = nodeMatchesLens(name, "filter");
      g.classList.toggle("lens-hit", hl === true);
      g.classList.toggle("lens-dim", fl === false);
      if (fl !== false) surviving.add(name);
    }
    // An edge belongs to the view only if BOTH ends survive: a wire with one
    // end suppressed points into blank space.
    for (const e of edgeEls) {
      e.el.classList.toggle("lens-dim", !(surviving.has(e.from) && surviving.has(e.to)));
    }

    // The findings list follows the FILTER lens only. Highlight is an
    // emphasis, and quietly dropping findings for an emphasis would hide
    // warnings nobody asked to stop seeing -- the same no-silent-suppression
    // rule --target obeys (V28).
    const filtering = lenses.filter.length > 0;
    let hidden = 0;
    rows.forEach((row, i) => {
      const f = findings[i];
      let keep = true;
      if (filtering) {
        // A finding ABOUT a lensed tag stays even when it is anchored
        // somewhere the lens does not reach -- D2's "consumed but produced
        // nowhere" is exactly the finding you dragged the tag out for, and
        // its whole point is that NO node produces it.
        const aboutTag = f.tag && lenses.filter.some((t) => t.toLowerCase() === f.tag.toLowerCase());
        keep = !!aboutTag || (f.node ? nodeMatchesLens(f.node, "filter") === true : false);
      }
      row.dataset.lensHidden = keep ? "" : "1";
      if (!keep) hidden++;
      applyRowVisibility(row, i);
    });
    if (filtering) {
      // V28's discipline applied to a UI control: never suppress a finding
      // silently. Say how many the lens is holding back.
      lensNote.textContent = `${hidden} finding(s) hidden by the filter`;
      lensNote.hidden = false;
    } else {
      lensNote.hidden = true;
    }
  }

  const toggleFindings = mkToggle("Findings", "Show or hide the findings list");
  const toggleDetails = mkToggle("Details", "Show or hide the inspector for the selected node");
  tools.append(toggles);

  // V60: one toggle restores everything the guard lens dimmed. Present only
  // when the lens dimmed something -- a control with nothing to do is noise.
  const showInactive = el("button", "toggle solo", "Show inactive");
  showInactive.type = "button";
  showInactive.title = "Undim the nodes, lanes and findings whose guards are false under these options";
  showInactive.setAttribute("aria-pressed", "false");
  showInactive.hidden = !lensHasEffect;
  showInactive.addEventListener("click", () => {
    const on = !root.classList.contains("show-inactive");
    root.classList.toggle("show-inactive", on);
    showInactive.classList.toggle("on", on);
    showInactive.setAttribute("aria-pressed", String(on));
  });
  tools.append(showInactive);

  // Slot for the shell's Options control (T72): render.js knows the option
  // list is in the result but not how to re-run the analysis -- app.js does.
  const optionsSlot = el("div", "report-options");
  tools.append(optionsSlot);

  // T64: an empty slot for the shell's Share control. This module knows
  // nothing about `files` or the share codec on purpose (V46) -- app.js is
  // the one holding the file set, so app.js is the one that fills this in
  // after renderReport returns. Keeping it a bare, styled slot (rather than
  // a stub button) means a report rendered without a filler here just shows
  // no share affordance, which is also what V55 wants when deflate-raw is
  // unsupported.
  const actions = el("div", "report-actions");
  tools.append(actions);
  header.append(tools);

  root.append(header);

  // A slot for notices the SHELL owns -- missing or tail-matched includes.
  // render.js knows nothing about the pick (V46), so app.js fills it in
  // after renderReport returns, the same way it fills the Share slot.
  const notices = el("div", "report-notices");
  notices.hidden = true;
  root.append(notices);

  /* ------------------------------------------------------------ body ---- */
  const body = el("div", "report-body");
  root.append(body);

  // findings panel
  const panel = el("aside", "findings-panel");
  const filters = el("div", "filter-row");
  let severityFloor = Severity.INFO;
  const chips = [];
  // Each chip carries its own count, so the tally lives in exactly one place
  // (the header legend is a colour key only). `aria-pressed` because "which
  // filter is on" is state a screen reader needs as much as the eye does.
  const chipCount = { "All": findings.length, "Warn+": counts.warn + counts.error, "Errors": counts.error };
  for (const [label, floor] of [["All", Severity.INFO], ["Warn+", Severity.WARN], ["Errors", Severity.ERROR]]) {
    const chip = el("button", "chip");
    chip.type = "button";
    chip.append(el("span", "chip-label", label), el("span", "chip-count", chipCount[label]));
    chip.setAttribute("aria-pressed", "false");
    chip.addEventListener("click", () => {
      severityFloor = floor;
      chips.forEach((c) => {
        const on = c === chip;
        c.classList.toggle("on", on);
        c.setAttribute("aria-pressed", String(on));
      });
      applyFilter();
    });
    chips.push(chip);
    filters.append(chip);
  }
  chips[0].classList.add("on");
  chips[0].setAttribute("aria-pressed", "true");
  panel.append(filters);
  // V60: findings on inactive nodes are dimmed below, and the count is said
  // here -- a dim with no number next to it is a quiet suppression.
  const inactiveFindings = findings.filter((f) => f.node && nodeState(f.node) === "inactive").length;
  if (inactiveFindings) {
    panel.append(el("div", "activity-note",
      `${inactiveFindings} finding${inactiveFindings === 1 ? "" : "s"} on nodes inactive under these options (dimmed, not hidden)`));
  }

  const list = el("div", "findings-list");
  const rows = findings.map((f, i) => {
    const row = el("div", `finding sev-${severityName(f.severity)}`);
    row.dataset.index = String(i);
    if (f.node && nodeState(f.node) === "inactive") row.classList.add("inactive");
    const head = el("div", "finding-head");
    head.append(el("span", `finding-sev sev-${severityName(f.severity)}`, severityName(f.severity)));
    head.append(el("span", "finding-det", f.detector));
    head.append(el("span", "finding-loc", `${f.file.split("/").pop()}:${f.line}`));
    row.append(head);
    row.append(el("div", "finding-msg", f.message));
    // A row is a control, so it is reachable without a pointer: focusable,
    // announced as a button, and Enter/Space do what a click does. The
    // `current` class marks the one just picked, so the eye can find it
    // again after the list re-sorts around a selection.
    row.tabIndex = 0;
    row.setAttribute("role", "button");
    const activate = () => {
      rows.forEach((r) => r.classList.toggle("current", r === row));
      if (f.node && graph.nodes.has(f.node)) selectNode(f.node);
      revealLine(f.file, f.line);
    };
    row.addEventListener("click", activate);
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); activate(); }
    });
    list.append(row);
    return row;
  });
  if (!findings.length) list.append(el("div", "empty", "No findings. Under its default options this script is clean."));
  panel.append(list);
  body.append(panel);

  /** ONE decision point for whether a finding row is visible. Two
   *  independent removers (severity floor, filter lens) writing `hidden`
   *  separately would fight, and the loser would look like a bug. */
  const applyRowVisibility = (row, i) => {
    row.hidden = findings[i].severity < severityFloor || row.dataset.lensHidden === "1";
  };
  const applyFilter = () => rows.forEach((row, i) => applyRowVisibility(row, i));

  /* ------------------------------------------------------------ tabs ---- */
  const main = el("div", "report-main");
  const tabstrip = el("div", "tabstrip");
  tabstrip.setAttribute("role", "tablist");
  tabstrip.setAttribute("aria-label", "Report view");
  const tabGraph = el("button", "tab on", "Graph");
  const tabSource = el("button", "tab", "Source");
  tabGraph.type = "button"; tabSource.type = "button";
  tabGraph.id = "tab-graph"; tabSource.id = "tab-source";
  for (const [tab, on] of [[tabGraph, true], [tabSource, false]]) {
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-selected", String(on));
  }
  tabstrip.append(tabGraph, tabSource);
  main.append(tabstrip);

  const graphArea = el("div", "graph-area");
  const sourceArea = el("div", "source-area");
  for (const [pane, tab] of [[graphArea, tabGraph], [sourceArea, tabSource]]) {
    pane.setAttribute("role", "tabpanel");
    pane.setAttribute("aria-labelledby", tab.id);
  }
  sourceArea.hidden = true;
  main.append(graphArea, sourceArea);
  body.append(main);

  /* --------------------------------------------------------- details ---- */
  // The inspector. Answers "what IS this node", which the graph can only
  // gesture at: a box shows that an edge exists, not which tag rode along it.
  const details = el("aside", "details-panel");
  const detailsBody = el("div", "details-body");
  details.append(detailsBody);
  body.append(details);

  const renderDetails = (name) => {
    detailsBody.replaceChildren();
    if (!name || !graph.nodes.has(name)) {
      detailsBody.append(el("div", "empty",
        "Nothing selected. Click a node in the graph, or a finding in the list, " +
        "to see what it produces, consumes and requires."));
      return;
    }
    const node = graph.nodes.get(name);
    detailsBody.append(el("h3", "details-title", name));

    const meta = el("dl", "details-meta");
    const pair = (k, v, onClick) => {
      meta.append(el("dt", null, k));
      const dd = el("dd", onClick ? "linky" : null, v);
      if (onClick) {
        dd.tabIndex = 0;
        dd.addEventListener("click", onClick);
        dd.addEventListener("keydown", (e) => { if (e.key === "Enter") onClick(); });
      }
      meta.append(dd);
    };
    pair("Agent", node.agent || "(none)");
    const [s0, s1] = node.lineSpan;
    pair("Source", `${node.file.split("/").pop()}:${s0}${s1 > s0 ? `-${s1}` : ""}` +
         (linkedNodes.has(name) ? ` · included file ${node.file}` : ""),
         () => { setTab("source"); revealLine(node.file, s0); });
    detailsBody.append(meta);

    // Every list is shown even when EMPTY, saying so. "Consumes: none" is a
    // fact the reader wants; a section that silently disappears reads as a
    // rendering gap and sends them back to the source to check.
    const section = (label, items, kind) => {
      const box = el("section", "details-sec");
      box.append(el("h4", null, `${label} (${items.length})`));
      if (!items.length) box.append(el("div", "none", "none"));
      else {
        const wrap = el("div", "chips");
        for (const item of items) {
          const chipEl = el("span", `tagchip ${kind}`, item);
          // Tag chips drag INTO a lens. Drag is the pleasant path, but it is
          // never the only one: Shift+click adds to Highlight, Ctrl/Cmd+click
          // to Filter -- a pointer-only affordance excludes people who do not
          // use one.
          if (kind === "produces" || kind === "creates" || kind === "consumes") {
            chipEl.draggable = true;
            chipEl.addEventListener("dragstart", (e) => e.dataTransfer.setData("text/plain", item));
            chipEl.title = "Drag into a lens, or Shift+click to highlight, Ctrl+click to filter";
            chipEl.addEventListener("click", (e) => {
              if (!e.shiftKey && !e.ctrlKey && !e.metaKey) return;
              e.preventDefault();
              e.stopPropagation();
              const which = (e.ctrlKey || e.metaKey) ? "filter" : "highlight";
              if (!lenses[which].some((t) => t.toLowerCase() === item.toLowerCase())) lenses[which].push(item);
              renderLens(which);
              applyLenses();
            });
          }
          // A token naming a node is clickable -- following a dependency is
          // the reason anyone opens this panel.
          const targets = graph.resolveRef(item);
          if (targets.length === 1 && graph.nodes.has(targets[0])) {
            chipEl.classList.add("linky");
            chipEl.tabIndex = 0;
            chipEl.title = `Go to ${targets[0]}`;
            const go = () => selectNode(targets[0]);
            chipEl.addEventListener("click", go);
            chipEl.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
          }
          wrap.append(chipEl);
        }
        box.append(wrap);
      }
      detailsBody.append(box);
    };
    section("Produces", [...node.produces].sort(), "produces");
    section("Creates", [...node.creates].sort(), "creates");
    section("Consumes", [...node.consumes].sort(), "consumes");
    section("Requires", node.requires, "requires");
    section("After", node.after, "after");

    // Conditions (§G's third invisible semantic). The analyser already knows
    // each guard's D12 verdict; the page simply never showed them, so a node
    // that can NEVER run looked exactly like one that always does.
    const conds = conditionsByNode.get(name) || [];
    const nodeAct = act.nodes.get(name) || { state: "active", guards: [] };
    const inherited = nodeAct.guards.filter((g) => g.owner !== "node");
    const cbox = el("section", "details-sec");
    cbox.append(el("h4", null, `Conditions (${conds.length + inherited.length})`));
    // The node's standing under THIS option-set, before the guards that
    // decide it. Active is the unremarkable case and says nothing.
    if (nodeAct.state !== "active") {
      cbox.append(el("div", `activity-state state-${nodeAct.state}`,
        nodeAct.state === "inactive" ? "Inactive under these options" : "Undecidable under these options"));
    }
    const NOW_HELP = {
      active: "true under these option values",
      inactive: "false under these option values",
      unknown: "cannot be decided under these values: an Exists(), an unexpanded reference, or a condition the parser rejects",
    };
    const nowChip = (verdict) => {
      const s = el("span", `cond-now now-${verdict}`, verdict === "active" ? "true" : verdict === "inactive" ? "false" : "unknown");
      s.title = NOW_HELP[verdict];
      return s;
    };
    if (!conds.length && !inherited.length) cbox.append(el("div", "none", "none"));
    else {
      // Own guards: D12's all-option-sets verdict, then the verdict NOW.
      const ownGuards = nodeAct.guards.filter((g) => g.owner === "node");
      for (const c of conds) {
        const row = el("div", `cond verdict-${c.verdict}`);
        // A guard on a TASK inside the node gates that task, not the node;
        // it is listed, labelled, and carries no activity verdict.
        if (!c.own) row.append(el("span", "cond-owner", `on task <${c.tag}> at line ${c.line}`));
        row.append(el("code", "cond-text", c.text));
        row.append(el("span", "cond-verdict", c.verdict));
        const g = c.own ? ownGuards.find((x) => x.raw === c.text) : null;
        if (g) row.append(nowChip(g.verdict));
        row.title = VERDICT_HELP[c.verdict] || c.verdict;
        cbox.append(row);
      }
      // Inherited guards: the Agent, Do, Case or Include this node sits in.
      for (const g of inherited) {
        const row = el("div", "cond inherited");
        row.append(el("span", "cond-owner", `from ${g.owner}`));
        row.append(el("code", "cond-text", g.raw));
        row.append(nowChip(g.verdict));
        cbox.append(row);
      }
    }
    detailsBody.append(cbox);

    const own = byNode.get(name) || [];
    const fbox = el("section", "details-sec");
    fbox.append(el("h4", null, `Findings (${own.length})`));
    if (!own.length) fbox.append(el("div", "none", "none"));
    else {
      for (const i of own) {
        const f = findings[i];
        const line = el("div", `details-finding sev-${severityName(f.severity)}`);
        line.append(el("span", `finding-sev sev-${severityName(f.severity)}`, severityName(f.severity)));
        line.append(el("span", "finding-det", f.detector));
        line.append(el("span", "details-finding-msg", f.message));
        line.addEventListener("click", () => { setTab("source"); revealLine(f.file, f.line); });
        fbox.append(line);
      }
    }
    detailsBody.append(fbox);
  };
  renderDetails(null);

  /* ---- T54: resizable panels -----------------------------------------
   * Floor 180px so a panel can never be dragged into uselessness; ceiling
   * min(720, 50vw) so one panel cannot swallow the window. `role="separator"`
   * with aria-value*, and arrow keys work -- a drag-only affordance excludes
   * anyone not using a pointer, which is the same objection as a
   * hover-only tooltip. */
  const PANEL_MIN = 180;
  const panelMax = () => Math.max(PANEL_MIN, Math.min(720, window.innerWidth * 0.5));

  const addResizer = (panelEl, side) => {
    const sep = el("div", `resizer resizer-${side}`);
    sep.setAttribute("role", "separator");
    sep.setAttribute("aria-orientation", "vertical");
    sep.setAttribute("aria-label", `Resize the ${side === "left" ? "findings" : "details"} panel`);
    sep.tabIndex = 0;
    const setW = (px) => {
      const w = Math.min(panelMax(), Math.max(PANEL_MIN, px));
      panelEl.style.width = `${w}px`;
      sep.setAttribute("aria-valuenow", String(Math.round(w)));
      sep.setAttribute("aria-valuemin", String(PANEL_MIN));
      sep.setAttribute("aria-valuemax", String(Math.round(panelMax())));
    };
    setW(panelEl.getBoundingClientRect().width || (side === "left" ? 340 : 320));

    let dragging = false;
    sep.addEventListener("pointerdown", (e) => {
      dragging = true; sep.setPointerCapture(e.pointerId); e.preventDefault();
      document.body.classList.add("resizing");
    });
    sep.addEventListener("pointermove", (e) => {
      if (!dragging) return;
      const r = panelEl.getBoundingClientRect();
      setW(side === "left" ? e.clientX - r.left : r.right - e.clientX);
    });
    const stop = () => { dragging = false; document.body.classList.remove("resizing"); };
    sep.addEventListener("pointerup", stop);
    sep.addEventListener("pointercancel", stop);
    sep.addEventListener("keydown", (e) => {
      const step = e.shiftKey ? 40 : 12;
      const cur = panelEl.getBoundingClientRect().width;
      if (e.key === "ArrowLeft") { e.preventDefault(); setW(cur + (side === "left" ? -step : step)); }
      else if (e.key === "ArrowRight") { e.preventDefault(); setW(cur + (side === "left" ? step : -step)); }
    });
    panelEl.append(sep);
  };
  addResizer(panel, "left");
  addResizer(details, "right");

  const setPanel = (btn, node_, on) => {
    btn.classList.toggle("on", on);
    btn.setAttribute("aria-pressed", String(on));
    node_.hidden = !on;
  };
  toggleFindings.addEventListener("click", () =>
    setPanel(toggleFindings, panel, panel.hidden));
  toggleDetails.addEventListener("click", () =>
    setPanel(toggleDetails, details, details.hidden));

  let pendingScroll = null;   // scrollIntoView is a no-op inside display:none,
                              // so a reveal requested from the graph tab is
                              // OWED and paid when Source is next shown.
  // T35: the Source tab STASHES both panels and restores them
  // INDEPENDENTLY -- the code column wants the width, and a gutter mark is
  // read next to its line, not next to a findings list. A manual toggle made
  // while on Source OUTRANKS the stash, so returning to the graph does not
  // undo what the user just asked for.
  let stashed = null;
  const setTab = (which) => {
    const isGraph = which === "graph";
    tabGraph.classList.toggle("on", isGraph);
    tabSource.classList.toggle("on", !isGraph);
    tabGraph.setAttribute("aria-selected", String(isGraph));
    tabSource.setAttribute("aria-selected", String(!isGraph));
    graphArea.hidden = !isGraph;
    sourceArea.hidden = isGraph;

    // T40: the legend swaps with the tab. It used to live inside the graph
    // area, so it vanished wholesale on Source -- exactly when a key for the
    // gutter tints is wanted.
    legendGraph.hidden = !isGraph;
    legendSource.hidden = isGraph;

    if (!isGraph) {
      if (!stashed) {
        stashed = { findings: panel.hidden, details: details.hidden };
        setPanel(toggleFindings, panel, false);
        setPanel(toggleDetails, details, false);
        panel.hidden = true; toggleFindings.classList.remove("on");
        toggleFindings.setAttribute("aria-pressed", "false");
        details.hidden = true; toggleDetails.classList.remove("on");
        toggleDetails.setAttribute("aria-pressed", "false");
      }
      if (pendingScroll) { pendingScroll(); pendingScroll = null; }
    } else if (stashed) {
      setPanel(toggleFindings, panel, !stashed.findings);
      setPanel(toggleDetails, details, !stashed.details);
      stashed = null;
    }
  };
  tabGraph.addEventListener("click", () => setTab("graph"));
  tabSource.addEventListener("click", () => setTab("source"));

  /* ----------------------------------------------------------- graph ---- */
  const canvas = svg("svg", { class: "graph", width: L.width, height: L.height,
                              viewBox: `0 0 ${L.width} ${L.height}` });
  const defs = svg("defs");
  for (const [id, cls] of [["arrow-dataflow", "dataflow"], ["arrow-order", "order"]]) {
    const marker = svg("marker", { id, viewBox: "0 0 10 10", refX: 9, refY: 5,
                                   markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" });
    marker.append(svg("path", { d: "M 0 0 L 10 5 L 0 10 z", class: `arrowhead ${cls}` }));
    defs.append(marker);
  }
  canvas.append(defs);

  const laneLayer = svg("g", { class: "lanes" });
  const edgeLayer = svg("g", { class: "edges" });
  const nodeLayer = svg("g", { class: "nodes" });
  canvas.append(laneLayer, edgeLayer, nodeLayer);
  const edgeEls = [];
  const nodeEls = new Map();

  /** Draw (or redraw) lanes, edges and nodes from the current collapse state.
   *  Collapsing changes the LAYOUT, not just visibility -- a folded lane
   *  gives its vertical space back -- so this re-runs layout() rather than
   *  hiding elements in place. */
  function drawGraph() {
    L = layout(graph, warnNodes, collapsed, linkedNodes);
    canvas.setAttribute("width", L.width);
    canvas.setAttribute("height", L.height);
    canvas.setAttribute("viewBox", `0 0 ${L.width} ${L.height}`);

      laneLayer.replaceChildren();
    for (const lane of L.lanes) {
      const laneState = agentState(lane.name);
      const g = svg("g", { class: "lane" + (laneState !== "active" ? ` ${laneState}` : "") });
      g.append(svg("rect", { class: "lane-bg", x: 2, y: lane.y, width: L.width - 4, height: lane.height, rx: 6 }));
      // x=26 leaves the caret its own column: at 14 the glyph ran into the
      // first letter of the lane name. A lane with nodes from an included
      // file carries the link glyph there, and the name steps right of it.
      const linkedFiles = laneLinkedFiles.get(lane.name || "") || new Set();
      const labelX = linkedFiles.size ? 42 : 26;
      if (linkedFiles.size) g.append(fileMark(24, lane.y + 11, "lane-filemark"));
      const label = svg("text", { class: "lane-label", x: labelX, y: lane.y + 21 });
      label.textContent = lane.name || "(no agent)";
      g.append(label);
      // A collapsed lane still reports its node COUNT. That is what keeps
      // folding honest -- the graph says how much is hidden rather than
      // quietly shrinking.
      // The header is a BAND across the top of the lane now, not a left
      // gutter, so the count sits beside the name rather than beneath it.
      const meta = svg("text", { class: "lane-meta", x: labelX + Math.max(90, (lane.name || "(no agent)").length * 6.8),
                                 y: lane.y + 21 });
      const fromFiles = linkedFiles.size === 0 ? ""
        : linkedFiles.size === 1 ? ` · from ${[...linkedFiles][0]}`
        : ` · from ${linkedFiles.size} included files`;
      meta.textContent = `${lane.count} node${lane.count === 1 ? "" : "s"}` +
                         (lane.collapsed ? " (collapsed)" : "") +
                         fromFiles +
                         (laneState === "inactive" ? " · inactive under these options"
                           : laneState === "unknown" ? " · guard undecidable" : "");
      g.append(meta);

      // The whole header row is the hit target, with a caret that says which
      // way it goes. Keyboard-reachable, and aria-expanded so it is not a
      // pointer-only affordance.
      // The whole header band is the hit target -- a caret alone is a
      // needlessly small thing to ask someone to hit.
      const hit = svg("rect", { class: "lane-toggle", x: 2, y: lane.y,
                                width: Math.max(L.width - 4, 4), height: LANE_HEADER_BAND,
                                rx: 5, tabindex: 0, role: "button" });
      hit.setAttribute("aria-expanded", String(!lane.collapsed));
      const caret = svg("text", { class: "lane-caret", x: 10, y: lane.y + 21 });
      caret.textContent = lane.collapsed ? "▸" : "▾";
      const laneName = lane.name;
      const toggle = () => {
        if (collapsed.has(laneName)) collapsed.delete(laneName); else collapsed.add(laneName);
        drawGraph();
        // A redraw builds new elements, so the selection has to be re-applied
        // rather than assumed to have survived.
        applyLenses();   // new elements -- the lens must be re-applied to them
        if (selected && nodeEls.has(selected)) selectNode(selected);
      };
      hit.addEventListener("click", (e) => { e.stopPropagation(); toggle(); });
      hit.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
      });
      const laneTitle = svg("title");
      const laneConds = conditionsByAgent.get(lane.name) || [];
      // Guards that sit OUTSIDE any node belong to the lane, not to a box.
      const NL = String.fromCharCode(10);
      const guardLines = laneConds.map((c) => `  If="${c.text}"  [${c.verdict}]`);
      laneTitle.textContent =
        `${lane.name || "(no agent)"} - ${lane.count} node(s). Click to ${lane.collapsed ? "expand" : "collapse"}.`
        + (linkedFiles.size ? NL + "Nodes from included file(s): " + [...linkedFiles].join(", ") : "")
        + (guardLines.length ? NL + NL + "Guards outside any node:" + NL + guardLines.join(NL) : "");
      // The band goes UNDER the name and count: it has a fill now (it reads
      // as a header row), and appended last it would paint over them. The
      // caret and tooltip ride on top.
      g.insertBefore(hit, label);
      g.append(caret, laneTitle);
      laneLayer.append(g);
    }
  

      edgeLayer.replaceChildren();
      edgeEls.length = 0;
    for (const e of L.edges) {
      const a = L.nodePos.get(e.from), b = L.nodePos.get(e.to);
      if (!a || !b) continue;
      const p = svg("path", { class: `edge ${e.kind}`, d: edgePath(a, b),
                              "marker-end": `url(#arrow-${e.kind})` });
      // A wire with an inactive end goes to a box that will not run (V60).
      if (nodeState(e.from) === "inactive" || nodeState(e.to) === "inactive") p.classList.add("inactive");
      edgeLayer.append(p);
      edgeEls.push({ el: p, ...e });
    }
  

      nodeLayer.replaceChildren();
      nodeEls.clear();
    for (const [name, pos] of L.nodePos) {
      const sevCls = worstByNode.has(name) ? ` warn sev-${severityName(worstByNode.get(name))}` : "";
      const st = nodeState(name);
      const g = svg("g", { class: "node" + sevCls + (st !== "active" ? ` ${st}` : ""), tabindex: 0, role: "button" });
      g.append(svg("rect", { class: "node-box", x: pos.x, y: pos.y, width: pos.w, height: pos.h, rx: 5 }));
      // The link glyph sits where the name used to start; layout.js widened
      // the box by the same amount, so the name steps right unclipped.
      const linked = linkedNodes.has(name);
      if (linked) g.append(fileMark(pos.x + 8, pos.y + (pos.h - 12) / 2, "node-filemark"));
      const t = svg("text", { class: "node-label", x: pos.x + 10 + (linked ? 16 : 0), y: pos.y + pos.h / 2 + 4 });
      t.textContent = name;                        // never innerHTML -- V8 by construction
      g.append(t);
      // Warn/error badge. Top-RIGHT because the label is left-aligned and
      // boxWidth() reserves its 18px there; a left-corner badge would print
      // over the node's own name. Drawn AFTER the label so it is never
      // overpainted by a long one.
      if (worstByNode.has(name)) {
        const sev = severityName(worstByNode.get(name));
        const own = (byNode.get(name) || []).filter((i) => findings[i].severity >= Severity.WARN);
        const bx = pos.x + pos.w - 8;
        const by = pos.y + 8;
        g.append(svg("circle", { class: `node-badge sev-${sev}`, cx: bx, cy: by, r: 7 }));
        const mark = svg("text", { class: "node-badge-text", x: bx, y: by + 3.5, "text-anchor": "middle" });
        mark.textContent = sev === "error" ? "×" : "!";
        g.append(mark);
        const btip = svg("title");
        btip.textContent = own.map((i) => `${severityName(findings[i].severity)}: [${findings[i].detector}] ${findings[i].message}`)
                              .join(String.fromCharCode(10));
        g.append(btip);
      }

      const title = svg("title");
      const node = graph.nodes.get(name);
      title.textContent = `${name}\nagent: ${node.agent || "(none)"}\n` +
        (linked ? `from included file ${node.file}:${node.line}` : `${node.file.split("/").pop()}:${node.line}`);
      if (st !== "active") {
        // Say WHY it is dimmed, in the tooltip, with the guards that did it.
        const why = (act.nodes.get(name) || { guards: [] }).guards
          .filter((gd) => gd.verdict === st)
          .map((gd) => `  ${gd.owner === "node" ? "" : `(${gd.owner}) `}If="${gd.raw}"`);
        title.textContent += `\n${st === "inactive" ? "inactive" : "undecidable"} under these options:\n${why.join("\n")}`;
      }
      g.append(title);
      g.addEventListener("click", (e) => { e.stopPropagation(); selectNode(name); });
      g.addEventListener("dblclick", (e) => {
        e.stopPropagation();
        setTab("source");
        revealLine(node.file, node.line);
      });
      g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectNode(name); } });
      nodeLayer.append(g);
      nodeEls.set(name, g);
    }
  
  }
  drawGraph();
  graphArea.append(canvas);

  /* ------------------------------------------------- pan / zoom --------- */
  let zoomLevel = ZOOM_DEFAULT_LEVEL;
  let zoom = ZOOM_LEVELS[zoomLevel][0];
  let panX = 0, panY = 0;
  let zoomLabel = null;   // the toolbar's level readout, created further down
  const applyTransform = () => {
    canvas.style.transform = `translate(${panX}px, ${panY}px) scale(${zoom})`;
    canvas.style.transformOrigin = "0 0";
    if (zoomLabel) zoomLabel.textContent = ZOOM_LEVELS[zoomLevel][1];
  };
  /** Move by whole zoom LEVELS, anchored on a point (R35).
   *
   * Two Unreal behaviours reproduced deliberately:
   *   - the wheel alone cannot go past 1:1. Zooming OUT is never limited;
   *     going beyond 1:1 needs the Ctrl limit-break. Without that ceiling a
   *     stray scroll blows a readable graph up to 2x and the user has to
   *     hunt their way back.
   *   - the anchor point stays under the cursor, which is what makes this
   *     feel like moving a map rather than dragging a slider.
   */
  const zoomTo = (level, anchorX, anchorY, allowBeyondOneToOne) => {
    const ceiling = allowBeyondOneToOne ? ZOOM_LEVELS.length - 1 : ZOOM_DEFAULT_LEVEL;
    const next = Math.max(0, Math.min(ceiling, level));
    if (next === zoomLevel) return;
    const z = ZOOM_LEVELS[next][0];
    panX = anchorX - ((anchorX - panX) / zoom) * z;
    panY = anchorY - ((anchorY - panY) / zoom) * z;
    zoomLevel = next;
    zoom = z;
    applyTransform();
  };

  graphArea.addEventListener("wheel", (e) => {
    e.preventDefault();
    const rect = graphArea.getBoundingClientRect();
    // One LEVEL per notch, rounded away from zero so a trackpad's fractional
    // deltas still move exactly one stop rather than none.
    const step = e.deltaY < 0 ? 1 : -1;
    zoomTo(zoomLevel + step, e.clientX - rect.left, e.clientY - rect.top, e.ctrlKey);
  }, { passive: false });

  let dragging = null;
  graphArea.addEventListener("pointerdown", (e) => {
    // Right or middle drag pans, matching Unreal. Left-drag is left alone so
    // it can stay a plain click on a node.
    if (e.button !== 2 && e.button !== 1) return;
    e.preventDefault();
    dragging = { x: e.clientX, y: e.clientY };
    graphArea.setPointerCapture(e.pointerId);
    graphArea.classList.add("panning");   // grabbing cursor only WHILE panning
  });
  graphArea.addEventListener("pointermove", (e) => {
    if (!dragging) return;
    panX += e.clientX - dragging.x;
    panY += e.clientY - dragging.y;
    dragging = { x: e.clientX, y: e.clientY };
    applyTransform();
  });
  const endDrag = () => { dragging = null; graphArea.classList.remove("panning"); };
  graphArea.addEventListener("pointerup", endDrag);
  graphArea.addEventListener("pointercancel", endDrag);
  graphArea.addEventListener("contextmenu", (e) => e.preventDefault());
  graphArea.addEventListener("click", (e) => { if (e.target === graphArea || e.target === canvas) clearSelection(); });

  const fit = () => {
    const rect = graphArea.getBoundingClientRect();
    if (!rect.width || !L.width) return;
    // ZoomToLocation's rule, not "nearest stop": walk UP the table and take
    // the one BEFORE the first that does not fit, both axes, never past 1:1.
    // GetNearestZoomLevel rounds up and overshoots -- measured, a Fit built
    // on it left a scrollbar.
    zoomLevel = fitZoomLevel(L.width, L.height, rect.width - 24, rect.height - 24);
    zoom = ZOOM_LEVELS[zoomLevel][0];
    // Centred, not pinned to the corner: a small graph in a wide pane reads
    // as the subject of the view rather than something left at the origin.
    panX = Math.max(12, Math.round((rect.width - L.width * zoom) / 2));
    panY = Math.max(12, Math.round((rect.height - L.height * zoom) / 2));
    applyTransform();
  };

  /* ---- zoom toolbar ----------------------------------------------------
   * The wheel and right-drag are the fast path, but they are invisible: a
   * reader who has never used Unreal has no way to discover either. The
   * buttons make zoom visible and keyboard-reachable, the readout is
   * Unreal's own zoom-stop name (R35), and the hint names the gestures.
   * Buttons zoom about the CENTRE of the view, which is where the eye is
   * when there is no cursor position to anchor on. */
  const toolbar = el("div", "graph-toolbar");
  toolbar.setAttribute("role", "toolbar");
  toolbar.setAttribute("aria-label", "Graph zoom");
  const mkZoomBtn = (text, title, onClick) => {
    const b = el("button", "zoom-btn", text);
    b.type = "button";
    b.title = title;
    b.setAttribute("aria-label", title);
    b.addEventListener("click", onClick);
    return b;
  };
  const viewCentre = () => {
    const r = graphArea.getBoundingClientRect();
    return [r.width / 2, r.height / 2];
  };
  zoomLabel = el("span", "zoom-level", ZOOM_LEVELS[zoomLevel][1]);
  zoomLabel.title = "Zoom level, in Unreal's zoom stops";
  toolbar.append(
    mkZoomBtn("−", "Zoom out", () => zoomTo(zoomLevel - 1, ...viewCentre(), true)),
    zoomLabel,
    mkZoomBtn("+", "Zoom in", () => zoomTo(zoomLevel + 1, ...viewCentre(), true)),
    mkZoomBtn("Fit", "Fit the whole graph in view", fit),
  );
  graphArea.append(toolbar);
  graphArea.append(el("div", "graph-hint",
    "Scroll to zoom · right- or middle-drag to pan · click a node to inspect it, double-click to open its source"));

  /* ---------------------------------------------------------- source ---- */
  const fileNames = [...ev.sources.keys()];
  const fileBar = el("div", "file-bar");
  const codeWraps = new Map();          // one view per file
  const ALL = Symbol("all");            // the composed view: every include injected in place
  let allWrap = null;
  let currentView = fileNames.length > 1 ? ALL : entryFile;

  // Gutter marks, keyed file -> line -> finding indices. Built from the same
  // findings array the panel renders, so the two can never disagree.
  const marks = new Map();
  findings.forEach((f, i) => {
    if (!marks.has(f.file)) marks.set(f.file, new Map());
    const m = marks.get(f.file);
    if (!m.has(f.line)) m.set(f.line, []);
    m.get(f.line).push(i);
  });

  /** One source row. Every row carries its OWN file and line, because the
   *  composed view mixes files and selection/reveal address rows by both. */
  const buildRow = (file, lineNo, text) => {
    const row = el("div", "code-row");
    row.dataset.file = file;
    row.dataset.line = String(lineNo);
    const hits = (marks.get(file) || new Map()).get(lineNo) || [];
    const gutter = el("span", "gutter");
    if (hits.length) {
      // One dot per DISTINCT severity, most severe first, each owning its
      // own findings -- so three infos on a line are one blue dot listing
      // all three, not three dots.
      const bySev = new Map();
      for (const i of hits) {
        const s = severityName(findings[i].severity);
        if (!bySev.has(s)) bySev.set(s, []);
        bySev.get(s).push(findings[i]);
      }
      for (const s of ["error", "warn", "info"]) {
        if (!bySev.has(s)) continue;
        const dot = el("span", `gutter-dot sev-${s}`);
        dot.setAttribute("role", "img");
        const label = bySev.get(s).map((f) => `${s}: [${f.detector}] ${f.message}`).join("\n");
        dot.title = label;
        dot.setAttribute("aria-label", label);
        gutter.append(dot);
      }
      const worst = ["error", "warn", "info"].find((s) => bySev.has(s));
      row.classList.add(`row-${worst}`);
    } else {
      gutter.setAttribute("aria-hidden", "true");
    }
    row.append(gutter);
    row.append(el("span", "line-no", String(lineNo)));
    row.append(el("span", "code-text", text));
    return row;
  };

  for (const file of fileNames) {
    const wrap = el("div", "code-wrap");
    wrap.hidden = true;
    splitSourceLines(ev.sources.get(file)).forEach((text, idx) => wrap.append(buildRow(file, idx + 1, text)));
    codeWraps.set(file, wrap);
    sourceArea.append(wrap);
  }

  /* ---- the composed view ("All") ---------------------------------------
   * The main script with every <Include> replaced by what it pulled in,
   * recursively: what the engine reads, laid out as one document. Each call
   * becomes a header row naming the file, its guard and whether it was
   * found; the injected lines keep their OWN file and line numbers, so the
   * gutter marks, the selection span and "reveal" still land where the
   * finding says. The entry file is shown whole; an injected fragment loses
   * only its XML prolog and <BuildGraph> wrapper, which carry nothing. A
   * missing include keeps its call (there is nothing to inject), a cycle
   * stops, and depth is capped so a pathological script cannot hang. */
  const matchedTo = new Map(((includes && includes.matched) || []).map((m) => [normCase(m.requested), m.matched]));
  const sourceByNorm = new Map(fileNames.map((p) => [normCase(p), p]));
  const includesIn = new Map();   // file -> Map(line -> { endLine, rawIf, parts: [{ rel, target }] })
  for (const r of ev.resolved) {
    if (r.elem.tag !== "Include") continue;
    if (!includesIn.has(r.elem.file)) includesIn.set(r.elem.file, new Map());
    const byLine = includesIn.get(r.elem.file);
    if (!byLine.has(r.elem.line)) byLine.set(r.elem.line, { endLine: r.elem.endLine || r.elem.line, rawIf: r.rawIf, parts: [] });
    const entry = byLine.get(r.elem.line);
    // A ForEach re-emits the same <Include> once per value, possibly with a
    // different expanded path each time: one header per distinct target.
    for (const rel of splitList(r.attrs.get("Script") || "")) {
      const key = resolveInclude(r.elem.file, rel);
      const target = sourceByNorm.get(normCase(matchedTo.get(normCase(key)) || key)) || null;
      if (!entry.parts.some((p) => p.rel === rel && p.target === target)) entry.parts.push({ rel, target });
    }
  }
  const INJECT_DEPTH_CAP = 16;
  const includeHeader = (file, lineNo, part, rawIf, state, depth) => {
    const row = buildRow(file, lineNo, "");
    row.classList.add("include-head");
    if (depth > 0) { row.classList.add("injected"); row.style.setProperty("--depth", String(depth)); }
    const text = row.querySelector(".code-text");
    text.append(fileMark(0, 0, "head-filemark"));
    text.append(el("span", "head-path", part.target || part.rel));
    const note = state === "missing" ? "not in the pick, so the call stays a call"
      : state === "cycle" ? "already being included above (a cycle)"
      : state === "deep" ? "nested too deeply to inject"
      : `included here${rawIf ? ` when If="${rawIf}"` : ""}`;
    text.append(el("span", "head-note", ` — ${note}`));
    if (part.target) {
      row.classList.add("linky");
      row.title = `Open ${part.target} on its own tab`;
      row.addEventListener("click", (e) => { e.stopPropagation(); showFile(part.target); });
    }
    return row;
  };
  const isProlog = (t) => /^\s*<\?xml/.test(t);
  const composeRows = (file, depth, stack) => {
    const lines = splitSourceLines(ev.sources.get(file));
    const byLine = includesIn.get(file) || new Map();
    const out = [];
    let skipRootOpen = depth > 0;
    let i = 0;
    while (i < lines.length) {
      const lineNo = i + 1;
      const text = lines[i];
      if (depth > 0) {
        if (isProlog(text)) { i++; continue; }
        if (skipRootOpen && /<BuildGraph\b/.test(text)) {
          while (i < lines.length && !/>/.test(lines[i])) i++;   // a multi-line open tag
          i++;
          skipRootOpen = false;
          continue;
        }
        if (/^\s*<\/BuildGraph>\s*$/.test(text)) { i++; continue; }
      }
      const inc = byLine.get(lineNo);
      if (inc) {
        for (const part of inc.parts) {
          const state = !part.target ? "missing"
            : stack.includes(part.target) ? "cycle"
            : depth >= INJECT_DEPTH_CAP ? "deep" : "ok";
          out.push(includeHeader(file, lineNo, part, inc.rawIf, state, depth));
          if (state === "ok") out.push(...composeRows(part.target, depth + 1, [...stack, part.target]));
        }
        i = inc.endLine;              // past the whole <Include ...> element
        continue;
      }
      const row = buildRow(file, lineNo, text);
      if (depth > 0) { row.classList.add("injected"); row.style.setProperty("--depth", String(depth)); }
      out.push(row);
      i++;
    }
    return out;
  };
  if (fileNames.length > 1) {
    allWrap = el("div", "code-wrap code-wrap-all");
    for (const row of composeRows(entryFile, 0, [entryFile])) allWrap.append(row);
    sourceArea.append(allWrap);
    const allBtn = el("button", "file-tab all", "All");
    allBtn.type = "button";
    allBtn.title = "Every included file injected where its <Include> is: what the engine reads, as one document";
    allBtn.addEventListener("click", () => showFile(ALL));
    fileBar.append(allBtn);
  }
  for (const file of fileNames) {
    const btn = el("button", "file-tab", file.split("/").pop());
    btn.type = "button";
    btn.dataset.file = file;
    btn.title = file === entryFile ? file : `${file} (included file)`;
    if (file !== entryFile) btn.prepend(fileMark(0, 0, "tab-filemark"));
    btn.addEventListener("click", () => showFile(file));
    fileBar.append(btn);
  }
  if (fileNames.length > 1) sourceArea.prepend(fileBar);

  /** Make `view` (a file, or ALL) the visible one. Single implementation,
   *  so the file tabs, revealLine and selectNode cannot drift. */
  function showFile(view) {
    if (view === ALL && !allWrap) view = entryFile;
    if (view !== ALL && !codeWraps.has(view)) return;
    currentView = view;
    for (const [f, w] of codeWraps) w.hidden = view === ALL || f !== view;
    if (allWrap) allWrap.hidden = view !== ALL;
    fileBar.querySelectorAll(".file-tab").forEach((b) =>
      b.classList.toggle("on", view === ALL ? b.classList.contains("all") : b.dataset.file === view));
  }
  showFile(currentView);

  /** The row for file:line in whichever view holds it -- the composed view
   *  when it is up and the file was injected there, else the file's own. */
  const rowFor = (file, line) => {
    const sel = `.code-row[data-file="${CSS.escape(file)}"][data-line="${line}"]`;
    const inAll = currentView === ALL && allWrap ? allWrap.querySelector(sel) : null;
    return inAll || (codeWraps.has(file) ? codeWraps.get(file).querySelector(sel) : null);
  };

  function revealLine(file, line) {
    const row = rowFor(file, line);
    if (!row) return;
    // A row the composed view does not hold (a cycle, a depth cap, a file
    // included nowhere) is shown on the file's own tab instead.
    if (!(allWrap && allWrap.contains(row))) showFile(file);
    const go = () => {
      sourceArea.querySelectorAll(".code-row.current").forEach((r) => r.classList.remove("current"));
      row.classList.add("current");
      row.scrollIntoView({ block: "center" });
    };
    if (sourceArea.hidden) pendingScroll = go; else go();
  }

  /* -------------------------------------------------------- selection --- */
  let selected = null;

  function selectNode(name) {
    if (!graph.nodes.has(name)) return;
    selected = name;
    for (const [n, g] of nodeEls) g.classList.toggle("selected", n === name);
    // ONE visual treatment for incident edges (weight + halo). Direction
    // already reads off the arrowhead, and colour/dash are spoken for by the
    // edge KIND -- overriding them would turn an After edge into what looks
    // like proven dataflow.
    for (const e of edgeEls) {
      e.el.classList.toggle("incident", e.from === name || e.to === name);
    }
    const related = new Set(byNode.get(name) || []);
    // DIMMED, never removed: the severity filter already hides rows, and a
    // second remover would make it impossible to tell which one acted.
    rows.forEach((row, i) => row.classList.toggle("dimmed", !related.has(i)));
    // Related findings LIFT to the top -- emphasis alone is not enough when
    // the matching rows are below the fold. Rows are MOVED, not rebuilt, so
    // they keep their listeners.
    const lifted = [...related].sort((a, b) => a - b).map((i) => rows[i]);
    lifted.reverse().forEach((row) => list.prepend(row));
    list.scrollTop = 0;
    const node = graph.nodes.get(name);
    markSourceFor(node.file, related, node.lineSpan);
    renderDetails(name);

    // Show the node's OWN file, so opening Source lands on the right one --
    // a node declared in an <Include>d file is otherwise marked in a pane
    // nobody is looking at.
    // -- unless the composed view is up, where an injected node is already
    // on screen at its injection point.
    if (currentView !== ALL) showFile(node.file);

    // T35's contract: selecting MARKS, it does not TRAVEL. Yanking the tab on
    // a plain click makes the graph unusable for clicking around. But the
    // scroll still has to happen eventually, and scrollIntoView is a no-op
    // inside display:none -- so while Source is hidden the scroll is OWED,
    // and setTab pays it. Double-click is what travels.
    const first = rowFor(node.file, node.lineSpan[0]);
    if (first) {
      const go = () => first.scrollIntoView({ block: "center" });
      if (sourceArea.hidden) pendingScroll = go; else go();
    }
  }

  const originalOrder = rows.slice();

  function clearSelection() {
    selected = null;
    for (const g of nodeEls.values()) g.classList.remove("selected");
    for (const e of edgeEls) e.el.classList.remove("incident");
    rows.forEach((row) => row.classList.remove("dimmed", "current"));
    originalOrder.forEach((row) => list.append(row));   // restore captured order
    renderDetails(null);
    sourceArea.querySelectorAll(".code-row").forEach((r) =>
      r.classList.remove("muted", "current", "span", "span-start", "span-end"));
  }

  /**
   * Mark the source for a selection.
   *
   * @param file    the selected node's own file
   * @param related indices of findings belonging to it
   * @param span    [startLine, endLine] of the WHOLE <Node>...</Node> element
   *
   * The span is the part that was missing. A node is not a line, it is a
   * range -- `<Node Name="X">` through `</Node>` -- and highlighting only the
   * opening tag (or only the lines that happen to carry findings) leaves the
   * reader to work out where the node ends. `Elem.endLine` is recorded for
   * every element precisely so this does not need re-parsing.
   */
  function markSourceFor(file, related, span) {
    // Every view at once, by each row's OWN file: the composed view mixes
    // files, so the wrap a row sits in says nothing about where it is from.
    sourceArea.querySelectorAll(".code-row").forEach((row) => {
      const f = row.dataset.file;
      const line = Number(row.dataset.line);
      const hits = (marks.get(f) || new Map()).get(line) || [];
      const isRelated = hits.some((i) => related.has(i));
      // Marks that are not this node's step BACK, they do not vanish --
      // the line really does carry a finding. Never touches .code-text:
      // de-emphasis must not cost readability, which is the view's job.
      row.classList.toggle("muted", hits.length > 0 && !isRelated);

      const inSpan = f === file && span && line >= span[0] && line <= span[1];
      row.classList.toggle("span", !!inSpan);
      // First and last row get the bracket ends, so a long node reads as
      // one block with a definite beginning and end rather than a stripe
      // that might continue past the fold.
      row.classList.toggle("span-start", !!inSpan && line === span[0]);
      row.classList.toggle("span-end", !!inSpan && line === span[1]);
    });
  }

  document.addEventListener("keydown", (e) => { if (e.key === "Escape") clearSelection(); });

  requestAnimationFrame(fit);
  return { selectNode, clearSelection, fit, setTab, actions, notices, options: optionsSlot };
}
