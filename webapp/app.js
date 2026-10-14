/* bgview web shell.
 *
 * Pure ES modules, no build step, no wasm, no framework. The browser loads
 * these files as-is, which is why the site is a directory of static files a
 * host only has to serve.
 *
 * This file does no analysis. It reads picked files into memory, hands them
 * to pipeline.analyse, and renders the result. If you find yourself about to
 * compute something ABOUT a BuildGraph script here, that is the bug -- the
 * analysis is one implementation, in bgview/, and it stays that way.
 */
"use strict";

import { Schema } from "./bgview/schema.js";
import { analyse, pathSegments, scoreTail, hasWildcard, MIN_TAIL_SEGMENTS } from "./bgview/pipeline.js";
import { renderReport } from "./bgview/render.js";
import { BgError } from "./bgview/loader.js";
import * as share from "./bgview/share.js";

const $ = (id) => document.getElementById(id);
const statusEl = $("status");
const errorEl = $("error");
const choicesEl = $("choices");
const pickerEl = $("picker");
const reportEl = $("report");
const reopenEl = $("reopen");

// Only these are worth reading. .xml because that is what scripts and their
// includes are; .xsd because a real UE tree carries
// Engine/Build/Graph/Schema.xsd, and picking the tree should use the REAL
// schema for that engine version rather than the bundled snapshot (R28).
const WANTED_EXT = [".xml", ".xsd"];
// One source of truth, imported rather than repeated: share.js enforces these
// same caps when decoding a link (V52), and a second copy here would be free
// to drift from it silently -- a folder that loads by picking would then be
// refused by share, or worse the reverse.
const { MAX_FILE_BYTES, MAX_TOTAL_BYTES } = share;

let bundledSchema = null;

// The file set behind the report on screen, and the result it rendered. The
// add-flows (missing includes) MERGE into this and re-analyse the SAME entry;
// only a fresh pick from the picker replaces it.
let current = null;         // { entry, files }
let lastResult = null;
let pendingNote = null;     // one-shot "what was just added" line for the next report
let pendingWarnings = [];   // one-shot warnings (skipped or unreadable files) for the next report
let noticeStatusEl = null;  // progress line inside the missing-includes notice
let aliases = new Map();    // requested include key -> picked file the USER chose for it (reset per script)
let noticesCollapsed = false; // the notices bar starts visible; the choice lasts for this script

function setNoticeStatus(text) {
  if (!noticeStatusEl) return;
  noticeStatusEl.textContent = text || "";
  noticeStatusEl.hidden = !text;
}

function setStatus(text, busy) {
  statusEl.textContent = text;
  statusEl.classList.toggle("busy", !!busy);
}
function showError(text) { errorEl.textContent = text; errorEl.hidden = false; }
function clearError() {
  errorEl.textContent = ""; errorEl.hidden = true;
  choicesEl.replaceChildren(); choicesEl.hidden = true;
}
const extOf = (name) => {
  const i = name.lastIndexOf(".");
  return i < 0 ? "" : name.slice(i).toLowerCase();
};

/** Strip `.`/`..` segments and normalise backslashes to `/`.
 *  Shared by readFiles (a picked file's webkitRelativePath) and a decoded
 *  share link (a path a stranger chose) -- V46's "one path" discipline
 *  applies even to a helper this small; two copies are two chances to drift.
 *  There is no filesystem here -- these are only Map keys -- so this is
 *  display hygiene, not a sandbox escape. */
const sanitizePath = (rel) =>
  rel.replace(/\\/g, "/").split("/").filter((p) => p && p !== "." && p !== "..").join("/");

/** The bundled schema fact table, fetched once and reused.
 *  R28 makes this the COMMON path, not a fallback: Schema.xsd is generated
 *  and gitignored, so it is frequently absent even from a real checkout.
 *  It is bgview's own derived table rather than a copy of Epic's file -- see
 *  bgview/data/NOTICE.md. */
async function loadBundledSchema() {
  if (bundledSchema) return bundledSchema;
  const resp = await fetch("./data/schema-facts.json");
  if (!resp.ok) throw new Error(`could not fetch the bundled schema table (HTTP ${resp.status})`);
  bundledSchema = Schema.fromFacts(await resp.json(), "data/schema-facts.json");
  return bundledSchema;
}

/** Read picked files into a virtual path -> text map.
 *  webkitRelativePath keeps the on-disk shape for a folder pick, which is
 *  what makes <Include> resolve; a single file has none, so it is just the
 *  name and any include will be reported missing (V47) rather than silently
 *  mis-analysed. */
async function readFiles(fileList) {
  const files = new Map();
  const skippedBig = [];
  let total = 0;
  let truncated = false;

  for (const file of Array.from(fileList)) {
    if (!WANTED_EXT.includes(extOf(file.name))) continue;
    if (file.size > MAX_FILE_BYTES) { skippedBig.push(file.name); continue; }
    if (total + file.size > MAX_TOTAL_BYTES) { truncated = true; break; }
    // bgPath is set by the drop handler: a dropped File has an EMPTY
    // webkitRelativePath, so the entries walk carries the path itself.
    const safe = sanitizePath(file.bgPath || file.webkitRelativePath || file.name);
    files.set(safe, await file.text());
    total += file.size;
  }
  return { files, skippedBig, truncated };
}

/** A Schema.xsd inside the picked folder wins over the bundled snapshot:
 *  it is the real schema for that engine version, and the bundled one can
 *  drift (R28). Prefers the canonical Engine/Build/Graph location. */
function pickSchema(files) {
  let best = null;
  for (const path of files.keys()) {
    if (!path.toLowerCase().endsWith("schema.xsd")) continue;
    if (!best || path.toLowerCase().includes("engine/build/graph/")) best = path;
  }
  return best;
}

function offerChoice(paths, files) {
  choicesEl.replaceChildren();
  choicesEl.append(el("p", "hint", `${paths.length} scripts found. Which one is the entry point?`));
  for (const path of paths) {
    const b = el("button", "btn choice", path);   // textContent -- never markup
    b.type = "button";
    b.addEventListener("click", () => analyseFiles(path, files));
    choicesEl.append(b);
  }
  choicesEl.hidden = false;
  setStatus("Pick the entry script.", false);
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = String(text);
  return n;
}

/** Fill the report header's actions slot with the Share control, or leave it
 *  empty. V54/V55 govern every line here:
 *
 *   - V55: `share.isSupported()` false means no button at all -- not a
 *     disabled one. A control with no working consumer is worse than no
 *     control (V28), and there is nothing to fall back to: deflate-raw is
 *     the only codec this feature has.
 *   - V54: the link is built ONLY on click, never on render, and the
 *     safety statement is shown in the SAME reveal, not as a tooltip
 *     someone can miss.
 *   - Never auto-copy. `navigator.clipboard.writeText` runs only from the
 *     Copy button's own click handler.
 */
function buildShareControl(actionsEl, entry, files) {
  actionsEl.replaceChildren();
  if (!share.isSupported()) return;   // V55 -- absent, not a dead button

  const btn = el("button", "btn share-btn", "Share");
  btn.type = "button";
  btn.setAttribute("aria-expanded", "false");

  const panelId = "share-panel";
  const panel = el("div", "share-panel");
  panel.id = panelId;
  panel.hidden = true;
  panel.setAttribute("role", "group");
  panel.setAttribute("aria-label", "Share link");
  btn.setAttribute("aria-controls", panelId);

  // Announces "link ready" / "copied" without moving focus -- the visible
  // text already says both, this is only for anyone using a screen reader
  // who is not looking at the panel at that instant.
  const liveStatus = el("span", "sr-only", "");
  liveStatus.setAttribute("role", "status");
  liveStatus.setAttribute("aria-live", "polite");

  actionsEl.append(btn, panel, liveStatus);

  let url = null;   // built once per report; re-clicking just re-shows it
  btn.addEventListener("click", async () => {
    if (url !== null) {
      const showing = panel.hidden;
      panel.hidden = !showing;
      btn.setAttribute("aria-expanded", String(showing));
      return;
    }
    btn.disabled = true;
    const originalLabel = btn.textContent;
    btn.textContent = "Building link...";
    try {
      // EXPLICIT and OPT-IN (V54): this is the one and only place encode()
      // is called, and it runs only because the user just clicked Share.
      const fragment = await share.encode(entry, files);
      url = `${location.origin}${location.pathname}#${fragment}`;

      panel.replaceChildren();
      // V54's whole safety story, stated plainly rather than as fine print:
      // the script is not attached to the link, it IS the link.
      panel.append(el("p", "share-warning",
        "The script itself is encoded in this URL -- nothing is uploaded, but " +
        "anyone who opens the link can read the whole script. Treat it like " +
        "the file: do not paste it anywhere the script itself should not go."));

      const field = el("div", "share-field");
      const labelId = "share-link-label";
      const label = el("label", "share-label", "Share link");
      label.id = labelId;
      const input = el("input", "share-input");
      input.type = "text";
      input.readOnly = true;
      input.spellcheck = false;
      input.setAttribute("aria-labelledby", labelId);
      input.value = url;
      input.addEventListener("focus", () => input.select());
      field.append(label, input);

      const copyBtn = el("button", "btn share-copy", "Copy");
      copyBtn.type = "button";
      copyBtn.addEventListener("click", async () => {
        // The ONLY clipboard write in this module, and it runs from this
        // button's own click -- V54 forbids copying on the user's behalf.
        try {
          await navigator.clipboard.writeText(url);
          liveStatus.textContent = "Link copied.";
        } catch {
          // A clipboard permission denial is not a bug in bgview; fall back
          // to selecting the text so the user's own Ctrl+C still works.
          input.select();
          liveStatus.textContent = "Could not copy automatically -- the link is selected, press Ctrl+C.";
        }
      });
      field.append(copyBtn);
      panel.append(field);

      panel.hidden = false;
      btn.setAttribute("aria-expanded", "true");
      liveStatus.textContent = "Share link ready.";
    } catch (err) {
      // ShareError here would mean encode() itself refused (V53 is a decode
      // concern, but encode shares the same class) -- either way this is not
      // a silent failure.
      showError(err instanceof share.ShareError ? err.message
        : `Could not build a share link (this is a bug in Rogue BuildGraph Viewer): ${err && err.message ? err.message : err}`);
    } finally {
      btn.disabled = false;
      btn.textContent = originalLabel;
    }
  });
}

/** Say what happened to the script's <Include>s (V28: never silent).
 *
 *  A missing include is already a D14 finding in the list; this is the
 *  one-glance version with the fix attached -- the folder picker -- because
 *  "pick the folder, not the file" is the answer nine times in ten and a
 *  findings row cannot offer a button. A tail-matched include is reported
 *  too: the pipeline used a file whose path merely ENDS like the one asked
 *  for, and the reader should know that rather than find out later.
 *  Every path shown here came off a script or a stranger's link, so it
 *  lands as textContent only (V48). */
function buildIncludeNotices(slot, result) {
  slot.replaceChildren();
  noticeStatusEl = null;
  const inc = result.includes || { missing: [], matched: [] };
  const note = pendingNote;
  pendingNote = null;
  const overridden = (result.options || []).filter((o) => o.value !== o.default);
  const warnings = pendingWarnings.splice(0);
  const readsProject = (result.findings || []).some((f) => f.detector === "D1" && /Property 'Project(Name|File|Dir)' is not defined/.test(f.message));
  if (!note && !warnings.length && !inc.missing.length && !inc.matched.length && !overridden.length && !aliases.size && !readsProject) {
    slot.hidden = true;
    return;
  }

  const codeList = (parent, items, sep) => items.forEach((item, i) => {
    if (i) parent.append(document.createTextNode(sep));
    parent.append(el("code", null, item));
  });

  // Files a pick or drop could NOT read or skipped (too big, over the total
  // cap, unreadable entry). Said here, in the report, because the picker's
  // error box is gone from view the moment the report is up.
  for (const w of warnings) {
    const n = el("div", "notice notice-warn");
    n.setAttribute("role", "status");
    n.append(el("p", "notice-text", w));
    slot.append(n);
  }

  // The three project built-ins exist only when the engine runs with
  // -project= (V32). This analysis has none, exactly like an unflagged CLI
  // run, so a script that reads them gets "" -- and a node name built from
  // $(ProjectName) comes out with two spaces in a row, which the engine
  // rejects (D18). Those errors are true of THIS run, not of the script, and
  // the report has to say so where the reader will look.
  const projectRefs = [...new Set((result.findings || [])
    .filter((f) => f.detector === "D1")
    .map((f) => (/Property '(ProjectName|ProjectFile|ProjectDir)' is not defined/.exec(f.message) || [])[1])
    .filter(Boolean))];
  if (projectRefs.length) {
    const consequent = (result.findings || []).filter((f) => f.detector === "D18" && /consecutive spaces/.test(f.message)).length;
    const n = el("div", "notice notice-info");
    n.setAttribute("role", "status");
    const text = el("p", "notice-text");
    text.append(el("strong", null, `This script reads ${projectRefs.map((p) => `$(${p})`).join(", ")}, which this analysis leaves undefined. `));
    text.append(document.createTextNode(
      "The engine defines the project built-ins only when run with -project=; this page runs without one, like an " +
      "unflagged command-line run, so they expanded to nothing. Names and paths built from them are affected"));
    if (consequent) {
      text.append(document.createTextNode(
        ` -- the ${consequent} "consecutive spaces" error${consequent === 1 ? "" : "s"} below ${consequent === 1 ? "is" : "are"} that gap, not a defect in the script`));
    }
    text.append(document.createTextNode(". The CLI's --project sets them; the web page does not yet."));
    n.append(text);
    slot.append(n);
  }
  if (aliases.size) {
    // Files the user pointed at for includes the evidence bar refused. Said
    // on every render, because the report is only right if these were.
    const n = el("div", "notice notice-info");
    n.setAttribute("role", "status");
    const text = el("p", "notice-text");
    text.append(el("strong", null,
      `${aliases.size} include${aliases.size === 1 ? "" : "s"} satisfied by files you chose: `));
    [...aliases].forEach(([req, cand], i) => {
      if (i) text.append(document.createTextNode("; "));
      text.append(el("code", null, req), document.createTextNode(" ← "), el("code", null, cand));
    });
    text.append(document.createTextNode(". Analyse another script to start over."));
    n.append(text);
    slot.append(n);
  }
  if (overridden.length) {
    // V61: a report evaluated with overrides SAYS so, names them, and says
    // what a share link would carry. Never grey fine print: a reader must
    // not take Shipping findings for the default run.
    const n = el("div", "notice notice-info");
    n.setAttribute("role", "status");
    const text = el("p", "notice-text");
    text.append(el("strong", null,
      `Evaluated with ${overridden.length} option override${overridden.length === 1 ? "" : "s"}: `));
    codeList(text, overridden.map((o) => `${o.name}=${o.value}`), ", ");
    text.append(document.createTextNode(
      ". Every branch is still analysed -- values change, branches do not -- and nodes whose guards are " +
      "false under these values are dimmed. A share link built from this page carries the defaults, not these values."));
    n.append(text);
    slot.append(n);
  }
  if (note) {
    // What the last add-flow actually read -- the exact file list, so the
    // claim "and nothing else" is checkable by the person reading it.
    const n = el("div", "notice notice-ok");
    n.setAttribute("role", "status");
    n.append(el("p", "notice-text", note));
    slot.append(n);
  }
  if (inc.missing.length) {
    const names = [...new Set(inc.missing)];
    const one = names.length === 1;
    const n = el("div", "notice notice-warn");
    n.setAttribute("role", "status");
    const body = el("div", "notice-body");
    const text = el("p", "notice-text");
    text.append(el("strong", null,
      `${names.length} included script${one ? " was" : "s were"} not in what you picked. `));
    text.append(document.createTextNode(
      `Properties and nodes ${one ? "it defines are" : "they define are"} absent from this report: `));
    codeList(text, names, ", ");
    text.append(document.createTextNode(
      ". Drop the files or their folder anywhere on this report, point Rogue BuildGraph Viewer at the folder and it reads just those files, or add them by hand."));
    const wild = names.filter(hasWildcard);
    if (wild.length) {
      // Fetching cannot help these, and saying so here beats a button that
      // appears to do nothing for them.
      text.append(document.createTextNode(
        ` ${wild.length === 1 ? "One of them uses" : `${wild.length} of them use`} a wildcard, which Rogue BuildGraph Viewer does not expand yet; no fetched file can stand in for it.`));
    }
    const unexpanded = names.filter((p) => p.includes("$("));
    if (unexpanded.length) {
      text.append(document.createTextNode(
        ` ${unexpanded.length === 1 ? "One path still contains" : `${unexpanded.length} paths still contain`} an unexpanded $(…): that built-in has no value in the browser, so the part after it is looked up as a path from the engine root in the folder you choose.`));
    }
    // Same-named files already in the pick, refused on path evidence alone.
    // Offered, never applied: one click per file, the path on the button.
    const cands = inc.candidates || new Map();
    const suggestable = names.filter((p) => cands.has(p));
    if (suggestable.length) {
      const sug = el("div", "notice-suggest");
      sug.append(el("p", "notice-suggest-lead",
        `${suggestable.length === 1 ? "A file with the same name is" : "Files with the same names are"} in your pick at a different path, ` +
        `so Rogue BuildGraph Viewer did not use ${suggestable.length === 1 ? "it" : "them"} on its own (a same-named file elsewhere in an engine tree is often a different file). ` +
        `Use ${suggestable.length === 1 ? "it" : "one"} if it is the right file:`));
      const firsts = new Map();
      for (const p of suggestable) {
        const line = el("div", "suggest-row");
        line.append(el("code", null, p), document.createTextNode(" ← "));
        for (const c of cands.get(p).slice(0, 3)) {
          const b = el("button", "btn suggest-btn", `Use ${c}`);
          b.type = "button";
          b.title = `Use this picked file as ${p}`;
          b.addEventListener("click", () => useAliases(new Map([[p, c]])));
          line.append(b);
        }
        firsts.set(p, cands.get(p)[0]);
        sug.append(line);
      }
      if (firsts.size > 1) {
        const all = el("button", "btn primary suggest-all", `Use all ${firsts.size} first suggestions`);
        all.type = "button";
        all.addEventListener("click", () => useAliases(firsts));
        sug.append(all);
      }
      body.append(sug);
    }
    const status = el("p", "notice-status");
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    status.hidden = true;
    noticeStatusEl = status;
    body.append(text, status);

    const actions = el("div", "notice-actions");
    const lazy = typeof window.showDirectoryPicker === "function";
    const findBtn = el("button", "btn primary", "Find them in a folder…");
    findBtn.type = "button";
    findBtn.title = lazy
      ? "Pick the folder they live in; the engine root is fine. Only the files asked for are read -- the rest of the folder is never touched."
      : "Pick the folder they live in. This browser has to list every file in it, so choose a small folder; only the wanted files are read.";
    findBtn.addEventListener("click", () => findInFolder(findBtn));
    const addBtn = el("button", "btn", "Add the files…");
    addBtn.type = "button";
    addBtn.title = "Choose the missing files yourself";
    addBtn.addEventListener("click", () => $("add-files").click());
    actions.append(findBtn, addBtn);
    n.append(body, actions);
    slot.append(n);
  }
  if (inc.matched.length) {
    const n = el("div", "notice notice-info");
    const text = el("p", "notice-text");
    text.append(el("strong", null,
      `${inc.matched.length} include${inc.matched.length === 1 ? "" : "s"} matched by path tail. `));
    text.append(document.createTextNode(
      "The exact path was not in the pick, so the one file whose path ends the same way was used: "));
    inc.matched.forEach((m, i) => {
      if (i) text.append(document.createTextNode("; "));
      text.append(el("code", null, m.requested));
      text.append(document.createTextNode(" → "));
      text.append(el("code", null, m.matched));
    });
    text.append(document.createTextNode("."));
    n.append(text);
    slot.append(n);
  }

  // One control folds the lot away, and the strip it leaves behind says how
  // many are folded -- a dismissed warning is still a warning (V28). Starts
  // visible; the choice lasts for this script and is reset by a new pick.
  slot.id = "report-notices";
  const bar = el("div", "notices-bar");
  const toggle = el("button", "notices-toggle");
  toggle.type = "button";
  toggle.setAttribute("aria-controls", slot.id);
  const paint = () => {
    const count = slot.querySelectorAll(".notice").length;
    slot.classList.toggle("collapsed", noticesCollapsed);
    toggle.textContent = noticesCollapsed
      ? `Show ${count} notice${count === 1 ? "" : "s"}`
      : "Hide notices";
    toggle.title = noticesCollapsed
      ? "Show the notices about includes, options and files"
      : "Fold the notices into one line";
    toggle.setAttribute("aria-expanded", String(!noticesCollapsed));
  };
  toggle.addEventListener("click", () => { noticesCollapsed = !noticesCollapsed; paint(); });
  paint();
  bar.append(toggle);
  slot.append(bar);
  slot.hidden = false;

  // Picking a node is the moment the reader turns from the verdicts to the
  // graph: the notices fold then, by pointer or keyboard, in the canvas or
  // through a finding row, to give the canvas and the inspector the room.
  // They stay one click away in the strip; nothing is dismissed.
  const foldOnNode = (e) => {
    if (noticesCollapsed) return;
    if (e.type === "keydown" && e.key !== "Enter" && e.key !== " ") return;
    if (!(e.target instanceof Element) || !e.target.closest(".node, .finding")) return;
    noticesCollapsed = true;
    paint();
  };
  for (const sel of [".graph-area", ".findings-list"]) {
    const area = reportEl.querySelector(sel);
    if (!area) continue;
    area.addEventListener("pointerdown", foldOnNode);
    area.addEventListener("keydown", foldOnNode);
  }

  // The green notices confirm something the user just did (a drop, a fetch,
  // an add, a choice). They have done their job once the user turns to the
  // report, so the first interaction with the report body -- a click on a
  // node or finding, a scroll on the graph, a key -- removes them. Warnings,
  // the tail-match and alias notes and the override banner stay: those
  // describe the report, not the gesture that produced it.
  const transient = [...slot.querySelectorAll(".notice-ok")];
  const body = reportEl.querySelector(".report-body");
  if (transient.length && body) {
    let done = false;
    const dismiss = () => {
      if (done) return;
      done = true;
      transient.forEach((n) => n.remove());
      if (!slot.querySelectorAll(".notice").length) slot.hidden = true; else paint();
    };
    for (const type of ["pointerdown", "wheel", "keydown"]) {
      body.addEventListener(type, dismiss, { once: true, passive: true });
    }
  }
}

/** The user's answer to "is this same-named file the one the script means?".
 *  The chosen file's text is stored under the REQUESTED key as well, so the
 *  include resolves exactly from now on (and from inside a share link built
 *  afterwards). Remembered in `aliases` so every render says it happened. */
function useAliases(pairs) {
  if (!current) return;
  const files = new Map(current.files);
  const used = [];
  for (const [requested, candidate] of pairs) {
    if (!files.has(candidate) || files.has(requested)) continue;
    files.set(requested, files.get(candidate));
    aliases.set(requested, candidate);
    used.push(`${requested} ← ${candidate}`);
  }
  if (!used.length) return;
  pendingNote = `Using ${used.length} file${used.length === 1 ? "" : "s"} you chose: ${used.join("; ")}.`;
  current.files = files;
  enqueue(() => analyseFiles(current.entry, files, current.overrides), setNoticeStatus);
}

/** The Options control (T72): a button with the count of overrides in force,
 *  and a popover listing every registered <Option> -- a <select> over its
 *  finite domain when the Restrict is a literal alternation, a text field
 *  otherwise -- with Apply and Reset. Apply re-runs the SAME tail with the
 *  values that differ from the defaults; a value equal to its default is not
 *  an override. No <Option> in the script means no control (V28). Every
 *  value here is user- or script-supplied text and lands as textContent or
 *  a form value, never markup (V48). */
function buildOptionsControl(slot, result) {
  slot.replaceChildren();
  const opts = result.options || [];
  if (!opts.length) return;
  const overridden = opts.filter((o) => o.value !== o.default);

  const btn = el("button", "btn options-btn");
  btn.type = "button";
  btn.append(document.createTextNode("Options"));
  if (overridden.length) btn.append(el("span", "chip-count", overridden.length));
  btn.title = overridden.length
    ? `${overridden.length} option${overridden.length === 1 ? "" : "s"} overridden -- the same as --set on the command line`
    : "Set option values and re-evaluate, the same as --set on the command line";
  btn.setAttribute("aria-expanded", "false");

  const panelId = "options-panel";
  const panel = el("div", "options-panel");
  panel.id = panelId;
  panel.hidden = true;
  panel.setAttribute("role", "group");
  panel.setAttribute("aria-label", "Option values");
  btn.setAttribute("aria-controls", panelId);
  panel.append(el("p", "options-lead",
    "Values for this evaluation, exactly as --set NAME=VALUE on the command line. " +
    "Every branch is still analysed; nodes whose guards are false under these values are dimmed, not removed."));

  const fields = new Map();
  for (const o of opts) {
    const row = el("div", "option-row" + (o.value !== o.default ? " overridden" : ""));
    const id = `opt-${fields.size}`;
    const head = el("div", "option-head");
    const label = el("label", "option-name", o.name);
    label.htmlFor = id;
    head.append(label);
    if (o.description) head.append(el("span", "option-desc", o.description));
    row.append(head);

    let control;
    if (o.domain) {
      control = el("select", "option-input");
      for (const v of o.domain) {
        const item = el("option", null, v);
        item.value = v;
        if (v === o.value) item.selected = true;
        control.append(item);
      }
      // A value outside its own Restrict (a default that violates it is a
      // D18, an earlier override may be anything) stays visible and chosen.
      if (!o.domain.includes(o.value)) {
        const item = el("option", null, o.value);
        item.value = o.value;
        item.selected = true;
        control.append(item);
      }
    } else {
      control = el("input", "option-input");
      control.type = "text";
      control.value = o.value;
      control.spellcheck = false;
      if (o.restrict) control.title = `Restrict: ${o.restrict}`;
    }
    control.id = id;
    control.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); apply.click(); } });
    row.append(control);
    const shownDefault = o.default === "" ? "(empty)" : o.default;
    row.append(el("div", "option-default",
      o.value === o.default ? `default: ${shownDefault}` : `default: ${shownDefault} → overridden`));
    fields.set(o.name, { control, def: o.default });
    panel.append(row);
  }

  const actions = el("div", "options-actions");
  const apply = el("button", "btn primary", "Apply");
  apply.type = "button";
  const reset = el("button", "btn", "Reset to defaults");
  reset.type = "button";
  apply.addEventListener("click", () => {
    const next = new Map();
    for (const [name, { control, def }] of fields) {
      if (control.value !== def) next.set(name, control.value);
    }
    enqueue(() => analyseFiles(current.entry, current.files, next), setNoticeStatus);
  });
  reset.addEventListener("click", () => enqueue(() => analyseFiles(current.entry, current.files, new Map()), setNoticeStatus));
  actions.append(apply, reset);
  panel.append(actions);

  btn.addEventListener("click", () => {
    const show = panel.hidden;
    panel.hidden = !show;
    btn.setAttribute("aria-expanded", String(show));
  });
  slot.append(btn, panel);
}

function run(entry, files, schema, overrides = new Map()) {
  clearError();
  setStatus("Analysing...", true);
  try {
    const result = analyse(entry, files, schema, overrides);
    lastResult = result;
    const controls = renderReport(reportEl, result);
    buildShareControl(controls.actions, entry, files);
    buildIncludeNotices(controls.notices, result);
    buildOptionsControl(controls.options, result);
    reportEl.hidden = false;
    pickerEl.hidden = true;
    reopenEl.hidden = false;
    document.body.dataset.view = "report";   // styles.css compacts the shell header on this
    const c = result.counts;
    document.title = `${entry.split("/").pop()} - Rogue BuildGraph Viewer`;
    setStatus(`${entry.split("/").pop()}: ${result.graph.nodes.size} nodes, ` +
              `${result.graph.agents.size} agents - ${c.error} error, ${c.warn} warn, ${c.info} info`, false);
  } catch (err) {
    setStatus("Ready.", false);
    // A BgError is a controlled, expected failure (malformed XML, a DOCTYPE,
    // the depth cap) and its message is already user-facing. Anything else
    // is a bug in this tool and says so, rather than masquerading as a
    // problem with the user's script.
    showError(err instanceof BgError ? err.message
      : `Unexpected error while analysing (this is a bug in Rogue BuildGraph Viewer): ${err && err.message ? err.message : err}`);
  }
}

/** Schema selection, then run() -- the tail BOTH a folder pick and a decoded
 *  share link run through unchanged (V46). A picker figures out its own
 *  entry point (the shallowest unambiguous script, or asks); a shared link
 *  already carries its entry, so it calls straight in here. Two callers that
 *  diverged past this point is exactly the "second path" V46 forbids. */
/** The schema for a file set: a picked Schema.xsd wins, else the bundled table. */
async function schemaFor(files) {
  const schemaPath = pickSchema(files);
  return schemaPath
    ? Schema.fromString(files.get(schemaPath), schemaPath)
    : await loadBundledSchema();
}

/** The common tail. `overrides` is the option-set (V58): a fresh pick or a
 *  shared link starts from the defaults; the Options panel and the add-flows
 *  pass the set the current report was evaluated with. */
async function analyseFiles(entry, files, overrides = new Map()) {
  clearError();
  setStatus("Reading schema...", true);
  let schema;
  try {
    schema = await schemaFor(files);
  } catch (err) {
    setStatus("Ready.", false);
    showError(`Could not read the schema: ${err && err.message ? err.message : err}`);
    return;
  }
  current = { entry, files, overrides };
  run(entry, files, schema, overrides);
}

async function onPick(fileList) {
  if (!fileList || !fileList.length) return;
  clearError();
  setStatus("Reading files...", true);

  const { files, skippedBig, truncated } = await readFiles(fileList);

  // Never silent: a file we refused to read is a file whose absence shows up
  // later as a puzzling missing include (V28's discipline). Queued for the
  // report's notices, because run() clears the picker's error box.
  if (skippedBig.length) pendingWarnings.push(`${skippedBig.length} file(s) over 8 MB were skipped: ${skippedBig.join(", ")}`);
  if (truncated) pendingWarnings.push("The selection exceeded 64 MB; the remaining files were not read.");

  const scripts = [...files.keys()].filter((p) => p.toLowerCase().endsWith(".xml"));
  const schemaPath = pickSchema(files);
  const scriptsOnly = scripts.filter((p) => p !== schemaPath);
  if (!scriptsOnly.length) {
    setStatus("Ready.", false);
    // No report will show these, so they go to the picker's box after all.
    showError(["No .xml script in that selection.", ...pendingWarnings.splice(0)].join("\n"));
    return;
  }

  // A folder usually holds one obvious entry at its shallowest level, with
  // fragments filed underneath. One candidate up there is unambiguous enough
  // to just run; anything else gets asked about, because BuildGraph has no
  // convention marking the entry point and guessing wrong buries the reader
  // in findings about an include fragment.
  aliases = new Map();   // a new script: whatever was chosen for the last one does not carry
  noticesCollapsed = false;
  const depth = (p) => p.split("/").length;
  const shallowest = Math.min(...scriptsOnly.map(depth));
  const top = scriptsOnly.filter((p) => depth(p) === shallowest);
  if (scriptsOnly.length === 1) analyseFiles(scriptsOnly[0], files);
  else if (top.length === 1) analyseFiles(top[0], files);
  else offerChoice(scriptsOnly, files);
}

// Picks are serialised: reading files is async, and two overlapping picks
// would otherwise interleave their reads and render whichever finished last.
let queue = Promise.resolve();
/** Everything that reads files runs through ONE queue, so two overlapping
 *  operations cannot interleave their reads and render whichever finished
 *  last (B8). Errors go to the picker's error box unless the caller has a
 *  better place -- the add-flows report into the notice they came from,
 *  because the picker is hidden while a report is up. */
const enqueue = (work, onError) => {
  queue = queue.then(work).catch((err) => {
    const msg = String(err && err.message ? err.message : err);
    if (onError) onError(msg); else { setStatus("Ready.", false); showError(msg); }
  });
};
// Accepts a FileList or a promise of one: the drop handler has to walk the
// entries API asynchronously, and that walk belongs in the same queue.
const pick = (fileListOrPromise) => enqueue(async () => onPick(await fileListOrPromise));

// The hidden file input is the keyboard fallback behind the drop zone.
$("pick-file").addEventListener("change", (e) => pick(e.target.files));

// The add-inputs live outside #picker (hidden while a report shows) and
// outside #report (rebuilt on every analysis); the notice's buttons open
// them. The input is reset only AFTER the read: resetting first invalidates
// the File objects it handed out (measured: "The requested file could not
// be read"), and the reset is only there so the same file can be chosen
// twice in a row and still fire `change`.
for (const [id, explicit] of [["add-files", true], ["add-dir", false]]) {
  $(id).addEventListener("change", (e) => {
    const input = e.target;
    const list = Array.from(input.files || []);
    enqueue(async () => {
      try { await addFromFileList(list, { explicit }); } finally { input.value = ""; }
    }, setNoticeStatus);
  });
}

/* ---- resolving missing includes from a folder, lazily ------------------
 * An engine checkout is hundreds of thousands of files; listing the whole
 * tree to find three .xml fragments is not an option, and that is exactly
 * what <input webkitdirectory> does. The File System Access API hands out a
 * directory HANDLE instead, and a handle is navigated, not enumerated: each
 * missing include is looked up by walking its path -- and every shorter tail
 * of it -- straight to the file. Only when that fails does a bounded search
 * list sub-folders, skipping the ones that are enormous and never hold a
 * BuildGraph script, and it stops after a fixed count. Files that are found
 * may include further files, so the rounds repeat until nothing new is
 * missing. Chrome and Edge have the API; elsewhere the button falls back to
 * the folder input, which has to list the folder but still reads only the
 * wanted NAMES. Found files are stored under the path the script ASKED for,
 * so their own relative includes resolve from where the script expects. */
const HEAVY_DIRS = new Set([
  "binaries", "intermediate", "saved", "deriveddatacache", "content", "source", "plugins",
  "shaders", "extras", "documentation", "programs", "thirdparty", "node_modules", ".git",
]);
const SEARCH_DIR_CAP = 1500;
const ROUND_CAP = 8;

/** The File at `segs` under `dir`, or null. Navigation only, no listing. */
async function fileAt(dir, segs) {
  try {
    let d = dir;
    for (const s of segs.slice(0, -1)) d = await d.getDirectoryHandle(s);
    return await (await d.getFileHandle(segs[segs.length - 1])).getFile();
  } catch {
    return null;
  }
}

/** How much of a request a found file has to agree with: the pipeline's bar
 *  (file name plus two parent folders), or the whole include AS WRITTEN when
 *  that is shorter. `Inc/X.xml` is fully proven by two segments however deep
 *  the entry script sits; a path into `Engine/Restricted/...` is not proven
 *  by a same-named file nearby. `relOf` maps a missing key to the written
 *  path (pipeline.js); without it the key itself is the measure. */
const evidenceNeeded = (requested, relOf) => {
  const written = (relOf && relOf.get(requested)) || requested;
  return Math.min(MIN_TAIL_SEGMENTS, pathSegments(written).length);
};

/** Walk the requested path from the handle root, then every shorter tail of
 *  it (`Engine/Build/Graph/X.xml`, `Build/Graph/X.xml`, ...). The first hit
 *  is the most specific one. A tail counts as evidence for every segment it
 *  agrees on by construction, plus one when the chosen folder's own NAME is
 *  the segment just above it -- someone who picked a folder called `Inc`
 *  for an `Inc/X.xml` include has said where it is. */
async function locateBySuffix(root, requested, minEvidence) {
  const segs = pathSegments(requested, true);   // author's casing, $(...) prefix dropped
  const need = minEvidence ?? evidenceNeeded(requested, null);
  const rootName = String(root.name || "").toLowerCase();
  for (let i = 0; i < segs.length; i++) {
    const tail = segs.slice(i);
    const named = i > 0 && segs[i - 1].toLowerCase() === rootName ? 1 : 0;
    if (tail.length + named < need) continue;
    const file = await fileAt(root, tail);
    if (file) return { file, realPath: tail.join("/") };
  }
  return null;
}

/** Bounded breadth-first listing that collects files whose lower-cased
 *  name is wanted. Reads NO file contents; it only lists names. */
async function searchByName(root, wantedNames, onProgress) {
  const found = new Map();
  const todo = [{ dir: root, path: "" }];
  let visited = 0;
  while (todo.length && visited < SEARCH_DIR_CAP) {
    const { dir, path } = todo.shift();
    visited++;
    if (visited % 50 === 0) onProgress(visited);
    try {
      for await (const [name, handle] of dir.entries()) {
        const lower = name.toLowerCase();
        const full = path ? `${path}/${name}` : name;
        if (handle.kind === "directory") {
          if (!HEAVY_DIRS.has(lower)) todo.push({ dir: handle, path: full });
        } else if (wantedNames.has(lower)) {
          if (!found.has(lower)) found.set(lower, []);
          found.get(lower).push({ handle, realPath: full });
        }
      }
    } catch { /* an unreadable directory is skipped, not fatal */ }
  }
  return found;
}

/** One round: fetch every path in `missing` from `root` into `files`, under
 *  the REQUESTED key. Returns what was added, with the real path each came
 *  from. A name found in several places is taken only when one candidate
 *  agrees best with the requested path's tail; a tie is left missing. */
async function fetchMissing(root, missing, files, relOf) {
  const hits = [];
  const unresolved = [];
  for (const requested of missing) {
    if (hasWildcard(requested)) continue;        // a set of files; nothing to fetch for it
    const hit = await locateBySuffix(root, requested, evidenceNeeded(requested, relOf));
    if (hit) hits.push({ requested, ...hit }); else unresolved.push(requested);
  }
  if (unresolved.length) {
    const wanted = new Set(unresolved.map((p) => pathSegments(p).at(-1)).filter(Boolean));
    setNoticeStatus(`Searching sub-folders for ${[...wanted].join(", ")}...`);
    const found = await searchByName(root, wanted, (n) => setNoticeStatus(`Searched ${n} folders...`));
    for (const requested of unresolved) {
      const want = pathSegments(requested);
      const need = evidenceNeeded(requested, relOf);
      let best = null, bestK = -1, tied = false;
      for (const cand of found.get(want.at(-1)) || []) {
        // The chosen folder's name is part of where the file really is.
        const k = scoreTail(want, pathSegments(`${root.name || ""}/${cand.realPath}`));
        if (k < need) continue;
        if (k > bestK) { best = cand; bestK = k; tied = false; }
        else if (k === bestK) tied = true;
      }
      if (best && !tied) hits.push({ requested, file: await best.handle.getFile(), realPath: best.realPath });
    }
  }
  let total = 0;
  for (const text of files.values()) total += text.length;
  const added = [];
  for (const h of hits) {
    if (h.file.size > MAX_FILE_BYTES) continue;
    const text = await h.file.text();
    if (total + text.length > MAX_TOTAL_BYTES) break;
    total += text.length;
    files.set(h.requested, text);
    added.push({ requested: h.requested, realPath: h.realPath });
  }
  return added;
}

/** A real Schema.xsd, if the folder is an engine tree and none was picked.
 *  Tails of at least two segments (`Graph/Schema.xsd`), so a stray file of
 *  that name at the folder root is not mistaken for the engine's. */
async function fetchSchema(root, files) {
  if (pickSchema(files)) return null;
  const hit = await locateBySuffix(root, "Engine/Build/Graph/Schema.xsd", 2);
  if (!hit || hit.file.size > MAX_FILE_BYTES) return null;
  files.set("Engine/Build/Graph/Schema.xsd", await hit.file.text());
  return hit.realPath;
}

/** The "Find them in a folder" button. */
async function findInFolder(btn) {
  if (!current) return;
  if (typeof window.showDirectoryPicker !== "function") { $("add-dir").click(); return; }
  let root;
  try {
    root = await window.showDirectoryPicker({ mode: "read" });
  } catch (err) {
    // Cancelling the dialog is not an error worth a message.
    if (!(err && err.name === "AbortError")) {
      setNoticeStatus(`Could not open that folder: ${err && err.message ? err.message : err}`);
    }
    return;
  }
  btn.disabled = true;
  enqueue(async () => {
    const files = new Map(current.files);
    const added = [];
    const schemaReal = await fetchSchema(root, files);
    for (let round = 0; round < ROUND_CAP; round++) {
      const schema = await schemaFor(files);
      const probe = analyse(current.entry, files, schema, current.overrides).includes;
      const missing = [...new Set(probe.missing)].filter((p) => !files.has(p));
      if (!missing.length) break;
      setNoticeStatus(`Looking for ${missing.length} file${missing.length === 1 ? "" : "s"} in '${root.name}'...`);
      const got = await fetchMissing(root, missing, files, probe.relOf);
      if (!got.length) break;
      added.push(...got);
    }
    if (schemaReal) added.push({ requested: "Engine/Build/Graph/Schema.xsd", realPath: schemaReal });
    if (!added.length) {
      setNoticeStatus(`Nothing that was asked for is in '${root.name}', its sub-folders included.`);
      btn.disabled = false;
      return;
    }
    pendingNote = `Read ${added.length} file${added.length === 1 ? "" : "s"} from '${root.name}' and nothing else: `
      + added.map((a) => a.realPath).join(", ") + ".";
    current.files = files;
    await analyseFiles(current.entry, files, current.overrides);
  }, (msg) => {
    setNoticeStatus(`Could not read from '${root.name}': ${msg}`);
    btn.disabled = false;
  });
}

/** Merge chosen files into the current set and re-analyse the same entry.
 *  Explicit files (the "Add the files" button) are all read; a folder's
 *  files (the fallback input) are read only when their NAME is wanted -- a
 *  missing include's, or Schema.xsd -- so the rest of the folder is never
 *  read into memory. Each file is stored under the missing include path it
 *  satisfies when that is unambiguous, else under its own path, where the
 *  pipeline's tail match gets a say. */
async function addFromFileList(fileList, { explicit }) {
  if (!current || !fileList.length) return;
  const inc = (lastResult && lastResult.includes) || { missing: [], relOf: new Map() };
  const missing = [...new Set(inc.missing)];
  const byName = new Map();
  for (const m of missing) {
    const name = pathSegments(m).at(-1);
    if (!byName.has(name)) byName.set(name, []);
    byName.get(name).push(m);
  }
  const files = new Map(current.files);
  let total = 0;
  for (const text of files.values()) total += text.length;
  const added = [];
  const unplaced = [];
  for (const file of fileList) {
    if (!WANTED_EXT.includes(extOf(file.name))) continue;
    const lower = file.name.toLowerCase();
    const isSchema = lower === "schema.xsd";
    if (!explicit && !isSchema && !byName.has(lower)) continue;   // folder: names only
    if (file.size > MAX_FILE_BYTES) continue;
    const rel = sanitizePath(file.bgPath || file.webkitRelativePath || file.name);
    let key = rel;
    const wants = byName.get(lower) || [];
    let best = null, bestK = -1, tied = false;
    for (const w of wants) {
      const k = scoreTail(pathSegments(w), pathSegments(rel));
      // A file chosen by hand IS the evidence; a folder's file has to earn
      // it the same way a fetched one does -- against the include as written.
      if (k < (explicit ? 1 : evidenceNeeded(w, inc.relOf))) continue;
      if (k > bestK) { best = w; bestK = k; tied = false; }
      else if (k === bestK) tied = true;
    }
    if (best && !tied) key = best;
    else if (!explicit && !isSchema) {
      // Same name, wrong place: a folder's file that cannot be placed is
      // NOT added under its own path -- that would read "Added" while the
      // include stays missing. It is reported instead.
      unplaced.push(rel);
      continue;
    }
    if (key === current.entry) continue;             // never clobber the entry itself
    const text = await file.text();
    if (total + text.length > MAX_TOTAL_BYTES) break;
    total += text.length;
    files.set(key, text);
    added.push(rel);
  }
  if (unplaced.length) {
    pendingWarnings.push(`${unplaced.length} file${unplaced.length === 1 ? "" : "s"} in that folder ${unplaced.length === 1 ? "has" : "have"} `
      + `a missing include's name but not its path, so ${unplaced.length === 1 ? "it was" : "they were"} not used: ${unplaced.join(", ")}. `
      + "Drop the file itself to use it anyway.");
  }
  if (!added.length) {
    // The notice (and its status line) may not exist when nothing is
    // missing, so the outcome goes to the next report's notices instead.
    // An "unplaced" warning above already explains the same-name case.
    if (!unplaced.length) {
      const wantedNames = [...new Set(missing.map((m) => pathSegments(m, true).at(-1)))];
      pendingWarnings.push(explicit
        ? "None of the dropped or chosen files is a .xml or .xsd that could be read."
        : wantedNames.length
          ? `No file named ${wantedNames.join(", ")} was in that folder; nothing was added.`
          : "Nothing is missing from this report, so the dropped folder added nothing. Drop individual files to add them anyway.");
    }
    await analyseFiles(current.entry, current.files, current.overrides);
    return;
  }
  pendingNote = `Added ${added.length} file${added.length === 1 ? "" : "s"}: ${added.join(", ")}.`;
  current.files = files;
  await analyseFiles(current.entry, files, current.overrides);
}

/** Files from a drop, including a whole folder via the File System Entries
 *  API. Produces the same File list an <input webkitdirectory> would have,
 *  with the relative path on `bgPath` (a dropped File's own
 *  webkitRelativePath is empty). A directory reader hands back batches and
 *  signals the end with an empty one, so it is drained before descending.
 *  Browsers without the entries API fall back to the flat file list. The
 *  synchronous prefix (reading `items`) runs during the drop event itself,
 *  which is the only time the DataTransfer is live. */
function filesFromDrop(dt) {
  const entries = Array.from(dt.items || [])
    .map((it) => (typeof it.webkitGetAsEntry === "function" ? it.webkitGetAsEntry() : null))
    .filter(Boolean);
  // What the walk did, so the report can SAY it (V28): how many folders it
  // listed, and every entry it could not read -- a cloud placeholder that is
  // not on disk, a permission error, a dangling link. Silently skipping one
  // is how "it did not pick up my sub-folder" happens with no trace.
  const result = { files: [], folders: 0, unreadable: [], hadDirectory: false };
  if (!entries.length) { result.files = Array.from(dt.files || []); return Promise.resolve(result); }
  const walk = (entry, prefix) => new Promise((resolve) => {
    if (entry.isFile) {
      entry.file(
        (f) => { f.bgPath = prefix + f.name; result.files.push(f); resolve(); },
        () => { result.unreadable.push(prefix + entry.name); resolve(); });
    } else if (entry.isDirectory) {
      result.hadDirectory = true;
      result.folders++;
      const reader = entry.createReader();
      const found = [];
      const readMore = () => reader.readEntries(async (batch) => {
        if (batch.length) { found.push(...batch); readMore(); return; }
        for (const e of found) await walk(e, `${prefix}${entry.name}/`);
        resolve();
      }, () => { result.unreadable.push(`${prefix}${entry.name}/`); resolve(); });
      readMore();
    } else resolve();
  });
  return (async () => { for (const e of entries) await walk(e, ""); return result; })();
}

/** Turn a walk's bookkeeping into notices for the next report. */
function noteDropOutcome(r) {
  if (r.hadDirectory) {
    // Name what was found, not just how many: "did it see my sub-folder?"
    // is answered by the paths themselves.
    const wanted = r.files.filter((f) => WANTED_EXT.includes(extOf(f.name)));
    const paths = wanted.map((f) => sanitizePath(f.bgPath || f.webkitRelativePath || f.name));
    const shown = paths.slice(0, 12).join(", ") + (paths.length > 12 ? `, ... (${paths.length - 12} more)` : "");
    pendingNote = `Dropped folder: ${wanted.length} .xml/.xsd file${wanted.length === 1 ? "" : "s"} found across `
      + `${r.folders} folder${r.folders === 1 ? "" : "s"}, nothing else read${paths.length ? `: ${shown}` : ""}.`;
  }
  if (r.unreadable.length) {
    const shown = r.unreadable.slice(0, 8).join(", ") + (r.unreadable.length > 8 ? ", ..." : "");
    pendingWarnings.push(`${r.unreadable.length} item${r.unreadable.length === 1 ? "" : "s"} in the drop could not be read `
      + `(a file not on disk yet, a permission error, or a broken link): ${shown}`);
  }
}

// Drop anywhere on the picker. The document-level handlers stop a drop that
// misses it from navigating the tab to the file -- which would lose the
// page, not analyse anything. A drop lands in the same pick() queue as the
// keyboard fallback's input: a shortcut to it, not a second path (V46).
const cardEl = pickerEl.querySelector(".card");
const dropzoneEl = $("dropzone");
let dragDepth = 0;
const setDragover = (on) => { cardEl.classList.toggle("dragover", on); dropzoneEl.classList.toggle("dragover", on); };
document.addEventListener("dragover", (e) => e.preventDefault());
document.addEventListener("drop", (e) => e.preventDefault());
pickerEl.addEventListener("dragenter", (e) => { e.preventDefault(); dragDepth++; setDragover(true); });
pickerEl.addEventListener("dragover", (e) => { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; });
pickerEl.addEventListener("dragleave", () => { if (--dragDepth <= 0) { dragDepth = 0; setDragover(false); } });
pickerEl.addEventListener("drop", (e) => {
  e.preventDefault();
  dragDepth = 0;
  setDragover(false);
  const walked = filesFromDrop(e.dataTransfer);   // starts NOW, while dataTransfer is live
  pick((async () => { const r = await walked; noteDropOutcome(r); return r.files; })());
});

// Drop onto the REPORT adds to the current set -- the same merge the
// missing-includes notice's buttons do, because dragging the folder onto the
// page is what people try first when the notice says files are missing. A
// dropped file is taken as the user's word; a dropped folder contributes
// only the files whose NAMES are wanted, so an engine checkout dragged here
// is listed, not read.
let reportDragDepth = 0;
reportEl.addEventListener("dragenter", (e) => { e.preventDefault(); reportDragDepth++; reportEl.classList.add("dragover"); });
reportEl.addEventListener("dragover", (e) => { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; });
reportEl.addEventListener("dragleave", () => { if (--reportDragDepth <= 0) { reportDragDepth = 0; reportEl.classList.remove("dragover"); } });
reportEl.addEventListener("drop", (e) => {
  e.preventDefault();
  reportDragDepth = 0;
  reportEl.classList.remove("dragover");
  const walked = filesFromDrop(e.dataTransfer);
  enqueue(async () => {
    const r = await walked;
    noteDropOutcome(r);
    await addFromFileList(r.files, { explicit: !r.hadDirectory });
  }, setNoticeStatus);
});
// Keyboard (and click) fallback: a drag-only entry point would exclude
// anyone without a pointer. The dialog it opens is the plain single-file
// one, which asks the browser for no folder permission.
const browseForFile = () => $("pick-file").click();
dropzoneEl.addEventListener("click", browseForFile);
dropzoneEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); browseForFile(); }
});

/* Theme: three states, the same way the --html report does it. Auto follows
 * the OS; light and dark are stamped on <html data-theme> and remembered in
 * this browser. theme-boot.js replays the stored choice before first paint;
 * this only cycles it. Storage can be unavailable (private mode, blocked),
 * in which case the choice simply lasts for this page. */
const THEME_KEY = "bgview-theme";
const THEME_ORDER = ["auto", "light", "dark"];
const THEME_LABEL = { auto: "Theme: auto", light: "Theme: light", dark: "Theme: dark" };
const themeEl = $("theme");
const currentTheme = () => document.documentElement.dataset.theme || "auto";
function applyTheme(mode) {
  if (mode === "light" || mode === "dark") document.documentElement.dataset.theme = mode;
  else delete document.documentElement.dataset.theme;
  themeEl.textContent = THEME_LABEL[mode];
  themeEl.title = "Follow the system theme, or pin light or dark";
  try {
    if (mode === "auto") localStorage.removeItem(THEME_KEY); else localStorage.setItem(THEME_KEY, mode);
  } catch { /* storage unavailable: see above */ }
}
themeEl.addEventListener("click", () =>
  applyTheme(THEME_ORDER[(THEME_ORDER.indexOf(currentTheme()) + 1) % THEME_ORDER.length]));
applyTheme(currentTheme());   // label only -- theme-boot.js already stamped the attribute

reopenEl.addEventListener("click", () => {
  reportEl.hidden = true;
  reportEl.replaceChildren();
  pickerEl.hidden = false;
  reopenEl.hidden = true;
  delete document.body.dataset.view;
  document.title = "Rogue BuildGraph Viewer - static analysis";
  clearError();
  setStatus("Ready.", false);
  // Otherwise a reload resurrects the shared script and "Analyse another"
  // looks broken -- replaceState, not a navigation, so it does not fire
  // hashchange or add a history entry for a state nobody asked to visit.
  if (location.hash) history.replaceState(null, "", location.pathname + location.search);
});

/** Sanitise a decoded share link's own path data the same way a picked
 *  folder's paths are sanitised (V46: one path, even for this). The payload
 *  comes from `decode()`, which is to say from a stranger -- but there is no
 *  filesystem here, so a hostile path can only ever become a slightly odd
 *  Map key, never escape anywhere. */
function sanitizeSharedFiles({ entry, files }) {
  const safeFiles = new Map();
  for (const [path, text] of files) safeFiles.set(sanitizePath(path), text);
  return { entry: sanitizePath(entry), files: safeFiles };
}

/** Open-on-load (T64): if the URL carries a share payload, decode it and run
 *  it through the SAME analyseFiles() tail a folder pick uses (V46). A
 *  shared link already names its own entry, so the entry-guessing in
 *  onPick() is skipped entirely rather than reproduced. */
async function openFromHash() {
  if (location.hash.length <= 1) return;   // no "#", or an empty one
  if (!share.isSupported()) {
    // decode() itself needs deflate-raw; failing that inside it would read
    // as a corrupt link when the real story is a browser capability gap.
    showError("This share link needs deflate-raw compression support, which this browser does not have.");
    return;
  }
  clearError();
  setStatus("Opening shared link...", true);
  let decoded;
  try {
    decoded = await share.decode(location.hash);
  } catch (err) {
    // V53: refuse and say so, and leave the picker up -- no report, partial
    // or otherwise, and the next action (pick a file) stays available.
    setStatus("Ready.", false);
    showError(err instanceof share.ShareError ? err.message
      : `Unexpected error while opening the shared link (this is a bug in Rogue BuildGraph Viewer): ${err && err.message ? err.message : err}`);
    return;
  }
  const { entry, files } = sanitizeSharedFiles(decoded);
  aliases = new Map();
  noticesCollapsed = false;
  await analyseFiles(entry, files);
}

// Warm the schema while the user is still finding their file, so the first
// analysis does not pay for a fetch it could have made earlier.
loadBundledSchema().catch(() => { /* reported on first use instead */ });
setStatus("Ready.", false);
openFromHash();
