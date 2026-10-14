# Rogue BuildGraph Viewer

Static analyzer and visualizer for Unreal Engine **BuildGraph** `.xml` scripts, by
[Rogue Component](https://roguecomponent.com). Use it at
**https://buildgraphviewer.roguecomponent.com**, or host your own copy: see
[Hosting your own](#hosting-your-own). Inside the code and on the command line the tool is called
`bgview`.

Pure Python 3.10+, **stdlib only** — no `pip install`, no Graphviz, no UE installation required.

---

## Why

BuildGraph hides three things that the XML text simply does not show:

1. **Dataflow runs through `#Tags`, not nesting.** A node's real inputs are file sets produced by
   some other node, possibly hundreds of lines away.
2. **Properties expand at parse time, top-to-bottom.** *Where* a `<Property>` sits changes what
   each node sees. A redefinition after a node does not reach back and change it.
3. **`<Agent>` means a different machine.** Parallelism and the file-transfer boundary are implied,
   never drawn.

Defects hide in exactly those blind spots — and the engine barely complains. Running Epic's own
`RunUAT BuildGraph -ListOnly -ShowDiagnostics` over a script with **12** known defects:

```
BUILD SUCCESSFUL
ExitCode=0
0 Error(s)
… one warning: "Property 'GameBinaries' is not defined"
```

**One of twelve, and a zero exit code.** Its "visualization" is nine flat lines of node names — no
tags, no dependencies, no conditions, no parallelism. `bgview` exists to close that gap.

On the same file, bgview reports **4 `warn`-level defects with exact source lines**, plus the
lower-confidence ones as `info`, and draws the graph.

## Usage

```bash
python -m bgview <script.xml> [options]
```

| option | meaning |
|---|---|
| `--set NAME=VALUE` | override an `<Option>` (repeatable). Defaults come from each `DefaultValue` |
| `--target <Name>` | graph root for display/pruning (repeatable) |
| `--html <path>` | write the self-contained HTML report |
| `--sarif <path>` | write SARIF 2.1.0 for CI / editor ingestion |
| `--project <path>` | uproject path; defines `ProjectFile`/`ProjectName`/`ProjectDir`. Without it they are undefined, exactly as a real engine run with no `-project=` |
| `--schema <path>` | override `Schema.xsd` discovery |
| `--fail-on {info,warn,error}` | exit-code threshold (default `warn`) |
| `--baseline <path>` | suppress already-accepted findings |

Exit codes: `0` clean · `1` findings at or above the threshold · `2` tool error.

```
<file>:<line>: <severity>: [<detector-id>] <message>
```

The schema resolves in three tiers: `--schema` → walking up from the script toward
`Engine/Build/Graph/Schema.xsd` → a table bgview derives and ships itself. That third tier matters
more than it looks: the schema is a **generated, gitignored artifact**, so it is often missing even
inside a real UE tree. bgview says on stderr when it falls back. The derived table carries only what
the analysis reads — element names, tag-producing attributes, required attributes — and no Unreal
Engine file is vendored here; see [Notice](#notice).

## Live picker

```bat
serve.bat                 :: double-click it; or from a prompt:
serve.bat --port 8765     :: pin the port instead of taking a free one
```

```bash
python -m bgview --serve  # the same thing, if you would rather type it
```

`serve.bat` finds a Python 3.10+ (preferring the `py` launcher, which sidesteps the
Microsoft Store stub), runs from its own directory so it works from a shortcut, passes any
extra arguments through, and only holds the window open if something went wrong. The server
opens your browser itself and prints the URL it opened — that URL carries a per-run token, so
it is not reusable between runs and cannot be bookmarked. Ctrl-C stops it.

Walk the filesystem, click any `.xml`. Every click re-runs the whole analysis, so edit a
script and click it again to see the new result. The report renders in place, identical to
what `--html` writes.

**The picker gets out of the way.** Once a script is analysed it folds away and the report
takes the full window; **Change script…** in the header (or `Esc`) brings it back, still on
the directory you left it in. It only folds on success — if a script fails to analyse the
picker stays up, because picking a different one is exactly what you need to do next.

It reads your disk on behalf of a browser, so it is deliberately locked down:
bound to **127.0.0.1 only** (never `0.0.0.0`), every request must carry a
per-run random token — which is what stops any other page open in your browser
from POSTing to `localhost` and reading your files — and it is strictly
**read-only**: nothing is written, deleted or executed, and the picker lists
directories and `.xml` files only.

## In the browser — no install

The same analysis, as a web page. Open the site, pick a BuildGraph script off
**your own** machine, and get the full report — findings panel, swimlane graph,
source view. It is a static site: no server process, no backend, no upload, and
nothing to install.

**Nothing you pick is ever uploaded.** The analyser is JavaScript —
`webapp/bgview/` is a port of the Python package in this repo — so your script
is read into memory, analysed in the tab, and never sent to any server. There
is no bundler and no WebAssembly: the browser loads plain ES modules as they
are, which is why the whole "build" is copying a directory. The one thing that
*can* leave the tab is a link you deliberately build and paste yourself — see
"Sharing a script" below, which is not an upload either, but is worth reading
before you assume nothing ever leaves the browser.

### Dropping a file, or a folder

The picker is a drop zone. Drag the script onto it, or the folder that holds
it, and the difference matters:

| You drop | What you get |
|---|---|
| a single `.xml` | fine for a self-contained script |
| a **folder** | the only way `<Include>` resolves at once |

Includes are relative to the including file's directory, so a single dropped
file genuinely cannot see them. bgview reports each unreachable include as a
`D14` and carries on analysing (it never dies on one), but the properties and
nodes that file would have defined really are missing, and the findings
downstream of them are noise. **If your script includes anything, drop the
folder** — or drop the file and let the report fetch the includes, below.

Dropping asks the browser for nothing: no permission prompt, no dialog. For
anyone without a pointer, the zone is focusable and Enter opens a plain
single-file dialog; that is the only file picker on the page apart from the
two buttons in the missing-includes notice.

A dropped folder is walked whole, sub-folders included, and the report then
says what the walk did — `Dropped folder: 6 .xml/.xsd files found across 4
folders, nothing else read: …` with the paths — and names anything it could
not read (a
cloud-synced file not yet on disk, a permission error), rather than skipping
it silently. Files and folders can also be dropped **onto a report**: a
dropped file is added to the set as it is, and a dropped folder contributes
only the files that match a missing include — by name *and* by as much of the
include's written path as it has (`Inc/X.xml` is satisfied by a folder called
`Inc`; a same-named file in some other folder is reported, not used) — so
dragging an engine checkout there lists it but does not read it.

Notices sit under the report header. Green ones confirm what you just did
(a drop, a fetch, a file you chose) and disappear the first time you interact
with the report; yellow warnings, the tail-match note and the override banner
stay until the cause does. **Hide notices** folds them all into a one-line
strip that still says how many are folded, and **Show N notices** brings them
back. Selecting a node folds them too, so the graph and inspector get the
room; a new script starts with them visible.

When a report still has unresolved includes it says so in a notice under the
header and names them. **Find them in a folder** asks for the folder they live
in — the engine root is fine — and reads *only* the files asked for. In
Chrome and Edge a chosen folder is a handle that is navigated, not listed:
each missing path is walked straight to its file, every shorter tail of it is
tried (`Engine/Build/Graph/X.xml`, then `Build/Graph/X.xml`, …), and only if
that fails does a bounded search of sub-folders look for the file by name,
skipping `Binaries`, `Content`, `Source`, `Plugins` and the other giants and
stopping after 1500 folders. A fragment that is found may include further
fragments, so the rounds repeat until nothing new is missing; a real
`Engine/Build/Graph/Schema.xsd` is picked up on the way. The notice then lists
exactly which files were read, and nothing else was. Browsers without that API
fall back to the ordinary folder input, which has to list the folder, but
still read only the wanted names. **Add the files** lets you hand-pick them
instead. Either way the new files are merged into the current set, the same
script is re-analysed, and a share link built afterwards carries them too.

Real scripts also reach *outside* their own folder — `../../../Engine/Build/…`
climbing above whatever you picked, or a path rooted at an engine built-in the
browser has no value for. On disk those land on a file that exists; in your
pick that file is usually present under a shorter path. So after an exact miss,
bgview looks for the one picked file whose path *ends* the same way, uses it,
and tells you it did in the same notice. The bar is deliberate: every segment
of the shorter path has to match, **and** at least the file name plus two
parent folders have to agree — `Inc/SharedProperties.xml` next to your script
shares those two segments with every overlay of that name elsewhere in an
engine tree (a `Restricted/NotForLicensees/…` copy, say), so it proves
nothing about which one was meant and is left missing rather than guessed. An
ambiguous match — two platform folders each carrying the same fragment — is
treated as missing too. When the bar refuses a same-named file that *is* in
your pick (a flattened copy of an engine folder keeps `Tasks/Inc/X.xml` as
plain `Inc/X.xml`, say), the notice lists it with a **Use …** button: one click
makes that file stand in for the include, the report says so on every render,
and a share link built afterwards carries the choice. The decision is yours
because the paths alone cannot make it — the same two segments are all a
Restricted overlay's public twin shares with it. An unexpanded `$(RootDir)` in a path (the built-in has
no value in the browser) is read as "from the engine root". Wildcard includes
(`Platforms/*/Build/Inc/Foo.xml`) name a *set* of files; they are not expanded
by either implementation yet, are never matched to a single file, and are
reported as missing with a finding that says so.

Dropping a folder has a bonus: if it is a real UE tree, its own
`Engine/Build/Graph/Schema.xsd` comes along and is used in preference to the
derived table. Only `.xml` and `.xsd` files are read; nothing else in the
folder is touched, and nothing leaves the tab (measured — see "How it is kept
honest").

One browser dialog can still appear, in the missing-includes notice: **Find
them in a folder…** has to ask permission to look inside a folder you choose.
In Chrome and Edge that dialog says "let the site view files", which is
exactly what happens. Browsers without that API fall back to the classic
folder input, whose dialog is worded "upload N files to this site"; that is the
browser's fixed text for the same permission, shown by every site that uses
it, and it is not an upload either — the wanted files are read into memory and
no request follows.

### Trying an option-set

A BuildGraph script declares `<Option>`s, and what it builds depends on their
values: a `Configuration`, a platform list, a `WithDDC` switch. The CLI takes
them as `--set NAME=VALUE`; in the browser the **Options** button in the report
header lists every option the script registers, with its description, its
default, and — when its `Restrict` is a plain list such as
`Debug|Development|Shipping` — a dropdown of exactly those values. **Apply**
re-runs the same analysis with your values; the header then carries a banner
naming every non-default value, and the button shows how many are in force.

Two things to be precise about, because "simulate" is a word that promises
more than this does:

- **It is the same evaluation the CLI does with `--set`.** Values change —
  what `$(Configuration)` expands to, hence node names, paths, which required
  attributes come out empty, which guards are satisfiable. *Which branches
  are analysed does not change.* bgview deliberately walks every `If=` branch
  and every `Case`, because a static tool cannot know which option-set a real
  run will use (that union is what lets it prove a guard can *never* hold).
  Nothing is built, and the script is not modified.
- **What you see for a chosen option-set is a lens over that union.** Every
  guard's `If` is evaluated under your values to *true*, *false*, or
  *unknown*; a node is active only if every guard around it — its own, its
  agent's, an enclosing `Do` or `Case`, the `<Include If=…>` that brought its
  file in, the `<Expand>` that placed it from a macro — is true. Inactive
  nodes, lanes, wires and the findings on them are **dimmed, never removed**,
  the counts are said under the title (`11 of 14 nodes active · 1
  undecidable`) and in the findings panel, and **Show inactive** undims
  everything at once. The inspector shows each guard's verdict under the
  current values next to its all-option-sets verdict.

*Unknown* is a real answer, not a hedge: `Exists()` touches a filesystem the
page does not have, `$(RootDir)` has no value while preprocessing, and a
condition the parser rejects proves nothing. Those nodes stay lit, with a
dashed border and the undecidable guard in their tooltip.

A share link carries the script and the defaults — not your option values —
and the banner says so. Wildcard includes are still not expanded, so a
per-platform fragment pulled in by `Platforms/*/Build/Inc/…` does not appear
under any option-set yet.

### The page itself

- **Theme.** The page follows your OS light/dark setting; the *Theme* button
  in the corner pins it to light or dark, remembered in this browser only. It
  is the same palette the `--html` report uses, so the two look like one tool.
- **Zoom.** The toolbar in the graph's corner zooms in and out through
  Unreal's own zoom stops and shows which one you are on; *Fit* frames the
  whole graph. The wheel zooms about the cursor, right- or middle-drag pans.
- **Linked files.** A node declared in an `<Include>`d file carries a small
  link glyph before its name; a lane whose nodes come from an included file
  carries the same glyph and names the file; the Source tab marks those files'
  tabs; the legend explains the glyph whenever the graph spans more than one
  file. Tooltips and the inspector give the full path.
- **Source → All.** When the script spans several files, the Source tab opens
  on **All**: the main script with every `<Include>` replaced by what it
  pulled in, recursively — what the engine reads, as one document. Each call
  becomes a header row naming the file, its `If=` guard and whether it was
  found (a missing include keeps its call); the injected lines keep their own
  file's line numbers, in italics with a rail and an indent per level, so
  gutter marks, the selected node's span and "jump to line" still land on the
  right line. Clicking a header opens that file on its own tab.
- **Keyboard.** Findings, nodes, lane headers, tabs, the panel resizers and
  the lens inputs are all reachable with Tab; Enter or Space activates, arrow
  keys resize a panel, Escape clears the selection.
- **No web fonts, no CDN, no third-party anything.** System fonts throughout —
  the only files the page loads are its own.

### Is the JavaScript the same analyser?

It is a second implementation, so the honest answer is "verified, not assumed".
Every module was compared against the Python over Epic's 19 shipped graphs,
output for output:

| Module | Agreement |
|---|---|
| loader | 19/19 files (818 elements: tag, line, end line, attributes) |
| schema | 98/98 element attribute tables |
| evaluator | 19/19 files (1545 resolved entries, findings, options, property defs and reads) |
| model | 19/19 files (182 nodes) |
| condition | 146/146 conditions (136 from the corpus, 10 written to cover the rest of the grammar) |
| algebra | 269/269 (237 guard classifications + a 32-case Kleene battery) |
| detectors | 19/19 files, 66 findings, field for field |
| FP budget | exactly the 3 pinned identities (V5/V21) |

That comparison found two real bugs in the new XML scanner, both of which would
have put findings on the wrong lines:

- **Line counting must follow the XML spec, not "count `
`".** CRLF is one
  break and a lone CR is also one. Epic ships `Examples/FPSBuildGraph/*.xml`
  with every line ending CR CR LF — a double LF→CRLF conversion — which the spec
  reads as *two* breaks, so those files hold 62 XML lines where an editor shows
  32. Counting only `
` put every finding in them at half its true line.
- **Attribute values need normalising** (spec 3.3.3): tabs and newlines become
  spaces, and only *then* are entities decoded, because a character reference is
  exempt — `&#10;` must survive as a newline where a literal newline becomes a
  space.

The browser cannot use `DOMParser` for any of this, incidentally: it exposes no
source positions at all, and V15 requires a real `file:line` on every finding.
The Python hit the same wall with ElementTree and dropped to expat; in a browser
there is no expat to drop to, so `loader.js` hand-scans the document.

### Sharing a script

Once a report is up, a **Share** button in its header builds a link. Clicking
it is the only thing that builds one — nothing is generated on load or on
completion, and nothing is copied to your clipboard until you press the
**Copy** button that appears next to it.

**The link contains the script.** Not a reference to it, not an upload of
it somewhere and a pointer back — the file's own text, compressed and encoded,
sitting in the URL itself after the `#`. A `#fragment` is never sent to any
server by the browser, which is what makes the whole feature possible without
a backend: there is nothing to host, nothing to retain, nothing to leak from a
server because there is no server in this path. But that also means **anyone
who receives the link can read the whole script**, exactly as if you had
pasted the file. Treat a share link like the file it carries: do not paste it
anywhere the script itself should not go, and do not treat "it's just a link"
as making it safer than an attachment. The app states this on screen at the
moment the link is built, in the warning colour, not as a tooltip you can
miss.

Whether your script fits is a matter of size, and it usually does by a wide
margin. Measured over Epic's 19 shipped example graphs, deflated and
base64url-encoded (R53): the largest single script (18,177 bytes raw) comes
out to 5,448 characters, none of the 19 crosses 8k, and a realistic six-file
folder (`Examples/FPSBuildGraph`) comes to 6,536. A URL has no practical length
limit that a BuildGraph script will hit first.

A link that arrives truncated or corrupted — a chat client wrapped it, a
paste lost the tail — is **refused, not analysed**. The payload carries its
own byte length and checksum; either one failing to match stops decoding
before any file set is built, because a half-decoded script still parses and
would produce fabricated findings. You get a plain refusal message, not a
partial report.

If your browser lacks the compression API the feature needs
(`CompressionStream`/`DecompressionStream` with `deflate-raw`; present in
Chrome, unmeasured elsewhere), the Share button is simply absent rather than
present and broken.

### Running and deploying it

**Live: https://buildgraphviewer.roguecomponent.com** (the Cloudflare Pages
address, https://buildgraphvisualizer.pages.dev, keeps working too)

Locally, any static server will do — there is nothing to build:

```bash
python -m http.server -d webapp 8000    # then open localhost:8000
```

That server is only a file server: it hands out the same static files the
Cloudflare deployment does, and does not see, store, or transform anything a
share link carries — the fragment never leaves the browser regardless of what
serves the page. This is also how self-hosting inside a studio network works:
point *any* static file server at the `webapp/` directory — an intranet web
server, IIS, nginx, `python -m http.server` on a box everyone can reach —
and every feature, share links included, behaves identically, because the
analysis and the share codec are both client-side JavaScript with no server
half to redeploy elsewhere. (`serve.bat` and `python -m bgview --serve`, a few
sections up, are a different thing: that is the Python CLI's own live picker,
deliberately bound to `127.0.0.1` and token-gated because it reads *your*
disk — do not point that one at a network interface. What is described here
is serving the `webapp/` directory, which reads nothing but what a visitor
picks in their own browser.) There is nothing to build first — `webapp/` is
already the deployable artifact.

Hosted on **Cloudflare Pages**, which serves static files from a *private*
repo for free (GitHub Pages will not, without a paid plan). It was created by
direct upload:

```bash
wrangler pages project create buildgraphvisualizer --production-branch main
wrangler pages deploy webapp --project-name buildgraphvisualizer
```

Direct upload means **pushing to git does not redeploy**. Re-run the second
command after a change, or connect the repo in the Cloudflare dashboard
(**Workers & Pages → Create → Pages → Connect to Git**; build command empty,
output directory `webapp`) to get automatic deploys instead.

`webapp/_headers` is served by Cloudflare and sets `nosniff` and
`no-referrer`. The `.mjs`/`.wasm` MIME pins it used to carry are gone with the
WebAssembly runtime that needed them (§B.9).

**It cannot be opened straight from `file://`.** Measured, not assumed: ES
modules and `webapp/data/schema-facts.json` are both fetches, and Chrome blocks
`fetch` from origin `null`. That is a browser rule no page can work around, and
it is exactly why "self-hosted" above means *serve the directory* — even the
cheapest static server gives every fetch a real origin to run from. If
you want something double-clickable, generate a per-script report instead —
`--html` writes one self-contained file that opens offline with zero network
requests, which is also the answer for handing someone a report without
handing them the script (a share link puts the script in the URL; an `--html`
file puts the already-computed findings in the file and nothing to re-derive
them from).

### How it is kept honest

- Nothing off the analysed script ever becomes **markup**. `render.js` and
  `app.js` use `textContent`, `createElement` and `setAttribute` exclusively —
  there is no `innerHTML` anywhere — so a node named `<img onerror=...>` is
  text, not an element. That makes V8 structural rather than a per-string
  escaping duty, which is also why the report no longer needs the sandboxed
  iframe the Pyodide version required.
- The Content-Security-Policy is the strict one: `default-src 'self'`,
  `script-src 'self'`, `connect-src 'self'`, and **neither `unsafe-inline` nor
  `unsafe-eval`**. Both of those were forced by the previous WebAssembly build;
  dropping Python from the browser dropped them too.
- No third-party origin is referenced at all — no CDN, no bundler runtime, no
  font host. The only fetch the page makes is `./data/schema-facts.json`.

## The HTML report

One self-contained file. No CDN, no web fonts, no network requests — it opens from `file://` and
survives being emailed to a colleague.

- **Findings first.** The verdict is the product; the picture is evidence for it. Click a finding
  to jump to the responsible node.
- **Agents as swimlanes**, which is what makes parallelism legible: nodes in different lanes with
  no dependency path between them are the ones that run at the same time.
- **Tag edges are drawn differently from order-only (`@After`) edges**, because that distinction is
  precisely what the XML hides.
- **Boxes are sized to their names**, and each column is packed to the widest box in it. Real node
  names run from `Compile` to `Compile $(EditorTarget) $(TargetPlatform)`; one fixed width for
  both means either a wall of half-empty boxes or a wall of truncated ones, and a truncated node
  name is not identifying information.
- **Rows come from the dependency structure, not declaration order.** Each dependent gets its own
  row, each subtree a contiguous band, and a parent is centred on the band it feeds. Siblings sort
  least-entangled first, counted within the lane before globally — fewest same-lane `Requires`,
  then same-lane `Consumes`, then the global counts, and finally longest reach — so short direct
  branches sit on top, tangled ones spread out underneath, and a wire that skips columns runs along
  the lane's edge where there is nothing for it to cross. In-lane leads because only a dependency that resolves
  inside the lane draws a wire in it; a node with six cross-agent `Requires` and one local one is,
  for this lane's picture, a simple node. An edge that skips a rank reserves a corridor at
  each rank it crosses, pushing boxes out of its way. Measured on Epic's shipped graphs, in-lane wires
  running through a box dropped from 6 to **zero** across 96 in-lane edges.

  What this does **not** fix: lanes stack vertically, so a wire from the first agent to the
  fortieth crosses every lane in between. On Epic's `BuildWorldPartitionHLODs.xml` — 105 nodes
  across 53 agents — 153 of 204 edges are cross-lane and account for 136 of its crossings,
  untouched by any row policy. That needs a different layout, not different rows.
- Lanes collapse, so the page stays usable from ten nodes to thousands.
- **Two tabs: Graph and Source.** The Source tab shows the script's own XML with line numbers,
  findings marked in the gutter by severity, and a picker for each `<Include>`d file.

### Following one tag through the graph

Click a node and every wire touching it lights up — in and out. In a swimlane layout a node's
dependencies are usually somewhere else entirely on the canvas, so "which of these lines is
mine" is otherwise a question you answer by tracing with a finger.

The header carries two fields, **Highlight** and **Filter**. In the details panel, everything
under *Produces* and *Consumes* is a chip you can pick up and drop into either one:

- **Highlight** accents every node that produces, creates or consumes that tag. Nothing is taken
  away — the rest of the graph stays as context.
- **Filter** suppresses everything that doesn't, findings panel included, and says how many
  findings it is holding back. Suppressed rather than deleted: position encodes dependency rank,
  so removing boxes would leave the survivors floating with nothing to read against.

Both fields hold any number of tags, OR-combined. Dragging is the discoverable gesture but not
the only one — a chip is a real button, so **click** adds it to Highlight and **Shift+click** to
Filter, and the whole thing works from the keyboard.

*Requires* and *After* stay plain text on purpose: they hold node references as well as tags, and
the tags among them already appear under *Consumes*.

### Getting from a verdict to the line

- **Single-click a node** → it is selected, the details panel fills, and its lines are *marked* in
  the Source tab — but you stay on the graph. Being yanked to another tab every time you click a
  box would make the graph useless for what it is mostly for: clicking around to read structure.
- **Double-click a node** → *now* the Source tab opens, already sitting on that node's whole
  `<Node>`…`</Node>` range with its opening line emphasised. Shift+Enter does the same from the
  keyboard.
- **Clicking a finding** marks its own line, which is more precise than the node's whole range;
  double-clicking goes there — the same contract as a node. Findings that point at no node at all
  (a dead `<Property>`, say) still mark their line.
- **Selecting a node lifts its own findings to the top of the list**, scrolls the pane up to them
  and dims the rest — all severities together, because the question being answered is "what is
  wrong with *this* node" and its own `info` outranks someone else's `error` there. (The severity
  filter is still there for the other question.) A node with no findings
  greys the whole list — that is the answer to "what is wrong with this one", not an empty
  screen. Dimmed, never removed: the severity filter and the tag lens already remove rows, and a
  third thing that removed them would make it impossible to tell which one did. Dimmed rows stay
  clickable.
- **Click blank canvas, or press `Esc`, to deselect** — the box, its lit wires, the details panel
  and the source highlight all clear together. A highlight left behind would be pointing at a node
  that is no longer selected.
- **The Source tab takes the window.** It is a wall of code and both side panels are about the
  *graph*, so they fold away while it is up and come back when you leave — each remembering its own
  state, so a details panel you had already closed stays closed. Reopening one *while* on the Source
  tab counts as an instruction and sticks.
- The source shown is the text that was *analysed*, captured while parsing — not re-read from disk
  afterwards, so its line numbers can never drift out of step with the findings drawn on it.

### Moving around the graph

Unreal's own graph-editor controls, read out of `SNodePanel.cpp` — the same file this report's
connection splines come from:

| | |
|---|---|
| **Wheel** | Zoom, one discrete stop per notch, anchored on the cursor |
| **Ctrl + wheel** | Zoom in past 1:1 — without Ctrl the wheel stops there, exactly as the engine does |
| **Right-drag / middle-drag** | Pan. Left-drag does not pan |
| **Fit** (or **Home**) | Largest stop at which the whole graph fits, both axes, never magnifying past 1:1 |

The zoom readout reads `Zoom -6` / `Zoom 1:1` / `Zoom +3` because those are the engine's own 21
stops, not a percentage of our invention.

### Panels

The findings panel and the details panel each have a drag handle and a **Findings** / **Details**
toggle in the header. Handles are keyboard-operable (arrow keys, Shift for a bigger step) and
double-click resets to the default width. Widths are clamped to 180px … min(720px, half the
window) — a side panel dragged past half the window stops being a side panel, and there would be
no way back once the graph is squeezed to nothing.

## What each detector *proves*

Severity is a claim about confidence, not importance. `warn` means **provable from the source**.
`info` means real but not provable — a judgement call left to you.

| id | proves | sev |
|---|---|---|
| D1 | `$(X)` is referenced but never defined — after subtracting the 16 unconditional engine built-ins (plus the 3 project ones when `--project` is given), `ForEach` vars, macro args and `$(Name:N)` slices | warn |
| D2 | a `#tag` consumed by a **task attribute** is produced nowhere. (`Node/@Requires` is D18's, at `error` — the engine hard-errors on that one but tolerates the task form) | warn |
| D3 | a tag in `@Produces` is consumed nowhere — usually fine, it is the file's public API | info |
| D4 | a tag created inside a node, absent from its `@Produces`, unused in that node — it **cannot** escape, so it is provably dead | warn |
| D5 | a tag is **provably empty**: every contributor is disjoint from the filter that selects it | warn |
| D6 | a `Compile` node has no dependency path to `SetVersion`, so it may stamp a stale version | info |
| D7 | a declared cross-agent dependency transfers a provably empty set | warn |
| D8 | a property is defined and never read | info |
| D9 | an `<Option>` is declared and never read | info |
| D10 | an empty list entry — harmless, the engine drops it. The message says which kind it is: a literal trailing `;`, or one left behind by a `$(Property)` that expanded to nothing (in which case there is no `;` in the source to find) | info |
| D11 | a schema-**required** attribute resolves to `""` under every reachable option-set | warn |
| D12 | a guard is unsatisfiable (`warn`) or tautological (`info`) | warn/info |
| D13 | a `<Property>` definition is dead on arrival — no reader can ever observe it | warn |
| D14 | an element kind we do not model — reported loudly, never skipped silently | warn |
| D15 | `Agent/@Type` is hardcoded rather than option-driven | info |
| D16 | a task reads a directory another node fills, with no tag flow to carry it | info |
| D17 | a macro contract the engine itself reports: undeclared macro, duplicate declaration, unknown or missing argument | error/warn |
| D18 | an engine **hard error**: an unresolvable `Requires` reference (with a did-you-mean for a missing `#`), one tag produced by two nodes, an `<Option>` whose `DefaultValue` violates its own `Restrict`, a duplicate name in the node/report/aggregate namespace, a `@Produces` entry missing its `#`, a node declaring the same output twice (including its own implicit `#<NodeName>`), a name the engine's `ValidateName` rejects, or an `<Artifact>` naming a tag no node produces | error |
| D19 | a node is ordered **after work its own agent cannot wait for**: it depends — directly or transitively — on a node belonging to an agent declared later than its own agent's first definition. Only reachable by reopening an `<Agent>`, and invisible at every individual site, because every name involved resolves perfectly well | error |
| D21 | a property is defined at an outer level **after** the same name was already written inside an inner scope (a node, agent, `<ForEach>` or macro body). The engine refuses this outright. Defining it outer-first and refining it inside — the ordinary accumulator idiom — is fine and never reported | error |
| D20 | something the engine itself **warns** about: a tag listed in both `@Requires` and `@OptionalRequires` (the optional one does nothing), a macro argument listed twice, or a `<ForEach>` `@Separator` longer than one character (the engine ignores it and splits on `;`, so the loop iterates over something other than what you wrote) | warn |

| D22 | an `<Option>` whose default is `true` or `false` has no `Restrict`, so a mistyped value on a manual `-set:` run (`-set:WithDDC=ture`) is accepted and read as *false*; `Restrict="true\|false"` makes it a parse-time error | info |

### Two things it deliberately will **not** tell you

Honest coverage beats fabricated coverage, so bgview stays **silent** on two tempting findings:

- **"The cross-agent split breaks the version dependency."** It doesn't. `SetVersion` registers the
  version files as build products, and `Requires="NodeName"` transfers a node's default output — so
  a *declared* cross-agent dependency is fine. We tested this belief and it was wrong; reporting it
  would be a false positive.
- **"`SetVersion` should have been guarded."** Whether a task *should* be conditional is intent, not
  a static property. No detector can decide it.

## The false-positive budget

A linter that cries wolf gets muted in a week, so this is enforced as a test, not a hope.

Run over **all 19 BuildGraph files Epic ships**, the entire permitted `warn`+ output is:

```
Examples/BuildEditorAndTools.xml                 D2  #BinaryFiles                          x1
Examples/FPSBuildGraph/BuildEditorAndTools.xml   D2  #BinaryFiles                          x1
Tests/IncrementalValidate.xml                    D1  Property 'ProjectDir' is not defined  x5
```

All three are **true positives**. The first two are a real latent bug in Epic's own shipped
example, where `SrcSrv/@BinaryFiles="#BinaryFiles"` consumes a tag nothing ever produces. The
third is what the engine itself warns when no project is supplied, since `ProjectDir` is only
defined with `-project=` — pass `--project` and it goes away.

Note the consequence: **"clean on Epic's originals" is an invalid target.** The originals contain a
real bug, so a tool reporting nothing there is broken in the other direction. The test asserts
*identity*, not a count — a run that misses `#BinaryFiles` but emits one bogus warning has the
right number and still fails.

Traps this budget exists to catch, with their measured blast radius:

| trap | cost if it regresses |
|---|---|
| `ProjectName`/`ProjectDir` defined unconditionally | +4 phantom "unresolvable reference" errors |
| an `error` detector firing under a guard | +1 — bgview unions all branches, so guarded refs can't be *proven* broken |
| treating agents/labels as sharing the node namespace | +3 — an `<Agent>` and `<Node>` may share a name, and duplicate agents merge |
| no built-in property table | **+44** false D1 findings |
| tag lists lexed on whitespace | +2 — tag names legitimately contain spaces |
| implicit `#<NodeName>` output missed | large — every default-output reference becomes a phantom |
| `@Produces` treated as dead code | +6 |
| lifetime analysis in document order | +3 — macros expand later than they are written |
| accumulator `$(X)` = `$(X);more` flagged | **+37** |

## Design note

Nothing here is hardcoded per task, across all ~70 BuildGraph tasks. The engine's schema types every
tag-producing attribute as `TagListType`, so **an attribute the schema types as a tag list produces
tags; any other attribute containing a `#Name` consumes them.** That rule was checked against all 70
task classes in the engine's C# source with zero contradictions, and it keeps working when Epic adds
task #71. The same trick drives D11 via `use="required"`.

## Known limits

- `<Regex>` / `<StringOp>` property-defining effects are not modelled (unused across Epic's corpus).
- A `<Property>` whose value is a multiline text body rather than `Value=` is not read (zero uses in
  Epic's corpus).
- `Exists()` in a condition is treated as opaque — it touches the filesystem, so it is never assumed
  true or false.
- `Copy/@Exclude` is not covered by D5. It is the opposite polarity to `Tag/@Filter` (removes
  rather than selects), so proving emptiness needs a subsumption test rather than a disjointness
  test. Reusing the wrong one would invert the detector, so it is deliberately absent.
- Branches are analysed as a **union** — every `If=` branch is walked. `error`-severity detectors
  therefore stay silent under a guard, since a guarded reference cannot be *proven* broken.
- `;` inside quotes is not treated as escaped, unlike the engine's own list splitter.

## Tests

```bash
python -m unittest discover -s tests -v
```

`tests/test_budget.py` is the false-positive budget. If you change a detector, it decides whether
you were right.

Some suites need files this repository does not ship, and fail rather than skip without them: the
BuildGraph scripts from an Unreal Engine source tree, and one real-world script for the end-to-end
tests, whose path goes in the `BGVIEW_TARGET_SCRIPT` environment variable. CI runs the suites that
carry their own fixtures; `.github/workflows/ci.yml` lists them.

`tests/test_source_tab.py` covers the source view and the viewport controls. Two habits there are
worth keeping: it asserts **containment and content** (does `#source-area` really enclose the
rows, do the rows really hold the file's text at the right line numbers) rather than document
order — an earlier test proved "the edge layer comes after the last lane header" using string
indices and passed while the edge layer sat outside the `<svg>` and the graph drew no wires. And
it can only assert that the interaction wiring *exists*; the behaviour was verified by driving the
generated report in headless Chrome, which is where two real bugs turned up — a `Fit` built on
`GetNearestZoomLevel` that left a scrollbar, and a `behavior: "smooth"` reveal that never scrolled
at all.

## Notice

bgview is an independent, unofficial tool. It is **not affiliated with, endorsed by, or sponsored
by Epic Games, Inc.** Unreal, Unreal Engine and BuildGraph are trademarks or registered trademarks
of Epic Games, Inc. in the US and elsewhere, used here only to identify the file format bgview
analyzes.

**No Unreal Engine file is vendored in this repository, and no Unreal Engine source code is copied
into it.** bgview's model of BuildGraph semantics was derived by reading the engine's own C#
implementation (`Engine/Source/Programs/Shared/EpicGames.BuildGraph/`) under an Unreal Engine
licence; every derived fact was recorded with the source file and line it came from.
A small number of interface constants are reproduced as facts about that interface, each attributed
in a comment where it is used:

| Constant | Where | Engine source |
|---|---|---|
| the 20-stop graph zoom table and its `-12`…`+7` labels | `bgview/html.py`, `webapp/bgview/layout.js` | `SNodePanel.cpp` |
| Blueprint spline tangent ranges | `bgview/html.py` | `FConnectionDrawingPolicy::ComputeSplineTangent` |
| `IllegalNameCharacters` | `bgview/detectors.py` | `BgSchema.cs:203` |
| the 16 unconditional built-in property values | `bgview/evaluator.py`, `webapp/bgview/evaluator.js` | `BuildGraph.cs:279-333` |

`bgview/data/schema-facts.json` and `webapp/data/schema-facts.json` are bgview's own derived table
of element names, tag-producing attributes and required attributes — the three facts the analysis
reads — extracted from a generated `Engine/Build/Graph/Schema.xsd`. The engine's schema itself is
Epic's file, subject to the Unreal Engine EULA, and is deliberately **not** included here.
Regenerate the table from your own engine tree with `tools/derive_schema.py`; see
`bgview/data/NOTICE.md` for the full provenance and the version-drift caveat.

The licence below covers bgview's own code and data only. It grants no rights in Unreal Engine.

## Design notes

Comments in the code refer to design documents (`SPEC.md`, `CONTRACTS.md`, `ACCEPTANCE.md`) and to
the ids in them, such as V15, T26 or R53. Those documents are kept privately by Rogue Component and
are not part of this repository. The behaviour they describe is in the code and its tests.

## Hosting your own

Each [release](https://github.com/RogueComponent/RogueBuildGraphViewer/releases) has a zip of the
web app. Unzip it and point any static file server at the folder: nginx, IIS, an intranet web
server, or `python -m http.server`. Nothing needs building, and every feature, share links
included, works the same as on our site, because the analysis runs in the visitor's browser.

## Licence

Rogue BuildGraph Viewer is **source-available**, under the Apache License 2.0 with the Commons
Clause condition; see [LICENSE](LICENSE). You may use it, change it, and host it for yourself, your
studio or anyone else, at no charge. You may **not sell it**: no charging for the software, for
hosting it, or for a product or service whose value comes from it, without written permission
from Rogue Component. To ask, get in touch through [roguecomponent.com](https://roguecomponent.com).

Because of that condition it is not open source in the OSI sense, even though the code is public.
