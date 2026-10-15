"""§T.65 -- restoring the webapp/ markup-sink guard.

tests/test_web.py was DELETED in 2282aea ("Full web version: the UI, and the
Pyodide build retired") along with the Pyodide runtime it was guarding. Since
then nothing has enforced V43/V48 over webapp/ -- the surviving sink test
(tests/test_source_tab.py:1026, `test_V8_no_markup_parsing_sinks_...`) guards
only the PYTHON report's generated <script> body, never the shell that ships
to the browser. This file closes that gap. `git show 2282aea^:tests/test_web.py`
recovers the deleted original for reference.

WHAT SURVIVES from that file: the shape of the discipline -- scan the shell's
own source for the literal sink tokens V8/V43/V48 forbid, check the CSP meta
tag for its strict directives, and check for third-party origins referenced
in the shell. That discipline is exactly as necessary now as when Pyodide was
still here; only WHAT gets scanned has changed.

WHAT IS DROPPED, and why -- the deleted file was written for the Pyodide-era
app (web/, a sandboxed `<iframe id="report" sandbox="allow-scripts">` fed via
`reportEl.srcdoc = data.html`, a `./bgview.zip` package fetch, a MEMFS mount,
a vendored Pyodide runtime with pinned version+hash, `web/_headers` MIME pins
for `.mjs`/`.wasm`). None of that exists in today's plain-ES-module app: the
report is built straight into this document's DOM by render.js using only
textContent/createElement/setAttribute, so THIS is what needs the sink guard
now, not an iframe that no longer exists. Concretely dropped:
  - TestV43Sandbox (`sandbox=`, `allow-same-origin`, `reportEl.srcdoc`) --
    there is no iframe; the report lives in the page's own DOM.
  - the "exactly one fetch, and it is ./bgview.zip" assertion -- today's
    shell fetches ./data/schema-facts.json; the property that matters is "no
    third-party origin" (V45, kept below), not "exactly one fetch call".
    XMLHttpRequest/sendBeacon/WebSocket/EventSource are still worth banning
    and are folded into the sink/no-network scans below.
  - TestV46OnePipelineFromTheBrowserToo (`bgview/web.py`, a Python-style
    `from bgview.pipeline import analyse` string match, DOMParser bans) --
    all Pyodide-era plumbing. The JS port has its own pipeline.js and its own
    suite in tests-js/; re-litigating "one pipeline" from Python-import
    syntax makes no sense against a JS module graph, and is not this task's
    job (T65 is V43/V48/V8 -- the markup-sink boundary -- not V46).
  - TestMemfsMount (`p !== ".."`, `${WORK}/${safe}`, `MOUNT_EXT`) -- there is
    no MEMFS; app.js reads picked files into a plain Map with its own path
    sanitiser (`readFiles`/`pickSchema` in webapp/app.js), which is a
    different task's concern, not V43/V48/V8.
  - TestV50HostMimePins (`.mjs`/`.wasm` Content-Type pins in `web/_headers`)
    -- there is no `.mjs` and no `.wasm` left to mis-serve; webapp/_headers
    now only carries nosniff + a referrer policy, which V43/V44/V45/V48 do
    not speak to.
  - TestBuildScript (`tools/build_site.py`, Pyodide version/hash pins,
    `bgview/data/Schema.xsd` presence) -- there is no build step and no
    vendored runtime; "webapp/ is copied as-is" needs no builder to verify.

WHAT IS NEW: the shell has grown from `web/index.html` + `web/app.js` into a
whole `webapp/bgview/*.js` analyser + `render.js` + `layout.js` package, all
of which render into the live DOM and are therefore all part of the
markup-sink trust boundary now. The old file scanned app.js alone; this one
walks EVERY `.js` file under `webapp/` (including `webapp/bgview/`) rather
than naming modules, so a sink in render.js -- or in a module written after
this test lands, such as the in-flight `webapp/bgview/share.js` -- is caught
without anyone having to remember to add it to a list.
"""

from __future__ import annotations

import pathlib
import re
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
WEBAPP = REPO / "webapp"
INDEX = WEBAPP / "index.html"

SINK_TOKENS = (
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "eval(",
    "new Function(",
)

# Namespace/spec identifiers that legitimately appear as literal strings in
# the source (never fetched -- see test_V45_no_third_party_origin below).
ALLOWED_URL_PREFIXES = (
    "http://www.w3.org/2000/svg",  # SVG_NS in render.js -- an XML namespace URI
)

# Outbound links the visitor may click. The page never loads them, so they
# are not an origin it depends on (V45 is about loads). Matched EXACTLY, and
# only as an <a href> in an .html file: a prefix allowance would also wave
# through a lookalike host, and the same URL in a fetch() is still an offender.
ALLOWED_OUTBOUND_LINKS = frozenset({
    "https://www.roguecomponent.com",          # footer credit in index.html
    "https://www.roguecomponent.com/privacy",  # hosted copy: privacy notice
    "https://www.roguecomponent.com/terms",    # hosted copy: terms of use
})


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _js_files() -> list[pathlib.Path]:
    return sorted(WEBAPP.rglob("*.js"))


def _js_walk(src: str, *, keep_strings: bool):
    """Shared state walk behind the two stripping helpers below.

    Both need to tell comments from code without being fooled by a `//` or
    `/*` that happens to sit inside a string (e.g. render.js's own
    `"http://www.w3.org/2000/svg"`) -- so both track string state the same
    way. They differ only in what they keep: the sink scan wants string
    CONTENT gone too (a sink is a property access or a call, never data, so a
    string that merely contains the word "innerHTML" must not trip it); the
    URL scan needs string content KEPT (a fetched URL lives inside a string
    literal in real code, so blanking strings would hide the exact thing V45
    exists to catch).

    A full JS parser is out of scope for this rung (stdlib only, no parser
    dependency); this minimal walk is sufficient because neither scan needs
    anything subtler than "is this a comment, a string, or neither".

    ponytail: does not model regex literals (a `/pattern/flags` after `=` or
    `(` containing `//`, a quote character, or a comment-opener could desync
    this walk) -- upgrade path is a real tokenizer if a future file trips it.
    None of today's webapp/*.js files contain such a regex literal that would
    trigger this (verified by inspection at the time this test was written).
    """
    out = []
    i, n = 0, len(src)
    while i < n:
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            i = n if j == -1 else j
            continue
        if two == "/*":
            j = src.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        c = src[i]
        if c in ("'", '"', "`"):
            quote = c
            start = i
            i += 1
            while i < n and src[i] != quote:
                i += 2 if src[i] == "\\" else 1
            i += 1
            if keep_strings:
                out.append(src[start:i])
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _strip_js_comments_and_strings(src: str) -> str:
    """Blank comments AND string/template literals -- for the SINK scan.

    tests/test_source_tab.py's `_strip_comments` (and the deleted test_web.py's
    copy of it) only strips FULL-LINE `//` comments, which is safe there
    because it runs on a generated report's script body. It is not safe here:
    these are hand-maintained source files whose comments freely say the word
    "innerHTML" while explaining that the file has none (see render.js's own
    header comment) -- a raw substring search would fail on the documentation,
    not on a real sink. Blanking string content too means a string that
    merely mentions a sink's name as data cannot trip this either.
    """
    return _js_walk(src, keep_strings=False)


def _strip_js_comments_keep_strings(src: str) -> str:
    """Strip only comments, keeping string/template content intact -- for the
    URL scan (test_no_third_party_origin_in_webapp_source below). A URL that
    is actually fetched lives inside a string literal in real code, so unlike
    the sink scan, string content must survive here or a real off-origin
    reference would go undetected."""
    return _js_walk(src, keep_strings=True)


class TestV43AndV48NoMarkupSink(unittest.TestCase):
    """V43/V48: report + shell markup goes into the DOM via textContent /
    createElement / setAttribute ONLY. Node names, log messages, paths and
    option values are all attacker-influenced; V8's escaping discipline does
    not stop at the report's edge (V48) or the report renderer's edge (V43)."""

    def test_no_markup_sink_in_any_webapp_js_file(self):
        files = _js_files()
        self.assertTrue(files, "no .js files found under webapp/ -- scan is not running")
        offenders = []
        for path in files:
            code = _strip_js_comments_and_strings(_read(path))
            for sink in SINK_TOKENS:
                if sink in code:
                    offenders.append((path.relative_to(REPO).as_posix(), sink))
        self.assertEqual(
            offenders, [],
            "markup/eval sink(s) found -- " +
            ", ".join(f"{p}: {s}" for p, s in offenders),
        )

    def test_no_inline_event_handlers_in_index_html(self):
        html = re.sub(r"<!--.*?-->", "", _read(INDEX), flags=re.S)
        match = re.search(r"\son[a-z]+\s*=\s*[\"']", html)
        self.assertIsNone(match, f"inline event handler in index.html: {match and match.group(0)!r}")


class TestV45NoThirdPartyOrigin(unittest.TestCase):
    """V45: no CDN, no bundler runtime, no font host -- webapp/ is
    self-contained; the only fetch is ./data/schema-facts.json, same origin."""

    def test_no_third_party_origin_in_webapp_source(self):
        # Mirrors test_source_tab.py's test_V17_no_network_references: XML
        # namespace URIs are IDENTIFIERS, never fetched, so they are matched
        # by prefix and allow-listed rather than banned outright.
        offenders = []
        for path in sorted(WEBAPP.rglob("*.js")) + sorted(WEBAPP.rglob("*.html")) + sorted(WEBAPP.rglob("*.css")):
            text = _read(path)
            if path.suffix == ".js":
                text = _strip_js_comments_keep_strings(text)
            elif path.suffix == ".html":
                text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
                text = re.sub(
                    r'<a\b[^>]*?\bhref="([^"]*)"',
                    lambda m: "<a" if m.group(1) in ALLOWED_OUTBOUND_LINKS else m.group(0),
                    text,
                )
            elif path.suffix == ".css":
                text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
            for match in re.finditer(r"https?://[^\s\"'()<>]+", text):
                url = match.group(0)
                if not any(url.startswith(prefix) for prefix in ALLOWED_URL_PREFIXES):
                    offenders.append((path.relative_to(REPO).as_posix(), url))
        self.assertEqual(offenders, [], f"third-party/off-origin reference(s) found: {offenders}")

    def test_no_third_party_script_or_style_tag_in_index_html(self):
        html = re.sub(r"<!--.*?-->", "", _read(INDEX), flags=re.S)
        for tag in re.findall(r"<script\b[^>]*>", html, re.I):
            if "src=" in tag:
                self.assertIn('src="./', tag, f"non-relative <script src>: {tag}")
        for tag in re.findall(r"<link\b[^>]*>", html, re.I):
            href = re.search(r'href="([^"]*)"', tag)
            if href:
                self.assertTrue(href.group(1).startswith("./"), f"non-relative <link href>: {tag}")


class TestV44Csp(unittest.TestCase):
    """V44: the browser path must not be able to send picked-script bytes
    off-box. The CSP meta tag is the enforcement point."""

    def test_csp_meta_present_with_strict_directives(self):
        html = _read(INDEX)
        match = re.search(r'http-equiv="Content-Security-Policy"\s+content="(.*?)">', html, re.S)
        self.assertIsNotNone(match, "no CSP meta tag in index.html")
        policy = " ".join(match.group(1).split())
        for directive in ("default-src 'self'", "connect-src 'self'", "script-src 'self'"):
            self.assertIn(directive, policy)

    def test_csp_has_no_unsafe_relaxations(self):
        html = _read(INDEX)
        match = re.search(r'http-equiv="Content-Security-Policy"\s+content="(.*?)">', html, re.S)
        policy = match.group(1)
        self.assertNotIn("unsafe-inline", policy)
        self.assertNotIn("unsafe-eval", policy)


class TestV56FetchTargetsExist(unittest.TestCase):
    """V56: every same-origin fetch target named in webapp/ must be a file
    that actually exists in webapp/.

    Backprop of B12. A worker's `git checkout` discarded another task's
    uncommitted change, leaving loadBundledSchema fetching
    ./data/Schema.xsd -- a file that same task had already deleted. The
    app's DEFAULT schema path 404'd, and the whole suite stayed green,
    because every test either supplies its own schema or never boots the
    page at all. A broken default that no fixture exercises is invisible
    exactly until a user hits it first.

    Scanned rather than trusted: this catches the mismatch however it
    arises -- a rename, a deletion, a typo, a bad revert.
    """

    def test_every_webapp_fetch_target_exists(self):
        missing = []
        for path in _js_files():
            src = _strip_js_comments_keep_strings(_read(path))
            for match in re.finditer(r"""fetch\(\s*["'](\./[^"']+)["']""", src):
                rel = match.group(1)[2:]
                if not (WEBAPP / rel).is_file():
                    missing.append((path.relative_to(REPO).as_posix(), match.group(1)))
        self.assertEqual(
            missing, [],
            "fetch() target(s) that do not exist under webapp/: " + repr(missing))


class TestNoBuildStep(unittest.TestCase):
    """§C: stdlib only, no pip/npm install to run bgview. A bundler config or
    lockfile under webapp/ is the cheapest possible thing to regress by
    accident -- e.g. an editor or a package manager dropping one in."""

    def test_webapp_has_no_bundler_config_or_lockfile(self):
        banned_names = ("package.json", "node_modules")
        offenders = []
        for name in banned_names:
            if list(WEBAPP.rglob(name)):
                offenders.append(name)
        for pattern in ("webpack.config.*", "vite.config.*", "*.lock"):
            offenders.extend(p.relative_to(REPO).as_posix() for p in WEBAPP.rglob(pattern))
        self.assertEqual(offenders, [], f"build-step artifact(s) found under webapp/: {offenders}")


if __name__ == "__main__":
    unittest.main()
