"""§T.25 -- the live picker's trust boundary.

`--serve` reads the local disk on behalf of a browser. That is a real trust
boundary, and these tests are the ones that keep it honest:

  V35  bound to 127.0.0.1 ONLY, never 0.0.0.0
  V36  every request needs the per-run token, else 403
  V37  read-only; directories and .xml only; traversal resolved, not string-matched
  V38  live HTML comes from the same renderer as --html, byte for byte
"""

import json
import os
import pathlib
import threading
import unittest
import urllib.error
import urllib.request

from bgview import detectors, evaluator, html as html_renderer, loader, model, schema, serve

# A real-world BuildGraph script the end-to-end tests run against. It is not
# shipped with the repo: set BGVIEW_TARGET_SCRIPT to its path to run them.
TARGET = pathlib.Path(
    os.environ.get("BGVIEW_TARGET_SCRIPT", "")
)


class _Server:
    """Start the picker on an OS-chosen free port so tests never collide."""

    def __enter__(self):
        self.url, self.httpd = serve.serve(port=0, open_browser=False)
        self.token = self.url.split("t=", 1)[1]
        self.base = self.url.split("/?", 1)[0]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def get(self, path):
        return urllib.request.urlopen(self.base + path, timeout=10)

    def post(self, path, obj):
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(obj).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return urllib.request.urlopen(req, timeout=30)


class BindingTests(unittest.TestCase):
    def test_v35_binds_loopback_only(self):
        """0.0.0.0 would turn a source-code analyser into a file-read service
        for anyone on the LAN."""
        url, httpd = serve.serve(port=0, open_browser=False)
        try:
            self.assertEqual(httpd.server_address[0], "127.0.0.1")
            self.assertTrue(url.startswith("http://127.0.0.1:"))
        finally:
            httpd.server_close()

    def test_token_is_long_and_unique_per_run(self):
        a, sa = serve.serve(port=0, open_browser=False)
        b, sb = serve.serve(port=0, open_browser=False)
        try:
            ta, tb = a.split("t=", 1)[1], b.split("t=", 1)[1]
            self.assertNotEqual(ta, tb)
            self.assertGreaterEqual(len(ta), 32)
        finally:
            sa.server_close()
            sb.server_close()


class TokenTests(unittest.TestCase):
    """V36 -- without this, any page open in the same browser could POST to
    localhost and read files off the machine."""

    def test_shell_without_token_is_403(self):
        with _Server() as s:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                s.get("/")
            self.assertEqual(ctx.exception.code, 403)

    def test_ls_without_token_is_403(self):
        with _Server() as s:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                s.get("/api/ls?dir=" + str(TARGET.parent))
            self.assertEqual(ctx.exception.code, 403)

    def test_analyze_without_token_is_403(self):
        with _Server() as s:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                s.post("/api/analyze", {"path": str(TARGET)})
            self.assertEqual(ctx.exception.code, 403)

    def test_an_unauthorised_POST_gets_a_403_not_a_reset_connection(self):
        """Regression, and it was a real defect rather than a flaky test.

        `_deny` used to answer before reading the request body, so the server
        closed the socket while the client was still writing and the peer saw
        a reset connection instead of the 403 -- on Windows,
        `ConnectionAbortedError` (WinError 10053). It surfaced as one of the
        token tests failing in maybe a third of full-suite runs and passing
        every time in isolation, which is exactly the shape of thing that
        gets waved through as environmental.

        It is not cosmetic: a browser `fetch` receives a network error rather
        than a status, so the page cannot tell "your token is stale, reload"
        from "the server has gone away". Repeated, because the whole point is
        that it did not fail every time.

        Body deliberately large-ish -- a body small enough to fit in the
        socket buffer completes its write before the reply and would pass
        even with the bug present."""
        payload = {"path": "x" * 200_000}
        with _Server() as s:
            for attempt in range(8):
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    s.post("/api/analyze", payload)
                self.assertEqual(ctx.exception.code, 403, f"attempt {attempt}")
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    s.post("/api/browse", payload)
                self.assertEqual(ctx.exception.code, 403, f"attempt {attempt}")
            # and the server is still healthy afterwards
            self.assertEqual(s.get("/?t=" + s.token).status, 200)

    def test_wrong_token_is_403(self):
        with _Server() as s:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                s.get("/api/ls?t=not-the-token&dir=.")
            self.assertEqual(ctx.exception.code, 403)

    def test_correct_token_is_accepted(self):
        with _Server() as s:
            self.assertEqual(s.get("/?t=" + s.token).status, 200)


class ConcurrencyTests(unittest.TestCase):
    """Regression for a bug found only by pointing a real browser at it.

    A browser opens several sockets at once and may leave one idle without ever
    sending a request line. On a single-threaded http.server that idle socket
    blocks every other request forever -- the picker just hangs. The sequential
    urllib calls in these tests never reproduced it.
    """

    def test_an_idle_socket_does_not_wedge_the_server(self):
        import socket as _socket

        with _Server() as s:
            host, port = s.httpd.server_address[0], s.httpd.server_address[1]
            idle = _socket.create_connection((host, port), timeout=5)
            try:
                # Connected, never sends a request line -- exactly what a
                # browser preconnect looks like.
                self.assertEqual(s.get("/?t=" + s.token).status, 200)
            finally:
                idle.close()

    def test_overlapping_requests_are_served(self):
        import concurrent.futures as cf

        with _Server() as s:
            with cf.ThreadPoolExecutor(max_workers=4) as pool:
                futures = [pool.submit(lambda: s.get("/?t=" + s.token).status) for _ in range(4)]
                self.assertEqual([f.result(timeout=20) for f in futures], [200] * 4)


class CspTests(unittest.TestCase):
    """The shell calls its own API with fetch(). `default-src 'none'` alone
    also blocks connect-src, so every fetch is refused and the picker never
    loads -- it looks like a dead page with errors only in the console."""

    def test_csp_allows_the_page_to_call_its_own_api(self):
        with _Server() as s:
            csp = s.get("/?t=" + s.token).headers.get("Content-Security-Policy") or ""
            self.assertIn("connect-src 'self'", csp)
            self.assertIn("frame-src 'self'", csp)   # srcdoc report iframe
            self.assertIn("default-src 'none'", csp) # still deny remote everything
            self.assertNotIn("connect-src *", csp)


class DialogTests(unittest.TestCase):
    """The native Windows dialog runs in a subprocess: Tk wants its own thread
    and event loop, and calling it from a handler thread while the main thread
    sits in serve_forever() is the shape that hangs."""

    def test_bad_mode_is_rejected_without_spawning_anything(self):
        self.assertIn("error", serve.native_dialog("rm -rf"))
        self.assertIn("error", serve.native_dialog(""))

    def test_browse_endpoint_requires_the_token(self):
        with _Server() as s:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                s.post("/api/browse", {"mode": "dir"})
            self.assertEqual(ctx.exception.code, 403)

    def test_dialog_timeout_is_reported_not_raised(self):
        """A dialog left open must not wedge the request forever."""
        out = serve.native_dialog("dir", start="", timeout=0.4)
        self.assertIn("error", out)
        self.assertIn("timed out", out["error"])


class ListingTests(unittest.TestCase):
    def test_lists_only_dirs_and_xml(self):
        """V37: this is a BuildGraph picker, not a general file browser."""
        with _Server() as s:
            body = json.loads(
                s.get(f"/api/ls?t={s.token}&dir={TARGET.parent}").read().decode("utf-8")
            )
            self.assertIn("dirs", body)
            for f in body["files"]:
                self.assertTrue(f["name"].lower().endswith(".xml"), f)
            names = [f["name"] for f in body["files"]]
            self.assertIn(TARGET.name, names)

    def test_traversal_is_resolved_not_string_matched(self):
        """'..' must be RESOLVED and the result re-checked. Rejecting on the
        literal substring misses symlinks and encoded forms while breaking
        legitimate navigation."""
        with _Server() as s:
            body = json.loads(
                s.get(f"/api/ls?t={s.token}&dir={TARGET.parent}/..").read().decode("utf-8")
            )
            self.assertNotIn("error", body, body)
            self.assertEqual(
                pathlib.Path(body["dir"]).resolve(), TARGET.parent.parent.resolve()
            )

    def test_a_file_path_is_rejected_as_a_directory(self):
        with _Server() as s:
            body = json.loads(
                s.get(f"/api/ls?t={s.token}&dir={TARGET}").read().decode("utf-8")
            )
            self.assertIn("error", body)


class AnalyzeTests(unittest.TestCase):
    def test_analyse_returns_the_pinned_counts(self):
        with _Server() as s:
            body = json.loads(
                s.post(f"/api/analyze?t={s.token}", {"path": str(TARGET)}).read().decode("utf-8")
            )
            self.assertNotIn("error", body)
            self.assertEqual(body["counts"], {"info": 9, "warn": 4, "error": 0})
            self.assertEqual(body["nodes"], 8)
            self.assertEqual(body["agents"], 2)

    def test_v38_live_html_is_identical_to_the_written_report(self):
        """One renderer, not two. If these ever diverge, the live view is
        lying about what the saved report contains."""
        sch = schema.discover(str(TARGET))
        ev = evaluator.evaluate(loader.load(TARGET), sch, {})
        graph, mf = model.build(ev, sch)
        findings = list(ev.findings) + list(mf) + list(detectors.run_all(graph, ev, sch))
        expected = html_renderer.render_html(graph, findings, ev)

        with _Server() as s:
            body = json.loads(
                s.post(f"/api/analyze?t={s.token}", {"path": str(TARGET)}).read().decode("utf-8")
            )
        self.assertEqual(body["html"], expected)

    def test_non_xml_is_refused(self):
        with _Server() as s:
            body = json.loads(
                s.post(f"/api/analyze?t={s.token}",
                       {"path": str(pathlib.Path(__file__))}).read().decode("utf-8")
            )
            self.assertIn("error", body)

    def test_a_broken_script_reports_instead_of_killing_the_server(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            bad = pathlib.Path(d) / "bad.xml"
            bad.write_text("<BuildGraph><unclosed>", encoding="utf-8")
            with _Server() as s:
                body = json.loads(
                    s.post(f"/api/analyze?t={s.token}", {"path": str(bad)}).read().decode("utf-8")
                )
                self.assertIn("error", body)
                # still alive afterwards
                self.assertEqual(s.get("/?t=" + s.token).status, 200)


class PickerCollapseTests(unittest.TestCase):
    """The picker folds away once it has done its job, with a way back.

    Asserted on the shell's rendered markup/JS. The behaviour itself was
    verified by driving the served page in headless Chrome against a stubbed
    `/api/*`: open on load, collapsed after selecting a file, reopened by the
    toggle with its listing and cwd intact, closed again by Escape. That run
    is what caught the button shipping the wrong label while open."""

    def setUp(self):
        self.shell = serve._shell("TESTTOKEN")

    def test_the_toggle_exists_and_controls_the_picker(self):
        self.assertIn('id="toggle-picker"', self.shell)
        self.assertIn('aria-controls="picker"', self.shell)
        self.assertIn('aria-expanded="true"', self.shell)

    def test_the_picker_can_actually_be_hidden(self):
        """`hidden` alone does nothing here: `#picker`'s own `display: flex`
        beats the UA stylesheet's `[hidden] { display: none }`. Without this
        rule the toggle would flip attributes while the panel stayed put."""
        self.assertIn("#picker[hidden] { display: none; }", self.shell)

    def test_it_collapses_only_on_a_SUCCESSFUL_analysis(self):
        analyse = self.shell[self.shell.index("function analyse("):]
        analyse = analyse[: analyse.index("function dialog(")]
        # The error branch returns early, before the report is staged and
        # before the collapse -- a failed pick must leave the picker up,
        # because picking again is exactly what the user needs to do next.
        self.assertLess(analyse.index("if (d.error)"), analyse.index("setPickerOpen(false)"))
        self.assertLess(analyse.index("stage.appendChild(frame)"), analyse.index("setPickerOpen(false)"))

    def test_the_initial_label_is_synced_to_the_open_state(self):
        """The markup ships the CLOSED-state label so the button still reads
        sensibly with no JS; once running, `setPickerOpen(true)` corrects it,
        or an open picker sits there offering to open itself."""
        self.assertIn("setPickerOpen(true);", self.shell)

    def test_escape_only_closes_when_there_is_a_report_to_go_back_to(self):
        self.assertIn('e.key === "Escape"', self.shell)
        self.assertIn('stage.querySelector("iframe")', self.shell)

    def test_reopening_does_not_re_walk_the_filesystem(self):
        """Hidden, never destroyed: `setPickerOpen` touches `hidden` and the
        button, nothing else, so the listing and cwd survive a round trip."""
        fn = self.shell[self.shell.index("function setPickerOpen("):]
        fn = fn[: fn.index("toggle.addEventListener")]
        self.assertNotIn("ls(", fn)
        self.assertNotIn("entries", fn)


if __name__ == "__main__":
    unittest.main()
