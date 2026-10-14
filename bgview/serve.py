"""bgview.serve -- the live picker (T23).

    python -m bgview --serve

Starts a local server, opens a browser, and lets you walk the filesystem and
click a BuildGraph `.xml` to analyse it. Every click re-runs the full pipeline,
so editing a script and clicking it again shows the new result immediately.

SECURITY POSTURE -- this module reads the local disk on behalf of a browser,
which is a real trust boundary, not a formality:

  V35  Binds 127.0.0.1 ONLY, never 0.0.0.0. A BuildGraph script is source
       code; the analyser must not become a file-read service on the LAN.
  V36  Every request must carry a per-run random token (32 bytes, urlsafe).
       Without it: 403. This is what stops any web page open in the same
       browser from POSTing to http://localhost:PORT and reading files off
       this machine -- the classic CSRF / DNS-rebinding attack against
       "harmless" localhost dev servers. The token lives in the URL that gets
       opened, is compared with `secrets.compare_digest`, and is never
       reflected into the page body.
  V37  READ-ONLY. No endpoint writes, deletes, or executes anything. `/api/ls`
       returns directories and `.xml` files and nothing else. Traversal is
       handled by RESOLVING the path and re-checking it, never by string
       matching on "..".
  V38  Rendering goes through `html.render_html` -- the same function
       `--html` uses -- so what you see live is byte-identical to the file.

Stdlib only: http.server, secrets, json, webbrowser.
"""

from __future__ import annotations

import html as _htmlmod
import http.server
import json
import pathlib
import secrets
import socket
import subprocess
import sys
import threading
import urllib.parse
import webbrowser

# `loader` for its BgError type (:302) and `html_renderer` for the report's
# _CSS, which the picker shell reuses so both look like one tool (:315).
# The five analysis modules this file used to import moved behind
# `pipeline.analyse` (T44/V46) -- serve no longer knows the pipeline's shape.
from bgview import html as html_renderer, loader, pipeline
from bgview.findings import Severity

_TOKEN_BYTES = 32
_MAX_UPLOAD = 8 * 1024 * 1024  # a BuildGraph script is kilobytes; cap the rest


def _drives() -> list[str]:
    """Windows drive roots, so the picker can start from 'anywhere'."""
    roots = []
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZAB":
        p = pathlib.Path(f"{letter}:\\")
        try:
            if p.exists():
                roots.append(str(p))
        except OSError:
            continue
    return roots or [str(pathlib.Path.home())]


def _listing(raw_dir: str) -> dict:
    """Directory entries for the picker. V37: read-only, and only ever
    directories plus `.xml` files -- this is a BuildGraph picker, not a
    general-purpose file browser."""
    target = pathlib.Path(raw_dir).expanduser() if raw_dir else pathlib.Path.cwd()
    # V37: resolve FIRST, then work from the resolved path. Rejecting on a
    # literal ".." substring is the classic mistake -- it misses symlinks,
    # "%2e%2e", and UNC forms while blocking legitimate names.
    try:
        target = target.resolve()
    except OSError as exc:
        return {"error": f"cannot resolve path: {exc}"}
    if not target.is_dir():
        return {"error": f"not a directory: {target}"}

    dirs, files = [], []
    try:
        for entry in sorted(target.iterdir(), key=lambda e: e.name.lower()):
            try:
                if entry.is_dir():
                    dirs.append({"name": entry.name, "path": str(entry)})
                elif entry.suffix.lower() == ".xml":
                    files.append({
                        "name": entry.name,
                        "path": str(entry),
                        "size": entry.stat().st_size,
                    })
            except OSError:
                continue  # unreadable entry: skip it, never fail the listing
    except PermissionError:
        return {"error": f"permission denied: {target}"}

    parent = None if target.parent == target else str(target.parent)
    return {
        "dir": str(target),
        "parent": parent,
        "dirs": dirs,
        "files": files,
        "drives": _drives(),
    }


_DIALOG_SNIPPET = r"""
import sys, tkinter as tk
from tkinter import filedialog
root = tk.Tk()
root.withdraw()
root.attributes("-topmost", True)   # otherwise it can open behind the browser
root.update()
start = sys.argv[2] if len(sys.argv) > 2 else ""
if sys.argv[1] == "dir":
    picked = filedialog.askdirectory(title="bgview - choose a folder", initialdir=start or None)
else:
    picked = filedialog.askopenfilename(
        title="bgview - choose a BuildGraph .xml",
        initialdir=start or None,
        filetypes=[("BuildGraph script", "*.xml"), ("All files", "*.*")],
    )
root.destroy()
sys.stdout.write(picked or "")
"""


def native_dialog(mode: str, start: str = "", timeout: int = 180) -> dict:
    """Open the real Windows folder/file dialog and return what was picked.

    Run in a SUBPROCESS on purpose. Tk wants a single thread and its own event
    loop; calling it from an http.server handler thread while the main thread
    sits in serve_forever() is exactly the shape that hangs or crashes. A short
    lived child process sidesteps the whole problem and cannot take the server
    down with it.

    Read-only: it returns a path string. Nothing is opened, written or executed.
    """
    if mode not in ("dir", "file"):
        return {"error": "bad dialog mode"}
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _DIALOG_SNIPPET, mode, start or ""],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": "dialog timed out"}
    except OSError as exc:
        return {"error": f"cannot open dialog: {exc}"}
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()[-1:] or ["unknown error"]
        return {"error": f"dialog failed: {detail[0]}"}
    picked = (proc.stdout or "").strip()
    if not picked:
        return {"cancelled": True}
    return {"path": str(pathlib.Path(picked))}


def analyse(path: str) -> dict:
    """Delegate to the one pipeline (V46, T44).

    This used to hold the body; it now lives in `bgview.pipeline` so the
    GitHub Pages app runs the SAME six calls rather than a second copy of
    them. V38 said one renderer; V46 says one pipeline -- a report served
    here and a report rendered in the browser are the same bytes because
    they are the same code, not because two code paths were kept in sync
    by hand.
    """
    return pipeline.analyse(path)


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "bgview"
    sys_version = ""
    token = ""  # set on the class by serve()

    # A real browser opens several sockets at once -- preconnect, favicon,
    # the page itself -- and may leave one idle without ever sending a request
    # line. On a single-threaded server that idle socket blocks every other
    # request forever. `timeout` bounds the wait for a request line so such a
    # socket is dropped instead of wedging the picker. (Found by running it
    # against an actual browser; sequential urllib calls in the tests never
    # reproduced it.)
    timeout = 10

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (socket.timeout, TimeoutError, ConnectionError, OSError):
            # A client hanging up mid-request is ordinary, not an error: the
            # browser drops preconnect sockets constantly, and Windows reports
            # that as ConnectionAbortedError (WinError 10053) rather than a
            # clean EOF. Close the connection quietly; never let a normal
            # disconnect print a traceback in the user's terminal.
            self.close_connection = True

    def handle_error(self, *args):
        pass  # same reasoning: a dropped client is not a server fault

    # -- plumbing ---------------------------------------------------------
    def log_message(self, fmt, *args):  # noqa: A002
        pass  # a picker does not need an access log on stdout

    def _authorised(self, query: dict) -> bool:
        """V36: constant-time token check on every single request."""
        supplied = (query.get("t") or [""])[0]
        return secrets.compare_digest(supplied, self.token)

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Deny remote everything, but the shell must still be able to call its
        # OWN api. `default-src 'none'` alone also blocks connect-src, which
        # silently kills every fetch() on the page -- the picker just never
        # loads. `frame-src 'self'` is what lets the srcdoc report iframe
        # render, since a srcdoc frame is governed by its embedder's policy.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; connect-src 'self'; frame-src 'self'; "
            "style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "img-src data:; font-src 'none'; base-uri 'none'; form-action 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def _deny(self) -> None:
        """403, after draining any request body.

        Replying to a POST while the client is still writing its body and
        then closing the socket makes the peer see a RESET CONNECTION rather
        than the 403 -- on Windows, `ConnectionAbortedError` (WinError
        10053). That is not merely a flaky test: a browser's `fetch` gets a
        network error instead of a status it can act on, so the page cannot
        tell "your token is stale, reload" from "the server is gone". The
        body is read and discarded so the exchange finishes cleanly.

        Still capped at `_MAX_UPLOAD`: this runs BEFORE authentication, so an
        unauthenticated client must not be able to make the server read an
        arbitrary number of bytes. Over the cap the socket is simply closed
        -- that client is unauthenticated and sending too much.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if 0 < length <= _MAX_UPLOAD:
            try:
                self.rfile.read(length)
            except OSError:
                pass
        elif length > _MAX_UPLOAD:
            self.close_connection = True
        self._send(403, b"forbidden: missing or bad token", "text/plain; charset=utf-8")

    # -- routes -----------------------------------------------------------
    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if not self._authorised(query):
            return self._deny()

        if parsed.path == "/":
            return self._send(200, _shell(self.token).encode("utf-8"), "text/html; charset=utf-8")
        if parsed.path == "/api/ls":
            return self._json(200, _listing((query.get("dir") or [""])[0]))
        self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if not self._authorised(query):
            return self._deny()
        if parsed.path not in ("/api/analyze", "/api/browse"):
            return self._send(404, b"not found", "text/plain; charset=utf-8")

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._json(400, {"error": "bad Content-Length"})
        if length > _MAX_UPLOAD:
            return self._json(413, {"error": "payload too large"})
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return self._json(400, {"error": f"bad JSON: {exc}"})

        if parsed.path == "/api/browse":
            return self._json(200, native_dialog(
                (req or {}).get("mode") or "dir", (req or {}).get("start") or ""))

        path = (req or {}).get("path") or ""
        if not path:
            return self._json(400, {"error": "no path given"})
        try:
            return self._json(200, analyse(path))
        except loader.BgError as exc:
            return self._json(200, {"error": str(exc)})
        except Exception as exc:  # a bad script must not kill the server
            return self._json(200, {"error": f"{type(exc).__name__}: {exc}"})


def _shell(token: str) -> str:
    """The picker shell. Styled from the same tokens as the report so the two
    halves read as one product."""
    t = _htmlmod.escape(token, quote=True)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>bgview — live</title>
<style>{html_renderer._CSS}
#picker-wrap {{ flex: 1 1 auto; display: flex; min-height: 0; }}
#picker {{
  flex: 0 0 clamp(280px, 28vw, 420px); display: flex; flex-direction: column;
  border-right: 1px solid var(--border); background: var(--panel-bg); min-width: 0;
}}
/* Once a script has been analysed the picker has done its job and the report
   is what the user came for, so it folds away and gives the report the full
   width. It is only HIDDEN, never destroyed: reopening it lands back on the
   same directory, already listed, instead of re-walking from a drive root. */
#picker[hidden] {{ display: none; }}
#toggle-picker {{
  margin-left: auto; font: inherit; font-size: 0.74rem; padding: 4px 12px;
  border-radius: 999px; cursor: pointer; white-space: nowrap;
  border: 1px solid var(--border-strong); background: var(--surface); color: var(--fg);
  transition: background 0.12s, color 0.12s, border-color 0.12s;
}}
#toggle-picker:hover {{ border-color: var(--accent); }}
#toggle-picker[aria-expanded="true"] {{ background: var(--accent-soft); border-color: var(--accent); }}
#picker-head {{ padding: 12px 14px; border-bottom: 1px solid var(--border); }}
#cwd {{
  font-family: var(--font-data); font-size: 0.7rem; color: var(--muted);
  overflow-wrap: anywhere; margin-top: 6px;
}}
#entries {{ flex: 1 1 auto; overflow-y: auto; padding: 8px; scrollbar-width: none; }}
#entries::-webkit-scrollbar {{ width: 0; }}
.entry {{
  display: flex; gap: 9px; align-items: center; width: 100%; text-align: left; font: inherit;
  padding: 7px 9px; margin-bottom: 4px; border-radius: 8px; cursor: pointer;
  border: 1px solid transparent; background: transparent; color: var(--fg);
}}
.entry:hover {{ background: var(--surface); border-color: var(--border); }}
.entry .ico {{ flex: 0 0 auto; font-family: var(--font-data); font-size: 0.7rem; color: var(--muted); }}
.entry .nm {{ flex: 1 1 auto; min-width: 0; overflow-wrap: anywhere; font-size: 0.82rem; }}
.entry.is-xml .nm {{ font-family: var(--font-data); font-size: 0.78rem; }}
.entry .sz {{ flex: 0 0 auto; font-family: var(--font-data); font-size: 0.68rem; color: var(--muted); }}
.drives {{ display: flex; gap: 5px; flex-wrap: wrap; margin-top: 8px; }}
.picker-actions {{ display: flex; gap: 6px; flex-wrap: wrap; }}
.filter-btn.primary {{ background: var(--accent); color: var(--accent-ink); border-color: var(--accent); }}
.filter-btn.primary:hover {{ filter: brightness(1.06); }}
.filter-btn:disabled {{ opacity: 0.45; cursor: default; }}
#stage {{ flex: 1 1 auto; min-width: 0; display: flex; flex-direction: column; }}
#stage iframe {{ flex: 1 1 auto; width: 100%; border: 0; background: var(--bg); }}
#stage-empty {{
  flex: 1 1 auto; display: flex; align-items: center; justify-content: center;
  color: var(--muted); font-size: 0.9rem; padding: 24px; text-align: center;
}}
#status {{ padding: 8px 14px; font-size: 0.76rem; color: var(--muted); border-top: 1px solid var(--border); }}
#status.err {{ color: var(--error); }}
@media (max-width: 900px) {{
  #picker-wrap {{ flex-direction: column; }}
  #picker {{ flex: 0 0 auto; max-height: 40vh; border-right: none; border-bottom: 1px solid var(--border); }}
}}
</style></head>
<body>
<header id="report-header">
  <h1>bgview <span style="color:var(--muted);font-weight:400">live</span></h1>
  <div class="stats"><span class="stat" id="hint">pick a .xml to analyse</span></div>
  <button type="button" id="toggle-picker" aria-expanded="true" aria-controls="picker"
          title="Show or hide the file picker">&#128193; Change script&#8230;</button>
</header>
<div id="picker-wrap">
  <nav id="picker" aria-label="File picker">
    <div id="picker-head">
      <div class="picker-actions">
        <button type="button" class="filter-btn primary" id="browse-dir">&#128193; Browse folder&#8230;</button>
        <button type="button" class="filter-btn" id="browse-file">Open .xml&#8230;</button>
        <button type="button" class="filter-btn" id="up">&#8593; parent</button>
      </div>
      <div class="drives" id="drives"></div>
      <div id="cwd"></div>
    </div>
    <div id="entries"></div>
    <div id="status">ready</div>
  </nav>
  <main id="stage">
    <div id="stage-empty">Choose a BuildGraph <code>.xml</code> on the left.<br/>
      Every click re-runs the analysis, so edit and click again to refresh.</div>
  </main>
</div>
<script>
(function () {{
  var TOKEN = {json.dumps(token)};
  var cwd = null;
  var entries = document.getElementById("entries");
  var status = document.getElementById("status");
  var stage = document.getElementById("stage");
  var picker = document.getElementById("picker");
  var toggle = document.getElementById("toggle-picker");

  function setPickerOpen(open) {{
    picker.hidden = !open;
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    // The label states what the button DOES next, not what it is looking at.
    toggle.textContent = open ? "\\u2715 Close picker" : "\\uD83D\\uDCC1 Change script\\u2026";
  }}
  toggle.addEventListener("click", function () {{ setPickerOpen(picker.hidden); }});
  // Escape closes it, but only once something is on the stage to go back to --
  // closing the picker with an empty stage would leave a blank window and no
  // obvious way forward.
  document.addEventListener("keydown", function (e) {{
    if (e.key === "Escape" && !picker.hidden && stage.querySelector("iframe")) {{ setPickerOpen(false); }}
  }});
  // Sync the label to the OPEN state we actually start in. The markup ships
  // the closed-state label so the button still says something useful without
  // JS; leaving it that way once running would have the button offer to open
  // a picker that is already open.
  setPickerOpen(true);

  function say(msg, isErr) {{
    status.textContent = msg;
    status.className = isErr ? "err" : "";
  }}
  function el(tag, cls, text) {{
    var e = document.createElement(tag);
    if (cls) {{ e.className = cls; }}
    if (text !== undefined) {{ e.textContent = text; }}
    return e;
  }}
  function kb(n) {{ return n < 1024 ? n + " B" : Math.round(n / 1024) + " KB"; }}

  function row(icon, name, cls, onClick, size) {{
    var b = el("button", "entry " + (cls || ""));
    b.type = "button";
    b.appendChild(el("span", "ico", icon));
    b.appendChild(el("span", "nm", name));
    if (size !== undefined) {{ b.appendChild(el("span", "sz", kb(size))); }}
    b.addEventListener("click", onClick);
    return b;
  }}

  function ls(dir) {{
    say("listing\\u2026");
    fetch("/api/ls?t=" + encodeURIComponent(TOKEN) + "&dir=" + encodeURIComponent(dir || ""))
      .then(function (r) {{ return r.json(); }})
      .then(function (d) {{
        if (d.error) {{ say(d.error, true); return; }}
        cwd = d.dir;
        document.getElementById("cwd").textContent = d.dir;
        document.getElementById("up").disabled = !d.parent;
        document.getElementById("up").onclick = function () {{ if (d.parent) {{ ls(d.parent); }} }};
        var dr = document.getElementById("drives");
        dr.textContent = "";
        (d.drives || []).forEach(function (root) {{
          var b = el("button", "filter-btn", root);
          b.type = "button";
          b.addEventListener("click", function () {{ ls(root); }});
          dr.appendChild(b);
        }});
        entries.textContent = "";
        d.dirs.forEach(function (x) {{
          entries.appendChild(row("DIR", x.name, "", function () {{ ls(x.path); }}));
        }});
        d.files.forEach(function (x) {{
          entries.appendChild(row("XML", x.name, "is-xml", function () {{ analyse(x.path); }}, x.size));
        }});
        say(d.dirs.length + " folder(s), " + d.files.length + " xml file(s)");
      }})
      .catch(function (e) {{ say(String(e), true); }});
  }}

  function analyse(path) {{
    say("analysing " + path + "\\u2026");
    fetch("/api/analyze?t=" + encodeURIComponent(TOKEN), {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{ path: path }})
    }})
      .then(function (r) {{ return r.json(); }})
      .then(function (d) {{
        if (d.error) {{ say(d.error, true); return; }}
        stage.textContent = "";
        var frame = document.createElement("iframe");
        frame.setAttribute("title", "bgview report for " + d.name);
        // srcdoc, not innerHTML: the report is a whole document and must stay
        // in its own browsing context rather than colliding with this shell.
        frame.srcdoc = d.html;
        stage.appendChild(frame);
        var c = d.counts;
        document.getElementById("hint").textContent =
          d.name + " \\u2014 " + d.nodes + " nodes, " + d.agents + " agents, " +
          c.error + " error / " + c.warn + " warn / " + c.info + " info";
        say("analysed " + d.path + (d.schemaBundled ? "  (bundled schema)" : ""));
        // The picker has served its purpose -- fold it away so the report gets
        // the whole window. Only on SUCCESS: an error must leave the picker up,
        // because the next thing the user needs to do is pick a different file.
        setPickerOpen(false);
      }})
      .catch(function (e) {{ say(String(e), true); }});
  }}

  function dialog(mode) {{
    say("waiting for the Windows dialog…");
    fetch("/api/browse?t=" + encodeURIComponent(TOKEN), {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{ mode: mode, start: cwd || "" }})
    }})
      .then(function (r) {{ return r.json(); }})
      .then(function (d) {{
        if (d.error) {{ say(d.error, true); return; }}
        if (d.cancelled) {{ say("cancelled"); return; }}
        if (mode === "dir") {{ ls(d.path); }} else {{ analyse(d.path); }}
      }})
      .catch(function (e) {{ say(String(e), true); }});
  }}
  document.getElementById("browse-dir").addEventListener("click", function () {{ dialog("dir"); }});
  document.getElementById("browse-file").addEventListener("click", function () {{ dialog("file"); }});

  ls("");
}})();
</script>
</body></html>
"""


def serve(port: int = 0, open_browser: bool = True) -> tuple[str, http.server.HTTPServer]:
    """Start the live picker. Returns (url, server).

    V35: bound to 127.0.0.1 explicitly. `port=0` lets the OS pick a free one,
    which is also what the tests use so they never collide with a real run.
    """
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    handler = type("_BoundHandler", (_Handler,), {"token": token})
    # ThreadingHTTPServer, not HTTPServer: browsers open concurrent sockets and
    # a single-threaded server serialises them, so one slow or idle connection
    # stalls the whole picker. daemon_threads means Ctrl-C actually exits.
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    actual = httpd.server_address[1]
    url = f"http://127.0.0.1:{actual}/?t={token}"
    if open_browser:
        threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
    return url, httpd


def main(port: int = 0) -> int:
    url, httpd = serve(port=port, open_browser=True)
    print(f"bgview live picker: {url}")
    print("  bound to 127.0.0.1 only; the token in that URL is required on every request.")
    print("  Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
    return 0


__all__ = ["serve", "main", "analyse", "native_dialog", "socket"]
