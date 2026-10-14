"""SS T.44 / SS T.45 -- one pipeline, and an include that cannot be read.

  V46  the browser path and `--serve` call the SAME `analyse()`; a report
       shown on GitHub Pages is byte-identical to one shown by the picker,
       because it is the same code and not two paths kept in sync by hand.
  V38  ... which in turn ends at the same `html.render_html` as `--html`.
  V47  a missing/unreadable `<Include>` is a loud D14 finding and the walk
       CONTINUES -- it never aborts the analysis. A single-file pick in the
       Pages app makes that the normal case, not an edge case.
  V9   same discipline as every other thing bgview cannot model: loud,
       located, never a silent skip.
"""

import pathlib
import tempfile
import unittest

from bgview import detectors, evaluator, html as html_renderer, loader, model, pipeline, schema, serve
from bgview.findings import Severity

_SCRIPT = """<?xml version='1.0' encoding='utf-8'?>
<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">
  <Property Name="Root" Value="D:/build"/>
  <Agent Name="Win" Type="Win64">
    <Node Name="Build" Produces="#Bin">
      <Log Message="root is $(Root)"/>
    </Node>
  </Agent>
</BuildGraph>
"""

_WITH_MISSING_INCLUDE = """<?xml version='1.0' encoding='utf-8'?>
<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">
  <Include Script="Definitely_Not_Here.xml"/>
  <Agent Name="Win" Type="Win64">
    <Node Name="Build" Produces="#Bin">
      <Log Message="after the bad include"/>
    </Node>
  </Agent>
</BuildGraph>
"""

_SHARED = """<?xml version='1.0' encoding='utf-8'?>
<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">
  <Property Name="Shared" Value="yes"/>
</BuildGraph>
"""

_WITH_GOOD_INCLUDE = """<?xml version='1.0' encoding='utf-8'?>
<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">
  <Include Script="Shared.xml"/>
  <Agent Name="Win" Type="Win64">
    <Node Name="Build">
      <Log Message="shared is $(Shared)"/>
    </Node>
  </Agent>
</BuildGraph>
"""


_BOOL_OPTIONS = """<?xml version='1.0' encoding='utf-8'?>
<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">
  <Option Name="WithDDC" DefaultValue="true" Description="fill the cache"/>
  <Option Name="Verbose" DefaultValue="False"/>
  <Option Name="Strict" DefaultValue="true" Restrict="true|false"/>
  <Option Name="Platforms" DefaultValue="Win64;PS5"/>
  <Agent Name="Win" Type="Win64">
    <Node Name="Build">
      <Log Message="$(WithDDC) $(Verbose) $(Strict) $(Platforms)"/>
    </Node>
  </Agent>
</BuildGraph>
"""


def _write(tmp: pathlib.Path, name: str, text: str) -> pathlib.Path:
    path = tmp / name
    path.write_text(text, encoding="utf-8")
    return path


class TestD22BooleanOptionWithoutRestrict(unittest.TestCase):
    """D22: an <Option> whose default is true/false but has no Restrict gets an
    info finding recommending Restrict="true|false" -- a mistyped value on a
    manual -set: run is otherwise accepted and read as false. Driven through
    the CLI so the whole pipeline is exercised the way a user runs it; the
    JS port carries the same two cases in tests-js/analyser.test.mjs."""

    def _run(self, text: str) -> str:
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as td:
            script = _write(pathlib.Path(td), "Opts.xml", text)
            proc = subprocess.run(
                [sys.executable, "-m", "bgview", str(script), "--fail-on", "error"],
                capture_output=True, text=True, encoding="utf-8",
                cwd=str(pathlib.Path(__file__).resolve().parent.parent),
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout

    def test_fires_once_per_unrestricted_boolean_option_and_names_the_fix(self):
        out = self._run(_BOOL_OPTIONS)
        d22 = [line for line in out.splitlines() if "[D22]" in line]
        self.assertEqual(len(d22), 2, out)
        self.assertIn("Opts.xml:3: info: [D22] Option 'WithDDC' defaults to 'true'", d22[0])
        self.assertIn('Restrict="true|false"', d22[0])
        self.assertIn("-set:WithDDC=ture", d22[0])
        # Case-insensitive match, quoted as written.
        self.assertIn("Opts.xml:4: info: [D22] Option 'Verbose' defaults to 'False'", d22[1])
        # The restricted one and the list-valued one stay silent.
        self.assertNotIn("Option 'Strict'", out)
        self.assertNotIn("Option 'Platforms' defaults", out)


class TestV46OnePipeline(unittest.TestCase):
    """V46: there is one implementation, and `serve` is a caller of it."""

    def test_serve_analyse_delegates_to_pipeline(self):
        """The picker must not hold its own copy of the six calls.

        Asserted structurally rather than by comparing two outputs: two
        copies of the pipeline would agree on the day they were written
        and drift later, which is precisely the failure V38/V46 exist to
        prevent. `serve.analyse` calling `pipeline.analyse` cannot drift.
        """
        with tempfile.TemporaryDirectory() as td:
            script = _write(pathlib.Path(td), "Simple.xml", _SCRIPT)
            calls = []
            real = pipeline.analyse

            def _spy(path):
                calls.append(path)
                return real(path)

            pipeline.analyse = _spy
            try:
                out = serve.analyse(str(script))
            finally:
                pipeline.analyse = real
        self.assertEqual(len(calls), 1, "serve.analyse did not go through pipeline.analyse")
        self.assertIn("html", out)

    def test_pipeline_html_is_the_render_html_bytes(self):
        """V38/V46: the dict's `html` is what `--html` would have written.

        Runs the pipeline by hand, exactly as `__main__` does, and demands
        the string come out identical -- so a front end can never show a
        finding the written report does not have.
        """
        with tempfile.TemporaryDirectory() as td:
            script = _write(pathlib.Path(td), "Simple.xml", _SCRIPT)
            got = pipeline.analyse(str(script))

            sch = schema.discover(str(script))
            ev = evaluator.evaluate(loader.load(script), sch, {})
            graph, model_findings = model.build(ev, sch)
            findings = list(ev.findings) + list(model_findings) + list(detectors.run_all(graph, ev, sch))
            expected = html_renderer.render_html(graph, findings, ev)

        self.assertEqual(got["html"], expected)
        self.assertEqual(got["nodes"], 1)
        self.assertEqual(got["agents"], 1)

    def test_pipeline_imports_nothing_pyodide_lacks(self):
        """V46 is only reachable if the shared module RUNS in the browser.

        Pyodide ships `socket`/`threading`/`multiprocessing` as non-functional
        stubs and removes `tkinter` outright; `subprocess` and `webbrowser`
        are equally useless there. Every one of those lives in `serve.py`,
        which the Pages app never imports -- and this test is what keeps it
        that way, because the cheapest possible regression is someone adding
        a convenience import to `pipeline.py` and only finding out in a
        browser console.
        """
        src = pathlib.Path(pipeline.__file__).read_text(encoding="utf-8")
        body = src.split('"""', 2)[-1]  # skip the module docstring, which names them
        for banned in ("import socket", "import subprocess", "import threading",
                       "import tkinter", "import webbrowser", "import multiprocessing",
                       "http.server"):
            self.assertNotIn(banned, body, f"pipeline.py must not use {banned} (V46)")


class TestV47MissingInclude(unittest.TestCase):
    """V47: an include we cannot read is a finding, never an abort."""

    def test_missing_include_reports_and_keeps_walking(self):
        with tempfile.TemporaryDirectory() as td:
            script = _write(pathlib.Path(td), "Broken.xml", _WITH_MISSING_INCLUDE)
            out = pipeline.analyse(str(script))

        self.assertNotIn("error", out, "a missing include must not abort the analysis")

        # The include was reported...
        self.assertIn("Cannot read included script", out["html"])
        # ...and everything AFTER it was still analysed. That is the half
        # that matters: aborting loses the whole report, and silently
        # skipping loses the reason the rest looks wrong.
        self.assertEqual(out["nodes"], 1, "walk stopped at the bad <Include>")
        self.assertEqual(out["agents"], 1)

    def test_missing_include_is_a_located_warn(self):
        """V15: every finding carries a real file:line. V47: severity warn."""
        with tempfile.TemporaryDirectory() as td:
            script = _write(pathlib.Path(td), "Broken.xml", _WITH_MISSING_INCLUDE)
            sch = schema.discover(str(script))
            ev = evaluator.evaluate(loader.load(script), sch, {})

        hits = [f for f in ev.findings if "Cannot read included script" in f.message]
        self.assertEqual(len(hits), 1, "expected exactly one finding for one bad include")
        self.assertEqual(hits[0].detector, "D14")
        self.assertEqual(hits[0].severity, Severity.WARN)
        self.assertEqual(hits[0].line, 3, "must point at the <Include> element itself")
        self.assertTrue(hits[0].file.endswith("Broken.xml"))

    def test_good_include_still_works(self):
        """The guard must not swallow includes that are perfectly fine."""
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            _write(tmp, "Shared.xml", _SHARED)
            main = _write(tmp, "Main.xml", _WITH_GOOD_INCLUDE)
            sch = schema.discover(str(main))
            ev = evaluator.evaluate(loader.load(main), sch, {})

        self.assertEqual([f for f in ev.findings if "Cannot read included script" in f.message], [])
        # $(Shared) resolved from the included file => no D1.
        self.assertEqual([f for f in ev.findings if f.detector == "D1"], [])


if __name__ == "__main__":
    unittest.main()
