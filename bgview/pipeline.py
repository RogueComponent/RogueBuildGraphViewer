"""bgview.pipeline -- the one analysis pipeline, shared by every front end (T44).

    schema.discover -> loader.load -> evaluator.evaluate -> model.build
    -> detectors.run_all -> html.render_html

`analyse()` used to live inside `serve.py`, where only the localhost picker
could reach it. V46 makes that arrangement untenable: the GitHub Pages app
(T46) runs the same package under Pyodide and needs the same result, and a
second front end re-listing those six calls is exactly the divergence V38
was written to prevent -- one caller would eventually gain a `--project`,
or drop a findings source, and two "identical" reports would quietly stop
being identical.

So the body moved here and `serve.analyse` became a one-line delegation.
There is one implementation; a finding shown on Pages is byte-identical to
one shown by `--serve`, and both are byte-identical to `--html`, because
all three end at the same `html.render_html` call.

Findings are pooled from THREE sources, exactly as `__main__` does it:
`ev.findings` (D1/D14/D17/D21, emitted by the evaluator during expansion),
`model.build`'s returned list, and `detectors.run_all`. Dropping any one
silently under-reports -- see `__main__`'s module docstring.

Stdlib only, and deliberately free of anything Pyodide cannot provide: no
socket, no subprocess, no threading, no tkinter. Those live in `serve.py`,
which the browser never imports.
"""

from __future__ import annotations

import pathlib

from bgview import detectors, evaluator, html as html_renderer, loader, model, schema


def analyse(path: str) -> dict:
    """Run the whole pipeline on `path` and return report HTML + counts.

    Returns a plain dict of str/int/bool -- no bgview types cross this
    boundary -- so it survives being handed to `json.dumps` (serve.py) or
    converted to a JS object by Pyodide (web/app.js) without either caller
    needing to know what a `Finding` is.

    An input that is not an existing `.xml` file comes back as
    `{"error": ...}` rather than raising: both callers are interactive
    front ends where "you picked the wrong thing" is a message, not a
    crash. A genuine tool error (malformed XML, DOCTYPE, depth cap) still
    raises `BgError` for the caller to render as it sees fit.
    """
    target = pathlib.Path(path).expanduser().resolve()
    if not target.is_file():
        return {"error": f"not a file: {target}"}
    if target.suffix.lower() != ".xml":
        return {"error": "not a .xml file"}

    sch = schema.discover(str(target))
    ev = evaluator.evaluate(loader.load(target), sch, {})
    graph, model_findings = model.build(ev, sch)
    findings = list(ev.findings) + list(model_findings) + list(detectors.run_all(graph, ev, sch))

    counts = {"info": 0, "warn": 0, "error": 0}
    for f in findings:
        counts[f.severity.name.lower()] += 1
    return {
        "path": str(target),
        "name": target.name,
        "counts": counts,
        "nodes": len(graph.nodes),
        "agents": len(graph.agents),
        "schemaBundled": bool(getattr(sch, "is_bundled", False)),
        "html": html_renderer.render_html(graph, findings, ev),
    }
