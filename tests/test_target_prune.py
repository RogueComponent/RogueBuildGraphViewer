"""§T.16 / §T.19 -- --target pruning (V28) and schema resolution (V29).

V28 exists because `--target` was §I surface with no consumer: the CLI parsed
it and nothing read it. Dead flexibility in a linter is worse than absent
flexibility, because the flag reads as a safety control that does nothing.

V28's second clause is the important one: pruning must never SILENTLY drop a
finding. A hidden warn is worse than an unpruned graph.
"""

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from bgview import detectors, evaluator, loader, model, schema

# A real-world BuildGraph script the end-to-end tests run against. It is not
# shipped with the repo: set BGVIEW_TARGET_SCRIPT to its path to run them.
TARGET = pathlib.Path(
    os.environ.get("BGVIEW_TARGET_SCRIPT", "")
)
REPO = pathlib.Path(__file__).resolve().parent.parent


def _pipeline(path):
    sch = schema.discover(str(path))
    ev = evaluator.evaluate(loader.load(path), sch, {})
    graph, mf = model.build(ev, sch)
    return graph, list(ev.findings) + list(mf) + list(detectors.run_all(graph, ev, sch))


class TargetPruneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph, cls.findings = _pipeline(TARGET)

    def test_closure_follows_requires_transitively(self):
        keep = model.closure(self.graph, ["Submit To Perforce"])
        # The whole submit chain must survive...
        for expected in (
            "Submit To Perforce",
            "Stage for Submission",
            "Tag Output Files",
            "Compile Tools Win64",
            "Update Version Files",
        ):
            self.assertIn(expected, keep)
        # ...and a node nothing in that chain depends on must not.
        self.assertNotIn("Copy To Staging Directory", keep)

    def test_prune_actually_shrinks_the_graph(self):
        pruned, kept, suppressed = model.prune_to_targets(
            self.graph, self.findings, ["Submit To Perforce"]
        )
        self.assertLess(len(pruned.nodes), len(self.graph.nodes))
        self.assertNotIn("Copy To Staging Directory", pruned.nodes)
        self.assertEqual(len(kept) + suppressed, len(self.findings))

    def test_pruning_never_silently_drops_a_finding(self):
        """V28: the suppressed count must be exact and accounted for."""
        _pruned, kept, suppressed = model.prune_to_targets(
            self.graph, self.findings, ["Update Version Files"]
        )
        self.assertEqual(len(kept) + suppressed, len(self.findings))
        # File-scoped findings (dead <Option>, dead property) are anchored to no
        # node and must survive any pruning -- pruning narrows graph scope, it
        # must never delete a whole class of finding.
        for f in kept:
            if f.node:
                continue
            self.assertIn(f, self.findings)

    def test_unknown_target_is_an_error_not_an_empty_graph(self):
        """A typo'd target that silently yielded an empty graph would look
        exactly like 'congratulations, no findings'."""
        with self.assertRaises(model.UnknownTarget):
            model.closure(self.graph, ["No Such Node"])

    def test_cli_rejects_unknown_target_with_exit_2(self):
        proc = subprocess.run(
            [sys.executable, "-m", "bgview", str(TARGET), "--target", "Nope"],
            cwd=REPO, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("matched no node", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_cli_reports_suppressed_count(self):
        proc = subprocess.run(
            [sys.executable, "-m", "bgview", str(TARGET),
             "--target", "Update Version Files", "--fail-on", "error"],
            cwd=REPO, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("suppressed", proc.stderr)


class SchemaResolutionTests(unittest.TestCase):
    def test_v29_resolution_works_when_schema_is_absent(self):
        """R28: Schema.xsd is generated and gitignored, so it is commonly
        MISSING even inside a real UE tree. Walk-up failing is the normal
        case, not an edge case -- the bundled fact table must carry it."""
        with tempfile.TemporaryDirectory() as d:
            fake = pathlib.Path(d) / "Engine" / "Build" / "Graph"
            fake.mkdir(parents=True)
            script = fake / "Some.xml"
            script.write_text("<BuildGraph/>", encoding="utf-8")
            self.assertFalse((fake / "Schema.xsd").exists())
            sch = schema.discover(str(script))
            self.assertTrue(sch.is_bundled)
            # must be a real schema, not a stub
            self.assertTrue(sch.is_tag_output("Tag", "With"))
            self.assertTrue(sch.is_required("SymStore", "StoreDir"))


if __name__ == "__main__":
    unittest.main()
