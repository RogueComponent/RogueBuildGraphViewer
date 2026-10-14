"""Tests for bgview.loader: V7 (hardened XML load) and V15 (real file:line)."""

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bgview.loader import MAX_DEPTH, MAX_ELEMENT_COUNT, BgError, load

REAL_EXAMPLE = pathlib.Path(
    r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph\Examples\BuildEditorAndTools.xml"
)


def _write(dirpath: pathlib.Path, content: str) -> pathlib.Path:
    p = dirpath / "fixture.xml"
    p.write_text(content, encoding="utf-8")
    return p


class DoctypeHardeningTests(unittest.TestCase):
    """V7: entity resolution OFF, no external DTD fetch, no network, capped depth/count."""

    def test_billion_laughs_doctype_rejected(self):
        # Classic entity-expansion-bomb shape. Must be rejected at the
        # DOCTYPE itself, before a single <!ENTITY> is even declared --
        # otherwise expat would happily expand this (verified separately:
        # without a StartDoctypeDeclHandler, expat parses internal entity
        # declarations by default).
        payload = (
            "<?xml version='1.0'?>\n"
            "<!DOCTYPE lolz [\n"
            ' <!ENTITY lol "lol">\n'
            ' <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
            "]>\n"
            "<BuildGraph xmlns='http://www.epicgames.com/BuildGraph'>&lol2;</BuildGraph>\n"
        )
        with tempfile.TemporaryDirectory() as d:
            path = _write(pathlib.Path(d), payload)
            with self.assertRaises(BgError):
                load(path)

    def test_external_entity_doctype_rejected_without_touching_filesystem(self):
        # XXE shape: a SYSTEM external entity pointing at a path that does
        # not exist. If the loader ever tried to resolve it we'd see some
        # other (OS-level "file not found") failure instead of a clean
        # BgError -- so getting BgError here is itself the proof the SYSTEM
        # URI was never dereferenced (no network, no external fetch).
        payload = (
            "<?xml version='1.0'?>\n"
            "<!DOCTYPE root [\n"
            ' <!ENTITY xxe SYSTEM "file:///path/does/not/exist/xxe.txt">\n'
            "]>\n"
            "<BuildGraph xmlns='http://www.epicgames.com/BuildGraph'>&xxe;</BuildGraph>\n"
        )
        with tempfile.TemporaryDirectory() as d:
            path = _write(pathlib.Path(d), payload)
            with self.assertRaises(BgError):
                load(path)

    def test_depth_cap_enforced(self):
        opens = "<a>" * (MAX_DEPTH + 1)
        closes = "</a>" * (MAX_DEPTH + 1)
        payload = (
            "<?xml version='1.0'?>\n"
            f"<BuildGraph xmlns='http://www.epicgames.com/BuildGraph'>{opens}{closes}</BuildGraph>\n"
        )
        with tempfile.TemporaryDirectory() as d:
            path = _write(pathlib.Path(d), payload)
            with self.assertRaises(BgError):
                load(path)

    def test_element_count_cap_enforced(self):
        siblings = "<a/>" * (MAX_ELEMENT_COUNT + 1)
        payload = (
            "<?xml version='1.0'?>\n"
            f"<BuildGraph xmlns='http://www.epicgames.com/BuildGraph'>{siblings}</BuildGraph>\n"
        )
        with tempfile.TemporaryDirectory() as d:
            path = _write(pathlib.Path(d), payload)
            with self.assertRaises(BgError):
                load(path)


class LineNumberTests(unittest.TestCase):
    """V15: every element carries a real, 1-based file:line."""

    def test_line_numbers_1_based_multiline(self):
        payload = (
            "<?xml version='1.0'?>\n"                                   # line 1
            "<BuildGraph xmlns='http://www.epicgames.com/BuildGraph'>\n"  # line 2
            "  <Agent Name='A'>\n"                                       # line 3
            "    <Node Name='N'>\n"                                      # line 4
            "      <Compile Tag='#X'/>\n"                                # line 5
            "    </Node>\n"
            "  </Agent>\n"
            "</BuildGraph>\n"
        )
        with tempfile.TemporaryDirectory() as d:
            path = _write(pathlib.Path(d), payload)
            root = load(path)

        self.assertEqual((root.tag, root.line), ("BuildGraph", 2))
        agent = root.children[0]
        self.assertEqual((agent.tag, agent.line), ("Agent", 3))
        node = agent.children[0]
        self.assertEqual((node.tag, node.line), ("Node", 4))
        compile_elem = node.children[0]
        self.assertEqual((compile_elem.tag, compile_elem.line), ("Compile", 5))
        for elem in root.iter():
            self.assertGreater(elem.line, 0)  # V15: line==0 is forbidden

    def test_namespace_is_stripped_from_tag(self):
        payload = (
            "<?xml version='1.0'?>\n"
            "<BuildGraph xmlns='http://www.epicgames.com/BuildGraph'>\n"
            "  <Node Name='N'/>\n"
            "</BuildGraph>\n"
        )
        with tempfile.TemporaryDirectory() as d:
            path = _write(pathlib.Path(d), payload)
            root = load(path)
        self.assertEqual(root.tag, "BuildGraph")
        self.assertNotIn("{", root.tag)
        self.assertNotIn("}", root.tag)
        self.assertEqual(root.children[0].tag, "Node")


class ElemTreeTests(unittest.TestCase):
    def test_iter_is_depth_first_self_first(self):
        payload = (
            "<?xml version='1.0'?>\n"
            "<BuildGraph xmlns='http://www.epicgames.com/BuildGraph'>\n"
            "  <A>\n"
            "    <B/>\n"
            "  </A>\n"
            "  <C/>\n"
            "</BuildGraph>\n"
        )
        with tempfile.TemporaryDirectory() as d:
            path = _write(pathlib.Path(d), payload)
            root = load(path)
        self.assertEqual([e.tag for e in root.iter()], ["BuildGraph", "A", "B", "C"])

    def test_parent_links(self):
        payload = (
            "<?xml version='1.0'?>\n"
            "<BuildGraph xmlns='http://www.epicgames.com/BuildGraph'>\n"
            "  <Agent><Node/></Agent>\n"
            "</BuildGraph>\n"
        )
        with tempfile.TemporaryDirectory() as d:
            path = _write(pathlib.Path(d), payload)
            root = load(path)
        self.assertIsNone(root.parent)
        agent = root.children[0]
        self.assertIs(agent.parent, root)
        node = agent.children[0]
        self.assertIs(node.parent, agent)

    def test_missing_file_raises_bgerror(self):
        with tempfile.TemporaryDirectory() as d:
            missing = pathlib.Path(d) / "does_not_exist.xml"
            with self.assertRaises(BgError):
                load(missing)


class RealExampleFileTests(unittest.TestCase):
    """Loading a real, unmodified Epic-shipped BuildGraph script end to end."""

    def test_loads_build_editor_and_tools_with_sane_lines(self):
        self.assertTrue(REAL_EXAMPLE.is_file(), f"fixture missing: {REAL_EXAMPLE}")
        root = load(REAL_EXAMPLE)

        self.assertEqual(root.tag, "BuildGraph")
        # xsi:schemaLocation is namespace-prefixed; expat's namespace
        # processing (and our stripping, matching Elem.tag) reduces it to
        # its bare local name same as every other attribute.
        self.assertEqual(
            root.attrib.get("schemaLocation"),
            "http://www.epicgames.com/BuildGraph ../Schema.xsd",
        )

        all_elems = list(root.iter())
        self.assertGreater(len(all_elems), 50)
        resolved = str(REAL_EXAMPLE.resolve())
        for elem in all_elems:
            self.assertGreater(elem.line, 0)
            self.assertEqual(elem.file, resolved)

        # First real child (after the leading <!-- comment --> block).
        first_option = root.children[0]
        self.assertEqual(first_option.tag, "Option")
        self.assertEqual(first_option.attrib.get("Name"), "EditorTarget")
        self.assertEqual(first_option.line, 41)

        # A node nested inside <Agent>, and its two task children, land on
        # their exact real source lines.
        node = next(
            e for e in all_elems
            if e.tag == "Node" and e.attrib.get("Name") == "Update Version Files"
        )
        self.assertEqual(node.line, 85)
        set_versions = [c for c in node.children if c.tag == "SetVersion"]
        self.assertEqual([c.line for c in set_versions], [86, 87])


if __name__ == "__main__":
    unittest.main()
