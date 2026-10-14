"""Tests for bgview.schema: R2 (tag polarity table) and schema discovery."""

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bgview.loader import BgError
from bgview.schema import Schema, discover

REAL_SCHEMA = pathlib.Path(r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph\Schema.xsd")
REAL_EXAMPLE = pathlib.Path(
    r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph\Examples\BuildEditorAndTools.xml"
)


class TagPolarityTests(unittest.TestCase):
    """R2: attr typed TagListType/TagType PRODUCES; everything else does not."""

    @classmethod
    def setUpClass(cls):
        if not REAL_SCHEMA.is_file():
            raise AssertionError(f"fixture missing: {REAL_SCHEMA}")
        cls.schema = Schema.from_file(REAL_SCHEMA)

    def test_known_true_producer_cases(self):
        producers = [
            ("Tag", "With"),
            ("Copy", "Tag"),
            ("Compile", "Tag"),
            ("Node", "Produces"),  # special: Node is structural, not a task element
        ]
        for tag, attr in producers:
            with self.subTest(tag=tag, attr=attr):
                self.assertTrue(
                    self.schema.is_tag_output(tag, attr),
                    f"{tag}/@{attr} should be a tag PRODUCER",
                )

    def test_known_true_non_producer_cases(self):
        not_producers = [
            ("Tag", "Files"),
            ("Tag", "Filter"),
            ("Tag", "Except"),
            ("Copy", "Files"),
            ("SymStore", "Files"),
        ]
        for tag, attr in not_producers:
            with self.subTest(tag=tag, attr=attr):
                self.assertFalse(
                    self.schema.is_tag_output(tag, attr),
                    f"{tag}/@{attr} should NOT be a tag producer",
                )

    def test_attr_type_exact_values(self):
        self.assertEqual(self.schema.attr_type("Copy", "Tag"), "TagListType")
        self.assertEqual(self.schema.attr_type("Tag", "With"), "TagListType")
        self.assertEqual(self.schema.attr_type("Copy", "Files"), "BalancedStringType")
        self.assertEqual(self.schema.attr_type("Node", "Produces"), "TagListType")
        self.assertIsNone(self.schema.attr_type("Copy", "NoSuchAttr"))
        self.assertIsNone(self.schema.attr_type("NoSuchTag", "Files"))

    def test_known_element(self):
        for tag in ("Node", "Agent", "Compile", "Tag", "SymStore", "Do", "Switch", "ForEach", "BuildGraph"):
            with self.subTest(tag=tag):
                self.assertTrue(self.schema.known_element(tag))
        self.assertFalse(self.schema.known_element("NotARealBuildGraphElement"))


class RequiredAttrTests(unittest.TestCase):
    """xs:attribute use="required", surfaced generically (feeds D11 -- no per-task table)."""

    @classmethod
    def setUpClass(cls):
        if not REAL_SCHEMA.is_file():
            raise AssertionError(f"fixture missing: {REAL_SCHEMA}")
        cls.schema = Schema.from_file(REAL_SCHEMA)

    def test_is_required_symstore(self):
        self.assertTrue(self.schema.is_required("SymStore", "StoreDir"))
        self.assertFalse(self.schema.is_required("SymStore", "Branch"))
        # Unknown tag/attr default to "not required" (nothing forces it).
        self.assertFalse(self.schema.is_required("SymStore", "NoSuchAttr"))
        self.assertFalse(self.schema.is_required("NoSuchTag", "StoreDir"))

    def test_required_attrs_symstore(self):
        self.assertEqual(
            self.schema.required_attrs("SymStore"),
            {"Platform", "Files", "StoreDir", "Product"},
        )

    def test_is_required_structural_element_node(self):
        # Non-task element sanity check, same as R2's Node/@Produces case:
        # requiredness is read straight off the schema regardless of whether
        # the element is a "task" or a structural one.
        self.assertTrue(self.schema.is_required("Node", "Name"))
        self.assertFalse(self.schema.is_required("Node", "Produces"))


class DiscoverTests(unittest.TestCase):
    """discover(): walk-up auto-discovery, explicit --schema override, clear failure."""

    def test_override_path_used_verbatim(self):
        self.assertTrue(REAL_SCHEMA.is_file(), f"fixture missing: {REAL_SCHEMA}")
        schema = discover("C:/wherever/unused/script.xml", override=str(REAL_SCHEMA))
        self.assertTrue(schema.is_tag_output("Tag", "With"))

    def test_override_missing_raises_bgerror(self):
        with tempfile.TemporaryDirectory() as d:
            bad_override = str(pathlib.Path(d) / "nope.xsd")
            with self.assertRaises(BgError):
                discover("C:/wherever/script.xml", override=bad_override)

    def test_walks_up_from_real_script_without_override(self):
        self.assertTrue(REAL_EXAMPLE.is_file(), f"fixture missing: {REAL_EXAMPLE}")
        schema = discover(str(REAL_EXAMPLE))
        self.assertTrue(schema.is_tag_output("Compile", "Tag"))

    def test_falls_back_to_bundled_facts_outside_any_ue_tree(self):
        """Tier 3 (§C): a script outside any UE tree still analyzes.

        This is the headline use case -- someone emails you a BuildGraph file
        and you point bgview at it -- and it is what makes §C's "no UE install
        required" actually true.
        """
        from bgview.schema import BUNDLED_FACTS

        self.assertTrue(BUNDLED_FACTS.is_file(), "bundled fact table missing")
        with tempfile.TemporaryDirectory() as d:
            script = pathlib.Path(d) / "script.xml"
            script.write_text("<BuildGraph/>", encoding="utf-8")
            schema = discover(str(script))
            self.assertTrue(schema.is_bundled, "should be flagged as the bundled fact table")
            # and it must be a genuinely usable schema, not an empty stub
            self.assertTrue(schema.is_tag_output("Compile", "Tag"))
            self.assertTrue(schema.is_required("SymStore", "StoreDir"))

    def test_walk_up_wins_over_bundled_facts(self):
        """A real UE tree's schema must beat the derived table -- that ordering is
        what keeps version drift from mattering whenever it can be avoided."""
        schema = discover(str(REAL_EXAMPLE))
        self.assertFalse(schema.is_bundled)

    def test_raises_bgerror_naming_schema_flag_when_bundled_absent_too(self):
        """With every tier exhausted it must still fail loudly and name --schema."""
        import bgview.schema as schema_mod

        original = schema_mod.BUNDLED_FACTS
        try:
            schema_mod.BUNDLED_FACTS = pathlib.Path("Z:/nonexistent/schema-facts.json")
            with tempfile.TemporaryDirectory() as d:
                script = pathlib.Path(d) / "script.xml"
                script.write_text("<BuildGraph/>", encoding="utf-8")
                with self.assertRaises(BgError) as ctx:
                    discover(str(script))
                self.assertIn("--schema", str(ctx.exception))
        finally:
            schema_mod.BUNDLED_FACTS = original


if __name__ == "__main__":
    unittest.main()


class DerivedFactTableTests(unittest.TestCase):
    """`data/schema-facts.json` must say exactly what the real schema says.

    bgview does not vendor Epic's generated `Schema.xsd` (EULA-licensed; see
    `bgview/data/NOTICE.md`) -- the tier-3 fallback is its own derived table
    of the three facts the detectors ask for. That makes the table a claim
    about the engine, and this is the check that keeps the claim honest:
    element for element, attribute for attribute, against a real 5.8 schema.
    Regenerate with `python tools/derive_schema.py <Schema.xsd>` when it
    drifts.
    """

    @classmethod
    def setUpClass(cls):
        from bgview.schema import BUNDLED_FACTS

        if not REAL_SCHEMA.is_file():
            raise AssertionError(f"fixture missing: {REAL_SCHEMA}")
        cls.from_xsd = Schema.from_file(REAL_SCHEMA)
        cls.from_facts = Schema.from_facts_file(BUNDLED_FACTS)

    def test_same_element_set(self):
        self.assertEqual(self.from_xsd.element_names(), self.from_facts.element_names())

    def test_same_tag_polarity_and_requiredness_for_every_element(self):
        for tag in self.from_xsd.element_names():
            with self.subTest(tag=tag):
                self.assertEqual(
                    self.from_xsd.required_attrs(tag),
                    self.from_facts.required_attrs(tag),
                    f"{tag}: required attrs disagree",
                )
                # Polarity has no public per-element accessor, so ask the
                # question every detector asks, for every attribute either
                # source knows about.
                attrs = self.from_xsd.required_attrs(tag) | self.from_facts.required_attrs(tag)
                attrs |= {"Tag", "With", "Produces", "Files", "From", "To"}
                for attr in sorted(attrs):
                    self.assertEqual(
                        self.from_xsd.is_tag_output(tag, attr),
                        self.from_facts.is_tag_output(tag, attr),
                        f"{tag}/@{attr}: tag polarity disagrees",
                    )

    def test_known_producers_survive_the_derivation(self):
        for tag, attr in (("Tag", "With"), ("Copy", "Tag"), ("Compile", "Tag"), ("Node", "Produces")):
            with self.subTest(tag=tag, attr=attr):
                self.assertTrue(self.from_facts.is_tag_output(tag, attr))

    def test_attr_type_is_xsd_only(self):
        """The derived table carries no types -- nothing consumes them, and
        saying so beats returning a plausible-looking guess."""
        self.assertEqual(self.from_xsd.attr_type("Copy", "Tag"), "TagListType")
        self.assertIsNone(self.from_facts.attr_type("Copy", "Tag"))
        # ...and the fact it exists to answer is still answered.
        self.assertTrue(self.from_facts.is_tag_output("Copy", "Tag"))
