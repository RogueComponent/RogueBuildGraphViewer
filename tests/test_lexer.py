"""Tests for bgview.lexer (T2)."""

import unittest

from bgview.lexer import apply_slice, had_empty_entry, is_tag, iter_refs, split_list


class SplitListTests(unittest.TestCase):
    """V1: tag lists split on ';' ONLY -- tag names may contain spaces."""

    def test_spaces_preserved_never_split_on_whitespace(self):
        result = split_list("#First Named Output;#Second Named Output")
        self.assertEqual(result, ["#First Named Output", "#Second Named Output"])
        # The defining property of V1: neither item was cut on a space --
        # each one still holds its internal space intact.
        self.assertTrue(all(" " in item for item in result))

    def test_strips_whitespace_and_drops_empty_items(self):
        self.assertEqual(split_list("#A; #B Named ;"), ["#A", "#B Named"])


class HadEmptyEntryTests(unittest.TestCase):
    """V6/D10: trailing ';' / ';;' -> info-only signal, never a warning."""

    def test_trailing_semicolon_is_empty_entry(self):
        self.assertTrue(had_empty_entry("#A;#B;"))

    def test_no_trailing_semicolon_is_not_empty_entry(self):
        self.assertFalse(had_empty_entry("#A;#B"))


class IsTagTests(unittest.TestCase):
    def test_hash_prefix_is_tag(self):
        self.assertTrue(is_tag("#Foo"))

    def test_no_hash_prefix_is_not_tag(self):
        self.assertFalse(is_tag("Foo"))


class ApplySliceTests(unittest.TestCase):
    """R18: n>0 -> first n chars, n<0 -> last n chars, applied ONLY when
    len(value) > abs(n)."""

    def test_positive_n_takes_first_n_chars(self):
        self.assertEqual(apply_slice("abcdef", 3), "abc")

    def test_negative_n_takes_last_n_chars(self):
        self.assertEqual(apply_slice("abcdef", -3), "def")

    def test_boundary_len_less_than_abs_n_is_unchanged(self):
        self.assertEqual(apply_slice("abc", -6), "abc")

    def test_boundary_len_equal_to_abs_n_is_unchanged(self):
        # Guard is strict '>' -- equality must NOT trigger the slice.
        self.assertEqual(apply_slice("abcdef", 6), "abcdef")
        self.assertEqual(apply_slice("abcdef", -6), "abcdef")

    def test_none_slice_is_unchanged(self):
        self.assertEqual(apply_slice("abcdef", None), "abcdef")


class IterRefsTests(unittest.TestCase):
    def test_simple_ref_no_slice(self):
        refs = iter_refs("$(Foo)")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0].name, "Foo")
        self.assertIsNone(refs[0].slice_n)
        self.assertFalse(refs[0].malformed)
        self.assertEqual(refs[0].raw, "$(Foo)")
        self.assertEqual(refs[0].start, 0)
        self.assertEqual(refs[0].end, len("$(Foo)"))

    def test_slice_suffix_parsed_positive_and_negative(self):
        pos_ref = iter_refs("$(Foo:6)")[0]
        self.assertEqual(pos_ref.name, "Foo")
        self.assertEqual(pos_ref.slice_n, 6)
        self.assertFalse(pos_ref.malformed)

        neg_ref = iter_refs("$(Foo:-6)")[0]
        self.assertEqual(neg_ref.name, "Foo")
        self.assertEqual(neg_ref.slice_n, -6)
        self.assertFalse(neg_ref.malformed)

    def test_real_world_slice_usage(self):
        # Real usage in Epic's tree: $(UE_HORDE_JOBID:-6)
        refs = iter_refs("$(UE_HORDE_JOBID:-6)")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0].name, "UE_HORDE_JOBID")
        self.assertEqual(refs[0].slice_n, -6)
        self.assertFalse(refs[0].malformed)

    def test_malformed_slice_sets_flag_and_does_not_raise(self):
        refs = iter_refs("$(Foo:bar)")  # engine's Int32.Parse would THROW
        self.assertEqual(len(refs), 1)
        ref = refs[0]
        self.assertEqual(ref.name, "Foo")
        self.assertIsNone(ref.slice_n)
        self.assertTrue(ref.malformed)

    def test_nested_reference_yields_both_refs_innermost_last(self):
        # Ascending start-offset (document) order: the container starts
        # before the ref nested inside it, so it sorts first -- the engine
        # mirrors this by always resolving refs[-1] next (see iter_refs'
        # docstring for the full mutate-and-rescan rationale).
        refs = iter_refs("$(Outer$(Inner))")
        self.assertEqual([r.name for r in refs], ["Outer$(Inner)", "Inner"])
        self.assertEqual(refs[-1].name, "Inner")

    def test_sibling_refs_are_in_document_order(self):
        refs = iter_refs("$(A)$(B)")
        self.assertEqual([r.name for r in refs], ["A", "B"])
        self.assertEqual(refs[-1].name, "B")

    def test_unterminated_outer_ref_drops_silently_keeps_inner(self):
        # "$(A$(B)" -- the inner ref closes properly; the outer never finds
        # its own ')' (mirrors the engine's ExpandProperties, which breaks
        # the scan when IndexOf(')') returns -1 for the current "$(").
        refs = iter_refs("$(A$(B)")
        self.assertEqual([r.name for r in refs], ["B"])

    def test_bare_paren_does_not_open_a_nested_ref(self):
        # Only "$(" opens a ref -- a bare '(' is just name text, matching
        # the engine's own IndexOf(')') scan, which does not track bare
        # parens either.
        refs = iter_refs("$(A(B))")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0].name, "A(B")

    def test_colon_beside_unresolved_nested_ref_is_not_flagged_malformed(self):
        # "$(Foo:$(N))" contains TWO refs: the inner "$(N)", and the outer
        # "$(Foo:$(N))" whose slice-suffix position holds that unresolved
        # ref rather than a plain int. "$(N)" isn't an int as written, but
        # resolves fine once N is substituted -- lexer.py has no evaluator,
        # so it must defer on the outer's slice rather than guess, per
        # V12a's "do not crash / do not fabricate" spirit extended to
        # false-malformed too.
        refs = iter_refs("$(Foo:$(N))")
        self.assertEqual(len(refs), 2)
        outer = next(r for r in refs if r.name == "Foo:$(N)")
        self.assertIsNone(outer.slice_n)
        self.assertFalse(outer.malformed)

    def test_no_refs_in_plain_text(self):
        self.assertEqual(iter_refs("plain text, no refs here"), [])


if __name__ == "__main__":
    unittest.main()
