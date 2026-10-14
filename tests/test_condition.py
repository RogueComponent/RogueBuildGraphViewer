"""Tests for bgview.condition (T7)."""

import glob
import os
import unittest
import xml.etree.ElementTree as ET

from bgview.condition import (
    And,
    Call,
    Cmp,
    CondParseError,
    Ident,
    Not,
    Or,
    Str,
    parse,
)

# Taken verbatim from Epic's shipped graphs (per the T7 task brief, plus
# Contains/ContainsItem per B1/V25 -- Examples/Properties.xml:90,98) -- all
# must parse without error.
REAL_CONDITIONS = [
    "$(IsBuildMachine)",
    "!$(Versioned) and $(Promoted)",
    "'$(SymbolStorePath)' == ''",
    "$(A) == 'True'",
    "$(A) != $(B)",
    "$(A) and ($(B) or $(C))",
    "$(IsBuildMachine) And !$(SubmitHLODs) And !$(ShelveHLODs)",
    "!HasTrailingSlash('$(TestDirWithSlash)')",
    "$(EngineMajorVersion) >= 5",
    "Contains('$(HaystackString)', '$(Needle)')",
    "ContainsItem('$(HaystackItems)', '$(Needle)',';')",
]


class RealConditionsParseTests(unittest.TestCase):
    """Every condition string actually shipped in Epic's graphs must parse
    without raising -- this is the parser's whole job."""

    def test_all_real_conditions_parse(self):
        for text in REAL_CONDITIONS:
            with self.subTest(text=text):
                parse(text)  # must not raise


class GrammarShapeTests(unittest.TestCase):
    """Spot checks that a representative sample builds the AST shape the
    grammar actually implies, not just "doesn't crash"."""

    def test_bare_ref_is_ident_with_raw_text(self):
        self.assertEqual(parse("$(IsBuildMachine)"), Ident("$(IsBuildMachine)"))

    def test_not_and_case_insensitive_and_keyword(self):
        node = parse("!$(Versioned) and $(Promoted)")
        self.assertEqual(node, And(Not(Ident("$(Versioned)")), Ident("$(Promoted)")))

    def test_string_equality_comparison_strips_quotes(self):
        node = parse("'$(SymbolStorePath)' == ''")
        self.assertEqual(node, Cmp("==", Str("$(SymbolStorePath)"), Str("")))

    def test_parenthesized_or_inside_and(self):
        node = parse("$(A) and ($(B) or $(C))")
        self.assertEqual(node, And(Ident("$(A)"), Or(Ident("$(B)"), Ident("$(C)"))))

    def test_capitalized_and_is_left_associative_chain(self):
        node = parse("$(IsBuildMachine) And !$(SubmitHLODs) And !$(ShelveHLODs)")
        self.assertEqual(
            node,
            And(
                And(Ident("$(IsBuildMachine)"), Not(Ident("$(SubmitHLODs)"))),
                Not(Ident("$(ShelveHLODs)")),
            ),
        )

    def test_not_hastrailingslash_call_case_insensitive(self):
        node = parse("!HasTrailingSlash('$(TestDirWithSlash)')")
        self.assertEqual(node, Not(Call("HasTrailingSlash", [Str("$(TestDirWithSlash)")])))

    def test_numeric_comparison_operand_is_ident(self):
        node = parse("$(EngineMajorVersion) >= 5")
        self.assertEqual(node, Cmp(">=", Ident("$(EngineMajorVersion)"), Ident("5")))


class CallArityTests(unittest.TestCase):
    """V25/R25/B1: the doc comment at BgCondition.cs:36-62 only lists
    Exists/HasTrailingSlash -- the actual implementation supports five
    functions with fixed arities. These pin the Call(name, args) shape and
    each function's exact arity so a future re-transcription of the (still
    stale) doc comment can't silently regress this again."""

    def test_exists_is_single_arg_call_list(self):
        node = parse("Exists('$(Path)')")
        self.assertEqual(node, Call("Exists", [Str("$(Path)")]))

    def test_length_is_single_arg_call_and_feeds_numeric_comparison(self):
        # Length(s) -> an INT, not a bool -- so "> 3" must parse (V18).
        node = parse("Length('$(X)') > 3")
        self.assertEqual(node, Cmp(">", Call("Length", [Str("$(X)")]), Ident("3")))

    def test_length_matched_case_insensitively(self):
        node = parse("length('$(X)') > 3")
        self.assertEqual(node, Cmp(">", Call("Length", [Str("$(X)")]), Ident("3")))

    def test_contains_is_two_arg_call(self):
        node = parse("Contains('$(HaystackString)', '$(Needle)')")
        self.assertEqual(node, Call("Contains", [Str("$(HaystackString)"), Str("$(Needle)")]))

    def test_containsitem_is_three_arg_call(self):
        node = parse("ContainsItem('$(HaystackItems)', '$(Needle)',';')")
        self.assertEqual(
            node,
            Call("ContainsItem", [Str("$(HaystackItems)"), Str("$(Needle)"), Str(";")]),
        )

    def test_contains_matched_case_insensitively(self):
        node = parse("contains('a', 'b')")
        self.assertEqual(node, Call("Contains", [Str("a"), Str("b")]))

    def test_wrong_arity_raises_cond_parse_error_naming_function(self):
        with self.assertRaises(CondParseError) as ctx:
            parse("Contains('$(OnlyOneArg)')")
        self.assertIn("Contains", str(ctx.exception))

    def test_containsitem_wrong_arity_raises(self):
        with self.assertRaises(CondParseError):
            parse("ContainsItem('a', 'b')")  # 2 given, 3 required

    def test_contains_too_many_args_raises(self):
        with self.assertRaises(CondParseError):
            parse("Contains('a', 'b', 'c')")


class MalformedConditionTests(unittest.TestCase):
    """Parse errors must raise CondParseError with the offending text --
    never a bare/unrelated exception, never a silent None."""

    def test_dangling_operator_raises_cond_parse_error(self):
        with self.assertRaises(CondParseError):
            parse("$(A) ==")

    def test_unclosed_paren_raises_cond_parse_error(self):
        with self.assertRaises(CondParseError):
            parse("($(A)")

    def test_error_type_is_exactly_cond_parse_error(self):
        # Guard against e.g. an IndexError leaking from running off the end
        # of the token list instead of a proper CondParseError.
        try:
            parse("$(A) and")
        except CondParseError:
            pass
        except Exception as exc:  # pragma: no cover - failure diagnostic
            self.fail(f"expected CondParseError, got {type(exc).__name__}: {exc}")
        else:
            self.fail("expected CondParseError, none was raised")


# --------------------------------------------------------------------------
# V25/B1 corpus regression: parse EVERY If= condition Epic actually ships.
# --------------------------------------------------------------------------
#
# This is the test that would have caught the original bug before it
# shipped: R11's first pass transcribed BgCondition.cs's grammar DOC
# COMMENT (stale) instead of its implementation, so Contains/ContainsItem
# were missing and the parser raised CondParseError on Epic's own
# Examples/Properties.xml -- which would have blown the V5/V21 FP budget.
#
# Reads (never writes) the read-only Unreal Engine reference tree. Uses
# only the stdlib XML parser to pull `If="..."` attribute values -- NOT
# bgview.loader (owned by another worker; condition.py and its tests stay
# dependency-free of the rest of the package).

_CORPUS_ROOT = r"c:\UnrealEngines\Source_5_8\Engine\Build\Graph"
_CORPUS_GLOBS = (
    os.path.join(_CORPUS_ROOT, "Examples", "*.xml"),
    os.path.join(_CORPUS_ROOT, "Tests", "*.xml"),
    os.path.join(_CORPUS_ROOT, "Examples", "FPSBuildGraph", "*.xml"),
)


def _corpus_files():
    files = []
    for pattern in _CORPUS_GLOBS:
        files.extend(sorted(glob.glob(pattern)))
    return files


def _if_conditions(path):
    """Every If="..." attribute value in the XML file at `path`, in
    document order, XML-entity-decoded by the stdlib parser."""
    conditions = []
    for elem in ET.parse(path).getroot().iter():
        value = elem.get("If")
        if value is not None:
            conditions.append(value)
    return conditions


class V25EpicCorpusRegressionTests(unittest.TestCase):
    """V25: the parser must accept every function the ENGINE IMPLEMENTATION
    supports, not just the ones a doc comment happens to list. Ground truth
    is 19 files / 136 If= conditions (R21, R25) across
    Engine/Build/Graph/{Examples,Tests} + Examples/FPSBuildGraph -- measured
    directly against this exact reference tree, not assumed."""

    def test_corpus_root_is_present(self):
        # A missing/renamed reference tree must fail loudly, not let the
        # next test quietly pass on zero files.
        self.assertTrue(
            os.path.isdir(_CORPUS_ROOT),
            f"read-only reference tree not found at {_CORPUS_ROOT!r} -- "
            "cannot run the V25 corpus regression test",
        )

    def test_all_19_corpus_files_found(self):
        files = _corpus_files()
        self.assertEqual(len(files), 19, f"expected 19 corpus files, found {len(files)}: {files}")

    def test_every_epic_if_condition_parses_without_error(self):
        all_conditions = []
        failures = []
        for path in _corpus_files():
            for condition in _if_conditions(path):
                all_conditions.append((path, condition))
                try:
                    parse(condition)
                except CondParseError as exc:
                    failures.append((path, condition, str(exc)))

        # R21 measured 136 If= conditions in this corpus -- a sanity floor
        # so a broken glob/extraction that silently finds ~0 conditions
        # can't masquerade as "zero failures".
        self.assertGreaterEqual(
            len(all_conditions), 130, "found suspiciously few If= conditions -- extraction is probably broken"
        )

        if failures:
            details = "\n".join(f"  {p}: {c!r}\n    -> {e}" for p, c, e in failures)
            self.fail(f"{len(failures)} of {len(all_conditions)} condition(s) failed to parse:\n{details}")


if __name__ == "__main__":
    unittest.main()
