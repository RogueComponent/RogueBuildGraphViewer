"""Tests for bgview.algebra (T8) -- the symbolic condition algebra.

Covers evaluate() (one AST, one concrete env -> bool | UNKNOWN) and
classify() (bounded enumeration over an AST's referenced options' abstract
domains -> "unsat" | "taut" | "contingent" | "unknown"), per the T8 plan
slice: V19 (case-insensitive scalars), V18 (integer comparisons), V10
(Exists is opaque), V10a (HasTrailingSlash is decidable), R25 (Contains /
ContainsItem / Length), sound And/Or short-circuiting, and the enumeration
cap's honest degradation to "unknown" instead of hanging.

Dependency-free of the rest of the package, same as test_condition.py:
only bgview.algebra (this task's own module) and bgview.condition.parse
(explicitly allowed -- CONTRACTS.md/T8 brief).
"""

import unittest

from bgview.algebra import UNKNOWN, Opt, classify, evaluate
from bgview.condition import parse


class ScalarCaseInsensitivityTests(unittest.TestCase):
    """V19: scalar comparison is case-insensitive; true / "true" / "True"
    are one scalar (R11). Epic's own graphs use both the quoted and bare
    spelling interchangeably."""

    def test_quoted_true_case_insensitive(self):
        self.assertIs(evaluate(parse("$(A) == 'True'"), {"A": "true"}), True)

    def test_bare_true_case_insensitive(self):
        self.assertIs(evaluate(parse("$(A) == true"), {"A": "true"}), True)

    def test_mixed_case_value_still_matches(self):
        self.assertIs(evaluate(parse("$(A) == 'true'"), {"A": "TRUE"}), True)

    def test_inequality_also_case_insensitive(self):
        self.assertIs(evaluate(parse("$(A) != 'true'"), {"A": "True"}), False)


class NumericComparisonTests(unittest.TestCase):
    """V18: < <= > >= decide numerically when BOTH sides parse as int, else
    UNKNOWN. == / != stay plain (case-insensitive) string compares -- never
    coerced to numbers."""

    def test_greater_than_true(self):
        self.assertIs(evaluate(parse("$(N) > 5"), {"N": "10"}), True)

    def test_greater_than_false(self):
        self.assertIs(evaluate(parse("$(N) > 5"), {"N": "2"}), False)

    def test_non_numeric_operand_is_unknown(self):
        self.assertIs(evaluate(parse("$(N) > 5"), {"N": "not-a-number"}), UNKNOWN)

    def test_less_equal_and_greater_equal_at_boundary(self):
        self.assertIs(evaluate(parse("$(N) <= 5"), {"N": "5"}), True)
        self.assertIs(evaluate(parse("$(N) >= 5"), {"N": "5"}), True)


class ExistsOpaqueTests(unittest.TestCase):
    """V10: Exists() touches the filesystem -- always UNKNOWN, never
    guessed true or false. A guard containing it must classify as
    "unknown", never "unsat"/"taut" (V10/V14) -- checked explicitly, not
    just by absence of the other two labels."""

    def test_evaluate_exists_is_always_unknown(self):
        self.assertIs(evaluate(parse("Exists('x')"), {}), UNKNOWN)

    def test_bare_exists_classifies_unknown(self):
        result = classify(parse("Exists('x')"), {}, {})
        self.assertEqual(result, "unknown")
        self.assertNotEqual(result, "unsat")
        self.assertNotEqual(result, "taut")

    def test_exists_combined_via_and_stays_unknown_when_not_shortcircuited(self):
        # Left side is a literal `true`, which can NOT short-circuit the
        # And away -- so the opaque Exists() must still surface as
        # "unknown" rather than a confident unsat/taut guess. Contrast with
        # ShortCircuitTests below, where the opposite polarity legitimately
        # decides despite Exists() being textually present.
        result = classify(parse("true And Exists('x')"), {}, {})
        self.assertEqual(result, "unknown")
        self.assertNotEqual(result, "unsat")
        self.assertNotEqual(result, "taut")


class HasTrailingSlashTests(unittest.TestCase):
    """V10a: unlike Exists(), HasTrailingSlash() IS syntactically decidable
    from the argument text alone."""

    def test_forward_slash_true(self):
        self.assertIs(evaluate(parse("HasTrailingSlash('a/')"), {}), True)

    def test_no_slash_false(self):
        self.assertIs(evaluate(parse("HasTrailingSlash('a')"), {}), False)

    def test_backslash_also_counts(self):
        # Routed through a substituted $(X) (rather than a backslash typed
        # directly into a condition-language string literal) so the test
        # itself doesn't have to reason about two layers of escaping at
        # once -- condition strings have none (R11), Python's does.
        self.assertIs(evaluate(parse("HasTrailingSlash($(X))"), {"X": "a\\"}), True)


class StringFunctionTests(unittest.TestCase):
    """R25/B1: Contains / ContainsItem / Length -- the three functions the
    stale BgCondition.cs doc comment omitted from R11's first pass. All
    three are decidable."""

    def test_contains_true(self):
        self.assertIs(evaluate(parse("Contains('abc', 'b')"), {}), True)

    def test_containsitem_true(self):
        self.assertIs(evaluate(parse("ContainsItem('a;b;c', 'b', ';')"), {}), True)

    def test_containsitem_false(self):
        self.assertIs(evaluate(parse("ContainsItem('a;b;c', 'd', ';')"), {}), False)

    def test_length_feeds_numeric_compare(self):
        # Length() returns an int, not a bool -- so "> 3" must work
        # end-to-end through the same numeric path as V18.
        self.assertIs(evaluate(parse("Length('abcd') > 3"), {}), True)


class ClassifyTests(unittest.TestCase):
    """classify(): bounded enumeration over referenced options' abstract
    domains -> unsat / taut / contingent / unknown."""

    def test_emptiness_guard_over_unrestricted_option_is_contingent(self):
        # X is a free (unrestricted) option defaulting to "" -- whether
        # $(X) == '' holds genuinely depends on what X ends up set to.
        opts = {"X": Opt(name="X", default="", restrict=None)}
        self.assertEqual(classify(parse("'$(X)' == ''"), opts, {}), "contingent")

    def test_self_contradiction_is_unsat(self):
        # $(A) cannot equal both 'x' and 'y' at once for ANY value of A --
        # true across the whole abstract domain the enumeration samples,
        # not just one arbitrarily-picked value.
        opts = {"A": Opt(name="A", default="", restrict=None)}
        ast = parse("$(A) == 'x' And $(A) == 'y'")
        self.assertEqual(classify(ast, opts, {}), "unsat")

    def test_literal_equality_is_taut(self):
        self.assertEqual(classify(parse("'a' == 'a'"), {}, {}), "taut")


class ShortCircuitTests(unittest.TestCase):
    """And/Or short-circuit where sound (Kleene 3-valued logic): `False
    And <opaque>` is False and `True Or <opaque>` is True without needing
    to resolve the opaque side at all -- this is what materially improves
    decidability rather than eagerly propagating UNKNOWN."""

    def test_false_and_exists_evaluates_false_not_unknown(self):
        result = evaluate(parse("false And Exists('x')"), {})
        self.assertIs(result, False)
        self.assertIsNot(result, UNKNOWN)

    def test_true_or_exists_evaluates_true_not_unknown(self):
        result = evaluate(parse("true Or Exists('x')"), {})
        self.assertIs(result, True)
        self.assertIsNot(result, UNKNOWN)


class EnumerationCapTests(unittest.TestCase):
    """classify() must degrade to "unknown" rather than hang when an ast
    references more options than the cap allows -- and the size check must
    happen BEFORE looping, so this test itself has to return promptly."""

    def test_many_referenced_options_returns_unknown_not_hang(self):
        # 8 unrestricted options, 3 abstract sample values each (distinct
        # non-empty default + "" + the nonempty sentinel) -> 3**8 = 6561,
        # comfortably past the 4096 cap.
        names = [f"Opt{i}" for i in range(8)]
        text = " And ".join(f"$({n}) == ''" for n in names)
        opts = {n: Opt(name=n, default=f"default{i}", restrict=None) for i, n in enumerate(names)}
        self.assertEqual(classify(parse(text), opts, {}), "unknown")


class SubstitutionTests(unittest.TestCase):
    """Leaf substitution rules from the T8 brief not already pinned by the
    invariant-specific test classes above."""

    def test_name_absent_from_env_is_unknown_not_empty(self):
        # Never silently treat an unresolvable name as "" -- that would
        # manufacture false unsat/taut verdicts in classify().
        self.assertIs(evaluate(parse("$(Undefined) == ''"), {}), UNKNOWN)

    def test_null_valued_builtin_leaves_literal_text_v12b(self):
        # V12(b): a builtin like RootDir (R17) may be null-valued; a name
        # PRESENT in env with value None leaves "$(RootDir)" verbatim
        # rather than substituting "" or raising -- and, critically, must
        # not loop forever re-processing the same now-inert reference.
        ast = parse("$(RootDir) == '$(RootDir)'")
        self.assertIs(evaluate(ast, {"RootDir": None}), True)

    def test_slice_applied_during_substitution(self):
        # R18: $(Name:N) is honoured via lexer.apply_slice as part of
        # evaluate()'s own substitution, not just by the lexer in isolation.
        self.assertIs(evaluate(parse("$(V:3) == 'abc'"), {"V": "abcdef"}), True)


class OptDomainTests(unittest.TestCase):
    """Opt.domain(): a Restrict that is a simple literal alternation
    enumerates exactly those literals; any real regex (or no restriction
    at all) falls back to the {default, empty, nonempty} abstract sample.
    Grounded against every Restrict= actually shipped in the reference
    corpus -- see algebra.py's _LITERAL_BRANCH docstring for the survey."""

    def test_true_false_restrict(self):
        opt = Opt(name="B", default="true", restrict="true|false")
        self.assertEqual(opt.domain(), ["true", "false"])

    def test_general_literal_alternation(self):
        opt = Opt(name="Platform", default="Win64", restrict="Win64|Linux|Mac")
        self.assertEqual(opt.domain(), ["Win64", "Linux", "Mac"])

    def test_regex_restrict_falls_back_to_abstract_sample(self):
        opt = Opt(name="Proj", default="_Unknown_", restrict=".+")
        self.assertEqual(opt.domain(), ["_Unknown_", "", "\x01nonempty"])

    def test_no_restriction_falls_back_to_abstract_sample(self):
        opt = Opt(name="X", default="", restrict=None)
        self.assertEqual(opt.domain(), ["", "\x01nonempty"])  # default "" dedupes away

    def test_empty_restrict_string_treated_as_no_restriction(self):
        # Real corpus usage: Restrict="" is common (e.g.
        # Examples/FPSBuildGraph/DeployToEpicGames.xml).
        opt = Opt(name="X", default="foo", restrict="")
        self.assertEqual(opt.domain(), ["foo", "", "\x01nonempty"])

    def test_from_dict_adapts_evaluator_shape(self):
        opt = Opt.from_dict({"name": "B", "default": "true", "restrict": "true|false"})
        self.assertEqual(opt, Opt(name="B", default="true", restrict="true|false"))


if __name__ == "__main__":
    unittest.main()
