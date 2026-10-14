"""bgview.algebra -- symbolic condition algebra (T8).

Evaluates and classifies `If="..."` condition ASTs (bgview.condition.parse
output) over an ABSTRACTED string domain -- not a full SAT/SMT solver, and
deliberately not one (user D3, SPEC §C: "Condition algebra symbolic w/
ABSTRACT string domain ... ⊥ external SAT dep"). The abstraction is what
makes this tractable with stdlib-only, hand-rolled logic: R21 measured that
~86% of Epic's 136 real `If=` conditions are decidable purely from
{empty, nonempty} ∪ literals ∪ int -- emptiness tests, literal compares,
bare bools, and numeric compares dominate; only opaque filesystem probes
(`Exists`) and a handful of compound expressions need the UNKNOWN escape
hatch.

Two entry points:

  evaluate(ast, env)              -- run one AST against ONE concrete env.
                                      bool | UNKNOWN.
  classify(ast, opts, base_env)   -- bounded enumeration over every OPTION
                                      actually referenced in the ast, per
                                      its abstract domain. "unsat" | "taut"
                                      | "contingent" | "unknown".

Dependency-free within the package except for the two modules this task is
explicitly allowed to build on: bgview.condition (the AST + parser -- T7)
and bgview.lexer ($(...) ref scanning + ':N' slicing -- T2). Nothing here
imports evaluator.py/model.py/detectors.py/loader.py/schema.py, and nothing
in those may import this module's Opt cycle-breaker back in the other
direction (see the CONTRACTS.md ruling reproduced on the Opt class below).
"""

from __future__ import annotations

import dataclasses
import itertools
import re

from bgview.condition import And, Call, Cmp, Ident, Not, Or, Str
from bgview import lexer

# --------------------------------------------------------------------------
# UNKNOWN sentinel
# --------------------------------------------------------------------------


class _UnknownType:
    """Singleton sentinel for "opaque -- cannot be decided symbolically".

    Never assume True, never assume False (V10). `__bool__` raises instead
    of silently picking a truthiness so a caller that forgets an `is
    UNKNOWN` check fails loudly at the mistake site instead of quietly
    treating an opaque guard as satisfied/unsatisfied -- exactly the
    "confidently-wrong finding" V10's docstring warns against.
    """

    def __repr__(self) -> str:
        return "UNKNOWN"

    def __bool__(self):
        raise TypeError(
            "UNKNOWN has no truthiness -- compare with `is UNKNOWN` explicitly"
        )


UNKNOWN = _UnknownType()


# --------------------------------------------------------------------------
# Opt -- one <Option>. Owned here per the orchestrator's Opt-cycle ruling
# (CONTRACTS.md): evaluator.py returns plain dicts (EvalResult.options:
# dict[str, dict] with keys {"name","default","restrict"}); algebra.py owns
# the Opt type and its domain() sampling logic; detectors.py (which imports
# both evaluator.py and algebra.py) adapts via Opt.from_dict. evaluator.py
# must NOT import algebra.py.
# --------------------------------------------------------------------------

# A Restrict value that, character-for-character, is nothing but one or more
# '|'-separated literal branches -- no regex metacharacters at all. Grounded
# against every Restrict= actually shipped in the reference corpus
# (Engine/Build/Graph/**/*.xml): literal alternations really do look like
# "true|false", "Option1|Option2|Option3", "Win64|Linux|Mac",
# "Development|Debug|Shipping" -- plain words, digits, underscore, hyphen,
# space. Every OTHER real Restrict= is an actual regex (".+", ".*", "\d*",
# "[^ ]*", "[a-zA-Z]+", "(?://.*)?", "^[0-9]{1,4}$", ...) and every one of
# those contains a character outside this allow-list, so it correctly falls
# through to the abstract-sample branch below rather than being misread as
# a literal. Restrict values are never pre-anchored/pre-parenthesized by the
# script author (BgScriptReader.cs wraps them in "^(...)$"" itself at match
# time), so no anchor-stripping is needed here.
_LITERAL_BRANCH = re.compile(r"^[A-Za-z0-9_\- ]+$")

# Sentinel "definitely nonempty, definitely not a realistic literal" sample
# value for the abstract {empty, nonempty} domain. Starts with a raw SOH
# control character specifically so it can never collide with a real
# option value (XML 1.0 disallows unescaped control chars in attribute
# content, so no shipped script's DefaultValue can ever equal this).
_NONEMPTY_SAMPLE = "\x01nonempty"


def _literal_alternation_domain(restrict: str) -> list[str] | None:
    """`restrict` split on '|', if -- and only if -- every branch is plain
    literal text (letters/digits/underscore/hyphen/space, nothing a regex
    engine would treat specially). Returns None for anything else (a real
    regex, or blank/absent), signalling "fall back to abstract sampling"."""
    if not restrict:
        return None
    branches = restrict.split("|")
    if any(not _LITERAL_BRANCH.match(b) for b in branches):
        return None
    return branches


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


@dataclasses.dataclass(frozen=True)
class Opt:
    """One `<Option>` declaration, as needed for symbolic enumeration."""

    name: str
    default: str
    restrict: str | None

    def domain(self) -> list[str]:
        """The finite set of abstract sample values classify() enumerates
        this option over. A `Restrict` that is a simple literal alternation
        (`true|false`, `a|b|c`, ...) contributes those literals exactly --
        the option can ONLY ever hold one of them, so there is nothing to
        abstract. Any other Restrict (a real regex) or none at all falls
        back to the {default, empty, nonempty} sample the spec calls for:
        the actual default (in case a condition compares against it
        specifically), the empty string (emptiness tests are 37/136 of the
        corpus, R21), and one sentinel standing in for "some other,
        arbitrary nonempty value"."""
        literals = _literal_alternation_domain(self.restrict) if self.restrict else None
        if literals is not None:
            return literals
        return _dedupe([self.default, "", _NONEMPTY_SAMPLE])

    @classmethod
    def from_dict(cls, d: dict) -> "Opt":
        """evaluator.py hands back plain `{"name","default","restrict"}`
        dicts (EvalResult.options); this adapts one into an Opt."""
        return cls(name=d["name"], default=d.get("default", ""), restrict=d.get("restrict"))


# --------------------------------------------------------------------------
# evaluate() -- one AST, one concrete env
# --------------------------------------------------------------------------

# Scalar values flowing through _eval are Python bool | int | str | UNKNOWN:
#   bool  -- result of a comparison / And / Or / Not / HasTrailingSlash /
#            Contains / ContainsItem
#   int   -- result of Length(); also whatever an Ident/Str leaf's
#            substituted text parses as, when a numeric compare needs it
#   str   -- a leaf (Ident/Str) after $(...) substitution
#   UNKNOWN -- substitution hit a name absent from env, or the value passed
#            through Exists() (always opaque, V10)


def _as_str(value) -> str:
    """Canonical string form used for case-insensitive equality (V19) and
    truthiness. NB bool must be checked before int -- Python's bool is an
    int subclass."""
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, int):
        return str(value)
    return value


def _try_int(value) -> int | None:
    """V18: numeric-compare operand. An already-int scalar (a Length()
    result) is used as-is; a string is accepted only if it parses cleanly
    as an integer. bool is deliberately excluded even though it is
    technically an int subclass -- a bare true/false is never "numeric" in
    a BuildGraph condition."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_bool(value):
    """Engine truthiness: a scalar is true iff its string form equals
    "true" case-insensitively (BgCondition's actual scalar->bool
    conversion) -- NOT Python/C-style nonzero-is-true. Applying `_as_str`
    first makes this uniform across bool/int/str inputs."""
    if value is UNKNOWN:
        return UNKNOWN
    return _as_str(value).casefold() == "true"


def _substitute(text: str, env: dict):
    """Resolve every "$(...)" reference in `text` against `env`, honouring
    the ':N' slice (R18/V12a). Mirrors the engine's own mutate-and-rescan
    expansion order exactly as documented on lexer.iter_refs: repeatedly
    take the LAST (innermost/rightmost-starting) ref, resolve it, splice
    the result back in, and re-scan the mutated string -- this is what
    correctly resolves "$(Outer$(Inner))" nesting (Inner before Outer)
    without relying on any position captured before a prior splice shifted
    it.

    A name absent from `env` makes the WHOLE leaf UNKNOWN (never silently
    treated as empty -- that would manufacture false unsat/taut verdicts
    downstream in classify()).

    V12(b): a name PRESENT in `env` with value None (e.g. the RootDir
    builtin, which may be null) is left as the literal "$(Name...)" text --
    no warning, no substitution -- exactly like the real expansion engine's
    "found but null" outcome. Such refs are tracked in `inert` so they are
    never re-picked: splicing a ref's own raw text back over itself is a
    textual no-op, and without this guard the rescan loop would pick the
    very same ref forever.
    """
    s = text
    inert: set[str] = set()
    while True:
        refs = [r for r in lexer.iter_refs(s) if r.raw not in inert]
        if not refs:
            return s
        ref = refs[-1]
        if ref.name not in env:
            return UNKNOWN
        value = env[ref.name]
        if value is None:
            inert.add(ref.raw)
            continue
        resolved = lexer.apply_slice(value, ref.slice_n)
        s = s[: ref.start] + resolved + s[ref.end :]


def _eval(node, env):
    """Recursively evaluate any condition.py AST node to a bool | int | str
    | UNKNOWN scalar. `evaluate()` below is the public entry point that
    coerces the final result down to bool | UNKNOWN."""
    if isinstance(node, Or):
        return _eval_or(node, env)
    if isinstance(node, And):
        return _eval_and(node, env)
    if isinstance(node, Cmp):
        return _eval_cmp(node, env)
    if isinstance(node, Not):
        operand = _to_bool(_eval(node.operand, env))
        return UNKNOWN if operand is UNKNOWN else not operand
    if isinstance(node, Call):
        return _eval_call(node, env)
    if isinstance(node, (Str, Ident)):
        return _substitute(node.value, env)
    raise TypeError(f"unrecognised condition AST node: {type(node).__name__}")


def _eval_and(node, env):
    """Kleene (strong 3-valued) AND: `False And <anything>` is False without
    even evaluating the right side -- this is the "short-circuit where
    sound" the T8 brief calls out (`false And Exists('x')` must evaluate
    False, never touch the opaque Exists call at all)."""
    left = _to_bool(_eval(node.left, env))
    if left is False:
        return False
    right = _to_bool(_eval(node.right, env))
    if left is True:
        return right
    # left is UNKNOWN: False on the right still forces False (symmetric to
    # the left-False case above); otherwise the AND stays UNKNOWN.
    return False if right is False else UNKNOWN


def _eval_or(node, env):
    """Kleene OR, mirroring _eval_and: `True Or <anything>` short-circuits
    to True without evaluating the right side."""
    left = _to_bool(_eval(node.left, env))
    if left is True:
        return True
    right = _to_bool(_eval(node.right, env))
    if left is False:
        return right
    return True if right is True else UNKNOWN


def _eval_cmp(node, env):
    left = _eval(node.left, env)
    right = _eval(node.right, env)
    if left is UNKNOWN or right is UNKNOWN:
        return UNKNOWN
    op = node.op
    if op in ("==", "!="):
        equal = _as_str(left).casefold() == _as_str(right).casefold()
        return equal if op == "==" else not equal
    li, ri = _try_int(left), _try_int(right)
    if li is None or ri is None:
        return UNKNOWN
    if op == "<":
        return li < ri
    if op == "<=":
        return li <= ri
    if op == ">":
        return li > ri
    if op == ">=":
        return li >= ri
    raise TypeError(f"unrecognised comparison operator: {op!r}")  # pragma: no cover


def _eval_call(node, env):
    name = node.name

    if name == "Exists":
        # V10: touches the filesystem, opaque no matter what the argument
        # is -- never even evaluate it, let alone guess true/false.
        return UNKNOWN

    if name == "HasTrailingSlash":
        # V10a: syntactically decidable, unlike Exists.
        arg = _eval(node.args[0], env)
        if arg is UNKNOWN:
            return UNKNOWN
        s = _as_str(arg)
        return s.endswith("/") or s.endswith("\\")

    if name == "Length":
        arg = _eval(node.args[0], env)
        if arg is UNKNOWN:
            return UNKNOWN
        return len(_as_str(arg))  # int -- feeds V18 numeric compare

    if name == "Contains":
        hay = _eval(node.args[0], env)
        if hay is UNKNOWN:
            return UNKNOWN
        needle = _eval(node.args[1], env)
        if needle is UNKNOWN:
            return UNKNOWN
        return _as_str(needle) in _as_str(hay)

    if name == "ContainsItem":
        hay = _eval(node.args[0], env)
        if hay is UNKNOWN:
            return UNKNOWN
        needle = _eval(node.args[1], env)
        if needle is UNKNOWN:
            return UNKNOWN
        sep = _eval(node.args[2], env)
        if sep is UNKNOWN:
            return UNKNOWN
        hay_s, needle_s, sep_s = _as_str(hay), _as_str(needle), _as_str(sep)
        # ponytail: an empty separator would make str.split raise ValueError
        # in Python (unlike a hypothetical C# Split, which tolerates it).
        # No real corpus usage passes a literal empty separator to
        # ContainsItem; treat it as "no delimiter found" (whole haystack is
        # the one item) rather than crash. Upgrade path: if a real script
        # is ever found relying on different empty-separator semantics,
        # special-case it here against the engine's actual behaviour.
        items = hay_s.split(sep_s) if sep_s else [hay_s]
        return needle_s in items

    raise TypeError(f"unrecognised Call name: {name!r}")  # pragma: no cover -- parser enforces the 5 names


def evaluate(ast, env: dict):
    """Evaluate `ast` (a bgview.condition.parse() result) against one
    concrete `env` mapping property name -> value (value may be None for a
    null-valued builtin, e.g. RootDir). Returns a Python bool, or the
    UNKNOWN sentinel when the result cannot be decided (an unresolvable
    name, or an opaque Exists() that the short-circuit couldn't eliminate).
    """
    return _to_bool(_eval(ast, env))


# --------------------------------------------------------------------------
# classify() -- bounded enumeration over referenced options' abstract domains
# --------------------------------------------------------------------------

# "e.g. 4096" per the T8 brief: real conditions reference 1-3 options (the
# corpus's compound And/Or share is only 4/136, R21), so this cap is never
# hit on real input -- it exists purely so a pathological/adversarial
# condition referencing many options can't make classify() hang.
_ENUM_CAP = 4096


def _referenced_ref_names(node) -> set[str]:
    """Every `$(Name...)` base name (':N' slice already stripped by
    lexer.iter_refs) that textually appears anywhere in `node`'s leaves.
    Deliberately over-collects (includes names that will turn out not to be
    options at all, and the synthetic composite name of an unresolved
    nested ref like "Outer$(Inner)") -- classify() intersects this against
    the actual `opts` keys, so the extra names are simply discarded there
    rather than needing to be filtered twice."""
    if isinstance(node, (Or, And)):
        return _referenced_ref_names(node.left) | _referenced_ref_names(node.right)
    if isinstance(node, Cmp):
        return _referenced_ref_names(node.left) | _referenced_ref_names(node.right)
    if isinstance(node, Not):
        return _referenced_ref_names(node.operand)
    if isinstance(node, Call):
        names: set[str] = set()
        for arg in node.args:
            names |= _referenced_ref_names(arg)
        return names
    if isinstance(node, (Str, Ident)):
        return {ref.name for ref in lexer.iter_refs(node.value)}
    raise TypeError(f"unrecognised condition AST node: {type(node).__name__}")  # pragma: no cover


def classify(ast, opts: dict, base_env: dict) -> str:
    """Bounded-enumeration satisfiability classification of `ast`.

    Collects only the option names the ast actually references (never the
    whole `opts` set -- real conditions touch 1-3 options, R21), enumerates
    the cartesian product of their abstract domains (Opt.domain()) overlaid
    on `base_env`, and evaluates the ast against every combination:

      - any combination UNKNOWN         -> "unknown"  (V10/V14: an opaque
                                            guard is neither unsat nor taut)
      - every combination True          -> "taut"
      - every combination False         -> "unsat"
      - a mix of True and False         -> "contingent"
      - product size exceeds the cap    -> "unknown"  (honest degradation,
                                            checked BEFORE enumerating so a
                                            pathological ast can't hang)
    """
    referenced = sorted(_referenced_ref_names(ast) & opts.keys())
    domains = [opts[name].domain() for name in referenced]

    total = 1
    for d in domains:
        total *= max(len(d), 1)
    if total > _ENUM_CAP:
        return "unknown"

    saw_true = False
    saw_false = False
    for combo in itertools.product(*domains):
        env = dict(base_env)
        env.update(zip(referenced, combo))
        outcome = evaluate(ast, env)
        if outcome is UNKNOWN:
            return "unknown"
        if outcome:
            saw_true = True
        else:
            saw_false = True

    if saw_true and saw_false:
        return "contingent"
    if saw_true:
        return "taut"
    return "unsat"
