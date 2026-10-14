"""bgview.evaluator -- property/option/envvar expansion engine (T3) +
control-flow walk (T4).

These two tasks are implemented together because they are the same walk:
BuildGraph reads a script top-to-bottom, expanding `$(...)` references
against a scope stack as it goes (T3), while `<ForEach>`/`<Switch>`/`<Do>`/
`<Macro>`+`<Expand>`/`<Include>` (T4) decide WHAT gets walked and in what
order. Splitting them into two passes would mean re-deriving the same
element order twice.

Ground truth for both is `BgScriptReader.cs` (Engine/Source/Programs/
AutomationTool/BuildGraph/), read directly for this task: `ExpandProperties`
(:2501), `TryGetPropertyValue`/`SetPropertyValue` (:585,634), `ReadForEachAsync`
(:1696), `ReadExpandAsync` (:1738), `ReadSwitchAsync` (:1679), `ReadNodeBodyAsync`
(:1616, its `default:` case dispatches to `ReadTaskAsync` for ANY tag it
doesn't recognize structurally -- this is why unknown-vs-task classification
below is schema-driven, not a hardcoded task list).

Key design decisions, so a later reader doesn't have to re-derive them:

* **Every visited element gets exactly one `Resolved` entry** (attrs
  expanded, `raw_if` captured, `agent`/`node`/`expand_depth` stamped),
  including structural wrappers like `<Do>`/`<Switch>`'s branches/`<ForEach>`/
  `<Expand>`/`<Include>`/`<Macro>`/`<Extend>` themselves. This is what lets a
  later detector (D12) find and reason about EVERY `If=` in the script by
  scanning `EvalResult.resolved`, not just leaf task attributes -- R21's
  "136 `If=` in Epic corpus" census spans exactly these element kinds.
  The synthetic `<BuildGraph>` root itself is the one exception (never
  visited as content, matching `ReadGraphBodyAsync(document.DocumentElement)`
  which iterates the root's children but never reads the root itself).

* **`If=` is never evaluated here, by explicit instruction.** Every
  structural branch (`<Do>`, every `<Switch>` child, every `<ForEach>`
  iteration) is walked unconditionally -- this tool analyses the UNION of
  possible executions, not one concrete run; a later task narrows by
  option-set. `raw_if` is still captured (unexpanded) on every element that
  has one, so that later narrowing has something to work with.

* **Unknown-element classification (V9/D14) is schema-driven, not a
  hardcoded task list.** R14's 22 names are the fixed "structural" surface
  (control flow + name-defining directives); anything else is checked
  against `schema.known_element(tag)` (Schema.xsd enumerates all ~70 real
  task classes). This mirrors `ReadNodeBodyAsync`'s `default: ReadTaskAsync`
  fallthrough, which accepts ANY tag as a task at read-time (real engine
  task-name validation happens later, via reflection, which this tool has no
  equivalent of -- Schema.xsd is the closest static source of truth we have).
  One accepted imprecision: classification is tag-name-only, not
  position-sensitive, so e.g. a `<Compile>` element appearing directly under
  `<BuildGraph>` (invalid in the real engine) would be accepted here rather
  than flagged -- a full grammar/position checker is out of scope for T3/T4.

* **`Opt` is declared locally, not imported from `bgview.algebra`.**
  `bgview/algebra.py` (T8, another worker's file) is off-limits per the task
  brief, AND does not exist yet in this tree. CONTRACTS.md pins
  `algebra.Opt` as `@dataclass(frozen=True) class Opt: name, default,
  restrict; def domain(self)`. The `Opt` below is a structural twin of the
  DATA shape (same three fields, same frozen-ness) with no `domain()` method
  -- that method's logic ("'true|false' restrict -> ['true','false']; else
  sampled") is algebra's job per CONTRACTS, not T3's. Whoever wires T9's
  detectors.py (which needs both `EvalResult.options` from here and
  `algebra.Opt`/`classify` from T8) will need to either accept this shape
  directly or adapt it -- flagged prominently for the orchestrator.

* **Regex/StringOp are treated as generic leaves.** Both are in R14's
  structural inventory (so they never trip D14), and their OWN attributes
  are expanded like any other element's, but their property-DEFINING effect
  (Regex capture-group assignment, StringOp Output=) is not modeled --
  that would mean re-implementing .NET regex/string-op execution, which is
  task-semantics territory, not property-engine/control-flow territory.
  Checked against the full corpus this tool targets (`Engine/Build/Graph/
  {Examples,Tests}`): neither `<Regex` nor `<StringOp` appears ANYWHERE in
  it, so this costs nothing in practice for V5's FP budget today.

* **Multiline `<Property>` text-body values (`<Property Name="X">body
  text</Property>`, no `Value=` attribute) are not modeled.** `bgview.loader.Elem`
  (T1, stable, not modifiable by this task) captures `attrib`/`children`
  but no text content at all -- there is no field to read a text body from.
  Only the `Value=` attribute is read (defaulting to "" when absent, same
  as the engine's `ReadAttribute` for a missing attribute). Upgrade path:
  add a `.text` field to `Elem` (T1's owner) if a future corpus needs this.
"""

from __future__ import annotations

import dataclasses
import pathlib
from collections.abc import Callable

from bgview.findings import Finding, Severity
from bgview.lexer import apply_slice, iter_refs, split_list
from bgview.loader import BgError, Elem, load
from bgview.schema import Schema

# ---------------------------------------------------------------------------
# V22/R17: the 19 engine built-in properties, pre-loaded before anything else
# so D1 never fires on them. Values are plausible static stand-ins (this is
# static analysis of SOURCE -- §C: "⊥ require UE install, ⊥ require script to
# be runnable" -- there is no real P4 branch/changelist/host to query).
# RootDir is the one deliberate exception: the engine genuinely sets it to
# `null` when preprocessing (BuildGraph.cs:301-308), and V12 case (b) exists
# specifically to make that survivable rather than a silent corruption bug.
# ---------------------------------------------------------------------------
BUILTINS: dict[str, str | None] = {
    "Branch": "Unknown",
    "Depot": "Unknown",
    "EscapedBranch": "Unknown",
    "Change": "0",
    "CodeChange": "0",
    "IsBuildMachine": "false",
    "HostPlatform": "Win64",
    "HostArchitecture": "X64",
    "RestrictedFolderNames": "NotForLicensees;NoRedist;CarefullyRedist",
    "RestrictedFolderFilter": ".../NotForLicensees/...;.../NoRedist/...;.../CarefullyRedist/...",
    "DataDrivenPlatforms": "Windows;Android;IOS;Mac;Linux",
    "RootDir": None,  # engine: null when preprocessing -- V12(b) is why this matters
    "EngineMajorVersion": "5",
    "EngineMinorVersion": "8",
    "EnginePatchVersion": "0",
    "EngineCompatibleChange": "0",
    # NOTE: ProjectFile / ProjectName / ProjectDir are deliberately NOT here.
    # BuildGraph.cs:325-333 sets them ONLY when a project is supplied, unlike
    # the 16 unconditional built-ins above. Defining them unconditionally was
    # a real modelling bug (§B.5): combined with R26 (an <Option> whose name
    # already holds a non-null value is silently NOT registered), it meant a
    # script's own `<Option Name="ProjectName" DefaultValue="_Unknown_"/>` was
    # skipped, so names built from $(ProjectName) diverged from the names the
    # engine would produce -- manufacturing phantom unresolvable references.
    # A real engine run is self-consistent either way; our hybrid was the one
    # configuration that was not. Supply them with --project.
}
# R17 counts 19 engine built-ins, but only 16 are UNCONDITIONAL. The other
# three (ProjectFile/ProjectName/ProjectDir) are set only when a project is
# supplied (BuildGraph.cs:325-333) and arrive via `project_properties()` /
# `--project` -- see §B.5 for why defining them unconditionally was a real bug.
# This guard is deliberately kept: it caught exactly that change.
assert len(BUILTINS) == 16, f"expected 16 unconditional built-ins, got {len(BUILTINS)}"

# R15/T4: cap on <Expand> recursion depth, so a self-referential (or mutually
# recursive) macro pair produces a finding instead of a Python RecursionError.
_MAX_EXPAND_DEPTH = 32

# R14: element kinds that are structural per the master inventory but need
# no more than generic attribute expansion + one Resolved entry (no child
# walk, no name-binding side effect). See module docstring re: Regex/StringOp.
_LEAF_STRUCTURAL = frozenset(
    {
        "Regex",
        "StringOp",
        "Aggregate",
        "Artifact",
        "Report",
        "Badge",
        "Label",
        "Trace",
        "Warning",
        "Error",
    }
)


@dataclasses.dataclass(frozen=True)
class Opt:
    """One `<Option>` declaration. See module docstring: structural twin of
    `bgview.algebra.Opt` (T8), duplicated rather than imported because that
    module is both off-limits and (as of this writing) does not exist yet."""

    name: str
    default: str
    restrict: str | None


@dataclasses.dataclass
class Resolved:
    elem: Elem
    attrs: dict[str, str]  # every attribute of `elem`, fully expanded (V12)
    agent: str | None  # name of nearest enclosing <Agent>, if any
    node: str | None  # name of nearest enclosing <Node>, if any
    raw_if: str | None  # UNEXPANDED If= text, for a later task's D12
    expand_depth: int  # >0 for elements produced by walking inside <Expand>


@dataclasses.dataclass
class EvalResult:
    resolved: list[Resolved]  # V23: post-Expand/ForEach/Include EXECUTION order
    findings: list[Finding]
    options: dict[str, Opt]
    prop_defs: list[tuple[str, Elem, int]]  # (name, elem, index into `resolved`)
    prop_reads: list[tuple[str, Elem, int]]
    # file path (exactly as it appears in `Elem.file`) -> that file's decoded
    # text, for every file this evaluation actually READ: the entry script
    # plus each `<Include>`d one. Populated straight off `Elem.source_text`,
    # never by re-reading the path, so the text is provably the text every
    # `file:line` in `findings` was computed against. Defaulted so a
    # hand-built EvalResult in a test stays valid.
    sources: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class _MacroDef:
    """Registered `<Macro>` (+ any `<Extend>`s of it). `containers` holds the
    `<Macro>` element itself followed by each `<Extend>` element that named
    it, in declaration order -- mirrors `BgScriptMacro.Elements`
    (BgScriptReader.cs:213,240): at expansion time the macro's body is every
    child of every container, walked in that order."""

    name: str
    arg_order: list[str] = dataclasses.field(default_factory=list)  # required first, then optional
    num_required: int = 0
    containers: list[Elem] = dataclasses.field(default_factory=list)


class _Evaluator:
    """Holds all mutable state for one `evaluate()` call. Not part of the
    public module surface -- `evaluate()` below is the only entry point."""

    def __init__(self, schema: Schema, overrides: dict[str, str], loader_fn: Callable[..., Elem]) -> None:
        self._schema = schema
        self._overrides = overrides
        self._loader = loader_fn

        # V11/R6: scope stack. One initial scope holding a COPY of BUILTINS
        # (never the module-level dict itself, so mutation from one
        # evaluate() call can never leak into another) -- matches the real
        # engine, which also seeds its one-and-only global scope with the
        # built-in table before reading a single script element
        # (BgScriptReader.cs:384-392: EnterScope() once, then
        # SetPropertyValue for every default property, all landing in that
        # same scope 0 that top-level <Property>/<Option> reads later share).
        self._scopes: list[dict[str, str | None]] = [dict(BUILTINS)]
        # Parallel to `_scopes`, one set per scope: names written in some
        # CHILD of that scope (BgScriptReader.cs:313,566). Drives D21.
        self._shadow: list[set[str]] = [set()]
        self._agent_stack: list[str] = []
        self._node_stack: list[str] = []
        self._include_stack: list[str] = []  # resolved absolute paths, ancestor chain only
        self._expand_depth = 0
        self._macros: dict[str, _MacroDef] = {}

        self.resolved: list[Resolved] = []
        self.findings: list[Finding] = []
        self.options: dict[str, Opt] = {}
        self.prop_defs: list[tuple[str, Elem, int]] = []
        self.prop_reads: list[tuple[str, Elem, int]] = []
        self.sources: dict[str, str] = {}

    def _record_source(self, root: Elem) -> None:
        """Remember a just-loaded file's own text, keyed on the same path
        string its elements carry in `Elem.file`. First one wins: a diamond
        include reads the same file twice and both reads are the same text,
        so overwriting would only churn."""
        if root.file and root.file not in self.sources:
            self.sources[root.file] = root.source_text

    # -- scope stack (V11/R5/R6) --------------------------------------

    def _enter_scope(self) -> None:
        self._scopes.append({})
        # EnterScope pushes onto BOTH stacks (BgScriptReader.cs:563-567).
        self._shadow.append(set())

    def _leave_scope(self) -> None:
        self._scopes.pop()
        self._shadow.pop()

    def _lookup(self, name: str) -> tuple[bool, str | None]:
        """R6: innermost-first, first hit wins. Returns (found, value) --
        `found=True, value=None` is the V12(b) "defined but null" case."""
        for scope in reversed(self._scopes):
            if name in scope:
                return True, scope[name]
        return False, None

    def _assign(self, name: str, value: str | None, elem: Elem | None = None) -> None:
        """R6/SetPropertyValue (BgScriptReader.cs:585): target the OUTERMOST
        scope that already holds `name`; else the current (innermost) scope.
        `CreateInParentScope` is not modeled (not cited by any V/R row in
        scope here; the default-false engine behavior this reproduces is
        what the overwhelming majority of real `<Property>` writes use).

        Also maintains the engine's `_shadowProperties` stack and emits D21
        (R44). Writing a property in an INNER scope marks that name in every
        OUTER scope (:619-623); a later write to the name in one of those
        outer scopes is then a hard engine error (:615). `elem` is the source
        element to blame; `None` suppresses the check, which is what the
        built-in seeding pass wants (the engine seeds via
        `SetPropertyValue(null!, ...)` at :391, with no element either).
        """
        idx = 0
        while idx < len(self._scopes) - 1 and name not in self._scopes[idx]:
            idx += 1

        folded = name.lower()  # :566 -- the shadow sets are OrdinalIgnoreCase
        if elem is not None and folded in self._shadow[idx]:
            self._finding(
                elem, "D21", Severity.ERROR,
                f"Property '{name}' was already used in a child scope; the engine "
                f"refuses this. Move the definition before the earlier use if they "
                f"are meant to share scope, or use a different name "
                f"(engine reports an error)",
            )
            # The engine returns WITHOUT assigning here. bgview assigns anyway
            # and keeps going: a script in this state never builds at all, so
            # there is no "real" downstream state to be faithful to, and
            # leaving the name unbound would manufacture cascading D1
            # "not defined" findings that say nothing new.
        else:
            for outer in range(idx):
                self._shadow[outer].add(folded)
        self._scopes[idx][name] = value

    # -- misc helpers ----------------------------------------------------

    def _current_node(self) -> str | None:
        return self._node_stack[-1] if self._node_stack else None

    def _finding(self, elem: Elem, detector: str, severity: Severity, message: str) -> None:
        self.findings.append(
            Finding(
                file=elem.file,
                line=elem.line,
                severity=severity,
                detector=detector,
                message=message,
                node=self._current_node(),
            )
        )

    # -- expansion (V12/V12a) ------------------------------------------

    def _expand(self, elem: Elem, text: str, resolved_index: int) -> str:
        """Expand every `$(...)` in `text` against the scope stack as it
        stands right now (V11: element-read-time, top-to-bottom).

        Mirrors `ExpandProperties`'s right-to-left mutate-and-rescan
        (BgScriptReader.cs:2501): repeatedly resolve the rightmost/innermost
        unresolved reference (nested refs resolve inside-out this way).
        `search_end` reproduces the engine's `LastIndexOf(text, idx, idx+1)`
        bound -- once an occurrence is left untouched (V12 outcome b), the
        next search is restricted to strictly BEFORE its start, so the same
        un-substituted occurrence is never re-selected (which would either
        spin forever, in the naive version of this loop, or -- the design
        actually used below -- double-count its `prop_reads` entry and, for
        a malformed slice, double-report its finding).
        """
        result = text
        search_end = len(result)
        while True:
            refs = [r for r in iter_refs(result) if r.start < search_end]
            if not refs:
                return result
            ref = refs[-1]

            if "$(" in ref.name:
                # Name still holds an unresolved nested ref. iter_refs always
                # sorts innermost-last, so refs[-1] should never have this
                # shape; guard defensively (skip past, untouched) rather
                # than treat a dynamic partial name as a lookup key.
                search_end = ref.start
                continue

            self.prop_reads.append((ref.name, elem, resolved_index))
            found, value = self._lookup(ref.name)

            if ref.malformed:
                # V12a: R18's `Int32.Parse` would throw here; we survive by
                # reporting once and substituting best-effort (unsliced) so
                # this occurrence is always consumed -- never re-visited,
                # so never double-reported.
                self._finding(
                    elem,
                    "D1",
                    Severity.WARN,
                    f"Property reference '{ref.raw}' has a malformed ':N' slice",
                )
                replacement = value if (found and value is not None) else ""
                result = result[: ref.start] + replacement + result[ref.end :]
                search_end = len(result)
                continue

            if not found:
                # V12 outcome (a).
                self._finding(elem, "D1", Severity.WARN, f"Property '{ref.name}' is not defined")
                result = result[: ref.start] + "" + result[ref.end :]
                search_end = len(result)
                continue

            if value is None:
                # V12 outcome (b): defined but null -- NO finding, and the
                # literal "$(Name)" text is left verbatim in the output.
                search_end = ref.start
                continue

            # V12 outcome (c).
            replacement = apply_slice(value, ref.slice_n)
            result = result[: ref.start] + replacement + result[ref.end :]
            search_end = len(result)

    # -- generic element handling ------------------------------------------

    def _emit_leaf(self, elem: Elem) -> Resolved:
        """Expand every attribute of `elem` and record one `Resolved` entry
        for it. Used both for genuine leaves (tasks, Aggregate, ...) and as
        the first step of every structural handler below (V23: the entry is
        appended in EXECUTION order, at the moment we visit this element)."""
        idx = len(self.resolved)
        attrs = {k: self._expand(elem, v, idx) for k, v in elem.attrib.items()}
        resolved = Resolved(
            elem=elem,
            attrs=attrs,
            agent=self._agent_stack[-1] if self._agent_stack else None,
            node=self._node_stack[-1] if self._node_stack else None,
            raw_if=elem.attrib.get("If"),
            expand_depth=self._expand_depth,
        )
        self.resolved.append(resolved)
        return resolved

    def _walk_body(self, children: list[Elem]) -> None:
        for child in children:
            self._visit(child)

    def _visit(self, elem: Elem) -> None:
        tag = elem.tag
        if tag == "Include":
            self._handle_include(elem)
        elif tag == "Option":
            self._handle_option(elem)
        elif tag == "Property":
            self._handle_property(elem)
        elif tag == "EnvVar":
            self._handle_envvar(elem)
        elif tag == "Macro":
            self._handle_macro(elem)
        elif tag == "Extend":
            self._handle_extend(elem)
        elif tag == "Agent":
            self._handle_agent(elem)
        elif tag == "Node":
            self._handle_node(elem)
        elif tag == "Do":
            self._handle_do(elem)
        elif tag == "Switch":
            self._handle_switch(elem)
        elif tag == "ForEach":
            self._handle_foreach(elem)
        elif tag == "Expand":
            self._handle_expand(elem)
        elif tag in _LEAF_STRUCTURAL:
            self._emit_leaf(elem)
        elif self._schema.known_element(tag):
            # Not one of R14's 22 structural kinds, but Schema.xsd knows it
            # -- a real task element (Compile, Copy, Tag, SetVersion, ...).
            self._emit_leaf(elem)
        else:
            # V9: loud finding, never a silent skip. Children of an unknown
            # element are not walked -- their shape/meaning is unknown, so
            # there is nothing safe to recurse into.
            self._finding(elem, "D14", Severity.WARN, f"Unsupported/unrecognized element <{tag}>")

    # -- structural handlers, in R14 order ----------------------------------

    def _handle_include(self, elem: Elem) -> None:
        r = self._emit_leaf(elem)
        base_dir = pathlib.Path(elem.file).parent
        for rel in split_list(r.attrs.get("Script", "")):
            candidate = (base_dir / rel).resolve(strict=False)
            key = str(candidate)
            if key in self._include_stack:
                # Guard against include cycles (A includes B includes A...):
                # a genuine cycle would otherwise recurse until the process
                # stack overflows. A diamond (A includes B and C, both
                # include D) is NOT a cycle -- `key` is checked against the
                # current ANCESTOR chain only, not a global "seen" set, so
                # legitimate repeated includes from different branches are
                # still allowed through, matching the engine's default
                # (non-`IgnoreDuplicateIncludes`) behavior.
                self._finding(
                    elem,
                    "D14",
                    Severity.WARN,
                    f"Include cycle: '{rel}' (resolved to '{key}') is already being included",
                )
                continue
            self._include_stack.append(key)
            try:
                try:
                    included_root = self._loader(candidate)
                except BgError as exc:
                    # V47: a script that includes a file we cannot read is a
                    # DEFECT IN THAT SCRIPT, not a reason to abandon the
                    # analysis. Letting BgError out of here kills the whole
                    # run and the user sees one error line instead of a
                    # report -- which is tolerable for a CLI pointed at a
                    # complete UE tree, and useless for the Pages app (T46),
                    # where picking a single .xml means every sibling
                    # `<Include>` is missing by construction. So: report it
                    # the way V9 reports every other thing we cannot model
                    # -- loudly, once, with a file:line -- and keep walking.
                    # Everything after the `<Include>` still gets analysed,
                    # which is the whole point: the properties and nodes the
                    # include would have defined show up as D1/D18 findings
                    # rather than vanishing along with the report.
                    self._finding(
                        elem,
                        "D14",
                        Severity.WARN,
                        f"Cannot read included script '{rel}' (resolved to '{key}'): {exc}",
                    )
                    continue
                self._record_source(included_root)
                self._walk_body(included_root.children)
            finally:
                self._include_stack.pop()

    def _handle_option(self, elem: Elem) -> None:
        r = self._emit_leaf(elem)
        name = r.attrs.get("Name", "")
        if not name:
            return
        found, _existing = self._lookup(name)
        if found:
            # Already defined by an earlier Property/Option/EnvVar with this
            # name -- ReadOptionAsync (BgScriptReader.cs:786) does not
            # re-register or reassign in this case, only validates Restrict
            # against the existing value (no §D detector covers that
            # validation, so it is not reproduced here). Leave it as-is.
            return
        default = r.attrs.get("DefaultValue", "")
        restrict = r.attrs.get("Restrict")  # None if the attribute is absent
        value = self._overrides.get(name, default)  # --set wins over DefaultValue
        self._assign(name, value, elem)  # engine: SetPropertyValue at :825
        self.options[name] = Opt(name=name, default=default, restrict=restrict)

    def _handle_property(self, elem: Elem) -> None:
        r = self._emit_leaf(elem)
        idx = len(self.resolved) - 1
        name = r.attrs.get("Name", "")
        if not name:
            return
        value = r.attrs.get("Value", "")
        self._assign(name, value, elem)  # engine: SetPropertyValue at :918
        self.prop_defs.append((name, elem, idx))

    def _handle_envvar(self, elem: Elem) -> None:
        r = self._emit_leaf(elem)
        idx = len(self.resolved) - 1
        name = r.attrs.get("Name", "")
        if not name:
            return
        # Deliberately never reads the real os.environ: this is static
        # analysis of SOURCE (§C), and binding to the actual value of
        # whatever machine happens to run this tool would make findings
        # non-deterministic across machines/CI runs. "" is also what the
        # engine itself falls back to for an unset variable
        # (`Environment.GetEnvironmentVariable(...) ?? ""`), so it is a
        # faithful stand-in, not just a safe default.
        self._assign(name, "", elem)  # engine: SetPropertyValue at :1062
        self.prop_defs.append((name, elem, idx))

    def _handle_macro(self, elem: Elem) -> None:
        r = self._emit_leaf(elem)  # records <Macro> itself; body NOT walked now
        name = r.attrs.get("Name", "")
        if not name:
            return
        if name in self._macros:
            # D17 / V31: the engine LogErrors here ("Macro '{Name}' has
            # already been declared", BgScriptReader.cs:1080). Being silent
            # where the engine itself errors is a coverage hole. Keep-first
            # matches the engine's own behaviour after it reports.
            self._finding(
                elem,
                "D17",
                Severity.ERROR,
                f"Macro '{name}' has already been declared; "
                f"this duplicate declaration is ignored (engine reports an error)",
            )
            return
        macro = _MacroDef(name=name)
        required = split_list(r.attrs.get("Arguments", ""))
        optional = split_list(r.attrs.get("OptionalArguments", ""))
        macro.arg_order = required + optional
        macro.num_required = len(required)
        macro.containers = [elem]
        self._macros[name] = macro

    def _handle_extend(self, elem: Elem) -> None:
        r = self._emit_leaf(elem)
        name = r.attrs.get("Name", "")
        macro = self._macros.get(name)
        if macro is not None:
            macro.containers.append(elem)
        else:
            # D17 / V31: engine LogErrors "Macro '{Name}' has not been
            # declared" (BgScriptReader.cs:1137).
            self._finding(
                elem,
                "D17",
                Severity.ERROR,
                f"Extend refers to macro '{name}', which has not been declared",
            )

    def _handle_agent(self, elem: Elem) -> None:
        r = self._emit_leaf(elem)
        name = r.attrs.get("Name", "")
        self._agent_stack.append(name)
        self._enter_scope()  # ReadAgentBodyAsync: EnterScope() (BgScriptReader.cs:1191)
        try:
            self._walk_body(elem.children)
        finally:
            self._leave_scope()
            self._agent_stack.pop()

    def _handle_node(self, elem: Elem) -> None:
        r = self._emit_leaf(elem)
        name = r.attrs.get("Name", "")
        self._node_stack.append(name)
        self._enter_scope()  # ReadNodeBodyAsync: EnterScope() (BgScriptReader.cs:1618)
        try:
            self._walk_body(elem.children)
        finally:
            self._leave_scope()
            self._node_stack.pop()

    def _handle_do(self, elem: Elem) -> None:
        self._emit_leaf(elem)
        # No new scope (ReadBlockAsync has none) and no If= evaluation (see
        # module docstring) -- the body is always walked.
        self._walk_body(elem.children)

    def _handle_switch(self, elem: Elem) -> None:
        self._emit_leaf(elem)
        for branch in elem.children:
            # Every direct child (conventionally <Case If=...> / <Default>,
            # though the real ReadSwitchAsync at BgScriptReader.cs:1679
            # does not actually check the tag name -- it just checks for a
            # literal "Default" or evaluates whatever If= is present) is its
            # own branch. The engine stops at the first match; this tool
            # treats every branch as taken (module docstring) and walks all
            # of them, exposing the union of possible bodies.
            self._emit_leaf(branch)
            self._walk_body(branch.children)

    def _handle_foreach(self, elem: Elem) -> None:
        r = self._emit_leaf(elem)
        name = r.attrs.get("Name", "")
        # Task brief/lexer.py contract: always ';'-split via split_list,
        # regardless of any Separator= attribute (lexer.split_list has no
        # separator parameter; a custom Separator is not modeled -- not
        # used anywhere in Examples/Macros.xml or BuildEditorAndTools.xml).
        values = split_list(r.attrs.get("Values", ""))
        if not name:
            return
        # ONE scope for the whole loop, matching ReadForEachAsync exactly
        # (BgScriptReader.cs:1696): EnterScope() once, then the loop
        # variable is MUTATED in place for each iteration rather than the
        # scope being re-entered -- so a <Property> written inside the body
        # on iteration 1 is still visible (and re-assignable) on iteration 2,
        # same as the real engine.
        self._enter_scope()
        try:
            for value in values:
                self._scopes[-1][name] = value
                self._walk_body(elem.children)  # V23: body emitted once per value
        finally:
            self._leave_scope()

    def _handle_expand(self, elem: Elem) -> None:
        r = self._emit_leaf(elem)  # expands ALL attrs once, args included
        name = r.attrs.get("Name", "")
        macro = self._macros.get(name)
        if macro is None:
            # D17 / V31: engine LogErrors "Macro '{Name}' does not exist"
            # (BgScriptReader.cs:1748). The graph is genuinely broken here --
            # a whole body silently fails to expand -- so error, not warn.
            self._finding(
                elem,
                "D17",
                Severity.ERROR,
                f"Expand refers to macro '{name}', which does not exist; "
                f"its body contributes nothing to the graph",
            )
            return
        if self._expand_depth >= _MAX_EXPAND_DEPTH:
            self._finding(
                elem,
                "D14",
                Severity.WARN,
                f"Macro '{name}' expansion exceeds max recursion depth ({_MAX_EXPAND_DEPTH}); "
                f"further expansion suppressed",
            )
            return

        # R15: arguments are values ALREADY expanded (by _emit_leaf, above)
        # in the scope stack as it stands at the EXPANSION site -- that is
        # the whole mechanism behind "macro body resolves in the lexical
        # scope of the expansion site": we bind those already-resolved
        # values into one new scope, then walk the macro's body using the
        # reader's current (expansion-site) scope stack, exactly as
        # ReadExpandAsync does (BgScriptReader.cs:1738).
        bound = {a: r.attrs[a] for a in macro.arg_order if a in r.attrs}

        # D17 / V31: engine LogWarns "Macro '{Name}' does not take an argument
        # '{ArgName}'" (BgScriptReader.cs:1765). Almost always a typo'd
        # argument name, which silently does nothing.
        for supplied in sorted(set(r.attrs) - {"Name", "If"} - set(macro.arg_order)):
            self._finding(
                elem,
                "D17",
                Severity.WARN,
                f"Macro '{name}' does not take an argument '{supplied}'; it is ignored",
            )

        missing_required = [a for a in macro.arg_order[: macro.num_required] if a not in bound]
        if missing_required:
            # D17 / V31: engine LogWarns "Macro '{Name}' is missing argument
            # '{ArgName}'" (BgScriptReader.cs:1776), then skips the expansion.
            # Skipping silently is the dangerous part: an entire macro body
            # vanishes from the graph with no trace.
            for arg_name in missing_required:
                self._finding(
                    elem,
                    "D17",
                    Severity.WARN,
                    f"Macro '{name}' is missing required argument '{arg_name}'; "
                    f"the whole macro body is skipped",
                )
            # Mirrors the engine's hasMissingArguments guard: skip expansion
            # entirely rather than run the body with holes in it.
            return
        for arg_name in macro.arg_order:
            bound.setdefault(arg_name, "")  # optional args default to ""

        self._enter_scope()
        for arg_name, value in bound.items():
            self._scopes[-1][arg_name] = value
        self._expand_depth += 1
        try:
            for container in macro.containers:
                self._walk_body(container.children)
        finally:
            self._expand_depth -= 1
            self._leave_scope()


def project_properties(project_path: str) -> dict[str, str]:
    """The three project-conditional built-ins, mirroring BuildGraph.cs:325-333.

    Supplied via `--project`. Without it they stay undefined, exactly as in a
    real engine run with no -project= argument -- so `$(ProjectDir)` correctly
    reports as undefined rather than silently expanding to "" (§B.5)."""
    p = pathlib.Path(project_path)
    return {
        "ProjectFile": str(p),
        "ProjectName": p.stem,
        "ProjectDir": str(p.parent),
    }


def evaluate(
    root: Elem,
    schema: Schema,
    overrides: dict[str, str],
    loader: Callable[..., Elem] = load,
    project: str | None = None,
) -> EvalResult:
    """Walk `root` top-to-bottom (V11), expanding properties (V12/V12a) and
    resolving control flow (ForEach/Switch/Do/Macro+Expand/Include) into a
    flat, POST-expansion execution-order trace (V23). See module docstring
    for the full design rationale; the short version: `If=` is captured
    (raw, unexpanded) but never evaluated -- every branch is taken."""
    ev = _Evaluator(schema, overrides, loader)
    if project:
        # Injected into the global scope alongside the unconditional built-ins,
        # exactly as the engine seeds defaultProperties before reading (§B.5).
        ev._scopes[0].update(project_properties(project))
    ev._record_source(root)
    ev._walk_body(root.children)
    return EvalResult(
        resolved=ev.resolved,
        findings=ev.findings,
        options=ev.options,
        prop_defs=ev.prop_defs,
        prop_reads=ev.prop_reads,
        sources=ev.sources,
    )
