/* Tests for the JavaScript analyser. `node --test`, no framework, no deps --
 * the package installs nothing and neither does its suite.
 *
 * These are self-contained: every fixture is written inline, so they run on a
 * bare CI runner. The exhaustive check -- every module compared against the
 * Python implementation over Epic's 19 shipped graphs -- needs that corpus and
 * lives outside CI; what is asserted here is the behaviour those comparisons
 * pinned down, especially the parts that were WRONG at first and had to be
 * measured into place.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { test, describe } from "node:test";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(HERE, "..", "webapp", "bgview");
// pathToFileURL, not a hand-built string: on Windows an absolute path starts
// with a drive letter, which the ESM loader reads as an unknown URL scheme.
const mod = (name) => import(pathToFileURL(path.join(APP, name)).href);

const { loadString, BgError, MAX_DEPTH } = await mod("loader.js");
const { splitList, hadEmptyEntry, iterRefs, applySlice } = await mod("lexer.js");
const { Schema } = await mod("schema.js");
const { evaluate, BUILTINS, resolveInclude } = await mod("evaluator.js");
const { build } = await mod("model.js");
const { parse, CondParseError } = await mod("condition.js");
const { classify, evaluate: algEval, Opt, UNKNOWN } = await mod("algebra.js");
const { analyse, pathSegments, scoreTail } = await mod("pipeline.js");
const { decide, combine } = await mod("activity.js");
const { Severity, Finding, sortFindings } = await mod("findings.js");
const fz = await mod("fuzzy.js");
const lay = await mod("layout.js");

// The derived fact table the site ships -- not a copy of Epic's Schema.xsd,
// which is EULA-licensed and deliberately not vendored (see
// bgview/data/NOTICE.md). tools/derive_schema.py regenerates it, and
// tests/test_schema.py asserts it agrees with a real engine schema entry for
// entry whenever one is present.
const FACTS = JSON.parse(
  fs.readFileSync(path.join(HERE, "..", "webapp", "data", "schema-facts.json"), "utf8"),
);
const schema = Schema.fromFacts(FACTS, "schema-facts.json");

const wrap = (body) =>
  `<?xml version='1.0' encoding='utf-8'?>\n<BuildGraph xmlns="http://www.epicgames.com/BuildGraph">\n${body}\n</BuildGraph>\n`;

const run = (body, extra = {}) => {
  const files = new Map([["Main.xml", wrap(body)], ...Object.entries(extra)]);
  return analyse("Main.xml", files, schema);
};
const dets = (result, id) => result.findings.filter((f) => f.detector === id);

/* ------------------------------------------------------------- loader --- */
describe("loader", () => {
  test("counts LF, CRLF and lone CR as one line break each (XML spec)", () => {
    const lf = loadString("<r>\n<a/>\n<b/>\n</r>", "f");
    assert.deepEqual([...lf.iter()].map((e) => e.line), [1, 2, 3]);
    const crlf = loadString("<r>\r\n<a/>\r\n<b/>\r\n</r>", "f");
    assert.deepEqual([...crlf.iter()].map((e) => e.line), [1, 2, 3]);
  });

  test("CR CR LF is TWO breaks -- Epic ships files like this", () => {
    // A double LF-to-CRLF conversion. Counting only LF put every finding in
    // Examples/FPSBuildGraph/*.xml at half its true line, and disagreed with
    // expat on all 19 corpus files until it was fixed.
    const doc = loadString("<r>\r\r\n<a/>\r\r\n</r>", "f");
    assert.deepEqual([...doc.iter()].map((e) => e.line), [1, 3]);
  });

  test("normalises attribute values, but not character references", () => {
    // Spec 3.3.3: literal tabs/newlines become spaces; a character reference
    // is EXEMPT, so &#10; must survive as a real newline. Order matters, and
    // decoding first would flatten the two cases together.
    const doc = loadString(`<r a="x\n\ty" b="p&#10;q"/>`, "f");
    assert.equal(doc.attrib.a, "x  y");
    assert.equal(doc.attrib.b, "p\nq");
  });

  test("drops xmlns declarations, which are not attributes", () => {
    const doc = loadString(`<r xmlns="urn:x" xmlns:xsi="urn:y" xsi:loc="z" Name="keep"/>`, "f");
    assert.deepEqual(Object.keys(doc.attrib).sort(), ["Name", "loc"]);
  });

  test("records an end line for every element, including self-closing", () => {
    const doc = loadString("<r>\n  <a>\n  </a>\n  <b/>\n</r>", "f");
    const [r, a, b] = [...doc.iter()];
    assert.deepEqual(r.lineSpan, [1, 5]);
    assert.deepEqual(a.lineSpan, [2, 3]);
    assert.deepEqual(b.lineSpan, [4, 4]);
  });

  test("rejects DOCTYPE outright (V7 trust boundary)", () => {
    // Blunt on purpose: refusing the subset means no <!ENTITY> can ever be
    // declared, killing billion-laughs and XXE together with no allowlist to
    // get subtly wrong.
    assert.throws(() => loadString(`<!DOCTYPE r [<!ENTITY x "y">]><r/>`, "f"),
      (e) => e instanceof BgError && /DOCTYPE/.test(e.message));
  });

  test("caps nesting depth rather than exhausting the stack", () => {
    const deep = "<a>".repeat(MAX_DEPTH + 5) + "</a>".repeat(MAX_DEPTH + 5);
    assert.throws(() => loadString(deep, "f"), (e) => e instanceof BgError && /nesting/.test(e.message));
  });

  test("reports parse errors with a line number (V15)", () => {
    assert.throws(() => loadString("<r>\n<a>\n</b>\n</r>", "f"), (e) => /f:3:/.test(e.message));
  });
});

/* -------------------------------------------------------------- lexer --- */
describe("lexer", () => {
  test("splits tag lists on ';' ONLY -- tag names contain spaces (V1)", () => {
    // `#First Named Output` is a real tag in Epic's TagsAndFiles.xml (R9); a
    // whitespace split shreds it and invents findings.
    assert.deepEqual(splitList("#First Named Output;#B"), ["#First Named Output", "#B"]);
  });

  test("drops empty entries but still reports that they were there", () => {
    assert.deepEqual(splitList("a;;b;"), ["a", "b"]);
    assert.equal(hadEmptyEntry("a;;b"), true);
    assert.equal(hadEmptyEntry("a;b"), false);
  });

  test("finds nested refs innermost-LAST, which is engine resolution order", () => {
    const refs = iterRefs("$(Outer$(Inner))");
    assert.deepEqual(refs.map((r) => r.name), ["Outer$(Inner)", "Inner"]);
  });

  test("parses ':N' slices the way Int32.Parse does, not Number()", () => {
    assert.equal(iterRefs("$(A:3)")[0].sliceN, 3);
    assert.equal(iterRefs("$(A:-6)")[0].sliceN, -6);
    // Number() would accept all of these; the engine THROWS on them, and
    // V12a says we survive as a finding instead.
    for (const bad of ["$(A:1.5)", "$(A:1e3)", "$(A:0x10)", "$(A:bar)"]) {
      assert.equal(iterRefs(bad)[0].malformed, true, bad);
    }
  });

  test("applies a slice only when the value is longer than it", () => {
    assert.equal(applySlice("abcdef", 3), "abc");
    assert.equal(applySlice("abcdef", -2), "ef");
    assert.equal(applySlice("ab", 5), "ab");
    assert.equal(applySlice("abc", 0), "abc");   // n===0 satisfies neither engine branch
  });
});

/* ---------------------------------------------------------- evaluator --- */
describe("evaluator", () => {
  test("preloads exactly 16 unconditional builtins (§B.5)", () => {
    // Defining ProjectFile/ProjectName/ProjectDir unconditionally
    // manufactured four phantom errors on Epic's corpus. Sixteen, not 19.
    assert.equal(BUILTINS.size, 16);
    for (const n of ["ProjectFile", "ProjectName", "ProjectDir"]) assert.equal(BUILTINS.has(n), false);
  });

  test("models all three expansion outcomes (V12)", () => {
    const r = run(`  <Property Name="Set" Value="v"/>
  <Agent Name="A" Type="T"><Node Name="N">
    <Log Message="a=$(Set) b=$(Nope) c=$(RootDir)"/>
  </Node></Agent>`);
    const log = r.ev.resolved.find((x) => x.elem.tag === "Log");
    // (a) not found -> warn + expands to ""   (b) found-but-null -> NO
    // warning and the literal text survives   (c) found -> expanded
    assert.equal(log.attrs.get("Message"), "a=v b= c=$(RootDir)");
    const d1 = dets(r, "D1");
    assert.equal(d1.length, 1);
    assert.match(d1[0].message, /'Nope' is not defined/);
  });

  test("a missing <Include> is a located D14, not an abort (V47)", () => {
    const r = run(`  <Include Script="Absent.xml"/>
  <Agent Name="A" Type="T"><Node Name="N"><Log Message="after"/></Node></Agent>`);
    const d14 = dets(r, "D14");
    assert.equal(d14.length, 1);
    assert.match(d14[0].message, /Cannot read included script 'Absent.xml'/);
    assert.equal(d14[0].severity, Severity.WARN);
    // The half that matters: everything AFTER the bad include still analysed.
    assert.equal(r.graph.nodes.size, 1);
  });

  test("a good <Include> resolves relative to the including file", () => {
    const r = run(`  <Include Script="Shared.xml"/>
  <Agent Name="A" Type="T"><Node Name="N"><Log Message="$(Shared)"/></Node></Agent>`,
      { "Shared.xml": wrap(`  <Property Name="Shared" Value="yes"/>`) });
    assert.equal(dets(r, "D1").length, 0);
    assert.equal(dets(r, "D14").length, 0);
  });

  test("resolveInclude collapses . and .. and unifies separators", () => {
    assert.equal(resolveInclude("a/b/Main.xml", "../Shared.xml"), "a/Shared.xml");
    assert.equal(resolveInclude("a/b/Main.xml", ".\\c\\S.xml"), "a/b/c/S.xml");
  });

  test("every ForEach value is walked, and one scope spans the loop", () => {
    const r = run(`  <ForEach Name="P" Values="Win64;Linux">
    <Agent Name="A $(P)" Type="T"><Node Name="N $(P)"/></Agent>
  </ForEach>`);
    assert.deepEqual([...r.graph.nodes.keys()].sort(), ["N Linux", "N Win64"]);
  });

  test("both Switch branches are taken -- the union, not one run", () => {
    const r = run(`  <Switch>
    <Case If="'a' == 'b'"><Agent Name="A1" Type="T"><Node Name="N1"/></Agent></Case>
    <Default><Agent Name="A2" Type="T"><Node Name="N2"/></Agent></Default>
  </Switch>`);
    assert.deepEqual([...r.graph.nodes.keys()].sort(), ["N1", "N2"]);
  });

  test("an unknown element is loud, never a silent skip (V9)", () => {
    const r = run(`  <Agent Name="A" Type="T"><Node Name="N"><NotARealTask X="1"/></Node></Agent>`);
    assert.match(dets(r, "D14")[0].message, /Unsupported\/unrecognized element <NotARealTask>/);
  });
});

/* -------------------------------------------------------------- model --- */
describe("model", () => {
  test("every node implicitly produces #<NodeName> (V2/R7)", () => {
    // The single largest false-positive source if missed: a reference to a
    // node's default output would look like a dangling tag.
    const r = run(`  <Agent Name="A" Type="T"><Node Name="Build"/></Agent>`);
    assert.deepEqual([...r.graph.nodes.get("Build").produces], ["#Build"]);
    assert.deepEqual(r.graph.producersOf("#build"), ["Build"]);   // case-insensitive
  });

  test("an explicit @Produces equal to the implicit output is de-duped", () => {
    const r = run(`  <Agent Name="A" Type="T"><Node Name="Build" Produces="#Build;#Extra"/></Agent>`);
    assert.deepEqual([...r.graph.nodes.get("Build").produces].sort(), ["#Build", "#Extra"]);
  });

  test("Requires consumes its own #tags; After never does (R23)", () => {
    const r = run(`  <Agent Name="A" Type="T">
    <Node Name="P" Produces="#Out"/>
    <Node Name="C" Requires="#Out" After="P"/>
  </Agent>`);
    assert.deepEqual([...r.graph.nodes.get("C").consumes], ["#Out"]);
  });

  test("bare names resolve node -> aggregate -> agent, in that order", () => {
    const r = run(`  <Agent Name="A" Type="T"><Node Name="N1"/><Node Name="N2"/></Agent>
  <Aggregate Name="Agg" Requires="N1;N2"/>`);
    assert.deepEqual(r.graph.resolveRef("N1"), ["N1"]);
    assert.deepEqual(r.graph.resolveRef("Agg").sort(), ["N1", "N2"]);
    assert.deepEqual(r.graph.resolveRef("A").sort(), ["N1", "N2"]);
  });
});

/* ---------------------------------------------- condition + algebra ----- */
describe("condition and algebra", () => {
  test("parses the three functions the engine's doc comment omits (§B.1)", () => {
    // The first version was transcribed from BgCondition.cs's doc comment,
    // which is stale against its own implementation. Epic's own
    // Properties.xml uses Contains/ContainsItem four times.
    for (const src of ["Length('abc') > 3", "Contains('a;b','a')", "ContainsItem('a;b','b',';')"]) {
      assert.doesNotThrow(() => parse(src), src);
    }
  });

  test("function names and And/Or match case-insensitively", () => {
    assert.equal(parse("EXISTS('x')").name, "Exists");
    assert.equal(parse("a AND b").kind, "And");
  });

  test("wrong argument count is an error naming the function", () => {
    assert.throws(() => parse("Contains('a')"), (e) => e instanceof CondParseError && /Contains\(\) expects 2/.test(e.message));
  });

  test("a bare identifier is LITERAL TEXT, not an env lookup", () => {
    // Worth pinning, because it is the opposite of the intuition: only
    // `$(Name)` reads the environment. By the time the engine sees a
    // condition every reference has already been textually expanded, so a
    // bare token is just a string -- and `A` is not "true".
    assert.equal(algEval(parse("A"), new Map([["A", "true"]])), false);
    assert.equal(algEval(parse("$(A)"), new Map([["A", "true"]])), true);
  });

  test("Exists is opaque and never guessed either way (V10)", () => {
    const env = new Map([["A", "true"], ["B", "false"]]);
    assert.equal(algEval(parse("Exists('x')"), env), UNKNOWN);
    // ...but Kleene short-circuiting still decides what it soundly can:
    // a false on either side of And forces false without ever touching the
    // opaque call, and a true on either side of Or forces true.
    assert.equal(algEval(parse("$(B) And Exists('x')"), env), false);
    assert.equal(algEval(parse("Exists('x') And $(B)"), env), false);
    assert.equal(algEval(parse("$(A) Or Exists('x')"), env), true);
    assert.equal(algEval(parse("Exists('x') Or $(A)"), env), true);
    // ...and stays UNKNOWN when it genuinely cannot decide.
    assert.equal(algEval(parse("$(A) And Exists('x')"), env), UNKNOWN);
  });

  test("HasTrailingSlash IS decidable, unlike Exists (V10a)", () => {
    const BS = String.fromCharCode(92);   // a real \ without an escape in this file
    const env = new Map([["D", "C:/x/"], ["W", "C:" + BS + "x" + BS], ["S", "C:/x"]]);
    assert.equal(algEval(parse("HasTrailingSlash($(D))"), env), true);
    assert.equal(algEval(parse("HasTrailingSlash($(W))"), env), true);
    assert.equal(algEval(parse("HasTrailingSlash($(S))"), env), false);
  });

  test("scalar comparison is case-insensitive (V19)", () => {
    const env = new Map([["S", "Win64"]]);
    assert.equal(algEval(parse("$(S) == 'win64'"), env), true);
    assert.equal(algEval(parse("$(S) != 'WIN64'"), env), false);
  });

  test("numeric compares need clean integers, and Length() feeds them (V18)", () => {
    const env = new Map([["N", "42"], ["X", "4.5"]]);
    assert.equal(algEval(parse("$(N) > 41"), env), true);
    assert.equal(algEval(parse("$(N) >= 42"), env), true);
    assert.equal(algEval(parse("Length('abcd') > 3"), env), true);
    // "4.5" is not an integer to Int32.Parse, so the compare is undecided
    // rather than silently coerced -- Number() would have made it 4.5.
    assert.equal(algEval(parse("$(X) > 4"), env), UNKNOWN);
  });

  test("an unresolvable name makes the whole leaf UNKNOWN, never empty", () => {
    assert.equal(algEval(parse("$(Missing) == 'x'"), new Map()), UNKNOWN);
  });

  test("classify separates unsat, taut and contingent", () => {
    const opts = new Map([["F", new Opt("F", "", "true|false")]]);
    assert.equal(classify(parse("'a' == 'b'"), new Map(), new Map()), "unsat");
    assert.equal(classify(parse("'a' == 'a'"), new Map(), new Map()), "taut");
    assert.equal(classify(parse("$(F) == 'true'"), opts, new Map()), "contingent");
    assert.equal(classify(parse("Exists('x')"), new Map(), new Map()), "unknown");
  });
});

/* ---------------------------------------------------------- detectors --- */
describe("detectors", () => {
  test("D22: a true/false option without a Restrict is flagged, info only", () => {
    const r = run(`  <Option Name="WithDDC" DefaultValue="true" Description="fill the cache"/>
  <Option Name="Verbose" DefaultValue="False"/>
  <Agent Name="A" Type="T"><Node Name="N"><Log Message="$(WithDDC) $(Verbose)"/></Node></Agent>`);
    const hits = dets(r, "D22");
    assert.deepEqual(hits.map((f) => [f.line, f.severity]), [[3, Severity.INFO], [4, Severity.INFO]]);
    assert.match(hits[0].message, /Restrict="true\|false"/);
    assert.match(hits[0].message, /-set:WithDDC=ture/);       // names the typo it guards against
    assert.match(hits[1].message, /defaults to 'False'/);     // quoted as written, matched case-insensitively
  });

  test("D22 stays silent when a Restrict exists or the default is not boolean", () => {
    const r = run(`  <Option Name="WithDDC" DefaultValue="true" Restrict="true|false"/>
  <Option Name="Cfg" DefaultValue="Development" Restrict="Debug|Development|Shipping"/>
  <Option Name="Platforms" DefaultValue="Win64;PS5"/>
  <Option Name="Toggle" DefaultValue="true" Restrict=".+"/>
  <Agent Name="A" Type="T"><Node Name="N"><Log Message="$(WithDDC)$(Cfg)$(Platforms)$(Toggle)"/></Node></Agent>`);
    assert.deepEqual(dets(r, "D22"), []);
  });

  test("D2 fires on a tag consumed but produced nowhere", () => {
    const r = run(`  <Agent Name="A" Type="T"><Node Name="N">
    <SrcSrv BinaryFiles="#Nope" SourceFiles="#Nope"/>
  </Node></Agent>`);
    assert.ok(dets(r, "D2").some((f) => f.tag === "#Nope"));
  });

  test("D2 stays silent when the tag is created and used inside one node", () => {
    // Measured false positive: four tags in the target file are created and
    // consumed within a node with no @Produces. It never needs to escape.
    const r = run(`  <Agent Name="A" Type="T"><Node Name="N">
    <Tag Files="x.txt" With="#Local"/>
    <SrcSrv BinaryFiles="#Local" SourceFiles="#Local"/>
  </Node></Agent>`);
    assert.equal(dets(r, "D2").length, 0);
  });

  test("D18 reports an unresolvable Requires, with a did-you-mean", () => {
    const r = run(`  <Agent Name="A" Type="T">
    <Node Name="P" Produces="#Thing"/>
    <Node Name="C" Requires="Thing"/>
  </Agent>`);
    const f = dets(r, "D18").find((x) => /references 'Thing'/.test(x.message));
    assert.ok(f, "expected an unresolvable-reference finding");
    assert.match(f.message, /did you mean '#Thing'\?/);
    assert.equal(f.severity, Severity.ERROR);
  });

  test("D18 stays silent under a guard, because every branch is unioned (V33)", () => {
    const r = run(`  <Agent Name="A" Type="T">
    <Node Name="C" Requires="Absent" If="'$(HostPlatform)' == 'Nope'"/>
  </Agent>`);
    assert.equal(dets(r, "D18").length, 0);
  });

  test("D18 catches a @Produces entry with no '#', which the engine drops", () => {
    const r = run(`  <Agent Name="A" Type="T"><Node Name="N" Produces="bare"/></Agent>`);
    assert.ok(dets(r, "D18").some((f) => /does not begin with '#'/.test(f.message)));
  });

  test("D18 catches a node re-declaring its own implicit output (R41)", () => {
    const r = run(`  <Agent Name="A" Type="T"><Node Name="Foo" Produces="#Foo"/></Agent>`);
    assert.ok(dets(r, "D18").some((f) => /duplicates the node's own implicit default output/.test(f.message)));
  });

  test("ValidateName accepts a single trailing space but not two (R33)", () => {
    // Not the obvious boundary, and it is how a node name becomes genuinely
    // unreferenceable while staying legal. Must never test trim().
    const okName = run(`  <Agent Name="A" Type="T"><Node Name="N "/></Agent>`);
    assert.equal(dets(okName, "D18").filter((f) => /is invalid/.test(f.message)).length, 0);
    const bad = run(`  <Agent Name="A" Type="T"><Node Name="N  x"/></Agent>`);
    assert.ok(dets(bad, "D18").some((f) => /consecutive spaces/.test(f.message)));
  });

  test("D20 reports a tag in both Requires and OptionalRequires", () => {
    const r = run(`  <Agent Name="A" Type="T">
    <Node Name="P" Produces="#O"/>
    <Node Name="C" Requires="#O" OptionalRequires="#O"/>
  </Agent>`);
    assert.ok(dets(r, "D20").some((f) => /both @Requires and @OptionalRequires/.test(f.message)));
  });

  test("D20 reports a multi-character ForEach separator the engine ignores", () => {
    const r = run(`  <ForEach Name="P" Values="a::b" Separator="::"><Property Name="Q" Value="$(P)"/></ForEach>`);
    assert.ok(dets(r, "D20").some((f) => /more than one character/.test(f.message)));
  });

  test("D12 calls an unsatisfiable guard a warning and a tautology info", () => {
    const r = run(`  <Option Name="F" DefaultValue="a" Restrict="a"/>
  <Agent Name="A" Type="T">
    <Node Name="N1" If="'$(F)' == 'a' And '$(F)' == 'b'"/>
    <Node Name="N2" If="'$(F)' == '$(F)'"/>
  </Agent>`);
    const d12 = dets(r, "D12");
    assert.ok(d12.some((f) => f.severity === Severity.WARN && /unsatisfiable/.test(f.message)));
    assert.ok(d12.some((f) => f.severity === Severity.INFO && /tautological/.test(f.message)));
  });

  test("D13 needs an UNCONDITIONAL clobber, not merely a later write", () => {
    // Measured: a guarded redefinition proves nothing, because a later reader
    // does observe the first value whenever that guard is false.
    const guarded = run(`  <Property Name="X" Value="1"/>
  <Property Name="X" Value="2" If="'$(HostPlatform)' == 'Win64'"/>
  <Agent Name="A" Type="T"><Node Name="N"><Log Message="$(X)"/></Node></Agent>`);
    assert.equal(dets(guarded, "D13").length, 0);

    const clobbered = run(`  <Property Name="X" Value="1"/>
  <Property Name="X" Value="2"/>
  <Agent Name="A" Type="T"><Node Name="N"><Log Message="$(X)"/></Node></Agent>`);
    assert.equal(dets(clobbered, "D13").length, 1);
  });

  test("the accumulator idiom never trips D13 (R20, 37 real uses)", () => {
    const r = run(`  <Property Name="X" Value="a"/>
  <Property Name="X" Value="$(X);b"/>
  <Agent Name="A" Type="T"><Node Name="N"><Log Message="$(X)"/></Node></Agent>`);
    assert.equal(dets(r, "D13").length, 0);
  });

  test("D10 says WHICH source an empty list entry came from", () => {
    const literal = run(`  <Agent Name="A" Type="T"><Node Name="P" Produces="#O"/>
    <Node Name="N" Requires="#O;"/></Agent>`);
    assert.ok(dets(literal, "D10").some((f) => /trailing or duplicate ';'/.test(f.message)));

    // The expansion case is invisible in the source -- there is no ';' to
    // hunt for -- and on the target file it is the downstream effect of a D1
    // on the SAME line, so naming it is what stops the pair reading as a
    // stray duplicate.
    const expanded = run(`  <Agent Name="A" Type="T"><Node Name="P" Produces="#O"/>
    <Node Name="N" Requires="#O;$(Gone)"/></Agent>`);
    assert.ok(dets(expanded, "D10").some((f) => /'\$\(Gone\)' expanded to nothing/.test(f.message)));
  });

  test("D15 reads the RAW Type, so an option-driven agent stays silent", () => {
    const literal = run(`  <Agent Name="A" Type="Win64Agent"><Node Name="N"/></Agent>`);
    assert.equal(dets(literal, "D15").length, 1);
    const driven = run(`  <Option Name="AT" DefaultValue="Win64Agent"/>
  <Agent Name="A" Type="$(AT)"><Node Name="N"/></Agent>`);
    assert.equal(dets(driven, "D15").length, 0);
  });
});

/* ----------------------------------------------------------- findings --- */
describe("findings", () => {
  test("a finding without a real line is refused at construction (V15)", () => {
    for (const line of [0, -1, undefined, null, 1.5]) {
      assert.throws(() => new Finding({ file: "f", line, severity: Severity.WARN, detector: "D1", message: "m" }));
    }
  });

  test("sorting is by code point, not locale", () => {
    // localeCompare puts 'a' before 'B'; Python's sorted() does not, and a
    // different order would make the two implementations diff for no reason.
    const mk = (file) => new Finding({ file, line: 1, severity: Severity.INFO, detector: "D1", message: "m" });
    assert.deepEqual(sortFindings([mk("a"), mk("B")]).map((f) => f.file), ["B", "a"]);
  });
});

/* ------------------------------------------------------------- layout --- */
describe("layout", () => {
  // A lane with a fan-out: one root, three dependents, and a wire that SKIPS
  // a rank -- the shape row banding alone cannot keep clear.
  const mk = (name, requires = []) => [name, {
    name, agent: "A", line: 1, file: "f", requires, after: [],
    produces: new Set(["#" + name]), creates: new Set(), consumes: new Set(),
  }];
  const graph = {
    nodes: new Map([mk("Root"), mk("A1", ["Root"]), mk("A2", ["Root"]),
                    mk("B1", ["A1"]), mk("Far", ["Root"])]),
    agents: new Map([["A", ["Root", "A1", "A2", "B1", "Far"]]]),
    resolveRef(token) { return this.nodes.has(token) ? [token] : []; },
  };
  // "Far" depends on Root but is dragged to a later rank by nothing, so give
  // it a real skip: it also waits on B1.
  graph.nodes.get("Far").requires = ["Root", "B1"];

  const L = lay.layout(graph, new Set(), new Set());

  test("columns are packed with real room for the splines", () => {
    // 116, not 44. The gap is not whitespace taste -- it is the room the
    // curved wires need to route without crossing boxes, and the earlier
    // layered version used a quarter of it.
    const xs = [...L.nodePos.values()].map((p) => p.x).sort((a, b) => a - b);
    const gaps = [];
    for (let i = 1; i < xs.length; i++) if (xs[i] !== xs[i - 1]) gaps.push(xs[i] - xs[i - 1]);
    assert.ok(gaps.every((g) => g >= 116), `column gaps: ${gaps}`);
  });

  test("rows are FLOAT, so a parent can centre between its dependents", () => {
    const rows = [...L.nodePos.values()].map((p) => p.row);
    assert.ok(rows.some((r) => !Number.isInteger(r)),
      `expected at least one half-row from banding, got ${rows}`);
  });

  test("same rank means same column across the whole graph", () => {
    // The one thing the layout exists to show: two nodes at equal dependency
    // depth line up, which is what makes "these run in parallel" legible.
    const byRank = new Map();
    for (const p of L.nodePos.values()) {
      if (!byRank.has(p.rank)) byRank.set(p.rank, new Set());
      byRank.get(p.rank).add(p.x);
    }
    for (const [rank, xs] of byRank) assert.equal(xs.size, 1, `rank ${rank} has ${xs.size} x positions`);
  });

  test("no in-lane wire passes through a node box", () => {
    // T33's own acceptance condition, asserted at ZERO rather than "fewer
    // than before". Measured over Epic's 19 graphs the previous layered
    // layout scored 14; this one scores 0.
    let crossings = 0;
    for (const e of L.edges) {
      const a = L.nodePos.get(e.from), b = L.nodePos.get(e.to);
      if (!a || !b || a.agent !== b.agent) continue;
      const x1 = a.x + a.w, y1 = a.y + a.h / 2, x2 = b.x, y2 = b.y + b.h / 2;
      const t = lay.splineTangent(x2 - x1, y2 - y1) / 3;
      const c1x = x1 + t, c2x = x2 - t;
      for (let i = 0; i <= 200; i++) {
        const s2 = i / 200, u = 1 - s2;
        const x = u*u*u*x1 + 3*u*u*s2*c1x + 3*u*s2*s2*c2x + s2*s2*s2*x2;
        const y = u*u*u*y1 + 3*u*u*s2*y1 + 3*u*s2*s2*y2 + s2*s2*s2*y2;
        for (const [n, p] of L.nodePos) {
          if (n === e.from || n === e.to) continue;
          if (x >= p.x && x <= p.x + p.w && y >= p.y && y <= p.y + p.h) { crossings++; i = 999; break; }
        }
      }
    }
    assert.equal(crossings, 0);
  });

  test("a collapsed lane reclaims its space but keeps its count", () => {
    const open = lay.layout(graph, new Set(), new Set());
    const shut = lay.layout(graph, new Set(), new Set(["A"]));
    assert.ok(shut.height < open.height);
    assert.equal(shut.lanes[0].count, 5);
    assert.equal(shut.nodePos.size, 0);
  });

  test("the spline tangent follows UE's policy, backwards differing", () => {
    // A backwards wire gets a stronger horizontal pull so it loops out and
    // back rather than doubling over itself.
    assert.ok(lay.splineTangent(-100, 0) > lay.splineTangent(100, 0));
  });
});

/* -------------------------------------------------------------- fuzzy --- */
describe("fuzzy matching for the tag lens", () => {
  const TAGS = ["#BinaryFiles", "#Binaries", "#EditorBinaries", "#ArchiveSymbols",
                "#First Named Output", "#ToolBinaries", "#SourceFiles"];

  test("edit distance counts a TRANSPOSITION as one edit", () => {
    // The whole reason this is Damerau and not plain Levenshtein: swapped
    // adjacent letters are the commonest typo, and Levenshtein charges two,
    // which pushes the right answer out of a short result list.
    assert.equal(fz.editDistance("bianry", "binary"), 1);
    assert.equal(fz.editDistance("kitten", "sitting"), 3);
    assert.equal(fz.editDistance("abc", "abc"), 0);
    assert.equal(fz.editDistance("", "abc"), 3);
  });

  test("it is OSA, which differs from unrestricted Damerau -- deliberately", () => {
    // The textbook case: OSA says 3 because it refuses to edit the same
    // region twice; unrestricted Damerau says 2. OSA is chosen because for
    // single-word typos the two are indistinguishable and OSA is far easier
    // to keep correct. Pinned so nobody "fixes" it into the other algorithm.
    assert.equal(fz.editDistance("ca", "abc"), 3);
  });

  test("the bound makes it bail early without changing a within-budget answer", () => {
    assert.equal(fz.editDistance("bianry", "binary", 1), 1);
    assert.ok(fz.editDistance("kitten", "sitting", 1) > 1);
  });

  test("folding ignores case, a leading # and separators", () => {
    assert.equal(fz.fold("#BinaryFiles"), "binaryfiles");
    assert.equal(fz.fold("#First Named Output"), "firstnamedoutput");
    assert.equal(fz.fold("Archive_Symbols"), "archivesymbols");
  });

  test("an exact match outranks a prefix, which outranks a substring", () => {
    assert.equal(fz.score("#Binaries", "#Binaries").tier, fz.TIER.EXACT);
    assert.equal(fz.score("bin", "#Binaries").tier, fz.TIER.PREFIX);
    assert.equal(fz.score("naries", "#Binaries").tier, fz.TIER.SUBSTRING);
  });

  test("a prefix wins, and a near-miss that is not within budget is not offered", () => {
    // "binary" is a clean PREFIX of #BinaryFiles. It is NOT a near-miss of
    // #Binaries -- binary/binaries is three edits, over the budget of one --
    // so #Binaries is correctly absent rather than offered as a guess. A
    // matcher that returned it would be inventing a correction the user did
    // not make.
    const r = fz.rank("binary", TAGS);
    assert.equal(r[0].value, "#BinaryFiles");
    assert.equal(r.length, 1, JSON.stringify(r));
  });

  test("exact beats substring, and every substring match is offered", () => {
    // "binaries" is exactly #Binaries, and a substring of two others. All
    // three are real matches; the exact one has to come first.
    const r = fz.rank("binaries", TAGS);
    assert.equal(r[0].value, "#Binaries");
    assert.equal(r[0].tier, fz.TIER.EXACT);
    assert.deepEqual(r.filter((x) => x.tier === fz.TIER.SUBSTRING).map((x) => x.value).sort(),
                     ["#EditorBinaries", "#ToolBinaries"]);
    // #BinaryFiles also matches, as a weaker SUBSEQUENCE (b-i-n-a-r...i-e-s),
    // and ranks below both substrings. That ordering is the point: weaker
    // kinds of match are offered, never promoted.
    assert.ok(r.every((x, i) => i === 0 || x.tier <= r[i - 1].tier), JSON.stringify(r));
  });

  test("a transposed typo still finds the tag", () => {
    const r = fz.rank("bianries", TAGS);
    assert.equal(r[0].value, "#Binaries", JSON.stringify(r.slice(0, 3)));
  });

  test("a missing letter still finds the tag", () => {
    assert.equal(fz.rank("arcivesymbols", TAGS)[0].value, "#ArchiveSymbols");
  });

  test("initials find a multi-word tag", () => {
    // "fno" is not a typo of anything -- it is how people actually type.
    const r = fz.rank("fno", TAGS);
    assert.equal(r[0].value, "#First Named Output");
  });

  test("a very short query forgives nothing, so it cannot match everything", () => {
    assert.equal(fz.typoBudget(2), 0);
    assert.equal(fz.typoBudget(4), 1);
    assert.equal(fz.typoBudget(12), 3);
    // "xy" is a typo of nothing here; with a budget it would match half the list.
    assert.deepEqual(fz.rank("xy", TAGS).map((r) => r.value), []);
  });

  test("nonsense matches nothing rather than guessing", () => {
    assert.deepEqual(fz.rank("qqqqzzzz", TAGS).map((r) => r.value), []);
  });

  test("an empty query returns nothing, not everything", () => {
    assert.deepEqual(fz.rank("", TAGS).map((r) => r.value), []);
  });

  test("results are capped and ordered deterministically", () => {
    const r = fz.rank("i", TAGS, 3);
    assert.ok(r.length <= 3);
    assert.deepEqual(r.map((x) => x.value), fz.rank("i", TAGS, 3).map((x) => x.value));
  });

  test("match positions index the ORIGINAL string, separators skipped", () => {
    const pos = fz.matchPositions("fno", "#First Named Output");
    assert.deepEqual(pos.map((i) => "#First Named Output"[i]), ["F", "N", "O"]);
    // No honest alignment exists for a typo correction, so none is offered.
    assert.deepEqual(fz.matchPositions("bianries", "#Binaries"), []);
  });
});

/* ----------------------------------------------------------- pipeline --- */
describe("pipeline", () => {
  test("analyses a whole script end to end", () => {
    const r = run(`  <Option Name="Cfg" DefaultValue="Development"/>
  <Agent Name="Win" Type="Win64">
    <Node Name="Compile" Produces="#Bin"><Log Message="cfg=$(Cfg)"/></Node>
    <Node Name="Package" Requires="#Bin"><Log Message="pack"/></Node>
  </Agent>`);
    assert.equal(r.graph.nodes.size, 2);
    assert.equal(r.graph.agents.size, 1);
    assert.equal(r.entryFile, "Main.xml");
    assert.ok(r.findings.every((f) => f.line > 0 && f.file));
  });

  test("include lookup is case-insensitive, as Windows authoring implies", () => {
    const files = new Map([
      ["Main.xml", wrap(`  <Include Script="shared.XML"/>
  <Agent Name="A" Type="T"><Node Name="N"><Log Message="$(S)"/></Node></Agent>`)],
      ["Shared.xml", wrap(`  <Property Name="S" Value="v"/>`)],
    ]);
    const r = analyse("Main.xml", files, schema);
    assert.equal(r.findings.filter((f) => f.detector === "D14").length, 0);
    assert.equal(r.findings.filter((f) => f.detector === "D1").length, 0);
  });

  test("malformed XML raises a controlled BgError, not a crash", () => {
    assert.throws(() => analyse("Main.xml", new Map([["Main.xml", "<r><a></r>"]]), schema),
      (e) => e instanceof BgError);
  });

  /* Include resolution over the browser's virtual filesystem. The picked
   * folder is the whole world here, and real scripts reach outside it --
   * `../../../Engine/Build/Graph/Tasks/Inc/X.xml` from an Examples/ script,
   * or a path rooted at a built-in that is null while preprocessing. On disk
   * those land on a file that exists; in the pick, that file is usually
   * present under a shorter key. The pipeline matches by path TAIL after an
   * exact miss, records every such match, and refuses an ambiguous one. */
  test("an include that climbs above the picked folder resolves by its path tail", () => {
    const files = new Map([
      ["Graph/Examples/Main.xml", wrap(`  <Include Script="../../../Engine/Build/Graph/Tasks/Inc/Common.xml"/>
  <Agent Name="A" Type="T"><Node Name="N"><Log Message="$(S)"/></Node></Agent>`)],
      ["Graph/Tasks/Inc/Common.xml", wrap(`  <Property Name="S" Value="v"/>`)],
    ]);
    const r = analyse("Graph/Examples/Main.xml", files, schema);
    assert.equal(dets(r, "D14").length, 0);
    assert.equal(dets(r, "D1").length, 0);
    assert.deepEqual(r.includes.missing, []);
    assert.deepEqual(r.includes.matched,
      [{ requested: "Engine/Build/Graph/Tasks/Inc/Common.xml", matched: "Graph/Tasks/Inc/Common.xml" }]);
  });

  test("a rooted include path (leading slash) resolves by its tail too", () => {
    const files = new Map([
      ["Main.xml", wrap(`  <Include Script="/Engine/Build/Inc/Shared.xml"/>
  <Agent Name="A" Type="T"><Node Name="N"><Log Message="$(S)"/></Node></Agent>`)],
      ["Build/Inc/Shared.xml", wrap(`  <Property Name="S" Value="v"/>`)],
    ]);
    const r = analyse("Main.xml", files, schema);
    assert.equal(dets(r, "D14").length, 0);
    assert.equal(r.includes.matched.length, 1);
    assert.equal(r.includes.matched[0].matched, "Build/Inc/Shared.xml");
  });

  test("an exact include is never second-guessed by a tail match", () => {
    const files = new Map([
      ["Main.xml", wrap(`  <Include Script="Inc/P.xml"/>
  <Agent Name="A" Type="T"><Node Name="N"><Log Message="$(S)"/></Node></Agent>`)],
      ["Inc/P.xml", wrap(`  <Property Name="S" Value="exact"/>`)],
      ["Other/Inc/P.xml", wrap(`  <Property Name="S" Value="other"/>`)],
    ]);
    const r = analyse("Main.xml", files, schema);
    assert.deepEqual(r.includes.matched, []);
    assert.deepEqual(r.includes.missing, []);
    assert.equal(dets(r, "D14").length, 0);
  });

  test("an ambiguous tail is a miss, never a guess", () => {
    // Two platform folders each carry the same fragment. Picking one of them
    // silently would analyse the other platform's values.
    const files = new Map([
      ["Main.xml", wrap(`  <Include Script="../../Inc/PGO.xml"/>`)],
      ["Platforms/Win64/Inc/PGO.xml", wrap(`  <Property Name="S" Value="a"/>`)],
      ["Platforms/Linux/Inc/PGO.xml", wrap(`  <Property Name="S" Value="b"/>`)],
    ]);
    const r = analyse("Main.xml", files, schema);
    assert.equal(dets(r, "D14").length, 1);
    assert.deepEqual(r.includes.matched, []);
    assert.deepEqual(r.includes.missing, ["Inc/PGO.xml"]);
  });

  test("a wildcard include is never satisfied by one file, and says why", () => {
    // `Platforms/*/Build/Inc/X.xml` means every platform overlay. The base
    // Inc/X.xml next to the script shares its last two segments and is
    // exactly the WRONG file to substitute.
    const files = new Map([
      ["Main.xml", wrap(`  <Include Script="../../../Platforms/*/Build/Inc/PlatformOptions.xml"/>`)],
      ["Inc/PlatformOptions.xml", wrap(`  <Property Name="S" Value="base"/>`)],
    ]);
    const r = analyse("Main.xml", files, schema);
    assert.deepEqual(r.includes.matched, []);
    assert.deepEqual(r.includes.missing, ["Platforms/*/Build/Inc/PlatformOptions.xml"]);
    const d14 = dets(r, "D14");
    assert.equal(d14.length, 1);
    assert.match(d14[0].message, /wildcard includes are not expanded/);
  });

  test("two agreeing segments are not evidence: a same-named base file is left alone", () => {
    // An unexpanded $(RootDir) marks "from the engine root"; the path then
    // names a Restricted overlay. The public Inc/SharedProperties.xml in the
    // pick agrees on `Inc/SharedProperties.xml` only, which every overlay of
    // that name does too -- so it is reported missing, not guessed.
    const files = new Map([
      ["Inc/Common.xml", wrap(`  <Include Script="$(RootDir)/Engine/Restricted/NotForLicensees/Build/Graph/Tasks/Inc/SharedProperties.xml"/>`)],
      ["Inc/SharedProperties.xml", wrap(`  <Property Name="S" Value="public"/>`)],
    ]);
    const r = analyse("Inc/Common.xml", files, schema);
    assert.deepEqual(r.includes.matched, []);
    assert.equal(r.includes.missing.length, 1);
    assert.equal(dets(r, "D14").length, 1);
  });

  test("three agreeing segments still match, and $(RootDir) prefixes are read as rooted", () => {
    const files = new Map([
      ["Graph/Examples/Main.xml", wrap(`  <Include Script="$(RootDir)/Engine/Build/Graph/Tasks/Inc/TestConfigs.xml"/>
  <Agent Name="A" Type="T"><Node Name="N"><Log Message="$(S)"/></Node></Agent>`)],
      ["Graph/Tasks/Inc/TestConfigs.xml", wrap(`  <Property Name="S" Value="v"/>`)],
    ]);
    const r = analyse("Graph/Examples/Main.xml", files, schema);
    assert.equal(dets(r, "D14").length, 0);
    assert.equal(dets(r, "D1").length, 0);
    assert.equal(r.includes.matched.length, 1);
    assert.equal(r.includes.matched[0].matched, "Graph/Tasks/Inc/TestConfigs.xml");
  });

  test("a missing include is reported with the path AS WRITTEN, not only the resolved key", () => {
    // The entry sits two folders deep, so `Inc/X.xml` resolves to a key with
    // that prefix; relOf keeps the author's path for the shell's evidence bar.
    const files = new Map([["Graph/Examples/Main.xml", wrap(`  <Include Script="Inc/PlatformOptions.xml"/>`)]]);
    const r = analyse("Graph/Examples/Main.xml", files, schema);
    assert.deepEqual(r.includes.missing, ["Graph/Examples/Inc/PlatformOptions.xml"]);
    assert.equal(r.includes.relOf.get("Graph/Examples/Inc/PlatformOptions.xml"), "Inc/PlatformOptions.xml");
  });

  test("a refused same-named file is offered as a candidate, best agreement first", () => {
    // A flattened copy of an engine folder: the script asks for
    // Tasks/Inc/Common.xml through an engine-rooted path, the copy keeps it
    // as plain Inc/Common.xml. Two agreeing segments: refused, but LISTED.
    const files = new Map([
      ["Main.xml", wrap(`  <Include Script="../../../Engine/Build/Graph/Tasks/Inc/Common.xml"/>`)],
      ["Inc/Common.xml", wrap(`  <Property Name="S" Value="flat"/>`)],
      ["Other/Common.xml", wrap(`  <Property Name="S" Value="other"/>`)],
    ]);
    const r = analyse("Main.xml", files, schema);
    const key = "Engine/Build/Graph/Tasks/Inc/Common.xml";
    assert.deepEqual(r.includes.missing, [key]);
    assert.deepEqual(r.includes.matched, []);
    assert.deepEqual(r.includes.candidates.get(key), ["Inc/Common.xml", "Other/Common.xml"]);
    // The user's choice, applied the way the shell applies it: the chosen
    // text stored under the requested key -- resolves exactly, no D14.
    files.set(key, files.get("Inc/Common.xml"));
    const r2 = analyse("Main.xml", files, schema);
    assert.equal(dets(r2, "D14").length, 0);
    assert.deepEqual(r2.includes.missing, []);
  });

  test("pathSegments and scoreTail are the one tail rule the loader and the shell share", () => {
    assert.deepEqual(pathSegments("..\\Engine/Build//Graph/./X.xml"), ["engine", "build", "graph", "x.xml"]);
    // Everything before an unexpanded $(...) is the including file's folder,
    // prepended by relative resolution; the reference means "from the root".
    assert.deepEqual(pathSegments("Inc/$(RootDir)/Engine/Build/X.xml"), ["engine", "build", "x.xml"]);
    // keepCase is for walking a real directory: the author's spelling survives.
    assert.deepEqual(pathSegments("Inc/$(RootDir)/Engine/Build/X.xml", true), ["Engine", "Build", "X.xml"]);
    // Shorter side matches in full, either way round: 2 agreeing segments.
    assert.equal(scoreTail(["engine", "build", "graph", "x.xml"], ["graph", "x.xml"]), 2);
    assert.equal(scoreTail(["graph", "x.xml"], ["engine", "build", "graph", "x.xml"]), 2);
    // Same file name under a different parent is NOT a match.
    assert.equal(scoreTail(["tasks", "inc", "x.xml"], ["examples", "inc", "x.xml"]), -1);
  });

  test("a genuinely absent include is listed in includes.missing and is still a D14", () => {
    const r = run(`  <Include Script="Inc/Nowhere.xml"/>`);
    assert.equal(dets(r, "D14").length, 1);
    assert.deepEqual(r.includes.missing, ["Inc/Nowhere.xml"]);
    assert.deepEqual(r.includes.matched, []);
  });
});

/* ------------------------------------------- options + guard activity --- */
describe("option-set and guard activity (V58, V59)", () => {
  const GUARDED = `  <Option Name="Cfg" DefaultValue="Development" Restrict="Debug|Development|Shipping" Description="Build configuration"/>
  <Option Name="Free" DefaultValue="x" Restrict=".+"/>
  <Agent Name="Ship" Type="T" If="'$(Cfg)' == 'Shipping'">
    <Node Name="Symbols"><Log Message="s"/></Node>
  </Agent>
  <Agent Name="Always" Type="T">
    <Node Name="Build $(Cfg)"><Log Message="b"/></Node>
    <Do If="Exists('$(Free)/marker')"><Node Name="Maybe"><Log Message="m"/></Node></Do>
    <Do If="'$(Cfg)' != 'Shipping'"><Node Name="DevOnly" If="Exists('y')"><Log Message="d"/></Node></Do>
  </Agent>`;

  test("overrides change values, never which branches are walked", () => {
    const def = run(GUARDED);
    const ship = analyse("Main.xml", new Map([["Main.xml", wrap(GUARDED)]]), schema, new Map([["Cfg", "Shipping"]]));
    // Same node and agent COUNT either way -- the union is untouched (V58).
    assert.equal(def.graph.nodes.size, 4);
    assert.equal(ship.graph.nodes.size, 4);
    assert.equal(def.graph.agents.size, ship.graph.agents.size);
    // What DID change is the value: the node's name expanded differently.
    assert.ok(def.graph.nodes.has("Build Development"));
    assert.ok(ship.graph.nodes.has("Build Shipping"));
    assert.ok(!ship.graph.nodes.has("Build Development"));
  });

  test("the script's options are exposed with their finite domain", () => {
    const r = analyse("Main.xml", new Map([["Main.xml", wrap(GUARDED)]]), schema, new Map([["Cfg", "Shipping"]]));
    const cfg = r.options.find((o) => o.name === "Cfg");
    assert.deepEqual(cfg.domain, ["Debug", "Development", "Shipping"]);
    assert.equal(cfg.default, "Development");
    assert.equal(cfg.value, "Shipping");
    assert.equal(cfg.description, "Build configuration");
    const free = r.options.find((o) => o.name === "Free");
    assert.equal(free.domain, null);           // a real regex: no finite list
    assert.equal(free.value, "x");
    assert.ok(r.overrides.get("Cfg") === "Shipping");
  });

  test("decide() is three-valued and never coerces", () => {
    assert.equal(decide(null), "active");
    assert.equal(decide("true"), "active");
    assert.equal(decide("'a' == 'b'"), "inactive");
    assert.equal(decide("Exists('x')"), "unknown");
    assert.equal(decide("$(RootDir) != ''"), "unknown");     // unexpanded reference
    assert.equal(decide("'unbalanced"), "unknown");           // parser rejects it
    assert.equal(combine(["active", "unknown"]), "unknown");
    assert.equal(combine(["inactive", "unknown"]), "inactive");
    assert.equal(combine([]), "active");
  });

  test("activity under the defaults: agent guard, Do guard, Exists()", () => {
    const r = run(GUARDED);
    const st = (n) => r.activity.nodes.get(n).state;
    assert.equal(st("Symbols"), "inactive");              // Agent If false under Development
    assert.equal(st("Build Development"), "active");
    assert.equal(st("Maybe"), "unknown");                 // Exists() is opaque
    assert.equal(st("DevOnly"), "unknown");               // Do true AND own Exists() unknown
    assert.deepEqual(r.activity.counts, { active: 1, inactive: 1, unknown: 2 });
    assert.equal(r.activity.agents.get("Ship").state, "inactive");
    assert.equal(r.activity.agents.get("Always").state, "active");
    // The inherited guard is attributed to its owner, for the inspector.
    const owners = r.activity.nodes.get("Symbols").guards.map((g) => g.owner);
    assert.deepEqual(owners, ["Agent Ship"]);
  });

  test("activity under Cfg=Shipping flips the same nodes the other way", () => {
    const r = analyse("Main.xml", new Map([["Main.xml", wrap(GUARDED)]]), schema, new Map([["Cfg", "Shipping"]]));
    const st = (n) => r.activity.nodes.get(n).state;
    assert.equal(st("Symbols"), "active");
    assert.equal(st("Build Shipping"), "active");
    assert.equal(st("DevOnly"), "inactive");              // false AND unknown = false
    assert.equal(st("Maybe"), "unknown");
    assert.equal(r.activity.agents.get("Ship").state, "active");
  });

  test("an Include's guard reaches every node of the included file", () => {
    const files = new Map([
      ["Main.xml", wrap(`  <Option Name="Cfg" DefaultValue="Development"/>
  <Include Script="Inc/Extra.xml" If="'$(Cfg)' == 'Shipping'"/>
  <Agent Name="A" Type="T"><Node Name="Here"><Log Message="h"/></Node></Agent>`)],
      ["Inc/Extra.xml", wrap(`  <Agent Name="B" Type="T"><Node Name="FromInc"><Log Message="i"/></Node></Agent>`)],
    ]);
    const r = analyse("Main.xml", files, schema);
    // Still walked (union), still a node -- and marked inactive, with the
    // Include named as the reason.
    assert.ok(r.graph.nodes.has("FromInc"));
    assert.equal(r.activity.nodes.get("FromInc").state, "inactive");
    assert.match(r.activity.nodes.get("FromInc").guards[0].owner, /^Include at Main\.xml:/);
    assert.equal(r.activity.nodes.get("Here").state, "active");
    assert.equal(r.activity.agents.get("B").state, "inactive");
  });

  test("a node inside a <Macro> inherits the guards of the <Expand> that placed it", () => {
    const r = run(`  <Option Name="Cfg" DefaultValue="Development"/>
  <Macro Name="Pack"><Node Name="Packed"><Log Message="p"/></Node></Macro>
  <Agent Name="A" Type="T">
    <Do If="'$(Cfg)' == 'Shipping'"><Expand Name="Pack"/></Do>
  </Agent>`);
    assert.ok(r.graph.nodes.has("Packed"));
    assert.equal(r.activity.nodes.get("Packed").state, "inactive");
    const owners = r.activity.nodes.get("Packed").guards.map((g) => g.owner);
    assert.equal(owners.length, 1);
    assert.match(owners[0], /^Do at Main\.xml:\d+$/);   // the Do around the Expand, not anything at the Macro
  });

  test("a ForEach body is judged by its own iteration's container", () => {
    const r = run(`  <Agent Name="A" Type="T">
    <ForEach Name="P" Values="Win64;PS5">
      <Do If="'$(P)' == 'Win64'"><Node Name="Only $(P)"><Log Message="x"/></Node></Do>
    </ForEach>
  </Agent>`);
    assert.equal(r.activity.nodes.get("Only Win64").state, "active");
    assert.equal(r.activity.nodes.get("Only PS5").state, "inactive");
  });
});
