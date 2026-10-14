/* Tests for the share-link codec, `webapp/bgview/share.js`. `node --test`,
 * no framework, no deps -- same conventions as tests-js/analyser.test.mjs.
 *
 * Node 24 ships `CompressionStream`/`DecompressionStream` globally, so these
 * run headless with no browser (T63, R54).
 *
 * The malicious/corrupt fixtures below build fragments BY HAND rather than
 * through `encode()`, because `encode()` only ever produces truthful
 * headers -- a lying header is exactly what a real corrupt or truncated
 * share link looks like, and that is what V52/V53 have to survive.
 */
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { test, describe } from "node:test";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(HERE, "..", "webapp", "bgview");
// pathToFileURL, not a hand-built string: on Windows an absolute path starts
// with a drive letter, which the ESM loader reads as an unknown URL scheme.
const mod = (name) => import(pathToFileURL(path.join(APP, name)).href);

const {
  encode, decode, isSupported, ShareError, CURRENT_VERSION, MAX_TOTAL_BYTES,
} = await mod("share.js");

/* A minimal, independent base64url encoder for building malformed fixtures
 * by hand -- deliberately NOT imported from share.js, so these tests do not
 * validate the codec against itself. */
function b64url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Compress `totalBytes` of a single repeating byte via deflate-raw, WITHOUT
 *  ever holding the uncompressed form as one JS value -- it is written into
 *  the CompressionStream in fixed-size chunks and only the (tiny, since it
 *  is maximally repetitive) compressed output is collected. This is how the
 *  V52 bomb test below stays cheap to run: the 70MB only ever exists as
 *  short-lived 1MB chunks passing through the stream. */
async function compressRepeatedByte(totalBytes, byte = 65) {
  const cs = new CompressionStream("deflate-raw");
  const writer = cs.writable.getWriter();
  const chunkSize = 1024 * 1024;
  const chunk = new Uint8Array(chunkSize).fill(byte);
  const writeAll = (async () => {
    let remaining = totalBytes;
    while (remaining > 0) {
      const n = Math.min(chunkSize, remaining);
      await writer.write(n === chunkSize ? chunk : chunk.slice(0, n));
      remaining -= n;
    }
    await writer.close();
  })();
  const reader = cs.readable.getReader();
  const parts = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
    total += value.byteLength;
  }
  await writeAll;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.byteLength; }
  return out;
}

describe("share codec", () => {
  test("isSupported() is true under Node 24", () => {
    assert.equal(isSupported(), true);
  });

  test("round-trips a multi-file set, entry included, through encode/decode", async () => {
    const files = new Map([
      ["Main.xml", "<BuildGraph/>"],
      ["Shared/Common.xml", "<Property Name=\"X\" Value=\"1\"/>"],
      ["notes.txt", "unicode too: éè —"],
    ]);
    const fragment = await encode("Main.xml", files);
    assert.match(fragment, /^s=1\.\d+\.[0-9a-f]{8}\./);

    const out = await decode(fragment);
    assert.equal(out.entry, "Main.xml");
    assert.deepEqual(out.files, files);
  });

  test("decode() accepts a leading '#', matching how location.hash arrives", async () => {
    const fragment = await encode("A.xml", new Map([["A.xml", "x"]]));
    const out = await decode("#" + fragment);
    assert.equal(out.entry, "A.xml");
  });

  /* -------------------------------------------------------- V53: refusal on corruption -- */

  test("V53: flipping one character in the base64 body is refused, not decoded", async () => {
    const fragment = await encode("Main.xml", new Map([["Main.xml", "<BuildGraph>hello world</BuildGraph>"]]));
    const idx = fragment.length - 5; // well inside the base64 tail
    const ch = fragment[idx];
    const swapped = ch === "A" ? "B" : "A";
    const mutated = fragment.slice(0, idx) + swapped + fragment.slice(idx + 1);

    await assert.rejects(decode(mutated), (e) => {
      assert.ok(e instanceof ShareError, "expected a ShareError");
      assert.match(e.message, /corrupt|truncat/i);
      return true;
    });
  });

  test("V53: truncating the tail is refused, not decoded", async () => {
    const fragment = await encode("Main.xml", new Map([["Main.xml", "<BuildGraph>" + "x".repeat(500) + "</BuildGraph>"]]));
    const truncated = fragment.slice(0, fragment.length - 20);

    await assert.rejects(decode(truncated), (e) => {
      assert.ok(e instanceof ShareError);
      assert.match(e.message, /corrupt|truncat/i);
      return true;
    });
  });

  test("V53: a mangled header (wrong segment count / non-numeric fields) is refused", async () => {
    await assert.rejects(decode("s=1.notanumber.deadbeef.AAAA"),
      (e) => e instanceof ShareError && /corrupt|truncat/i.test(e.message));
    await assert.rejects(decode("s=1.10.deadbeef"), // missing the base64 segment
      (e) => e instanceof ShareError && /corrupt|truncat/i.test(e.message));
    await assert.rejects(decode("not-a-share-fragment-at-all"),
      (e) => e instanceof ShareError);
  });

  test("V53: no partial file set ever escapes a refused decode", async () => {
    // A corrupt fragment must REJECT, full stop -- there is no code path in
    // decode() that resolves with a partially-filled Map, because `files`
    // is only ever constructed after every check (version, length, cap,
    // checksum, JSON shape) has already passed.
    const good = await encode("Main.xml", new Map([["Main.xml", "<BuildGraph/>"]]));
    const mutated = good.slice(0, -3) + (good.endsWith("A") ? "B" : "A") + "9";
    await assert.rejects(decode(mutated), (e) => e instanceof ShareError);
  });

  /* --------------------------------------------------------------- V55 -- */

  test("V55: a payload claiming a newer version is refused with a specific message, not garbled", async () => {
    const real = await encode("Main.xml", new Map([["Main.xml", "<BuildGraph/>"]]));
    const bumped = real.replace(/^s=1\./, "s=99.");
    assert.notEqual(bumped, real);

    await assert.rejects(decode(bumped), (e) => {
      assert.ok(e instanceof ShareError);
      assert.match(e.message, /newer version/i);
      return true;
    });
  });

  test("V55: CURRENT_VERSION is 1, the starting version", () => {
    assert.equal(CURRENT_VERSION, 1);
  });

  /* --------------------------------------------------------------- V52 -- */

  test("V52: a header declaring a length over the cap is refused BEFORE decompression", async () => {
    let inflated = false;
    const realDS = globalThis.DecompressionStream;
    // Swap in a spy just long enough to prove decode() never even
    // constructs a DecompressionStream for this fragment -- the cheap
    // header check has to short-circuit before that point.
    globalThis.DecompressionStream = function (...args) {
      inflated = true;
      return new realDS(...args);
    };
    try {
      const overCap = MAX_TOTAL_BYTES + 1;
      const fragment = `s=1.${overCap}.deadbeef.${b64url(new Uint8Array([1, 2, 3, 4]))}`;
      await assert.rejects(decode(fragment), (e) => {
        assert.ok(e instanceof ShareError);
        assert.match(e.message, /too large/i);
        return true;
      });
      assert.equal(inflated, false, "decode() decompressed a link its own header said was too big");
    } finally {
      globalThis.DecompressionStream = realDS;
    }
  });

  test("V52: a genuine bomb (lying header) is refused mid-stream, not allocated in full", async () => {
    // 70MB of one repeating byte compresses to a few hundred bytes under
    // deflate-raw (R54 measured ~1000:1 on far less regular input than
    // this). The header below LIES and declares a small length, so the
    // cheap pre-check cannot catch it -- only the running total kept while
    // reading the DecompressionStream can, which is exactly what V52
    // requires ("catches a LYING header").
    const compressed = await compressRepeatedByte(70 * 1024 * 1024);
    const fragment = `s=1.10.deadbeef.${b64url(compressed)}`;

    await assert.rejects(decode(fragment), (e) => {
      assert.ok(e instanceof ShareError);
      assert.match(e.message, /too large/i);
      return true;
    });
  });
});
