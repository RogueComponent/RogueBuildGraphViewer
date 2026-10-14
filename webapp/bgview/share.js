/* bgview/share.js -- share-link codec: a picked file set <-> a URL fragment.
 *
 * The fragment crosses a TRUST BOUNDARY the picker never has to think about:
 * a file the user opened is already on their disk, but a share link can
 * arrive from anyone, wrapped by any chat client, and land in `decode()`
 * before this module knows whether it is honest. Two invariants follow from
 * that, and both are non-negotiable regardless of how short the "happy path"
 * could otherwise be:
 *
 *   V52 -- the size cap has to sit ON THE DECOMPRESSION STREAM, not on the
 *   result. R54 measured deflate at ~1000:1 on repetitive text: 67,962
 *   fragment characters inflate to 50MB. Checking the RESULT's size means the
 *   50MB is already sitting in memory by the time you notice -- the bomb
 *   already went off. So there are two checks, not one: the declared length
 *   in the header is checked before a single byte is decompressed (rejects
 *   an HONEST oversized link for free), and the running total is checked
 *   after every chunk the DecompressionStream reader hands back (rejects a
 *   LYING header, which the first check cannot see).
 *
 *   V53 -- a mismatched checksum or a truncated stream must REFUSE, never
 *   analyse. Chat apps wrap and reflow long URLs; a half-arrived link can
 *   still contain a well-formed compressed prefix that inflates to a
 *   syntactically valid (but semantically wrong) file set. Handing that to
 *   the pipeline would produce real-looking, fabricated findings -- exactly
 *   what V24 forbids on the analysis side. So every failure path below stops
 *   before `files` is ever constructed; there is no partial Map to leak.
 *
 * Checksum is a hand-rolled CRC32 (~12 lines below), not
 * `crypto.subtle.digest`. `crypto.subtle` is only defined in a secure
 * context, and the self-host case this feature exists for is a studio
 * serving the app off `http://intranet-box/` -- a plain-http LAN address is
 * NOT a secure context. The native API would work everywhere you'd test it
 * from (https, localhost) and fail exactly where the feature is aimed. CRC32
 * is a truncation/corruption check, not a security primitive -- nothing here
 * is being defended against a forger, only against a chat client's line
 * wrapping and a copy-paste that lost the tail -- so CRC32's cryptographic
 * weakness is irrelevant to what it is being asked to catch.
 *
 * Ladder: rung 4 (native platform API). `CompressionStream`/
 * `DecompressionStream` with 'deflate-raw' does the compression; no
 * dependency is added for it (R54: measured present and correct in Chrome).
 * V55 says that support is NOT assumed elsewhere -- `isSupported()` below
 * lets app.js hide the share affordance entirely rather than ship a button
 * that throws (V28).
 *
 * Fragment shape (the caller owns the leading '#'):
 *
 *   s=<version>.<declaredLen>.<crc32hex>.<base64url>
 *
 * `declaredLen` and the checksum are both over the DECOMPRESSED payload
 * bytes -- the plain deflate-raw format carries no integrity check of its
 * own (that is the whole reason a checksum has to be hand-rolled here), so
 * both are measured on the JSON body before it is ever compressed.
 *
 * Payload body (before compression): JSON `{entry, files}`, UTF-8 encoded --
 * `entry` the root script's relative path, `files` a plain object of
 * relative path -> text, mirroring the `Map` pipeline.analyse expects.
 *
 * Pure and DOM-free: no `document`, no globals beyond the streams,
 * `TextEncoder`/`TextDecoder`, `atob`/`btoa` and `URLSearchParams` -- all of
 * which exist in Node 24 too, which is what makes this testable under
 * `node --test` with no browser.
 */
"use strict";

export const CURRENT_VERSION = 1;
// The picker's limits live HERE and app.js imports them (V52 says reuse the
// picker's own limits; the way you actually get that is one declaration, not
// two that agree today). This module is the right home: it is DOM-free, so
// the numbers stay testable without a browser.
export const MAX_FILE_BYTES = 8 * 1024 * 1024;
export const MAX_TOTAL_BYTES = 64 * 1024 * 1024;

const NEWER_VERSION_MESSAGE = "this link was made by a newer version of Rogue BuildGraph Viewer";
const TOO_LARGE_MESSAGE = "this share link is too large to open";
const CORRUPT_PREFIX = "this share link is corrupted or truncated";

/** Thrown for every refusal (V53/V55). A caller checks `instanceof
 *  ShareError` and shows `.message` verbatim -- there is never a partial
 *  result alongside it. */
export class ShareError extends Error {
  constructor(message) { super(message); this.name = "ShareError"; }
}

/** Does this runtime actually support what encode/decode need?
 *
 * The global existing is not enough (V55): some runtimes expose
 * `CompressionStream` but reject 'deflate-raw' as a format, so the format is
 * probed by actually constructing one. app.js hides the share button when
 * this is false, rather than surface a control with no consumer (V28).
 */
export function isSupported() {
  if (typeof CompressionStream === "undefined" || typeof DecompressionStream === "undefined") return false;
  try {
    // eslint-disable-next-line no-new -- probing for a thrown format error is the point
    new CompressionStream("deflate-raw");
    new DecompressionStream("deflate-raw");
    return true;
  } catch {
    return false;
  }
}

/* ---------------------------------------------------------------- CRC32 -- */

// Standard reflected CRC-32 (polynomial 0xEDB88320, the one PNG/zlib/gzip
// use). Built once, lazily, rather than as a 256-entry literal -- the table
// is derivable from the polynomial in eight lines and that is shorter and
// less error-prone to review than transcribing it.
let CRC_TABLE = null;
function crcTable() {
  if (CRC_TABLE) return CRC_TABLE;
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c >>> 0;
  }
  CRC_TABLE = table;
  return table;
}

/** CRC32 of a byte array, as an 8-digit lowercase hex string. */
function crc32Hex(bytes) {
  const table = crcTable();
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) crc = table[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  return ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, "0");
}

/* ------------------------------------------------------------ base64url -- */

/** Bytes -> base64url, no '=' padding. Built with a char-code loop rather
 *  than `String.fromCharCode(...bytes)` -- spreading a large typed array as
 *  call arguments risks blowing the engine's argument-count limit, and a
 *  BuildGraph tree bundled for sharing is exactly the kind of input that can
 *  be large. */
function bytesToBase64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** base64url -> bytes. Throws ShareError on anything that isn't clean
 *  base64url -- a stray character or a length that pads impossibly is
 *  exactly the shape a chat client's line-wrap or a lost tail produces
 *  (V53), so it is refused here rather than handed to `atob` to mangle. */
function base64UrlToBytes(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new ShareError(`${CORRUPT_PREFIX} (malformed base64)`);
  const rem = s.length % 4;
  if (rem === 1) throw new ShareError(`${CORRUPT_PREFIX} (malformed base64)`);
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "====".slice(rem || 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new ShareError(`${CORRUPT_PREFIX} (malformed base64)`);
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/* ------------------------------------------------------- stream helpers -- */

function concatBytes(chunks, total) {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.byteLength; }
  return out;
}

async function deflateRaw(bytes) {
  const cs = new CompressionStream("deflate-raw");
  const writer = cs.writable.getWriter();
  const writeDone = writer.write(bytes).then(() => writer.close());
  // The write side and the read side of a stream reject independently. If
  // the read loop below throws first, `writeDone` would otherwise reject
  // with nobody listening -- an "unhandled rejection" that node's test
  // runner (rightly) treats as a failure of its own. Marking it handled
  // here does not swallow a real error: the read side surfaces the same
  // underlying failure through `reader.read()`.
  writeDone.catch(() => {});
  const chunks = [];
  let total = 0;
  const reader = cs.readable.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.byteLength;
  }
  await writeDone;
  return concatBytes(chunks, total);
}

/** Inflate `bytes`, aborting the moment decompressed output exceeds `cap`
 *  WITHOUT ever materialising the full result -- the second half of V52's
 *  two-layer cap, the one that catches a header that lies about how big the
 *  payload really is. `new Response(stream).arrayBuffer()` was deliberately
 *  not used here: that call buffers the whole stream before returning
 *  anything, which is the exact bomb this function exists to defuse. */
async function inflateRawCapped(bytes, cap) {
  const ds = new DecompressionStream("deflate-raw");
  const writer = ds.writable.getWriter();
  const writeDone = writer.write(bytes).then(() => writer.close());
  // See the matching comment in deflateRaw: the write side can reject
  // (e.g. once `reader.cancel()` tears the stream down below) independently
  // of the read side, which is what actually surfaces the failure here.
  writeDone.catch(() => {});
  const reader = ds.readable.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      // ponytail: a single chunk larger than `cap` still gets read into
      // memory once before this check can reject it -- DecompressionStream
      // implementations hand back chunks on the order of tens of KB in
      // practice, never the whole stream at once, so this does not defeat
      // the cap. Upgrade path if that assumption ever breaks: read via a
      // BYOB reader with a fixed-size buffer so no chunk can be bigger than
      // one is willing to allocate.
      if (total > cap) {
        reader.cancel().catch(() => {});
        throw new ShareError(TOO_LARGE_MESSAGE);
      }
      chunks.push(value);
    }
  } catch (e) {
    if (e instanceof ShareError) throw e;
    // A genuinely truncated or corrupt deflate stream throws here (V53) --
    // never garble it into a partial `chunks` array and carry on.
    throw new ShareError(`${CORRUPT_PREFIX} (could not decompress)`);
  }
  return concatBytes(chunks, total);
}

/* -------------------------------------------------------------- public -- */

/**
 * @param {string} entry  relative path of the root script
 * @param {Map<string,string>} files  relative path -> file text
 * @returns {Promise<string>}  the fragment, e.g. "s=1.842.a1b2c3d4.<b64>"
 *   (caller prepends '#')
 */
export async function encode(entry, files) {
  const body = JSON.stringify({ entry, files: Object.fromEntries(files) });
  const bytes = new TextEncoder().encode(body);
  const compressed = await deflateRaw(bytes);
  return `s=${CURRENT_VERSION}.${bytes.length}.${crc32Hex(bytes)}.${bytesToBase64Url(compressed)}`;
}

/**
 * @param {string} fragment  the "s=..." string (a leading '#', if present,
 *   is stripped)
 * @returns {Promise<{entry:string, files:Map<string,string>}>}
 * @throws {ShareError} on any version mismatch, corruption, truncation or
 *   oversize input -- never returns a partial file set (V53).
 */
export async function decode(fragment) {
  const trimmed = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  const s = new URLSearchParams(trimmed).get("s");
  if (s === null) throw new ShareError(`${CORRUPT_PREFIX} (no share payload found)`);

  const parts = s.split(".");
  if (parts.length !== 4) throw new ShareError(`${CORRUPT_PREFIX} (malformed header)`);
  const [verStr, lenStr, crcStr, b64] = parts;
  if (!/^\d+$/.test(verStr) || !/^\d+$/.test(lenStr) || !/^[0-9a-fA-F]{8}$/.test(crcStr)) {
    throw new ShareError(`${CORRUPT_PREFIX} (malformed header)`);
  }

  // V55: a newer version gets a clear, specific message -- never a garbled
  // decode attempt. Versions only ever count up from 1, so anything else
  // that isn't newer is a corrupt/impossible header, not "older" (there is
  // no older format to fall back to).
  const version = Number(verStr);
  if (version !== CURRENT_VERSION) {
    if (version > CURRENT_VERSION) throw new ShareError(NEWER_VERSION_MESSAGE);
    throw new ShareError(`${CORRUPT_PREFIX} (malformed header)`);
  }

  // V52, layer 1: reject an HONEST oversized link before decompressing a
  // single byte. Cheap, and catches the common case (R54: a real 50MB bomb
  // declares its own true size) for free.
  const declaredLen = Number(lenStr);
  if (declaredLen > MAX_TOTAL_BYTES) throw new ShareError(TOO_LARGE_MESSAGE);

  const compressed = base64UrlToBytes(b64);

  // V52, layer 2: the streaming cap catches a header that LIES about being
  // small while the compressed bytes actually inflate past the limit.
  const decompressed = await inflateRawCapped(compressed, MAX_TOTAL_BYTES);

  if (decompressed.length !== declaredLen) {
    throw new ShareError(`${CORRUPT_PREFIX} (length mismatch)`);
  }
  if (crc32Hex(decompressed) !== crcStr.toLowerCase()) {
    throw new ShareError(`${CORRUPT_PREFIX} (checksum mismatch)`);
  }

  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder().decode(decompressed));
  } catch {
    throw new ShareError(`${CORRUPT_PREFIX} (malformed payload)`);
  }
  if (!parsed || typeof parsed.entry !== "string" || typeof parsed.files !== "object" || parsed.files === null) {
    throw new ShareError(`${CORRUPT_PREFIX} (malformed payload)`);
  }

  // Built only after every check above has passed -- a Map only half filled
  // in would be exactly the "half-decoded script still parses" case V53
  // warns about.
  const files = new Map();
  for (const [path, text] of Object.entries(parsed.files)) {
    if (typeof text !== "string") throw new ShareError(`${CORRUPT_PREFIX} (malformed payload)`);
    if (new TextEncoder().encode(text).length > MAX_FILE_BYTES) throw new ShareError(TOO_LARGE_MESSAGE);
    files.set(path, text);
  }
  return { entry: parsed.entry, files };
}
