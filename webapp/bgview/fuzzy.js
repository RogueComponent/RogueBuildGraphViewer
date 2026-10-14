/* bgview/fuzzy.js -- typo-tolerant ranking for the tag lens.
 *
 * Tag names are identifiers a person retypes from memory: `#BinaryFiles`,
 * `#First Named Output`, `#ArchiveSymbols`. Three different things go wrong
 * when someone types one, and they need three different answers:
 *
 *   1. they type a PREFIX or a fragment      -> substring / prefix match
 *   2. they type INITIALS or skip letters    -> subsequence match ("bf")
 *   3. they MISTYPE                          -> edit distance
 *
 * Any one of these alone is visibly wrong. Pure edit distance ranks
 * `#Binaries` above `#BinaryFiles` for the query "binary" (distance 3 vs 5),
 * even though the second is a clean prefix. Pure substring finds nothing at
 * all for "bianry". So matching is TIERED: an exact match always beats a
 * prefix, which always beats a substring, which beats a subsequence, which
 * beats a typo correction. Within a tier, a cheaper match wins.
 *
 * The distance used is Damerau-Levenshtein (optimal string alignment), not
 * plain Levenshtein, because a TRANSPOSITION is the most common typo there
 * is -- "bianry" for "binary" -- and Levenshtein charges two edits for it,
 * which is usually enough to push the right answer out of the results.
 */
"use strict";

export const TIER = Object.freeze({
  EXACT: 5, PREFIX: 4, SUBSTRING: 3, SUBSEQUENCE: 2, TYPO: 1, NONE: 0,
});

/** Fold for comparison: case, the leading '#', and separator noise.
 *
 * A user typing `binaryfiles` means `#BinaryFiles`, and one typing
 * `first named output` means `#First Named Output` -- so spaces, hyphens and
 * underscores are all equivalent to nothing when matching. The ORIGINAL text
 * is always what gets displayed and inserted; this form exists only to
 * compare with.
 */
export function fold(s) {
  return String(s).toLowerCase().replace(/^#/, "").replace(/[\s_\-.]/g, "");
}

/** Damerau-Levenshtein (optimal string alignment) with an early bail.
 *
 * `max` bounds the work: if every cell in a row already exceeds it, no
 * completion can come back under it, so the rest of the matrix cannot change
 * the answer. That keeps a per-keystroke pass over hundreds of tags cheap
 * without an index.
 *
 * OSA rather than unrestricted Damerau: it does not allow editing a
 * substring twice, which for single-word typos is indistinguishable and is
 * markedly simpler to get right.
 */
export function editDistance(a, b, max = Infinity) {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  if (Math.abs(m - n) > max) return max + 1;

  let prev2 = null;
  let prev = new Array(n + 1);
  let cur = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;

  for (let i = 1; i <= m; i++) {
    cur[0] = i;
    let rowMin = cur[0];
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(
        cur[j - 1] + 1,        // insertion
        prev[j] + 1,           // deletion
        prev[j - 1] + cost,    // substitution
      );
      // Transposition: the whole reason this is not plain Levenshtein.
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        v = Math.min(v, prev2[j - 2] + 1);
      }
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;   // cannot recover -- stop early
    // Rotate: the transposition rule needs the row from TWO back, so three
    // rows are kept in flight rather than the usual two.
    prev2 = prev;
    prev = cur;
    cur = new Array(n + 1);
  }
  return prev[n];
}

/** Are `q`'s characters an in-order subsequence of `t`, and how tightly?
 *  Returns {ok, span, start} -- `span` is how far apart the matched
 *  characters ended up, so "bf" scores better against `BinaryFiles` than
 *  against a name where those letters are pages apart. */
export function subsequence(q, t) {
  if (!q.length) return { ok: true, span: 0, start: 0 };
  let i = 0, start = -1, last = -1;
  for (let j = 0; j < t.length && i < q.length; j++) {
    if (t[j] === q[i]) {
      if (start < 0) start = j;
      last = j;
      i++;
    }
  }
  return i === q.length ? { ok: true, span: last - start, start } : { ok: false, span: 0, start: 0 };
}

/** How many typos to forgive at this query length.
 *
 * Scaled, not fixed: allowing 2 edits on a 3-character query would match
 * essentially everything, and allowing only 1 on a 20-character tag would
 * catch almost nothing. One per four characters, minimum one.
 */
export function typoBudget(len) {
  return len <= 2 ? 0 : Math.max(1, Math.floor(len / 4));
}

/** Score one candidate. Higher is better; `tier` dominates, `detail` breaks
 *  ties within it (lower detail = better). */
export function score(query, candidate) {
  const q = fold(query);
  const c = fold(candidate);
  if (!q) return { tier: TIER.NONE, detail: 0 };
  if (q === c) return { tier: TIER.EXACT, detail: 0 };
  if (c.startsWith(q)) return { tier: TIER.PREFIX, detail: c.length - q.length };
  const idx = c.indexOf(q);
  if (idx >= 0) return { tier: TIER.SUBSTRING, detail: idx * 100 + (c.length - q.length) };
  const sub = subsequence(q, c);
  if (sub.ok) return { tier: TIER.SUBSEQUENCE, detail: sub.span * 10 + sub.start };
  const budget = typoBudget(q.length);
  if (budget > 0) {
    const d = editDistance(q, c, budget);
    if (d <= budget) return { tier: TIER.TYPO, detail: d * 1000 + Math.abs(c.length - q.length) };
  }
  return { tier: TIER.NONE, detail: 0 };
}

/**
 * Rank `candidates` against `query`, best first.
 *
 * @param {string} query
 * @param {string[]} candidates
 * @param {number} limit
 * @returns {{value:string, tier:number, detail:number}[]}
 */
export function rank(query, candidates, limit = 8) {
  const out = [];
  for (const value of candidates) {
    const s = score(query, value);
    if (s.tier === TIER.NONE) continue;
    out.push({ value, tier: s.tier, detail: s.detail });
  }
  out.sort((a, b) =>
    b.tier - a.tier ||
    a.detail - b.detail ||
    a.value.length - b.value.length ||
    (a.value < b.value ? -1 : a.value > b.value ? 1 : 0));
  return out.slice(0, limit);
}

/** Character positions in `candidate` that `query` matched, for emphasis.
 *  Best-effort and in-order; returns [] when the match was a typo
 *  correction, because there is no honest per-character alignment to show
 *  when the letters do not actually line up. */
export function matchPositions(query, candidate) {
  const q = fold(query);
  if (!q) return [];
  // Walk the ORIGINAL candidate, folding as we go, so the positions returned
  // index the string the caller is going to render.
  const positions = [];
  let qi = 0;
  for (let i = 0; i < candidate.length && qi < q.length; i++) {
    const ch = fold(candidate[i]);
    if (!ch) continue;                       // a separator, folded away
    if (ch === q[qi]) { positions.push(i); qi++; }
  }
  return qi === q.length ? positions : [];
}
