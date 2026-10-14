/* bgview/layout.js -- swimlane layout for the graph view.
 *
 * A faithful port of the Python renderer's layout (T32/T33), replacing the
 * plain layered version this file used to hold. The difference is not
 * cosmetic: the old version packed columns 44px apart where the reference
 * uses 116 ("horizontal room for the connection splines"), and had no
 * crossing avoidance at all, so wires routed straight through boxes.
 *
 * Agents are lanes stacked vertically; dependency depth is the horizontal
 * axis. That pairing is the point: §G names the agent boundary as one of the
 * three invisible semantics, so which lane a node sits in has to be as
 * visible as what it depends on. Columns are packed to the widest box in
 * them ACROSS ALL LANES, because same-column-different-lane is precisely the
 * "these run in parallel" signal -- a per-lane packing would destroy the one
 * thing the layout exists to show.
 *
 * Rows are FLOAT. A parent at 1.5, centred between two dependents, is the
 * whole point of banding.
 */
"use strict";

const ROW_H = 66;
const NODE_H = 34;
const LANE_HEADER_H = 34;
const LANE_PAD = 22;
const LANE_GAP = 16;
const MARGIN_X = 24;

const NODE_FONT_PX = 11;
const NODE_CHAR_W = NODE_FONT_PX * 0.62;   // top of the real advance range
const NODE_PAD_X = 9;
const NODE_BADGE_W = 18;                   // room the warn badge needs, top-right
const NODE_MIN_W = 96;
const NODE_MAX_W = 460;
const COL_GAP = 116;                       // horizontal room for the splines

/* A box only fills NODE_H of ROW_H, so demanding a full row of clearance
 * from a wire reserves roughly four times what is needed. Half a box height
 * plus a little is what the reference uses. */
const WIRE_CLEARANCE = (NODE_H / 2 + 6) / ROW_H;

const COLLAPSED_H = LANE_HEADER_H;

/* UE's own spline tangent policy, so the corridor sampling below follows the
 * curve the renderer actually draws rather than an approximation of it. */
const SPLINE_FWD_RANGE = 1000.0, SPLINE_FWD_H = 1.0, SPLINE_FWD_V = 1.0;
const SPLINE_BACK_RANGE = 200.0, SPLINE_BACK_H = 2.0, SPLINE_BACK_V = 1.5;

export function splineTangent(dx, dy) {
  const backwards = dx < 0;
  const rng = backwards ? SPLINE_BACK_RANGE : SPLINE_FWD_RANGE;
  const h = backwards ? SPLINE_BACK_H : SPLINE_FWD_H;
  const v = backwards ? SPLINE_BACK_V : SPLINE_FWD_V;
  return Math.min(Math.abs(dx), rng) * h + Math.min(Math.abs(dy), rng) * v;
}

/* Unreal's zoom is a TABLE, not a multiplier (R35): 20 discrete stops, and
 * the default level is 12 -- exactly 1:1. */
export const ZOOM_LEVELS = [
  [0.100, "-12"], [0.125, "-11"], [0.150, "-10"], [0.175, "-9"], [0.200, "-8"],
  [0.225, "-7"], [0.250, "-6"], [0.375, "-5"], [0.500, "-4"], [0.675, "-3"],
  [0.750, "-2"], [0.875, "-1"], [1.000, "1:1"], [1.250, "+1"], [1.375, "+2"],
  [1.500, "+3"], [1.675, "+4"], [1.750, "+5"], [1.875, "+6"], [2.000, "+7"],
];
export const ZOOM_DEFAULT_LEVEL = 12;
export const LARGE_NODE_THRESHOLD = 40;
export const LARGE_LANE_THRESHOLD = 12;

/** ZoomToLocation's rule: walk UP the table and take the stop BEFORE the
 *  first that does not fit, both axes, never past 1:1. GetNearestZoomLevel
 *  rounds up and overshoots -- measured, it left a scrollbar. */
export function fitZoomLevel(contentW, contentH, viewW, viewH) {
  let best = 0;
  for (let i = 0; i <= ZOOM_DEFAULT_LEVEL; i++) {
    const z = ZOOM_LEVELS[i][0];
    if (contentW * z <= viewW && contentH * z <= viewH) best = i;
    else break;
  }
  return best;
}

const NODE_MARK_W = 16;                    // room the "from an included file" glyph needs, top-left

function boxWidth(name, hasBadge, hasMark) {
  const w = NODE_PAD_X * 2 + name.length * NODE_CHAR_W + (hasBadge ? NODE_BADGE_W : 0) + (hasMark ? NODE_MARK_W : 0);
  return Math.max(NODE_MIN_W, Math.min(NODE_MAX_W, Math.round(w)));
}

/** Every OTHER node this one has a real scheduling dependency on, for LAYOUT
 *  only: the union of Requires and After. Deliberately the union, unlike the
 *  two DISPLAYED edge kinds -- only Requires is proven dataflow, but a node's
 *  POSITION should reflect every real ordering constraint, tagged or not. */
function dependencyTargets(graph, node, resolve) {
  const seen = new Set();
  const out = [];
  for (const token of node.requires.concat(node.after)) {
    for (const r of resolve(token)) {
      if (graph.nodes.has(r) && !seen.has(r)) { seen.add(r); out.push(r); }
    }
  }
  return out;
}

/** Displayed edges, kept separate from the layout union: Requires is
 *  dataflow, After is order-only. Drawing them alike would erase exactly the
 *  distinction the tool exists to show. */
export function buildEdges(graph) {
  const edges = [];
  const seen = new Set();
  for (const [name, node] of graph.nodes) {
    for (const [tokens, kind] of [[node.requires, "dataflow"], [node.after, "order"]]) {
      for (const token of tokens) {
        for (const from of graph.resolveRef(token)) {
          if (from === name || !graph.nodes.has(from)) continue;
          const key = from + "" + name + "" + kind;
          if (seen.has(key)) continue;
          seen.add(key);
          edges.push({ from, to: name, kind });
        }
      }
    }
  }
  return edges;
}

/** Longest-path rank over the layout dependency union, shared across the
 *  whole graph so the same column lines up between lanes. Iterative: a
 *  browser stack is smaller than Python's and a wide graph is ordinary. */
function computeRanks(graph, resolve) {
  const preds = new Map();
  for (const [name, node] of graph.nodes) preds.set(name, dependencyTargets(graph, node, resolve));

  const rank = new Map();
  const state = new Map();     // 0 unvisited, 1 in progress, 2 done
  for (const name of graph.nodes.keys()) {
    const stack = [name];
    while (stack.length) {
      const cur = stack[stack.length - 1];
      if (state.get(cur) === 2) { stack.pop(); continue; }
      if (state.get(cur) === 1) {
        let r = 0;
        for (const p of preds.get(cur) || []) {
          if (state.get(p) === 2) r = Math.max(r, rank.get(p) + 1);
        }
        rank.set(cur, r);
        state.set(cur, 2);
        stack.pop();
        continue;
      }
      state.set(cur, 1);
      for (const p of preds.get(cur) || []) {
        // R38 proves a real cycle is impossible; this is defence in depth.
        if (!state.get(p)) stack.push(p);
        else if (state.get(p) === 1 && !rank.has(p)) rank.set(p, 0);
      }
    }
  }
  return rank;
}

/**
 * Rows for one lane: subtree banding, least-entangled siblings first, then
 * corridor reservation for rank-skipping wires.
 *
 * Cost, stated plainly: a lane is now about as tall as it has leaves, where
 * a naive layout is as tall as its widest rank. That is the price of not
 * routing wires through boxes -- and lanes collapse.
 */
function assignRows(graph, laneNodes, ranks, colX, colW, widths, resolve) {
  const inLane = new Set(laneNodes);
  const order = new Map(laneNodes.map((n, i) => [n, i]));

  // children[x] = nodes in THIS lane that depend on x.
  const children = new Map(laneNodes.map((n) => [n, []]));
  const edges = [];
  for (const name of laneNodes) {
    for (const dep of dependencyTargets(graph, graph.nodes.get(name), resolve)) {
      if (inLane.has(dep) && dep !== name && !children.get(dep).includes(name)) {
        children.get(dep).push(name);
        edges.push([dep, name]);
      }
    }
  }

  const rankOf = (n) => ranks.get(n) ?? 0;

  const laneProduced = new Set();
  for (const n of laneNodes) {
    const node = graph.nodes.get(n);
    for (const t of node.produces) laneProduced.add(t.toLowerCase());
    for (const t of node.creates) laneProduced.add(t.toLowerCase());
  }

  /* How entangled a node is, for sibling ordering. IN-LANE counts come
   * first, and that ordering is the whole point: only an in-lane dependency
   * becomes a wire drawn IN this lane, and in-lane wires are the only ones
   * row allocation can do anything about. A node with six cross-agent
   * Requires and one local one is, as far as this lane's picture goes, a
   * SIMPLE node -- ranking it by global totals would sink it to the bottom
   * on account of wires drawn somewhere else.
   *
   * Reach is NEGATED so the longest sorts first: a wire that skips columns
   * has everything between its ends in its way, so putting its source at the
   * top of the band runs it along the lane's edge where there is nothing to
   * cross. */
  const weights = new Map();
  for (const n of laneNodes) {
    const node = graph.nodes.get(n);
    let reach = 0;
    for (const c of children.get(n)) reach = Math.max(reach, rankOf(c) - rankOf(n));
    let localReq = 0;
    for (const token of node.requires) {
      if (resolve(token).some((r) => inLane.has(r))) localReq++;
    }
    let localCon = 0;
    for (const tag of node.consumes) if (laneProduced.has(tag.toLowerCase())) localCon++;
    weights.set(n, [localReq, localCon, node.requires.length, node.consumes.length, -reach]);
  }
  const weightOf = (n) => weights.get(n) || [0, 0, 0, 0, 0];

  const cmpTuple = (a, b) => {
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      const x = a[i] ?? 0, y = b[i] ?? 0;
      if (x !== y) return x - y;
    }
    return 0;
  };
  const siblingKey = (n) => [...weightOf(n), rankOf(n), order.get(n) ?? 0];

  for (const kids of children.values()) {
    kids.sort((a, b) => cmpTuple(siblingKey(a), siblingKey(b)));
  }

  // Subtree banding: a parent centres on its dependents' band.
  const base = new Map();
  let cursor = 0;
  const visiting = new Set();
  const place = (name) => {
    if (base.has(name)) return base.get(name);
    if (visiting.has(name)) return null;      // cycle: break, do not recurse
    visiting.add(name);
    const kidRows = [];
    for (const c of children.get(name) || []) {
      const r = place(c);
      if (r !== null) kidRows.push(r);
    }
    visiting.delete(name);
    let row;
    if (kidRows.length) row = (Math.min(...kidRows) + Math.max(...kidRows)) / 2;
    else { row = cursor; cursor += 1; }
    base.set(name, row);
    return row;
  };

  // Roots go through the SAME least-entangled-first ordering as any other
  // sibling set. A lane's top-level nodes ARE siblings of each other, and the
  // first one walked claims the whole downstream subtree and the top band
  // with it -- so exempting them would let declaration order decide the shape
  // of everything below.
  const hasParent = new Set();
  for (const kids of children.values()) for (const c of kids) hasParent.add(c);
  const roots = laneNodes.filter((n) => !hasParent.has(n))
    .sort((a, b) => cmpTuple(siblingKey(a), siblingKey(b)));
  for (const n of roots) place(n);
  for (const n of laneNodes) place(n);       // isolated nodes, cycle members

  const byRank = new Map();
  for (const n of laneNodes) {
    const r = rankOf(n);
    if (!byRank.has(r)) byRank.set(r, []);
    byRank.get(r).push(n);
  }

  /* Corridors for wires that SKIP a rank.
   *
   * Banding keeps a wire clear of its siblings' boxes but can do nothing
   * about an edge spanning rank 0 to rank 2: that wire crosses rank 1
   * wherever rank 1 happens to be. The corridor has to be where the WIRE is
   * -- the row band it occupies while inside the crossed COLUMN -- not the
   * target's row. Anchoring it to the target is wrong in a way that looks
   * right.
   *
   * Sampled off the real cubic, not interpolated in rank space: columns are
   * packed to their own contents and are not evenly spaced, so the curve's
   * midpoint in `t` is not where the crossed column sits.
   */
  const obstaclesFrom = (rows) => {
    const out = new Map();
    for (const [dep, name] of edges) {
      if (rankOf(name) - rankOf(dep) <= 1) continue;
      const ax = colX.get(rankOf(dep)) + widths.get(dep);
      const bx = colX.get(rankOf(name));
      const ay = (rows.get(dep) ?? 0) * ROW_H;
      const by = (rows.get(name) ?? 0) * ROW_H;
      const tang = splineTangent(bx - ax, by - ay) / 3;
      const c1x = ax + tang, c2x = bx - tang;
      const spans = [];
      for (let r = rankOf(dep) + 1; r < rankOf(name); r++) {
        spans.push([r, colX.get(r), colX.get(r) + colW.get(r)]);
      }
      const lo = new Map(), hi = new Map();
      for (let i = 0; i <= 64; i++) {
        const t = i / 64, u = 1 - t;
        const x = u * u * u * ax + 3 * u * u * t * c1x + 3 * u * t * t * c2x + t * t * t * bx;
        const y = u * u * u * ay + 3 * u * u * t * ay + 3 * u * t * t * by + t * t * t * by;
        const row = y / ROW_H;
        for (const [r, x0, x1] of spans) {
          if (x >= x0 && x <= x1) {
            lo.set(r, Math.min(lo.has(r) ? lo.get(r) : row, row));
            hi.set(r, Math.max(hi.has(r) ? hi.get(r) : row, row));
          }
        }
      }
      for (const [r] of spans) {
        if (!lo.has(r)) continue;
        if (!out.has(r)) out.set(r, []);
        out.get(r).push([lo.get(r), hi.get(r)]);
      }
    }
    return out;
  };

  /* Place every box at the nearest free row at or below its banded row.
   * TWO clearances, because they guard different things: a box must not
   * overlap another BOX (a full row), but only has to clear a WIRE by half a
   * box height. */
  const separate = (obstacles) => {
    const out = new Map();
    for (const [rank, names] of byRank) {
      const wires = obstacles.get(rank) || [];
      const boxes = [];
      // Ties on the banded row are common -- two parents centred over the
      // same subtree land on exactly the same row -- so the tie goes to the
      // SAME least-entangled key used everywhere else, not to declaration
      // order. A rule that stops applying where it decides something is not
      // a rule.
      const ordered = [...names].sort((a, b) =>
        (base.get(a) - base.get(b)) || cmpTuple(weightOf(a), weightOf(b)) ||
        (order.get(a) - order.get(b)));
      for (const name of ordered) {
        let want = base.get(name);
        for (let guard = 0; guard < 64; guard++) {   // each step clears one blocker
          let push = null;
          for (const b of boxes) {
            if (Math.abs(want - b) < 1) push = push === null ? b + 1 : Math.max(push, b + 1);
          }
          for (const [lo, hi] of wires) {
            if (want > lo - WIRE_CLEARANCE && want < hi + WIRE_CLEARANCE) {
              const edge = hi + WIRE_CLEARANCE;
              push = push === null ? edge : Math.max(push, edge);
            }
          }
          if (push === null) break;
          want = push;
        }
        out.set(name, want);
        boxes.push(want);
      }
    }
    return out;
  };

  // Iterate: obstacles from the last pass, boxes re-placed from their
  // ORIGINAL banded rows each round -- never from the previous pass's, or a
  // box nudged down once keeps drifting down for ever. Converges in a couple
  // of rounds; the cap is a backstop against a shape that oscillates.
  let rows = separate(new Map());
  for (let i = 0; i < 4; i++) {
    const next = separate(obstaclesFrom(rows));
    let same = next.size === rows.size;
    if (same) for (const [k, v] of next) if (rows.get(k) !== v) { same = false; break; }
    if (same) break;
    rows = next;
  }

  if (rows.size) {
    const top = Math.min(...rows.values());
    for (const k of rows.keys()) rows.set(k, rows.get(k) - top);   // lane starts at row 0
  }
  return rows;
}

/**
 * Lane boxes, node rectangles and edges.
 *
 * @param graph     Graph
 * @param warnNodes Set of node names carrying a warn+ finding -- an INPUT to
 *                  width, since the badge reserves room, not decoration
 *                  applied afterwards
 * @param collapsed Set of agent names to draw folded
 */
/** @param markedNodes  nodes that carry the "from an included file" glyph
 *  before their name; the box widens by NODE_MARK_W for them so the name
 *  never prints over it. */
export function layout(graph, warnNodes, collapsed, markedNodes = new Set()) {
  const isCollapsed = (n) => !!(collapsed && collapsed.has(n));

  // resolveRef walks every node per token, and Requires lists repeat the same
  // tokens across a lane constantly -- memoised so the ordering below stays
  // linear-ish rather than quadratic on a thousand-node graph.
  const resolvedCache = new Map();
  const resolve = (token) => {
    if (!resolvedCache.has(token)) resolvedCache.set(token, graph.resolveRef(token));
    return resolvedCache.get(token);
  };

  const edges = buildEdges(graph);
  const ranks = computeRanks(graph, resolve);

  const widths = new Map();
  for (const name of graph.nodes.keys()) widths.set(name, boxWidth(name, warnNodes.has(name), markedNodes.has(name)));

  const colW = new Map();
  for (const name of graph.nodes.keys()) {
    const col = ranks.get(name) ?? 0;
    colW.set(col, Math.max(colW.get(col) ?? NODE_MIN_W, widths.get(name)));
  }
  const colX = new Map();
  let running = MARGIN_X;
  for (const col of [...colW.keys()].sort((a, b) => a - b)) {
    colX.set(col, running);
    running += colW.get(col) + COL_GAP;
  }
  const totalWidth = colX.size ? Math.max(running - COL_GAP + MARGIN_X, 400) : 400;

  const lanes = [];
  const nodePos = new Map();
  let y = 0;

  for (const [agentName, nodeNames] of graph.agents) {
    const present = nodeNames.filter((n) => graph.nodes.has(n));

    // A collapsed lane keeps its header and its node COUNT, and contributes
    // no node positions. Keeping the count is what stops folding being a lie.
    if (isCollapsed(agentName)) {
      lanes.push({ name: agentName, y, height: COLLAPSED_H, count: present.length, collapsed: true });
      y += COLLAPSED_H + LANE_GAP;
      continue;
    }

    const rows = assignRows(graph, present, ranks, colX, colW, widths, resolve);
    let maxRow = 0;
    for (const name of present) {
      const rank = ranks.get(name) ?? 0;
      const row = rows.get(name) ?? 0;
      nodePos.set(name, {
        x: colX.get(rank),
        y: y + LANE_HEADER_H + LANE_PAD / 2 + row * ROW_H,
        w: widths.get(name),
        h: NODE_H,
        rank,
        row,
        agent: agentName,
      });
      maxRow = Math.max(maxRow, row + 1);
    }
    const laneH = LANE_HEADER_H + LANE_PAD + Math.max(maxRow, 1) * ROW_H;
    lanes.push({ name: agentName, y, height: laneH, count: present.length, collapsed: false });
    y += laneH + LANE_GAP;
  }

  return { lanes, nodePos, edges, rank: ranks, width: totalWidth, height: y, labelW: MARGIN_X };
}

/** A Blueprint-style wire, using the same tangent policy the corridor
 *  sampling assumes -- so what is drawn and what was reserved for agree. */
export function edgePath(a, b) {
  const x1 = a.x + a.w, y1 = a.y + a.h / 2;
  const x2 = b.x, y2 = b.y + b.h / 2;
  const t = splineTangent(x2 - x1, y2 - y1) / 3;
  return `M ${x1.toFixed(1)} ${y1.toFixed(1)} C ${(x1 + t).toFixed(1)} ${y1.toFixed(1)}, ` +
         `${(x2 - t).toFixed(1)} ${y2.toFixed(1)}, ${x2.toFixed(1)} ${y2.toFixed(1)}`;
}
