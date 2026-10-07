/**
 * graphLayout.js — PURE layered-by-tier layout for the relationship graph (no React,
 * no canvas), so it can be unit-tested with mock graphs (scripts/graph-layout-demo.ts).
 *
 * Vertical: one row per distinct topology layer present in the data (compact — no empty
 * rows), lowest layer on top. A node's `layer == null` falls back to the HOST tier: it
 * shares the row of the host layers if any exist, otherwise a row just below the last
 * real tier. Peers (same layer, same component) therefore share a y.
 *
 * Horizontal: connected components are laid out in disjoint left-to-right bands (no
 * overlap). Within a band, rows are placed top-down; a node's x is the barycenter of its
 * already-placed neighbours in the rows above (so a host linked to two gateways sits
 * between them), pushed right only as far as the minimum spacing requires. Ties break by
 * IP. Output is deterministic.
 *
 * Nodes with no edges go in a separate wrapped band at the bottom (the "No known
 * relationships" band), never in a tier row.
 */

export const NODE_SEP = 130   // min horizontal gap between node centres
export const ROW_SEP  = 120   // vertical gap between tiers
export const PAD      = 60
export const BAND_GAP = NODE_SEP * 2   // gap between connected components
export const ISO_GAP  = 90    // gap above the isolated band

const ipToNum = (ip) =>
  (typeof ip === 'string' && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip))
    ? ip.split('.').reduce((a, o) => a * 256 + (+o), 0)
    : Number.MAX_SAFE_INTEGER

/**
 * @param {{id:string, layer:number|null, ip?:string, deviceType?:string}[]} nodes
 * @param {{source:string, target:string}[]} edges
 * @param {{width?:number}} [opts]
 * @returns {{ pos: Map<string,{x:number,y:number,rank:number,isolated:boolean}>,
 *            tiers: {layer:number|null,y:number}[], isolatedBandY:number, hasIsolated:boolean }}
 */
export function layoutGraph(nodes, edges, opts = {}) {
  const width = opts.width ?? 900
  const adj = new Map(nodes.map(n => [n.id, []]))
  for (const e of edges) {
    if (adj.has(e.source) && adj.has(e.target) && e.source !== e.target) {
      adj.get(e.source).push(e.target)
      adj.get(e.target).push(e.source)
    }
  }
  const ipOf = new Map(nodes.map(n => [n.id, ipToNum(n.ip)]))
  const connected = nodes.filter(n => adj.get(n.id).length > 0)
  const isolated  = nodes.filter(n => adj.get(n.id).length === 0)

  // ── Tiers: distinct layers present among connected nodes (null → one tier below). ──
  const HOST_FALLBACK = Number.POSITIVE_INFINITY
  const layerVal = (n) => (n.layer == null ? HOST_FALLBACK : n.layer)
  const distinct = [...new Set(connected.map(layerVal))].sort((a, b) => a - b)
  const rankOf = new Map(distinct.map((l, i) => [l, i]))
  const rank = (n) => rankOf.get(layerVal(n)) ?? 0

  // ── Connected components (BFS over undirected adjacency). ──
  const comp = new Map()
  let cid = 0
  for (const n of connected) {
    if (comp.has(n.id)) continue
    const q = [n.id]; comp.set(n.id, cid)
    while (q.length) { const x = q.shift(); for (const m of adj.get(x)) if (!comp.has(m)) { comp.set(m, cid); q.push(m) } }
    cid++
  }
  // Component order: by lowest IP in the component (deterministic).
  const compMinIp = new Map()
  for (const n of connected) {
    const c = comp.get(n.id), v = ipOf.get(n.id)
    if (!compMinIp.has(c) || v < compMinIp.get(c)) compMinIp.set(c, v)
  }
  const compOrder = [...new Set(connected.map(n => comp.get(n.id)))]
    .sort((a, b) => compMinIp.get(a) - compMinIp.get(b))

  const pos = new Map()

  // ── Lay out each component in its own horizontal band, left → right. ──
  let bandLeft = PAD
  for (const c of compOrder) {
    const cNodes = connected.filter(n => comp.get(n.id) === c)
    const byRank = new Map()
    for (const n of cNodes) {
      const r = rank(n)
      if (!byRank.has(r)) byRank.set(r, [])
      byRank.get(r).push(n)
    }
    const localX = new Map()
    let bandWidth = 0
    for (const r of [...byRank.keys()].sort((a, b) => a - b)) {
      const row = byRank.get(r)
      const desired = (n) => {
        const placed = adj.get(n.id).filter(m => localX.has(m))
        if (!placed.length) return null
        return placed.reduce((s, m) => s + localX.get(m), 0) / placed.length
      }
      row.sort((a, b) => {
        const da = desired(a), db = desired(b)
        if (da != null && db != null && da !== db) return da - db
        if (da != null && db == null) return -1
        if (da == null && db != null) return 1
        return ipOf.get(a.id) - ipOf.get(b.id)
      })
      let x = 0
      for (const n of row) {
        const d = desired(n)
        x = d != null ? Math.max(d, x) : x   // keep barycenter, but never overlap
        localX.set(n.id, x)
        bandWidth = Math.max(bandWidth, x)
        x += NODE_SEP
      }
    }
    for (const n of cNodes) {
      pos.set(n.id, { x: bandLeft + (localX.get(n.id) ?? 0), y: PAD + rank(n) * ROW_SEP, rank: rank(n), isolated: false })
    }
    bandLeft += bandWidth + BAND_GAP
  }

  // ── Isolated nodes: wrapped band at the bottom. ──
  const isolatedBandY = PAD + Math.max(1, distinct.length) * ROW_SEP + ISO_GAP
  const perRow = Math.max(1, Math.floor((width - 2 * PAD) / NODE_SEP))
  isolated.sort((a, b) => ipOf.get(a.id) - ipOf.get(b.id))
  isolated.forEach((n, i) => {
    pos.set(n.id, {
      x: PAD + (i % perRow) * NODE_SEP,
      y: isolatedBandY + Math.floor(i / perRow) * ROW_SEP,
      rank: -1, isolated: true,
    })
  })

  const tiers = distinct.map((l, i) => ({ layer: l === HOST_FALLBACK ? null : l, y: PAD + i * ROW_SEP }))
  return { pos, tiers, isolatedBandY, hasIsolated: isolated.length > 0 }
}
