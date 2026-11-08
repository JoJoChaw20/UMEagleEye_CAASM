/**
 * networkMapLayout.js: PURE layout of the network map (GET /network/map; the server's tree
 * is in workers/src/lib/networkMap.ts). No React, no DOM, so scripts can check it.
 *
 * Routers, switches, neighbours and VLAN groups form a top-down tidy tree: each subtree
 * gets the width it needs and its parent sits over the middle of it. The devices under one
 * parent are leaves; they go in a grid of up to LEAF_COLS columns just below it, and when
 * there are more than MAX_LEAVES they collapse into one "+N devices" node until expanded.
 * Separate parts of the network sit side by side.
 */

export const NODE_W = 150
export const NODE_H = 48
export const GAP_X = 24
export const ROW = 110          // between tree levels
export const LEAF_ROW = 70      // between rows of a device grid
export const LEAF_COLS = 4
export const MAX_LEAVES = 8
export const PAD = 40

const isLeaf = (n) => n.kind === 'device'

/**
 * @param {{nodes: object[], edges: object[]}} map  from GET /network/map
 * @param {Set<string>} expanded  parents whose devices are all shown
 * @returns {{nodes: object[], edges: object[], width: number, height: number}}
 */
export function layoutNetworkMap(map, expanded = new Set()) {
  const byId = new Map(map.nodes.map((n) => [n.id, n]))
  const kids = new Map()
  for (const n of map.nodes) {
    if (n.parent && byId.has(n.parent)) {
      if (!kids.has(n.parent)) kids.set(n.parent, [])
      kids.get(n.parent).push(n)
    }
  }
  const byLabel = (a, b) => a.label.localeCompare(b.label, undefined, { numeric: true })
  for (const list of kids.values()) list.sort(byLabel)

  // what each parent shows: its tree children, and its leaves (maybe collapsed)
  const visible = new Map()
  const hiddenOf = new Map()
  for (const [parent, list] of kids) {
    const branches = list.filter((n) => !isLeaf(n))
    let leaves = list.filter(isLeaf)
    if (leaves.length > MAX_LEAVES && !expanded.has(parent)) {
      const shown = leaves.slice(0, MAX_LEAVES - 1)
      const more = { id: `more:${parent}`, kind: 'more', label: `+${leaves.length - shown.length} devices`,
                     parent, count: leaves.length - shown.length, asset_id: null }
      hiddenOf.set(parent, leaves.slice(shown.length).map((n) => n.id))
      leaves = [...shown, more]
    }
    visible.set(parent, { branches, leaves })
  }

  // widths: a leaf grid is LEAF_COLS wide at most; branches sit side by side
  const width = new Map()
  const gridCols = (n) => Math.min(LEAF_COLS, n)
  const unit = NODE_W + GAP_X
  const measure = (id) => {
    const v = visible.get(id) ?? { branches: [], leaves: [] }
    const grid = v.leaves.length ? gridCols(v.leaves.length) * unit : 0
    const branches = v.branches.reduce((s, b) => s + measure(b.id), 0)
    const w = Math.max(unit, grid + branches)
    width.set(id, w)
    return w
  }

  const placed = new Map()
  const place = (node, left, y) => {
    const w = width.get(node.id)
    placed.set(node.id, { ...node, x: left + w / 2, y })
    const v = visible.get(node.id) ?? { branches: [], leaves: [] }
    let cursor = left
    if (v.leaves.length) {
      const cols = gridCols(v.leaves.length)
      v.leaves.forEach((leaf, i) => {
        const col = i % cols, row = Math.floor(i / cols)
        placed.set(leaf.id, { ...leaf, x: cursor + col * unit + unit / 2, y: y + ROW + row * LEAF_ROW, leaf: true })
      })
      cursor += cols * unit
    }
    for (const b of v.branches) {                    // beside the device grid, one level down
      place(b, cursor, y + ROW)
      cursor += width.get(b.id)
    }
  }

  const rootRank = { router: 0, switch: 1, neighbour: 2, vlan: 3, device: 4 }
  const roots = map.nodes.filter((n) => !n.parent || !byId.has(n.parent))
    .sort((a, b) => (rootRank[a.kind] ?? 9) - (rootRank[b.kind] ?? 9) || byLabel(a, b))
  let left = PAD
  for (const r of roots) {
    measure(r.id)
    place(r, left, PAD + NODE_H / 2)
    left += width.get(r.id) + unit
  }

  // edges between drawn nodes; a hidden device's edge is redrawn to its "+N" node
  const hidden = new Map()
  for (const [parent, ids] of hiddenOf) for (const id of ids) hidden.set(id, `more:${parent}`)
  const edges = []
  const seenMore = new Set()
  for (const e of map.edges) {
    const to = hidden.get(e.to) ?? e.to
    if (to !== e.to) {
      if (seenMore.has(to)) continue
      seenMore.add(to)
    }
    const a = placed.get(e.from), b = placed.get(to)
    if (!a || !b) continue
    edges.push({ ...e, to, x1: a.x, y1: a.y, x2: b.x, y2: b.y, collapsed: to !== e.to })
  }

  let maxX = 0, maxY = 0
  for (const p of placed.values()) { maxX = Math.max(maxX, p.x); maxY = Math.max(maxY, p.y) }
  return { nodes: [...placed.values()], edges, width: maxX + NODE_W / 2 + PAD, height: maxY + NODE_H / 2 + PAD }
}
