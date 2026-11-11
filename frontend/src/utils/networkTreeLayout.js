/**
 * networkTreeLayout.js: PURE layout of a measured tree (the routers and switches a network agent
 * read, GET /network/map nodes and edges) inside its network's band on the Network map. No React,
 * no DOM.
 *
 * Routers, switches, neighbours and VLAN groups form a top-down tidy tree: each subtree gets the
 * width it needs and its parent sits over the middle of it. The devices under one parent do not
 * each get a node and a line: they go in ONE box below it, a list of BOX_MAX devices until it is
 * opened, so a switch with 40 devices is as wide as one with 2. The box sits left of the parent's
 * branches, one level down.
 */

export const NODE_W = 168
export const NODE_H = 52
export const BOX_W = 236
export const BOX_HEAD = 30      // the box's title line
export const BOX_ROW = 40       // one device in the box
export const BOX_MAX = 6        // devices a closed box lists
export const GAP_X = 28
export const ROW = 104          // from a node's top to its children's top
export const PAD = 12

const byLabel = (tree) => (a, b) => tree.nodes.get(a).label.localeCompare(tree.nodes.get(b).label, undefined, { numeric: true })

/**
 * @param {string[]} roots  the trees drawn in one band (their root node ids)
 * @param {{nodes: Map, children: Map, edge: Map}} tree  NetworkBands.treeIndex
 * @param {Set<string>} openBoxes  parents whose device box lists every device
 * @returns {{nodes: object[], boxes: object[], edges: object[], width: number, height: number}}
 *   nodes {id, left, top}; boxes {parent, devices: id[], shown, hidden, left, top, height};
 *   edges {kind, ports, x1, y1, x2, y2} from the bottom middle of the parent to the top middle of the child
 */
export function layoutTree(roots, tree, openBoxes = new Set()) {
  const order = byLabel(tree)
  const kidsOf = (id) => tree.children.get(id) ?? []
  const branches = (id) => kidsOf(id).filter((k) => tree.nodes.get(k).kind !== 'device').sort(order)
  const devices = (id) => kidsOf(id).filter((k) => tree.nodes.get(k).kind === 'device').sort(order)
  const boxHeight = (count, shown) => BOX_HEAD + shown * BOX_ROW + (count > shown ? BOX_ROW : 0) + 8

  const width = new Map()
  const measure = (id) => {
    const box = devices(id).length ? BOX_W + GAP_X : 0
    const w = Math.max(NODE_W + GAP_X, box + branches(id).reduce((s, k) => s + measure(k), 0))
    width.set(id, w)
    return w
  }

  const nodes = [], boxes = [], edges = []
  let bottom = 0
  const place = (id, left, top) => {
    const w = width.get(id)
    const cx = left + w / 2
    nodes.push({ id, left: cx - NODE_W / 2, top })
    bottom = Math.max(bottom, top + NODE_H)
    let cursor = left
    const devs = devices(id)
    if (devs.length) {
      const shown = openBoxes.has(id) ? devs.length : Math.min(devs.length, BOX_MAX)
      const height = boxHeight(devs.length, shown)
      const box = { parent: id, devices: devs, shown, hidden: devs.length - shown, left: cursor, top: top + ROW, height }
      boxes.push(box)
      const first = tree.edge.get(`${id}>${devs[0]}`)
      edges.push({ kind: first?.kind ?? 'port', ports: null, x1: cx, y1: top + NODE_H, x2: cursor + BOX_W / 2, y2: top + ROW })
      bottom = Math.max(bottom, box.top + height)
      cursor += BOX_W + GAP_X
    }
    for (const k of branches(id)) {
      const kw = width.get(k)
      const link = tree.edge.get(`${id}>${k}`)
      const ports = link && (link.parentPort || link.childPort) ? [link.parentPort, link.childPort].filter(Boolean).join(' – ') : null
      edges.push({ kind: link?.kind ?? 'cable', ports, x1: cx, y1: top + NODE_H, x2: cursor + kw / 2, y2: top + ROW })
      place(k, cursor, top + ROW)
      cursor += kw
    }
  }

  let left = PAD
  for (const r of [...roots].sort(order)) {
    measure(r)
    place(r, left, PAD)
    left += width.get(r)
  }
  return { nodes, boxes, edges, width: left + PAD, height: bottom + PAD }
}
