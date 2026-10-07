/**
 * graph-mock.ts — small, generic mock graphs for testing graph traversal/plotting.
 *
 * NO real hostnames or IPs (synthetic lab addresses only). Shared by
 * blast-radius-demo.ts now and the later topology/plotting review, so keep the
 * shapes generic and well described rather than tied to any one test.
 *
 * Node device_type uses the production enum values: server | workstation | network
 * | iot | unknown. 'network' is the only infrastructure type (topology turns it into
 * gateway/router/switch/access_point), so it is what the blast-radius hub brake keys on.
 */

export interface MockNode {
  assetId:          string
  hostname:         string
  ip:               string
  deviceType:       'server' | 'workstation' | 'network' | 'iot' | 'unknown'
  inMyAssets:       boolean
  criticalityScore?: number
}
export interface MockEdge {
  source: string
  target: string
  type:   string   // connects_to | depends_on | same_subnet | <anything else>
}
export interface MockGraph {
  name:  string
  nodes: MockNode[]
  edges: MockEdge[]
}

const node = (
  id: string,
  deviceType: MockNode['deviceType'],
  opts: { inMyAssets?: boolean; ip?: string; crit?: number } = {},
): MockNode => ({
  assetId: id,
  hostname: `host-${id}`,
  ip: opts.ip ?? `10.0.0.${(parseInt(id.replace(/\D/g, ''), 10) || 0) % 254 + 1}`,
  deviceType,
  inMyAssets: opts.inMyAssets ?? true,
  criticalityScore: opts.crit ?? 5,
})

// ── TREE ──────────────────────────────────────────────────────────
// core ─connects_to→ dist1, dist2 ; dist1 ─connects_to→ leaf1, leaf2 ;
// dist2 ─connects_to→ leaf3, leaf4. Impact flows source→target, so downstream from
// core = everything below, a leaf has no downstream, and upstream from a leaf = its
// chain back to core. Deliberately all 'server' (low degree, not gateway-type) so
// this fixture exercises DIRECTION only — the hub brake is covered by `star()`.
export const TREE: MockGraph = {
  name: 'tree',
  nodes: [
    node('core', 'server'),
    node('dist1', 'server'), node('dist2', 'server'),
    node('leaf1', 'server'), node('leaf2', 'server'),
    node('leaf3', 'server'), node('leaf4', 'server'),
  ],
  edges: [
    { source: 'core', target: 'dist1', type: 'connects_to' },
    { source: 'core', target: 'dist2', type: 'connects_to' },
    { source: 'dist1', target: 'leaf1', type: 'connects_to' },
    { source: 'dist1', target: 'leaf2', type: 'connects_to' },
    { source: 'dist2', target: 'leaf3', type: 'connects_to' },
    { source: 'dist2', target: 'leaf4', type: 'connects_to' },
  ],
}

// ── STAR ──────────────────────────────────────────────────────────
// One network hub with `spokeCount` server spokes, hub ─connects_to→ spoke.
export function star(spokeCount = 30): MockGraph {
  const nodes: MockNode[] = [node('hub', 'network')]
  const edges: MockEdge[] = []
  for (let i = 0; i < spokeCount; i++) {
    const id = `spoke${i}`
    nodes.push(node(id, 'server'))
    edges.push({ source: 'hub', target: id, type: 'connects_to' })
  }
  return { name: `star-${spokeCount}`, nodes, edges }
}

// ── DUAL GATEWAY ──────────────────────────────────────────────────
// Primary + backup gateway (network), both ─connects_to→ the same child (server).
// Downstream from either gateway reaches the child; the OTHER gateway is never reached.
export const DUAL_GATEWAY: MockGraph = {
  name: 'dual-gateway',
  nodes: [node('gwA', 'network'), node('gwB', 'network'), node('child', 'server')],
  edges: [
    { source: 'gwA', target: 'child', type: 'connects_to' },
    { source: 'gwB', target: 'child', type: 'connects_to' },
  ],
}

// ── DEPENDS_ON ────────────────────────────────────────────────────
// app (server) depends_on db (server): if db fails, app is impacted → impact flows
// target→source. Same stored pair as a connects_to control to show the reversal.
export const DEPENDS: MockGraph = {
  name: 'depends',
  nodes: [node('app', 'server'), node('db', 'server')],
  edges: [{ source: 'app', target: 'db', type: 'depends_on' }],
}
export const CONNECTS_CONTROL: MockGraph = {
  name: 'connects-control',
  nodes: [node('app', 'server'), node('db', 'server')],
  edges: [{ source: 'app', target: 'db', type: 'connects_to' }],
}

// ── MIXED TYPES ───────────────────────────────────────────────────
// a ─same_subnet→ b (never traversed), a ─mystery_link→ c (unknown → skipped_types),
// a ─connects_to→ d (traversed).
export const MIXED_TYPES: MockGraph = {
  name: 'mixed-types',
  nodes: [node('a', 'server'), node('b', 'server'), node('c', 'server'), node('d', 'server')],
  edges: [
    { source: 'a', target: 'b', type: 'same_subnet' },
    { source: 'a', target: 'c', type: 'mystery_link' },
    { source: 'a', target: 'd', type: 'connects_to' },
  ],
}

// ── NON-MEMBER IN THE MIDDLE ──────────────────────────────────────
// m1 → gap(non-member) → m2, all connects_to. The gap breaks both edges (both
// endpoints must be members), so m1 reaches nothing and m2 is unreachable.
export const BROKEN_CHAIN: MockGraph = {
  name: 'broken-chain',
  nodes: [node('m1', 'server'), node('gap', 'server', { inMyAssets: false }), node('m2', 'server')],
  edges: [
    { source: 'm1', target: 'gap', type: 'connects_to' },
    { source: 'gap', target: 'm2', type: 'connects_to' },
  ],
}

// ── NON-MEMBER START ──────────────────────────────────────────────
export const NON_MEMBER_START: MockGraph = {
  name: 'non-member-start',
  nodes: [node('out', 'server', { inMyAssets: false }), node('in', 'server')],
  edges: [{ source: 'out', target: 'in', type: 'connects_to' }],
}

// ── CYCLE ─────────────────────────────────────────────────────────
// a → b → c → a (connects_to). Traversal must terminate, each node once.
export const CYCLE: MockGraph = {
  name: 'cycle',
  nodes: [node('a', 'server'), node('b', 'server'), node('c', 'server')],
  edges: [
    { source: 'a', target: 'b', type: 'connects_to' },
    { source: 'b', target: 'c', type: 'connects_to' },
    { source: 'c', target: 'a', type: 'connects_to' },
  ],
}

// ── LINE ──────────────────────────────────────────────────────────
// n0 → n1 → … → n(len-1), all connects_to (server). For the depth-cap test.
export function line(len = 8): MockGraph {
  const nodes: MockNode[] = []
  const edges: MockEdge[] = []
  for (let i = 0; i < len; i++) {
    nodes.push(node(`n${i}`, 'server'))
    if (i > 0) edges.push({ source: `n${i - 1}`, target: `n${i}`, type: 'connects_to' })
  }
  return { name: `line-${len}`, nodes, edges }
}
