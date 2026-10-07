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

// ═══════════════════════════════════════════════════════════════════════════
// Classification / topology scenarios for classification-topology-demo.ts.
// RAW inputs are fed through the CURRENT (unchanged) pipeline: inferDeviceType →
// classifyAsset → resolveParent → classifyRelType → computeCriticality. Each asset
// carries the OWNER'S EXPECTATION from normal network logic (gateways above hosts,
// peers side by side, endpoints are leaves) so the harness can mark EXPECTED / WRONG.
// Generic synthetic hostnames/IPs only.
// ═══════════════════════════════════════════════════════════════════════════

export interface MockPort { port: number; product?: string; service?: string; protocol?: string }
export interface ClassAsset {
  id:        string
  hostname:  string | null
  ip:        string
  ports?:    MockPort[]
  os?:       Record<string, unknown> | null  // OS/DHCP hint for inferDeviceType fallback
  vendor?:   string | null
  owner?:    string | null
  internetFacingOverride?: boolean | null  // analyst override; null/absent = infer from gateway
  // Owner expectation (normal network logic):
  expectNodeType?: 'gateway' | 'router' | 'switch' | 'access_point' | 'host'
  expectRoot?: boolean     // belongs at the top (no parent)
  expectLeaf?: boolean     // endpoint — should have no children
  why?:        string
}
export interface ClassScenario {
  name:            string
  expectation:     string
  gatewayReported: string | null   // agent's reported default gateway (null = none reported)
  assets:          ClassAsset[]
}

// S1 — gateway pair. Agent reported NO gateway, so the '.1/.254' fallbacks fire. The
// end host at .1 should be a leaf; the two real gateways should sit on top as peers.
export const S1_GATEWAY_PAIR: ClassScenario = {
  name: 'S1 gateway pair',
  expectation: 'Real gateways .11/.12 on top as peers; end host at .1 is a leaf.',
  gatewayReported: null,
  assets: [
    { id: 'h1',  hostname: 'host-one', ip: '10.0.0.1',  ports: [{ port: 445, service: 'microsoft-ds' }], expectNodeType: 'host', expectLeaf: true, why: 'ordinary PC that happens to sit at .1' },
    { id: 'gwp', hostname: 'edge-a',   ip: '10.0.0.11', ports: [{ port: 22, product: 'cisco' }], expectNodeType: 'gateway', expectRoot: true, why: 'primary gateway' },
    { id: 'gwb', hostname: 'edge-b',   ip: '10.0.0.12', ports: [{ port: 22, product: 'cisco' }], expectNodeType: 'gateway', expectRoot: true, why: 'backup gateway, peer of primary' },
    { id: 'pc1', hostname: 'pc-1',     ip: '10.0.0.21', ports: [{ port: 3389, service: 'ms-wbt-server' }], expectNodeType: 'host', expectLeaf: true },
    { id: 'pc2', hostname: 'pc-2',     ip: '10.0.0.22', ports: [{ port: 445 }], expectNodeType: 'host', expectLeaf: true },
  ],
}

// S2 — three-tier (like the real My Assets graph). Gateway reported = the firewall.
export const S2_THREE_TIER: ClassScenario = {
  name: 'S2 three-tier',
  expectation: 'firewall on top → core → distribution/access → hosts as leaves.',
  gatewayReported: '10.1.0.1',
  assets: [
    { id: 'fw',   hostname: 'fw-main',    ip: '10.1.0.1',  ports: [{ port: 22, product: 'fortigate' }], expectNodeType: 'gateway', expectRoot: true },
    { id: 'core', hostname: 'core-sw-1',  ip: '10.1.0.2',  ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'd1',   hostname: 'dist-sw-1',  ip: '10.1.0.3',  ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'd2',   hostname: 'dist-sw-2',  ip: '10.1.0.4',  ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'as',   hostname: 'acc-sw-1',   ip: '10.1.0.5',  ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'srv1', hostname: 'app-1',      ip: '10.1.0.20', ports: [{ port: 443, service: 'https' }], expectNodeType: 'host', expectLeaf: true },
    { id: 'ws1',  hostname: 'ws-1',       ip: '10.1.0.30', ports: [{ port: 3389 }], expectNodeType: 'host', expectLeaf: true },
  ],
}

// S3 — one gateway + `spokes` hosts in its /24, plus a few hosts in other subnets
// (to exercise cross-subnet parenting). Gateway reported = the hub.
export function s3Hub(spokes = 30): ClassScenario {
  const assets: ClassAsset[] = [
    { id: 'gw', hostname: 'edge-hub', ip: '10.2.0.1', ports: [{ port: 22, product: 'cisco' }], expectNodeType: 'gateway', expectRoot: true },
  ]
  for (let i = 0; i < spokes; i++) {
    assets.push({ id: `s${i}`, hostname: `srv-${i}`, ip: `10.2.0.${i + 10}`, ports: [{ port: 443 }], expectNodeType: 'host', expectLeaf: true })
  }
  // hosts in other subnets, no local lower-layer node → cross-subnet parent choice
  assets.push({ id: 'x1', hostname: 'rem-1', ip: '10.2.5.50', ports: [{ port: 443 }], expectNodeType: 'host', expectLeaf: true })
  assets.push({ id: 'x2', hostname: 'rem-2', ip: '10.2.6.60', ports: [{ port: 443 }], expectNodeType: 'host', expectLeaf: true })
  return { name: `S3 hub (${spokes} spokes)`, expectation: 'gateway on top; all same-subnet hosts are its leaves; cross-subnet hosts parent deterministically.', gatewayReported: '10.2.0.1', assets }
}

// S4 — name/position traps. No gateway reported, so the only way to 'network' is real
// evidence (SNMP/router product text) — never IP position.
export const S4_NAME_TRAPS: ClassScenario = {
  name: 'S4 name traps',
  expectation: 'device_type follows real evidence, not hostname text or IP position.',
  gatewayReported: null,
  assets: [
    { id: 'db',  hostname: 'sw-billing-db', ip: '10.3.0.40',  ports: [{ port: 443, service: 'https' }], expectNodeType: 'host', expectLeaf: true, why: 'a server that merely looks like a switch by name' },
    { id: 'sw',  hostname: null,            ip: '10.3.0.2',   ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch', why: 'real switch, no hostname — SNMP evidence' },
    { id: 'ws',  hostname: 'desk-9',        ip: '10.3.0.254', ports: [{ port: 3389 }], expectNodeType: 'host', expectLeaf: true, why: 'workstation that happens to sit at .254' },
    { id: 'iot', hostname: 'cam-9',         ip: '10.3.0.1',   ports: [], os: { name: 'android' }, expectNodeType: 'host', expectLeaf: true, why: 'IoT device that happens to sit at .1' },
    { id: 'net', hostname: 'sw-real',       ip: '10.3.1.1',   ports: [{ port: 22, product: 'cisco' }], expectNodeType: 'switch', why: 'a .1 host WITH real network evidence stays network' },
  ],
}

// PROD_CROSS_SUBNET — the production case: two /24s each with their own switch + host,
// plus three hosts in 142.19.0.0/24 that have NO network device of their own. Expected:
// only the two same-subnet infra→host edges; the 142.19.0.x hosts get no parent.
export const PROD_CROSS_SUBNET: ClassScenario = {
  name: 'production cross-subnet orphans',
  expectation: 'hosts with no network device in their own /24 get NO parent; each .1 switch parents only its own-subnet host.',
  gatewayReported: null,
  assets: [
    { id: 'n100_1',  hostname: null,             ip: '192.168.100.1',  ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'jojo',    hostname: 'JoJochaw',        ip: '192.168.100.71', ports: [{ port: 3389 }], expectNodeType: 'host', expectLeaf: true },
    { id: 'n0_1',    hostname: null,             ip: '192.168.0.1',    ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'desktop', hostname: 'DESKTOP-8RMHVMR', ip: '192.168.0.14',   ports: [{ port: 443 }], expectNodeType: 'host', expectLeaf: true },
    { id: 'u12', hostname: null, ip: '142.19.0.12', ports: [], expectNodeType: 'host', expectRoot: true, why: 'no network device in 142.19.0.0/24 → no parent' },
    { id: 'u11', hostname: null, ip: '142.19.0.11', ports: [], expectNodeType: 'host', expectRoot: true },
    { id: 'u1',  hostname: null, ip: '142.19.0.1',  ports: [], expectNodeType: 'host', expectRoot: true },
  ],
}

// TIERED_CROSS_SUBNET — a core switch above two distribution switches in OTHER subnets,
// each with a host. Infrastructure must still be parented across subnets.
export const TIERED_CROSS_SUBNET: ClassScenario = {
  name: 'tiered infra across subnets',
  expectation: 'core parents distribution switches in other /24s (infra cross-subnet kept); hosts attach to their own-subnet switch.',
  gatewayReported: null,
  assets: [
    { id: 'core', hostname: 'core-sw-1', ip: '10.30.0.1',  ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'd1',   hostname: 'dist-sw-1', ip: '10.30.1.1',  ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'd2',   hostname: 'dist-sw-2', ip: '10.30.2.1',  ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'ha',   hostname: 'app-a',     ip: '10.30.1.50', ports: [{ port: 443 }], expectNodeType: 'host', expectLeaf: true },
    { id: 'hb',   hostname: 'app-b',     ip: '10.30.2.50', ports: [{ port: 443 }], expectNodeType: 'host', expectLeaf: true },
  ],
}

// PROD_REDUNDANT — the owner's screenshot: 142.19.0.11/.12 are network switches (same
// /24) and 142.19.0.1 is a server end host → the host links to BOTH switches. Two more
// subnets (192.168.0 gateway+server, 192.168.100 switch+workstation). Expected edges:
// g0→dsk, g100→jojo, s11→srv1, s12→srv1 — and NO 142.19↔192.168 edge.
export const PROD_REDUNDANT: ClassScenario = {
  name: 'production redundant switches',
  expectation: 'the .1 server links to BOTH same-/24 switches; the two 192.168 nets are separate; no 142.19↔192.168 edge.',
  gatewayReported: '192.168.0.1',
  assets: [
    { id: 'g0',   hostname: null,              ip: '192.168.0.1',    ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'gateway' },
    { id: 'dsk',  hostname: 'DESKTOP-8RMHVMR',  ip: '192.168.0.14',   ports: [{ port: 443 }], expectNodeType: 'host', expectLeaf: true },
    { id: 'g100', hostname: null,              ip: '192.168.100.1',  ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'jojo', hostname: 'JoJochaw',         ip: '192.168.100.71', ports: [{ port: 3389 }], expectNodeType: 'host', expectLeaf: true },
    { id: 's11',  hostname: 'mtlwalic101',      ip: '142.19.0.11',    ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 's12',  hostname: 'mtllipf01',        ip: '142.19.0.12',    ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'srv1', hostname: null,              ip: '142.19.0.1',     ports: [{ port: 443 }], expectNodeType: 'host', expectLeaf: true },
  ],
}

// THREE_GATEWAYS — three equal switches + five hosts in one /24: every host links to all
// three (redundancy), deterministic.
export function threeGateways(): ClassScenario {
  const assets: ClassAsset[] = [
    { id: 'gw1', hostname: null, ip: '10.50.0.11', ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'gw2', hostname: null, ip: '10.50.0.12', ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'gw3', hostname: null, ip: '10.50.0.13', ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
  ]
  for (let i = 0; i < 5; i++) assets.push({ id: `h${i}`, hostname: null, ip: `10.50.0.${21 + i}`, ports: [{ port: 443 }], expectNodeType: 'host', expectLeaf: true })
  return { name: 'three equal gateways', expectation: 'every host links to all three switches of its /24.', gatewayReported: null, assets }
}

// DIFFERENT_SIXTEEN — infrastructure in two different /16s must NOT be linked.
export const DIFFERENT_SIXTEEN: ClassScenario = {
  name: 'infra across different /16s',
  expectation: 'a switch in 172.16.0.0/24 is NOT parented to a core in 10.30.0.0/24 (different /16) — no edge.',
  gatewayReported: null,
  assets: [
    { id: 'core', hostname: 'core-sw-1', ip: '10.30.0.1',  ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
    { id: 'dist', hostname: 'dist-sw-9', ip: '172.16.0.1', ports: [{ port: 161, service: 'snmp' }], expectNodeType: 'switch' },
  ],
}

// S5 — a workstation PATCHed to network. Modelled as two cases: the stale-layer state
// (node layer still the workstation layer) vs a refreshed-layer state.
export const S5_TYPE_CHANGE = {
  name: 'S5 type change (workstation → network)',
  hostname: 'host-x', ip: '10.4.0.50', ports: [{ port: 445 }] as MockPort[], owner: null,
  staleLayer: 5,   // node still carries the old workstation layer until /topology/infer
}

// S6 — membership edge cases: an asset with NO topology node (layer null), and one
// removed from My Assets that still carries a stale node (and therefore a layer).
export const S6_MEMBERSHIP = {
  name: 'S6 membership',
  noNode:       { hostname: 'orphan-1', ip: '10.5.0.60', deviceType: 'server' as const, ports: [{ port: 443 }] as MockPort[], layer: null as number | null },
  removedStale: { hostname: 'left-1',  ip: '10.5.0.61', deviceType: 'network' as const, ports: [{ port: 161, service: 'snmp' }] as MockPort[], layer: 1 as number | null },
}

// S7 — owner / internet-facing variants of one base asset (server), to show the score
// deltas (owner +1 when unowned, internet-facing +2).
export const S7_SCORE_VARIANTS = {
  name: 'S7 owner / internet-facing',
  base: { hostname: 'app-x', ip: '10.6.0.70', deviceType: 'server' as const, ports: [{ port: 443 }] as MockPort[] },
}
