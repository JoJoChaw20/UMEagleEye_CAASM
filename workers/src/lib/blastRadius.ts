/**
 * blastRadius.ts — PURE blast-radius traversal (no DB access).
 *
 * The route prefetches the tenant's member-to-member edges + the start asset in a
 * constant number of queries, then hands them here. Keeping the walk pure lets it
 * be unit-tested with mock graphs (scripts/blast-radius-demo.ts) and keeps the
 * Cloudflare subrequest count independent of graph size.
 *
 * Impact semantics are table-driven by relationship type (IMPACT_ORIENTATION):
 *   connects_to  source = upstream, target = downstream  → impact flows source→target
 *   depends_on   source depends on target                → impact flows target→source
 *   same_subnet  symmetric / non-transitive              → never traversed
 *   anything else                                        → never traversed, reported
 *
 * Direction:
 *   downstream  "what is impacted if this asset fails"  (follow impact flow)
 *   upstream    "what does this asset depend on"        (follow impact flow in reverse)
 *   both        undirected over traversable edge types
 *
 * Infrastructure is not transitive: in upstream/both a hub (gateway-type device or
 * traversable degree ≥ HUB_DEGREE) is returned but NOT expanded, so one gateway can't
 * turn every result into "everything". A hub that is the START node is still expanded,
 * and downstream expansion from a hub is normal (its children really are impacted).
 */

export type Direction = 'downstream' | 'upstream' | 'both'

export interface BlastNodeInput {
  assetId:          string
  hostname:         string | null
  ipAddress:        string | null
  deviceType:       string
  criticalityScore: number | null
  inMyAssets:       boolean
}

export interface BlastEdgeInput {
  source: string
  target: string
  type:   string
}

export interface BlastOptions {
  hubDegree?:    number    // default DEFAULT_HUB_DEGREE
  nodeCap?:      number    // default DEFAULT_NODE_CAP
  gatewayTypes?: string[]  // default GATEWAY_DEVICE_TYPES
}

export interface BlastResultNode {
  assetId:          string
  hostname:         string | null
  ipAddress:        string | null
  deviceType:       string
  criticalityScore: number | null
  depth:            number
  path:             string[]
  hub:              boolean       // reached hub that was NOT expanded (upstream/both only)
  via:              string | null // relationship type of the edge used to reach it
}

export interface BlastResult {
  startId:      string
  direction:    Direction
  reason:       string | null   // 'not_in_my_assets' when the start is not a member, else null
  truncated:    boolean         // node cap hit
  skippedTypes: string[]        // unknown relationship types present but not traversed
  nodes:        BlastResultNode[]
}

// source→target orientation of impact flow per relationship type.
//  'as_stored' impact flows source → target   (connects_to)
//  'reversed'  impact flows target → source   (depends_on)
//  null        known but symmetric/non-transitive — never traversed (same_subnet)
// A type absent from this map is unknown → never traversed, surfaced in skippedTypes.
export const IMPACT_ORIENTATION: Record<string, 'as_stored' | 'reversed' | null> = {
  connects_to: 'as_stored',
  depends_on:  'reversed',
  same_subnet: null,
}

export const DEFAULT_MAX_DEPTH = 3
export const MAX_DEPTH_CAP     = 5
export const DEFAULT_HUB_DEGREE = 10
export const DEFAULT_NODE_CAP   = 200
// device_type values treated as non-transitive infrastructure. Only 'network' — the
// single device type the topology classifier turns into gateway/router/switch/
// access_point (relationships.ts INFRA_TYPES). server/workstation/iot/unknown are
// endpoints and must never be treated as hubs by type.
export const GATEWAY_DEVICE_TYPES = ['network']

export function clampDepth(depth: number | undefined): number {
  const d = Number.isFinite(depth) ? Math.floor(depth as number) : DEFAULT_MAX_DEPTH
  return Math.max(1, Math.min(d, MAX_DEPTH_CAP))
}

export function normalizeDirection(value: unknown): Direction {
  return value === 'upstream' || value === 'both' ? value : 'downstream'
}

export function computeBlastRadius(args: {
  startId:   string
  nodes:     BlastNodeInput[]
  edges:     BlastEdgeInput[]
  depth?:    number
  direction?: Direction
  options?:  BlastOptions
}): BlastResult {
  const direction   = normalizeDirection(args.direction)
  const maxDepth     = clampDepth(args.depth)
  const hubDegree    = args.options?.hubDegree ?? DEFAULT_HUB_DEGREE
  const nodeCap      = args.options?.nodeCap ?? DEFAULT_NODE_CAP
  const gatewayTypes = new Set(args.options?.gatewayTypes ?? GATEWAY_DEVICE_TYPES)
  const applyHubBrake = direction === 'upstream' || direction === 'both'

  const nodeById = new Map(args.nodes.map(n => [n.assetId, n]))
  const start = nodeById.get(args.startId)

  const empty = (reason: string | null): BlastResult =>
    ({ startId: args.startId, direction, reason, truncated: false, skippedTypes: [], nodes: [] })

  // Only members take part; a non-member (or unknown) start yields the handled reason.
  if (!start || !start.inMyAssets) return empty('not_in_my_assets')

  // Build impact-oriented adjacency + per-node traversable degree. An edge only
  // participates when BOTH endpoints are known members (hidden edges never traversed).
  const skipped = new Set<string>()
  const fwd = new Map<string, { to: string; via: string }[]>()  // impactFrom → impactTo
  const rev = new Map<string, { to: string; via: string }[]>()  // impactTo → impactFrom
  const degree = new Map<string, number>()
  const add = (m: Map<string, { to: string; via: string }[]>, from: string, to: string, via: string) => {
    const l = m.get(from); if (l) l.push({ to, via }); else m.set(from, [{ to, via }])
  }

  for (const e of args.edges) {
    if (!(e.type in IMPACT_ORIENTATION)) { skipped.add(e.type); continue }
    const orient = IMPACT_ORIENTATION[e.type]
    if (orient === null) continue  // same_subnet — known, intentionally not traversed
    const s = nodeById.get(e.source), t = nodeById.get(e.target)
    if (!s || !t || !s.inMyAssets || !t.inMyAssets) continue
    const from = orient === 'as_stored' ? e.source : e.target
    const to   = orient === 'as_stored' ? e.target : e.source
    add(fwd, from, to, e.type)
    add(rev, to, from, e.type)
    degree.set(from, (degree.get(from) ?? 0) + 1)
    degree.set(to,   (degree.get(to)   ?? 0) + 1)
  }

  const neighbors = (id: string): { to: string; via: string }[] => {
    if (direction === 'downstream') return fwd.get(id) ?? []
    if (direction === 'upstream')   return rev.get(id) ?? []
    return [...(fwd.get(id) ?? []), ...(rev.get(id) ?? [])]
  }
  const isHub = (n: BlastNodeInput): boolean =>
    gatewayTypes.has(n.deviceType) || (degree.get(n.assetId) ?? 0) >= hubDegree

  // BFS. visited excludes nothing; the start is seeded at depth 0 and dropped from
  // the result. A reached hub is recorded but, under the brake, not expanded.
  const visited = new Map<string, { depth: number; path: string[]; via: string | null }>()
  visited.set(args.startId, { depth: 0, path: [args.startId], via: null })
  const queue: { id: string; depth: number }[] = [{ id: args.startId, depth: 0 }]
  let truncated = false

  while (queue.length > 0) {
    const cur = queue.shift()!
    if (cur.depth >= maxDepth) continue
    const curNode = nodeById.get(cur.id)!
    if (applyHubBrake && cur.id !== args.startId && isHub(curNode)) continue  // hub not transitive
    const curMeta = visited.get(cur.id)!
    let stop = false
    for (const { to, via } of neighbors(cur.id)) {
      if (visited.has(to)) continue
      if (!nodeById.has(to)) continue
      if (visited.size - 1 >= nodeCap) { truncated = true; stop = true; break }  // result already at cap
      visited.set(to, { depth: cur.depth + 1, path: [...curMeta.path, to], via })
      queue.push({ id: to, depth: cur.depth + 1 })
    }
    if (stop) break
  }

  const nodes: BlastResultNode[] = []
  for (const [id, meta] of visited) {
    if (id === args.startId) continue
    const n = nodeById.get(id)!
    nodes.push({
      assetId: id, hostname: n.hostname, ipAddress: n.ipAddress, deviceType: n.deviceType,
      criticalityScore: n.criticalityScore, depth: meta.depth, path: meta.path,
      hub: applyHubBrake && isHub(n), via: meta.via,
    })
  }
  nodes.sort((a, b) => a.depth - b.depth)

  return { startId: args.startId, direction, reason: null, truncated, skippedTypes: [...skipped].sort(), nodes }
}
