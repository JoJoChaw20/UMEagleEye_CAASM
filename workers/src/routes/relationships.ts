import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, or, sql, getTableColumns } from 'drizzle-orm'
import { alias } from 'drizzle-orm/pg-core'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { assets, assetRelationships, tenants, topologyNodes } from '../db/schema'
import { inferForTenant, resolveParents } from './topology'
import { computeBlastRadius, clampDepth, normalizeDirection, type BlastNodeInput, type BlastEdgeInput } from '../lib/blastRadius'

// Chunk size for the relationship rebuild INSERT, so one statement never grows without
// bound now that a host can link to several equal-level gateways/switches.
const REL_INSERT_CHUNK = 200

const app = new Hono<{ Bindings: Env }>()
const VIEW_ROLES   = ['superadmin', 'tenant_superadmin', 'tenant_admin'] as const
const WRITE_ROLES  = ['tenant_superadmin', 'tenant_admin'] as const
const DELETE_ROLES = ['tenant_superadmin', 'tenant_admin'] as const

// ── Helpers ───────────────────────────────────────────────────────
// `layer` is the asset's topology layer (the graph MAY read topology; the engine never
// does). Used only by the layered layout on the client.
function toSnakeNode(n: typeof assets.$inferSelect & { topoLayer?: number | null }, edgeCount: number) {
  return {
    asset_id:         n.assetId,
    hostname:         n.hostname,
    ip_address:       n.ipAddress,
    device_type:      n.deviceType,
    criticality_score: n.criticalityScore,
    is_internet_facing: n.isInternetFacing,
    hardware_vendor:  n.hardwareVendor,
    layer:            n.topoLayer ?? null,
    edge_count:       edgeCount,
  }
}

// Infrastructure node types (topology). A parent of one of these is network gear.
export const INFRA_TYPES = new Set(['gateway', 'router', 'switch', 'access_point'])

// How a topology parent→child link maps to a relationship edge. Exported + pure so
// the classification harness can test it. A network/infra parent to a HOST child is a
// downstream-impact edge (connects_to) regardless of subnet — previously an in-subnet
// infra→host link was `same_subnet`, which the blast-radius walk skips, so clicking a
// switch showed none of its hosts. Infra→infra is an uplink; host→host is a dependency.
export function classifyRelType(parentType: string, childType: string): (typeof assetRelationships.$inferInsert)['relationshipType'] {
  const parentInfra = INFRA_TYPES.has(parentType)
  const childInfra  = INFRA_TYPES.has(childType)
  if (parentInfra && childInfra) return 'connects_to'
  if (parentInfra && !childInfra) return 'connects_to'
  return 'depends_on'
}

async function getTenantAssetIds(db: ReturnType<typeof getDb>, tenantId: string): Promise<string[]> {
  const rows = await db.select({ assetId: assets.assetId }).from(assets).where(
    and(eq(assets.tenantId, tenantId), eq(assets.inMyAssets, true))
  )
  return rows.map(r => r.assetId)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function anyOfUuids(col: any, ids: string[]) {
  return sql`${col} = ANY(ARRAY[${sql.join(ids.map(id => sql`${id}::uuid`), sql`, `)}])`
}

// ── Graph data loader (constant queries) ─────────────────────────
// Loads the My Assets member nodes + edges in a constant number of queries
// (tenant-scoped: getTenantAssetIds + nodes + edges = 3; superadmin unscoped:
// nodes + edges = 2). The nodes query LEFT JOINs topology_nodes for each node's layer
// (the graph may read topology) — still ONE query; an asset with >1 node yields >1 row
// which is collapsed to the lowest layer in memory. Exported so the demo can assert
// the query count with a stub.
type GraphNodeRow = typeof assets.$inferSelect & { topoLayer: number | null }

function collapseByLowestLayer(rows: GraphNodeRow[]): GraphNodeRow[] {
  const m = new Map<string, GraphNodeRow>()
  for (const r of rows) {
    const ex = m.get(r.assetId)
    if (!ex) m.set(r.assetId, { ...r })
    else if (r.topoLayer != null && (ex.topoLayer == null || r.topoLayer < ex.topoLayer)) ex.topoLayer = r.topoLayer
  }
  return [...m.values()]
}

export async function loadGraphData(
  db: ReturnType<typeof getDb>,
  params: { tenantScopeId: string | null },
): Promise<{ rawNodes: GraphNodeRow[]; rawEdges: (typeof assetRelationships.$inferSelect)[] }> {
  const nodeSel = { ...getTableColumns(assets), topoLayer: topologyNodes.layer }
  if (params.tenantScopeId) {
    const allowed = await getTenantAssetIds(db, params.tenantScopeId)
    if (allowed.length === 0) return { rawNodes: [], rawEdges: [] }
    const nodeRows = await db.select(nodeSel).from(assets)
      .leftJoin(topologyNodes, eq(topologyNodes.assetId, assets.assetId))
      .where(and(eq(assets.tenantId, params.tenantScopeId), eq(assets.inMyAssets, true)))
    const rawEdges = await db.select().from(assetRelationships).where(
      and(anyOfUuids(assetRelationships.sourceAssetId, allowed), anyOfUuids(assetRelationships.targetAssetId, allowed)))
    return { rawNodes: collapseByLowestLayer(nodeRows as GraphNodeRow[]), rawEdges }
  }
  const nodeRows = await db.select(nodeSel).from(assets)
    .leftJoin(topologyNodes, eq(topologyNodes.assetId, assets.assetId))
    .where(eq(assets.inMyAssets, true))
  const rawEdges = await db.select().from(assetRelationships)
  return { rawNodes: collapseByLowestLayer(nodeRows as GraphNodeRow[]), rawEdges }
}

export interface UnconnectedMember { id: string; hostname: string | null; ip: string | null; device_type: string; reason: 'unknown_type' | 'no_network_device' }

// PURE: the My Assets members that have NO edge to another member (both endpoints must
// be members — an edge to a non-member doesn't count). reason distinguishes an
// unclassified device (scan it to classify) from a known-type device whose /24 has no
// gateway/switch in My Assets to link to (add/scan its gateway). Both are the two only
// ways a member ends up edgeless now that a host is never cross-subnet parented, so
// the old `no_relationships` code is gone. No DB.
export function computeUnconnected(
  members: { assetId: string; hostname: string | null; ipAddress: string | null; deviceType: string }[],
  edges: { sourceAssetId: string; targetAssetId: string }[],
): UnconnectedMember[] {
  const memberIds = new Set(members.map(m => m.assetId))
  const connected = new Set<string>()
  for (const e of edges) {
    if (memberIds.has(e.sourceAssetId) && memberIds.has(e.targetAssetId)) {
      connected.add(e.sourceAssetId); connected.add(e.targetAssetId)
    }
  }
  return members
    .filter(m => !connected.has(m.assetId))
    .map(m => ({
      id: m.assetId, hostname: m.hostname, ip: m.ipAddress, device_type: m.deviceType,
      reason: m.deviceType === 'unknown' ? 'unknown_type' : 'no_network_device',
    }))
}

// PURE: build the /graph response body from the member nodes + edges. Only edges with
// BOTH endpoints in My Assets are shown; `unconnected` lists members with no such edge.
// Exported so the demo can assert the response shape without a DB.
export function buildGraphResponse(
  rawNodes: (typeof assets.$inferSelect & { topoLayer?: number | null })[],
  rawEdges: (typeof assetRelationships.$inferSelect)[],
) {
  const nodeIdSet = new Set(rawNodes.map(n => n.assetId))
  const visibleEdges = rawEdges.filter(e => nodeIdSet.has(e.sourceAssetId) && nodeIdSet.has(e.targetAssetId))
  const edgeCounts = new Map<string, number>()
  for (const e of visibleEdges) {
    edgeCounts.set(e.sourceAssetId, (edgeCounts.get(e.sourceAssetId) ?? 0) + 1)
    edgeCounts.set(e.targetAssetId, (edgeCounts.get(e.targetAssetId) ?? 0) + 1)
  }
  const nodes = rawNodes.map(n => toSnakeNode(n, edgeCounts.get(n.assetId) ?? 0))
  const edges = visibleEdges.map(e => ({ source: e.sourceAssetId, target: e.targetAssetId, relationship_type: e.relationshipType }))
  const unconnected = computeUnconnected(rawNodes, visibleEdges)
  return { nodes, edges, total_nodes: nodes.length, total_edges: edges.length, unconnected }
}

// ── GET /graph ───────────────────────────────────────────────────
// Returns nodes + edges with snake_case field names and edge_count per node, plus an
// `unconnected` list of My Assets members with no edge to another member (so they are
// not silently hidden — the graph tab shows them as a notice, not as graph nodes).
app.get('/graph', authMiddleware, requireRoles(...VIEW_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const tenantIdParam = c.req.query('tenant_id')

    // Determine the effective tenant scope
    let tenantScopeId: string | null = null
    if (user.role !== 'superadmin') {
      tenantScopeId = user.tenantId ?? null
    } else if (tenantIdParam) {
      tenantScopeId = tenantIdParam
    }

    const { rawNodes, rawEdges } = await loadGraphData(db, { tenantScopeId })
    // Only edges with BOTH endpoints in My Assets are shown; members with no such edge
    // go in `unconnected` so they aren't silently hidden. All built in memory.
    return c.json(buildGraphResponse(rawNodes, rawEdges))
  } catch (err) {
    console.error('GET /graph error:', err)
    return c.json({ detail: 'Failed to fetch graph' }, 500)
  }
})

// ── GET /graph/:assetId — subgraph for one asset ─────────────────
app.get('/graph/:assetId', authMiddleware, requireRoles(...VIEW_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()

    const [asset] = await db.select().from(assets).where(eq(assets.assetId, assetId)).limit(1)
    if (!asset) return c.json({ detail: 'Asset not found' }, 404)
    if (user.role !== 'superadmin' && user.tenantId && asset.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    const edges = await db.select().from(assetRelationships).where(
      or(eq(assetRelationships.sourceAssetId, assetId), eq(assetRelationships.targetAssetId, assetId))
    )

    const neighborIds = new Set<string>()
    for (const edge of edges) {
      if (edge.sourceAssetId !== assetId) neighborIds.add(edge.sourceAssetId)
      if (edge.targetAssetId !== assetId) neighborIds.add(edge.targetAssetId)
    }

    let neighbors: (typeof asset)[] = []
    if (neighborIds.size > 0) {
      const ids = Array.from(neighborIds)
      neighbors = await db.select().from(assets).where(anyOfUuids(assets.assetId, ids))
    }

    const allNodes = [asset, ...neighbors]
    const edgeCounts = new Map<string, number>()
    for (const e of edges) {
      edgeCounts.set(e.sourceAssetId, (edgeCounts.get(e.sourceAssetId) ?? 0) + 1)
      edgeCounts.set(e.targetAssetId, (edgeCounts.get(e.targetAssetId) ?? 0) + 1)
    }

    return c.json({
      nodes: allNodes.map(n => toSnakeNode(n, edgeCounts.get(n.assetId) ?? 0)),
      edges: edges.map(e => ({ source: e.sourceAssetId, target: e.targetAssetId, relationship_type: e.relationshipType })),
    })
  } catch (err) {
    console.error('GET /graph/:assetId error:', err)
    return c.json({ detail: 'Failed to fetch subgraph' }, 500)
  }
})

// ── Blast-radius data loader (2 queries, constant) ───────────────
// One query for the start asset (tenant guard + its attributes), one for every
// My-Assets-to-My-Assets edge in scope (both endpoints joined for node attributes +
// membership), capped at BLAST_EDGE_CAP. No per-node queries. Exported so the demo
// can assert the query count with a counting stub.
export const BLAST_EDGE_CAP = 5000

export async function loadBlastGraph(
  db: ReturnType<typeof getDb>,
  params: { startId: string; tenantScopeId: string | null },
): Promise<{ start: BlastNodeInput | null; startTenantId: string | null; nodes: BlastNodeInput[]; edges: BlastEdgeInput[]; truncated: boolean }> {
  // Q1 — start asset
  const [startRow] = await db
    .select({
      assetId: assets.assetId, tenantId: assets.tenantId, hostname: assets.hostname, ipAddress: assets.ipAddress,
      deviceType: assets.deviceType, criticalityScore: assets.criticalityScore, inMyAssets: assets.inMyAssets,
    })
    .from(assets).where(eq(assets.assetId, params.startId)).limit(1)

  // Q2 — member-to-member edges, both endpoints joined for attributes (+1 to detect cap)
  const src = alias(assets, 'blast_src')
  const tgt = alias(assets, 'blast_tgt')
  const edgeRows = await db
    .select({
      source: assetRelationships.sourceAssetId, target: assetRelationships.targetAssetId, type: assetRelationships.relationshipType,
      srcHostname: src.hostname, srcIp: src.ipAddress, srcDeviceType: src.deviceType, srcCrit: src.criticalityScore,
      tgtHostname: tgt.hostname, tgtIp: tgt.ipAddress, tgtDeviceType: tgt.deviceType, tgtCrit: tgt.criticalityScore,
    })
    .from(assetRelationships)
    .innerJoin(src, eq(src.assetId, assetRelationships.sourceAssetId))
    .innerJoin(tgt, eq(tgt.assetId, assetRelationships.targetAssetId))
    .where(and(
      params.tenantScopeId ? eq(src.tenantId, params.tenantScopeId) : undefined,
      eq(src.inMyAssets, true),
      eq(tgt.inMyAssets, true),
    ))
    .limit(BLAST_EDGE_CAP + 1)

  const truncated = edgeRows.length > BLAST_EDGE_CAP
  const capped = truncated ? edgeRows.slice(0, BLAST_EDGE_CAP) : edgeRows

  const nodeMap = new Map<string, BlastNodeInput>()
  for (const r of capped) {
    if (!nodeMap.has(r.source)) nodeMap.set(r.source, { assetId: r.source, hostname: r.srcHostname, ipAddress: r.srcIp, deviceType: r.srcDeviceType, criticalityScore: r.srcCrit, inMyAssets: true })
    if (!nodeMap.has(r.target)) nodeMap.set(r.target, { assetId: r.target, hostname: r.tgtHostname, ipAddress: r.tgtIp, deviceType: r.tgtDeviceType, criticalityScore: r.tgtCrit, inMyAssets: true })
  }

  // The start may be isolated (no edges) or a non-member — seed/override it with its
  // own authoritative row so computeBlastRadius can decide membership.
  const start: BlastNodeInput | null = startRow
    ? { assetId: startRow.assetId, hostname: startRow.hostname, ipAddress: startRow.ipAddress, deviceType: startRow.deviceType, criticalityScore: startRow.criticalityScore, inMyAssets: startRow.inMyAssets }
    : null
  if (start) nodeMap.set(start.assetId, start)

  const edges: BlastEdgeInput[] = capped.map(r => ({ source: r.source, target: r.target, type: r.type }))
  return { start, startTenantId: startRow?.tenantId ?? null, nodes: [...nodeMap.values()], edges, truncated }
}

// ── GET /blast-radius/:assetId ───────────────────────────────────
// Directional impact walk over My-Assets edges. Prefetches the graph in a constant
// 2 queries, then runs the pure traversal. Response is backward compatible with
// BlastRadiusModal (origin_asset_id, affected_assets[], total_affected, max_depth)
// with added fields: direction, reason, truncated, skipped_types, per-node hub + via.
app.get('/blast-radius/:assetId', authMiddleware, requireRoles(...VIEW_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()
    const maxDepth  = clampDepth(parseInt(c.req.query('max_depth') ?? '', 10))
    const direction = normalizeDirection(c.req.query('direction'))
    const tenantScopeId = user.role === 'superadmin' ? (c.req.query('tenant_id') ?? null) : (user.tenantId ?? null)

    const { start, startTenantId, nodes, edges, truncated: edgeTruncated } =
      await loadBlastGraph(db, { startId: assetId, tenantScopeId })

    // Tenant isolation: unknown or cross-tenant start is a 404, exactly as before.
    if (!start) return c.json({ detail: 'Asset not found' }, 404)
    if (user.role !== 'superadmin' && user.tenantId && startTenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    const result = computeBlastRadius({ startId: assetId, nodes, edges, depth: maxDepth, direction })

    return c.json({
      origin_asset_id: assetId,
      direction:       result.direction,
      reason:          result.reason,                       // 'not_in_my_assets' or null
      truncated:       edgeTruncated || result.truncated,   // edge-cap OR node-cap hit
      skipped_types:   result.skippedTypes,
      affected_assets: result.nodes.map(n => ({
        asset_id:          n.assetId,
        hostname:          n.hostname,
        ip_address:        n.ipAddress,
        device_type:       n.deviceType,
        criticality_score: n.criticalityScore,
        depth:             n.depth,
        path:              n.path,
        hub:               n.hub,
        via:               n.via,
      })),
      total_affected: result.nodes.length,
      max_depth:      result.nodes.length > 0 ? Math.max(...result.nodes.map(n => n.depth)) : 0,
    })
  } catch (err) {
    console.error('GET /blast-radius error:', err)
    return c.json({ detail: 'Failed to compute blast radius' }, 500)
  }
})

// ── Shared inference logic (also called from scan ingest) ────────
type DbClient = ReturnType<typeof getDb>

// Derives relationship edges from the topology tree's parent→child links so that
// the relationship graph always matches the topology view exactly.
// If topology hasn't been built yet it is auto-inferred first.
export async function inferRelationshipsForTenant(db: DbClient, tenantId: string): Promise<number> {
  const tenantAssetIds = await getTenantAssetIds(db, tenantId)
  if (tenantAssetIds.length === 0) return 0

  // Auto-build topology if missing
  let topoNodes = await db.select().from(topologyNodes).where(eq(topologyNodes.tenantId, tenantId))
  if (topoNodes.length === 0) {
    const tenantAssets = await db.select().from(assets).where(
      and(eq(assets.tenantId, tenantId), eq(assets.inMyAssets, true))
    )
    await inferForTenant(db, tenantAssets, tenantId)
    topoNodes = await db.select().from(topologyNodes).where(eq(topologyNodes.tenantId, tenantId))
  }

  // Clear old relationships for this tenant
  await db.delete(assetRelationships).where(
    or(
      anyOfUuids(assetRelationships.sourceAssetId, tenantAssetIds),
      anyOfUuids(assetRelationships.targetAssetId, tenantAssetIds),
    )
  )

  if (topoNodes.length === 0) return 0

  // nodeId → { assetId, nodeType } lookup
  const nodeToInfo = new Map<string, { assetId: string; nodeType: string }>()
  for (const n of topoNodes) {
    if (n.assetId) nodeToInfo.set(n.nodeId, { assetId: n.assetId, nodeType: n.nodeType })
  }

  // Re-derive parents with resolveParents so a child links to EVERY equal-level
  // gateway/switch (primary + backups), not just the single stored parent_node_id.
  // IP comes from the node metadata captured at topology infer — no extra query.
  const ipOf = (n: typeof topoNodes[number]): string => {
    const ip = (n.metadata as Record<string, unknown> | null)?.ip_address
    return typeof ip === 'string' ? ip : ''
  }
  const flat = topoNodes
    .filter(n => n.assetId)
    .map(n => ({ nodeId: n.nodeId, nodeType: n.nodeType, layer: n.layer, ip: ipOf(n), subnet: ipOf(n).split('.').slice(0, 3).join('.') }))

  const newRels: (typeof assetRelationships.$inferInsert)[] = []
  for (const node of flat) {
    const child = nodeToInfo.get(node.nodeId)
    if (!child) continue
    for (const parentNodeId of resolveParents(node, flat.filter(f => f.nodeId !== node.nodeId)).all) {
      const parent = nodeToInfo.get(parentNodeId)
      if (!parent) continue
      newRels.push({
        sourceAssetId:    parent.assetId,
        targetAssetId:    child.assetId,
        relationshipType: classifyRelType(parent.nodeType, node.nodeType),
        confidence:       '1.00',
      })
    }
  }

  // Chunked insert so one statement stays bounded even with redundant links; the
  // unique index on (source, target, type) dedups.
  for (let i = 0; i < newRels.length; i += REL_INSERT_CHUNK) {
    await db.insert(assetRelationships).values(newRels.slice(i, i + REL_INSERT_CHUNK)).onConflictDoNothing()
  }
  return newRels.length
}

// ── POST /infer ──────────────────────────────────────────────────
// Rebuilds relationship edges from the topology parent→child tree: infra→host and
// infra→infra become connects_to (downstream), host→host becomes depends_on.
app.post('/infer', authMiddleware, requireRoles(...WRITE_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    if (!user.tenantId && user.role !== 'superadmin') {
      return c.json({ detail: 'User has no tenant assigned' }, 400)
    }

    const tenantsToProcess: string[] = user.role === 'superadmin'
      ? (await db.select({ tenantId: tenants.tenantId }).from(tenants)).map(t => t.tenantId)
      : [user.tenantId!]

    let totalCreated = 0

    for (const tenantId of tenantsToProcess) {
      totalCreated += await inferRelationshipsForTenant(db, tenantId)
    }

    return c.json({ relationships_created: totalCreated, message: `Inferred ${totalCreated} relationships across ${tenantsToProcess.length} tenant(s)` })
  } catch (err) {
    console.error('POST /infer error:', err)
    return c.json({ detail: 'Failed to infer relationships' }, 500)
  }
})

// ── POST / — Create a relationship manually ───────────────────────
app.post('/', authMiddleware, requireRoles(...WRITE_ROLES),
  zValidator('json', z.object({
    source_asset_id:   z.string().uuid(),
    target_asset_id:   z.string().uuid(),
    relationship_type: z.enum(['connects_to', 'depends_on', 'same_subnet', 'authenticates_to', 'exposes_service']),
    confidence:        z.number().min(0).max(1).optional(),
  })),
  async (c) => {
    try {
      const user = c.get('user')
      const db = getDb(c.env.DATABASE_URL)
      const body = c.req.valid('json')

      const [srcAsset, tgtAsset] = await Promise.all([
        db.select({ tenantId: assets.tenantId }).from(assets).where(eq(assets.assetId, body.source_asset_id)).limit(1),
        db.select({ tenantId: assets.tenantId }).from(assets).where(eq(assets.assetId, body.target_asset_id)).limit(1),
      ])

      if (srcAsset.length === 0 || tgtAsset.length === 0) {
        return c.json({ detail: 'One or both assets not found' }, 404)
      }
      if (user.role !== 'superadmin' && user.tenantId) {
        if (srcAsset[0]?.tenantId !== user.tenantId || tgtAsset[0]?.tenantId !== user.tenantId) {
          return c.json({ detail: 'Assets not accessible' }, 403)
        }
      }

      const [rel] = await db.insert(assetRelationships).values({
        sourceAssetId: body.source_asset_id,
        targetAssetId: body.target_asset_id,
        relationshipType: body.relationship_type,
        confidence: body.confidence?.toString(),
      }).returning()

      return c.json(rel, 201)
    } catch (err) {
      console.error('POST / error:', err)
      return c.json({ detail: 'Failed to create relationship' }, 500)
    }
  }
)

// ── DELETE /:relationshipId ───────────────────────────────────────
app.delete('/:relationshipId', authMiddleware, requireRoles(...DELETE_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { relationshipId } = c.req.param()

    const [rel] = await db.select().from(assetRelationships)
      .where(eq(assetRelationships.relationshipId, relationshipId)).limit(1)
    if (!rel) return c.json({ detail: 'Relationship not found' }, 404)

    if (user.role !== 'superadmin' && user.tenantId) {
      const [srcAsset] = await db.select({ tenantId: assets.tenantId }).from(assets)
        .where(eq(assets.assetId, rel.sourceAssetId)).limit(1)
      if (!srcAsset || srcAsset.tenantId !== user.tenantId) {
        return c.json({ detail: 'Relationship not found' }, 404)
      }
    }

    await db.delete(assetRelationships).where(eq(assetRelationships.relationshipId, relationshipId))
    return c.json({ message: 'Relationship deleted' })
  } catch (err) {
    console.error('DELETE error:', err)
    return c.json({ detail: 'Failed to delete relationship' }, 500)
  }
})

export default app
