import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, or, sql } from 'drizzle-orm'
import { alias } from 'drizzle-orm/pg-core'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { assets, assetRelationships, tenants, topologyNodes } from '../db/schema'
import { inferForTenant } from './topology'
import { computeBlastRadius, clampDepth, normalizeDirection, type BlastNodeInput, type BlastEdgeInput } from '../lib/blastRadius'

const app = new Hono<{ Bindings: Env }>()
const VIEW_ROLES   = ['superadmin', 'tenant_superadmin', 'tenant_admin'] as const
const WRITE_ROLES  = ['tenant_superadmin', 'tenant_admin'] as const
const DELETE_ROLES = ['tenant_superadmin', 'tenant_admin'] as const

// ── Helpers ───────────────────────────────────────────────────────
function toSnakeNode(n: typeof assets.$inferSelect, edgeCount: number) {
  return {
    asset_id:         n.assetId,
    hostname:         n.hostname,
    ip_address:       n.ipAddress,
    device_type:      n.deviceType,
    criticality_score: n.criticalityScore,
    is_internet_facing: n.isInternetFacing,
    hardware_vendor:  n.hardwareVendor,
    edge_count:       edgeCount,
  }
}

function getSubnet(ip: string): string {
  return ip.split('.').slice(0, 3).join('.')
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

// ── GET /graph ───────────────────────────────────────────────────
// Returns nodes + edges with snake_case field names and edge_count per node.
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

    let allowedAssetIds: string[] | null = null
    if (tenantScopeId) {
      allowedAssetIds = await getTenantAssetIds(db, tenantScopeId)
      if (allowedAssetIds.length === 0) {
        return c.json({ nodes: [], edges: [], total_nodes: 0, total_edges: 0 })
      }
    }

    const rawNodes = tenantScopeId
      ? await db.select().from(assets).where(and(eq(assets.tenantId, tenantScopeId), eq(assets.inMyAssets, true)))
      : await db.select().from(assets).where(eq(assets.inMyAssets, true))

    const rawEdges = allowedAssetIds !== null
      ? await db.select().from(assetRelationships).where(
          and(anyOfUuids(assetRelationships.sourceAssetId, allowedAssetIds), anyOfUuids(assetRelationships.targetAssetId, allowedAssetIds))
        )
      : await db.select().from(assetRelationships)

    // Hide any edge unless BOTH endpoints are in My Assets. Removing an asset from
    // My Assets drops its node here, so its edges disappear — but are never deleted,
    // so re-adding the asset restores the full graph. (Also covers the superadmin
    // unscoped case where rawEdges isn't pre-filtered by allowedAssetIds.)
    const nodeIdSet = new Set(rawNodes.map(n => n.assetId))
    const visibleEdges = rawEdges.filter(e => nodeIdSet.has(e.sourceAssetId) && nodeIdSet.has(e.targetAssetId))

    // edge_count per node
    const edgeCounts = new Map<string, number>()
    for (const e of visibleEdges) {
      edgeCounts.set(e.sourceAssetId, (edgeCounts.get(e.sourceAssetId) ?? 0) + 1)
      edgeCounts.set(e.targetAssetId, (edgeCounts.get(e.targetAssetId) ?? 0) + 1)
    }

    const nodes = rawNodes.map(n => toSnakeNode(n, edgeCounts.get(n.assetId) ?? 0))
    const edges = visibleEdges.map(e => ({
      source:            e.sourceAssetId,
      target:            e.targetAssetId,
      relationship_type: e.relationshipType,
    }))

    return c.json({ nodes, edges, total_nodes: nodes.length, total_edges: edges.length })
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

  // assetId → IP for subnet classification
  const assetRows = await db
    .select({ assetId: assets.assetId, ipAddress: assets.ipAddress })
    .from(assets)
    .where(and(eq(assets.tenantId, tenantId), eq(assets.inMyAssets, true)))
  const assetIp = new Map(assetRows.map(a => [a.assetId, a.ipAddress]))

  const INFRA_TYPES = new Set(['gateway', 'router', 'switch', 'access_point'])

  function classifyRelType(parentType: string, childType: string, sameSubnet: boolean): (typeof assetRelationships.$inferInsert)['relationshipType'] {
    const parentInfra = INFRA_TYPES.has(parentType)
    const childInfra  = INFRA_TYPES.has(childType)
    if (parentInfra && childInfra) return 'connects_to'   // network infrastructure uplink/trunk
    if (parentInfra && !childInfra) return sameSubnet ? 'same_subnet' : 'connects_to'  // access layer
    return 'depends_on'  // host-to-host
  }

  const newRels: (typeof assetRelationships.$inferInsert)[] = []

  for (const node of topoNodes) {
    if (!node.parentNodeId || !node.assetId) continue
    const parentInfo = nodeToInfo.get(node.parentNodeId)
    if (!parentInfo) continue

    const nodeIp   = assetIp.get(node.assetId)      ?? ''
    const parentIp = assetIp.get(parentInfo.assetId) ?? ''
    const sameSubnet = !!(nodeIp && parentIp && getSubnet(nodeIp) === getSubnet(parentIp))

    newRels.push({
      sourceAssetId:    parentInfo.assetId,
      targetAssetId:    node.assetId,
      relationshipType: classifyRelType(parentInfo.nodeType, node.nodeType, sameSubnet),
      confidence:       '1.00',
    })
  }

  if (newRels.length > 0) {
    await db.insert(assetRelationships).values(newRels).onConflictDoNothing()
  }
  return newRels.length
}

// ── POST /infer ──────────────────────────────────────────────────
// Rebuilds relationships from asset inventory:
//   • same_subnet  (star topology per /24 subnet, hub = network device or lowest IP)
//   • connects_to  (router → hub of every other subnet)
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
