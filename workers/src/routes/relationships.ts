import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, or, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { assets, assetRelationships, tenants } from '../db/schema'

const app = new Hono<{ Bindings: Env }>()
const WRITE_ROLES = ['ops_lead', 'security_engineer', 'superadmin'] as const
const DELETE_ROLES = ['ops_lead', 'superadmin'] as const

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
  const rows = await db.select({ assetId: assets.assetId }).from(assets).where(eq(assets.tenantId, tenantId))
  return rows.map(r => r.assetId)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function anyOfUuids(col: any, ids: string[]) {
  return sql`${col} = ANY(ARRAY[${sql.join(ids.map(id => sql`${id}::uuid`), sql`, `)}])`
}

// ── GET /graph ───────────────────────────────────────────────────
// Returns nodes + edges with snake_case field names and edge_count per node.
app.get('/graph', authMiddleware, async (c) => {
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
      ? await db.select().from(assets).where(eq(assets.tenantId, tenantScopeId))
      : await db.select().from(assets)

    const rawEdges = allowedAssetIds !== null
      ? await db.select().from(assetRelationships).where(
          and(anyOfUuids(assetRelationships.sourceAssetId, allowedAssetIds), anyOfUuids(assetRelationships.targetAssetId, allowedAssetIds))
        )
      : await db.select().from(assetRelationships)

    // edge_count per node
    const edgeCounts = new Map<string, number>()
    for (const e of rawEdges) {
      edgeCounts.set(e.sourceAssetId, (edgeCounts.get(e.sourceAssetId) ?? 0) + 1)
      edgeCounts.set(e.targetAssetId, (edgeCounts.get(e.targetAssetId) ?? 0) + 1)
    }

    const nodes = rawNodes.map(n => toSnakeNode(n, edgeCounts.get(n.assetId) ?? 0))
    const edges = rawEdges.map(e => ({
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
app.get('/graph/:assetId', authMiddleware, async (c) => {
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

// ── GET /blast-radius/:assetId ───────────────────────────────────
// BFS up to max_depth hops. Returns per-asset depth + path.
app.get('/blast-radius/:assetId', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()
    const maxDepth = Math.min(parseInt(c.req.query('max_depth') ?? '3', 10), 5)

    const [rootAsset] = await db.select().from(assets).where(eq(assets.assetId, assetId)).limit(1)
    if (!rootAsset) return c.json({ detail: 'Asset not found' }, 404)
    if (user.role !== 'superadmin' && user.tenantId && rootAsset.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    // BFS tracking depth + path per visited node
    const visited = new Map<string, { depth: number; path: string[] }>()
    visited.set(assetId, { depth: 0, path: [assetId] })
    const queue: Array<{ id: string; depth: number; path: string[] }> = [
      { id: assetId, depth: 0, path: [assetId] },
    ]

    while (queue.length > 0) {
      const current = queue.shift()!
      if (current.depth >= maxDepth) continue

      const edges = await db.select().from(assetRelationships).where(
        or(eq(assetRelationships.sourceAssetId, current.id), eq(assetRelationships.targetAssetId, current.id))
      )

      for (const edge of edges) {
        const neighborId = edge.sourceAssetId === current.id ? edge.targetAssetId : edge.sourceAssetId
        if (!visited.has(neighborId)) {
          const depth = current.depth + 1
          const path = [...current.path, neighborId]
          visited.set(neighborId, { depth, path })
          queue.push({ id: neighborId, depth, path })
        }
      }
    }

    const affectedIds = Array.from(visited.keys()).filter(id => id !== assetId)
    let affectedAssets: (typeof rootAsset)[] = []
    if (affectedIds.length > 0) {
      affectedAssets = await db.select().from(assets).where(anyOfUuids(assets.assetId, affectedIds))
    }

    const result = affectedAssets.map(a => ({
      asset_id:         a.assetId,
      hostname:         a.hostname,
      ip_address:       a.ipAddress,
      device_type:      a.deviceType,
      criticality_score: a.criticalityScore,
      depth:            visited.get(a.assetId)?.depth ?? 1,
      path:             visited.get(a.assetId)?.path ?? [],
    })).sort((a, b) => a.depth - b.depth)

    return c.json({
      origin_asset_id: assetId,
      affected_assets: result,
      total_affected:  result.length,
      max_depth:       result.length > 0 ? Math.max(...result.map(a => a.depth)) : 0,
    })
  } catch (err) {
    console.error('GET /blast-radius error:', err)
    return c.json({ detail: 'Failed to compute blast radius' }, 500)
  }
})

// ── POST /infer ──────────────────────────────────────────────────
// Rebuilds relationships from asset inventory:
//   • same_subnet  (star topology per /24 subnet, hub = network device or lowest IP)
//   • connects_to  (internet-facing gateway → hub of every other subnet)
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
      const tenantAssetIds = await getTenantAssetIds(db, tenantId)
      if (tenantAssetIds.length === 0) continue

      // Delete all existing relationships for this tenant's assets in one query
      await db.delete(assetRelationships).where(
        or(
          anyOfUuids(assetRelationships.sourceAssetId, tenantAssetIds),
          anyOfUuids(assetRelationships.targetAssetId, tenantAssetIds),
        )
      )

      const tenantAssets = await db.select().from(assets).where(eq(assets.tenantId, tenantId))

      // Group by /24 subnet
      const subnetGroups = new Map<string, (typeof tenantAssets)>()
      for (const a of tenantAssets) {
        const s = getSubnet(a.ipAddress)
        if (!subnetGroups.has(s)) subnetGroups.set(s, [])
        subnetGroups.get(s)!.push(a)
      }

      // Pick hub of a subnet: prefer network device, then lowest IP
      function pickHub(subnetAssets: typeof tenantAssets) {
        return [...subnetAssets].sort((a, b) => {
          if (a.deviceType === 'network' && b.deviceType !== 'network') return -1
          if (a.deviceType !== 'network' && b.deviceType === 'network') return 1
          // numeric IP sort by last octet
          const lastA = parseInt(a.ipAddress.split('.').pop() ?? '0', 10)
          const lastB = parseInt(b.ipAddress.split('.').pop() ?? '0', 10)
          return lastA - lastB
        })[0]
      }

      const newRels: (typeof assetRelationships.$inferInsert)[] = []

      // same_subnet: star per subnet
      for (const subnetAssets of subnetGroups.values()) {
        if (subnetAssets.length < 2) continue
        const hub = pickHub(subnetAssets)!
        for (const a of subnetAssets) {
          if (a.assetId === hub.assetId) continue
          newRels.push({ sourceAssetId: hub.assetId, targetAssetId: a.assetId, relationshipType: 'same_subnet', confidence: '1.00' })
        }
      }

      // connects_to: internet-facing gateway → each other subnet's hub
      const gateway = tenantAssets
        .filter(a => a.isInternetFacing && a.deviceType === 'network')
        .sort((a, b) => {
          const lastA = parseInt(a.ipAddress.split('.').pop() ?? '0', 10)
          const lastB = parseInt(b.ipAddress.split('.').pop() ?? '0', 10)
          return lastA - lastB
        })[0]

      if (gateway) {
        const gwSubnet = getSubnet(gateway.ipAddress)
        for (const [subnet, subnetAssets] of subnetGroups.entries()) {
          if (subnet === gwSubnet) continue
          const hub = pickHub(subnetAssets)
          if (hub) {
            newRels.push({ sourceAssetId: gateway.assetId, targetAssetId: hub.assetId, relationshipType: 'connects_to', confidence: '0.90' })
          }
        }
      }

      if (newRels.length > 0) {
        await db.insert(assetRelationships).values(newRels).onConflictDoNothing()
        totalCreated += newRels.length
      }
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
