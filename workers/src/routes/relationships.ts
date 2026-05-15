import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, or, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { assets, assetRelationships } from '../db/schema'

const app = new Hono<{ Bindings: Env }>()

const WRITE_ROLES = ['ops_lead', 'security_engineer', 'superadmin']
const DELETE_ROLES = ['ops_lead', 'superadmin']

// Helper: get tenant-scoped asset IDs
async function getTenantAssetIds(
  db: ReturnType<typeof import('../db/client').getDb>,
  tenantId: string,
): Promise<string[]> {
  const rows = await db.select({ assetId: assets.assetId }).from(assets).where(eq(assets.tenantId, tenantId))
  return rows.map((r) => r.assetId)
}

// ── GET /graph ───────────────────────────────────────────────────
app.get('/graph', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    let assetCondition = undefined
    let allowedAssetIds: string[] | null = null

    if (user.role !== 'superadmin' && user.tenantId) {
      allowedAssetIds = await getTenantAssetIds(db, user.tenantId)
      if (allowedAssetIds.length === 0) {
        return c.json({ nodes: [], edges: [] })
      }
      assetCondition = eq(assets.tenantId, user.tenantId)
    }

    const nodes = await db.select().from(assets).where(assetCondition)

    let edgeQuery = db.select().from(assetRelationships)
    const edges =
      allowedAssetIds !== null
        ? await db
            .select()
            .from(assetRelationships)
            .where(
              and(
                sql`${assetRelationships.sourceAssetId} = ANY(ARRAY[${sql.join(allowedAssetIds.map(id => sql`${id}::uuid`), sql`, `)}])`,
                sql`${assetRelationships.targetAssetId} = ANY(ARRAY[${sql.join(allowedAssetIds.map(id => sql`${id}::uuid`), sql`, `)}])`,
              ),
            )
        : await edgeQuery

    return c.json({ nodes, edges })
  } catch (err) {
    console.error('relationships GET /graph error:', err)
    return c.json({ detail: 'Failed to fetch graph' }, 500)
  }
})

// ── GET /graph/:assetId ──────────────────────────────────────────
app.get('/graph/:assetId', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()

    // Verify the asset exists and is in user's tenant
    const [asset] = await db.select().from(assets).where(eq(assets.assetId, assetId)).limit(1)
    if (!asset) {
      return c.json({ detail: 'Asset not found' }, 404)
    }
    if (user.role !== 'superadmin' && user.tenantId && asset.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    // Get direct edges (1 hop)
    const edges = await db
      .select()
      .from(assetRelationships)
      .where(
        or(eq(assetRelationships.sourceAssetId, assetId), eq(assetRelationships.targetAssetId, assetId)),
      )

    // Collect neighbor asset IDs
    const neighborIds = new Set<string>()
    for (const edge of edges) {
      if (edge.sourceAssetId !== assetId) neighborIds.add(edge.sourceAssetId)
      if (edge.targetAssetId !== assetId) neighborIds.add(edge.targetAssetId)
    }

    let neighborAssets: typeof asset[] = []
    if (neighborIds.size > 0) {
      const neighborArr = Array.from(neighborIds)
      neighborAssets = await db
        .select()
        .from(assets)
        .where(
          sql`${assets.assetId} = ANY(ARRAY[${sql.join(neighborArr.map(id => sql`${id}::uuid`), sql`, `)}])`,
        )
    }

    return c.json({ nodes: [asset, ...neighborAssets], edges })
  } catch (err) {
    console.error('relationships GET /graph/:assetId error:', err)
    return c.json({ detail: 'Failed to fetch subgraph' }, 500)
  }
})

// ── GET /blast-radius/:assetId ───────────────────────────────────
app.get('/blast-radius/:assetId', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()

    // Verify the asset
    const [rootAsset] = await db.select().from(assets).where(eq(assets.assetId, assetId)).limit(1)
    if (!rootAsset) {
      return c.json({ detail: 'Asset not found' }, 404)
    }
    if (user.role !== 'superadmin' && user.tenantId && rootAsset.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    // BFS up to 5 hops
    const MAX_HOPS = 5
    const visited = new Set<string>([assetId])
    const queue: Array<{ id: string; hop: number }> = [{ id: assetId, hop: 0 }]
    const affectedIds: string[] = []
    let maxHop = 0

    while (queue.length > 0) {
      const current = queue.shift()!
      if (current.hop >= MAX_HOPS) continue

      const edges = await db
        .select()
        .from(assetRelationships)
        .where(
          or(
            eq(assetRelationships.sourceAssetId, current.id),
            eq(assetRelationships.targetAssetId, current.id),
          ),
        )

      for (const edge of edges) {
        const neighborId =
          edge.sourceAssetId === current.id ? edge.targetAssetId : edge.sourceAssetId
        if (!visited.has(neighborId)) {
          visited.add(neighborId)
          affectedIds.push(neighborId)
          const nextHop = current.hop + 1
          if (nextHop > maxHop) maxHop = nextHop
          queue.push({ id: neighborId, hop: nextHop })
        }
      }
    }

    let affectedAssets: typeof rootAsset[] = []
    if (affectedIds.length > 0) {
      affectedAssets = await db
        .select()
        .from(assets)
        .where(
          sql`${assets.assetId} = ANY(ARRAY[${sql.join(affectedIds.map(id => sql`${id}::uuid`), sql`, `)}])`,
        )
    }

    return c.json({
      asset_id: assetId,
      affected_assets: affectedAssets,
      hop_count: maxHop,
    })
  } catch (err) {
    console.error('relationships GET /blast-radius error:', err)
    return c.json({ detail: 'Failed to compute blast radius' }, 500)
  }
})

// ── POST / ───────────────────────────────────────────────────────
const createRelSchema = z.object({
  source_asset_id: z.string().uuid(),
  target_asset_id: z.string().uuid(),
  relationship_type: z.enum(['connects_to', 'depends_on', 'same_subnet', 'authenticates_to', 'exposes_service']),
  confidence: z.number().min(0).max(1).optional(),
})

app.post('/', authMiddleware, requireRoles(...WRITE_ROLES), zValidator('json', createRelSchema), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const body = c.req.valid('json')

    // Verify both assets exist and belong to same tenant (if scoped)
    const [srcAsset, tgtAsset] = await Promise.all([
      db.select({ tenantId: assets.tenantId }).from(assets).where(eq(assets.assetId, body.source_asset_id)).limit(1),
      db.select({ tenantId: assets.tenantId }).from(assets).where(eq(assets.assetId, body.target_asset_id)).limit(1),
    ])

    if (srcAsset.length === 0 || tgtAsset.length === 0) {
      return c.json({ detail: 'One or both assets not found' }, 404)
    }

    if (user.role !== 'superadmin' && user.tenantId) {
      const srcTenant = srcAsset[0]?.tenantId
      const tgtTenant = tgtAsset[0]?.tenantId
      if (srcTenant !== user.tenantId || tgtTenant !== user.tenantId) {
        return c.json({ detail: 'Assets not accessible' }, 403)
      }
    }

    const [rel] = await db
      .insert(assetRelationships)
      .values({
        sourceAssetId: body.source_asset_id,
        targetAssetId: body.target_asset_id,
        relationshipType: body.relationship_type,
        confidence: body.confidence?.toString(),
      })
      .returning()

    return c.json(rel, 201)
  } catch (err) {
    console.error('relationships POST / error:', err)
    return c.json({ detail: 'Failed to create relationship' }, 500)
  }
})

// ── DELETE /:relationshipId ──────────────────────────────────────
app.delete('/:relationshipId', authMiddleware, requireRoles(...DELETE_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { relationshipId } = c.req.param()

    const [rel] = await db
      .select()
      .from(assetRelationships)
      .where(eq(assetRelationships.relationshipId, relationshipId))
      .limit(1)

    if (!rel) {
      return c.json({ detail: 'Relationship not found' }, 404)
    }

    // Tenant check via source asset
    if (user.role !== 'superadmin' && user.tenantId) {
      const [srcAsset] = await db
        .select({ tenantId: assets.tenantId })
        .from(assets)
        .where(eq(assets.assetId, rel.sourceAssetId))
        .limit(1)
      if (!srcAsset || srcAsset.tenantId !== user.tenantId) {
        return c.json({ detail: 'Relationship not found' }, 404)
      }
    }

    await db
      .delete(assetRelationships)
      .where(eq(assetRelationships.relationshipId, relationshipId))

    return c.json({ message: 'Relationship deleted' })
  } catch (err) {
    console.error('relationships DELETE error:', err)
    return c.json({ detail: 'Failed to delete relationship' }, 500)
  }
})

export default app
