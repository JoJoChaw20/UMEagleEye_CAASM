import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, desc, ilike, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { assets } from '../db/schema'

const app = new Hono<{ Bindings: Env }>()

const READ_ROLES = ['ops_lead', 'security_engineer', 'mssp_analyst', 'business_owner', 'superadmin']
const WRITE_ROLES = ['ops_lead', 'security_engineer', 'superadmin']
const DELETE_ROLES = ['ops_lead', 'superadmin']

// ── GET / ────────────────────────────────────────────────────────
app.get('/', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const page = Math.max(1, parseInt(c.req.query('page') ?? '1'))
    const limit = Math.min(200, Math.max(1, parseInt(c.req.query('limit') ?? '50')))
    const offset = (page - 1) * limit
    const device_type = c.req.query('device_type')
    const hostname = c.req.query('hostname')
    const tenant_id_param = c.req.query('tenant_id')

    const conditions = []

    // Superadmin can query any tenant; others are scoped to their own tenantId
    if (user.role !== 'superadmin') {
      if (user.tenantId) {
        conditions.push(eq(assets.tenantId, user.tenantId))
      }
    } else if (tenant_id_param) {
      conditions.push(eq(assets.tenantId, tenant_id_param))
    }

    if (device_type) {
      conditions.push(
        eq(assets.deviceType, device_type as 'server' | 'workstation' | 'network' | 'iot' | 'unknown'),
      )
    }

    if (hostname) {
      conditions.push(ilike(assets.hostname, `%${hostname}%`))
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined

    const [rows, countRows] = await Promise.all([
      db
        .select()
        .from(assets)
        .where(whereClause)
        .orderBy(desc(assets.createdAt))
        .limit(limit)
        .offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(assets).where(whereClause),
    ])

    return c.json({ total: countRows[0]?.count ?? 0, page, limit, items: rows })
  } catch (err) {
    console.error('assets GET / error:', err)
    return c.json({ detail: 'Failed to fetch assets' }, 500)
  }
})

// ── GET /:assetId ────────────────────────────────────────────────
app.get('/:assetId', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()

    const [asset] = await db.select().from(assets).where(eq(assets.assetId, assetId)).limit(1)

    if (!asset) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    if (user.role !== 'superadmin' && user.tenantId && asset.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    return c.json(asset)
  } catch (err) {
    console.error('assets GET /:assetId error:', err)
    return c.json({ detail: 'Failed to fetch asset' }, 500)
  }
})

// ── POST / ───────────────────────────────────────────────────────
const createAssetSchema = z.object({
  ip_address: z.string().min(1).max(45),
  hostname: z.string().max(255).optional(),
  mac_address: z.string().max(17).optional(),
  owner: z.string().max(255).optional(),
  device_type: z.enum(['server', 'workstation', 'network', 'iot', 'unknown']).optional(),
  hardware_vendor: z.string().max(255).optional(),
  os_info: z.record(z.unknown()).optional(),
  criticality_score: z.number().int().min(1).max(10).optional(),
  is_internet_facing: z.boolean().optional(),
})

app.post('/', authMiddleware, requireRoles(...WRITE_ROLES), zValidator('json', createAssetSchema), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const body = c.req.valid('json')

    const [asset] = await db
      .insert(assets)
      .values({
        ipAddress: body.ip_address,
        hostname: body.hostname,
        macAddress: body.mac_address,
        owner: body.owner,
        deviceType: body.device_type ?? 'unknown',
        hardwareVendor: body.hardware_vendor,
        osInfo: body.os_info ?? {},
        criticalityScore: body.criticality_score ?? 5,
        isInternetFacing: body.is_internet_facing ?? false,
        tenantId: user.tenantId ?? null,
      })
      .returning()

    return c.json(asset, 201)
  } catch (err) {
    console.error('assets POST / error:', err)
    return c.json({ detail: 'Failed to create asset' }, 500)
  }
})

// ── PATCH /:assetId ──────────────────────────────────────────────
const updateAssetSchema = z.object({
  ip_address: z.string().min(1).max(45).optional(),
  hostname: z.string().max(255).optional(),
  mac_address: z.string().max(17).optional(),
  owner: z.string().max(255).optional(),
  device_type: z.enum(['server', 'workstation', 'network', 'iot', 'unknown']).optional(),
  hardware_vendor: z.string().max(255).optional(),
  os_info: z.record(z.unknown()).optional(),
  criticality_score: z.number().int().min(1).max(10).optional(),
  is_internet_facing: z.boolean().optional(),
})

app.patch('/:assetId', authMiddleware, requireRoles(...WRITE_ROLES), zValidator('json', updateAssetSchema), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()
    const body = c.req.valid('json')

    const [existing] = await db.select().from(assets).where(eq(assets.assetId, assetId)).limit(1)
    if (!existing) {
      return c.json({ detail: 'Asset not found' }, 404)
    }
    if (user.role !== 'superadmin' && user.tenantId && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    const updateData: Partial<typeof assets.$inferInsert> = { updatedAt: new Date() }
    if (body.ip_address !== undefined) updateData.ipAddress = body.ip_address
    if (body.hostname !== undefined) updateData.hostname = body.hostname
    if (body.mac_address !== undefined) updateData.macAddress = body.mac_address
    if (body.owner !== undefined) updateData.owner = body.owner
    if (body.device_type !== undefined) updateData.deviceType = body.device_type
    if (body.hardware_vendor !== undefined) updateData.hardwareVendor = body.hardware_vendor
    if (body.os_info !== undefined) updateData.osInfo = body.os_info
    if (body.criticality_score !== undefined) updateData.criticalityScore = body.criticality_score
    if (body.is_internet_facing !== undefined) updateData.isInternetFacing = body.is_internet_facing

    const [updated] = await db
      .update(assets)
      .set(updateData)
      .where(eq(assets.assetId, assetId))
      .returning()

    if (!updated) {
      return c.json({ detail: 'Asset not found after update' }, 404)
    }

    return c.json(updated)
  } catch (err) {
    console.error('assets PATCH error:', err)
    return c.json({ detail: 'Failed to update asset' }, 500)
  }
})

// ── DELETE /:assetId ─────────────────────────────────────────────
app.delete('/:assetId', authMiddleware, requireRoles(...DELETE_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()

    const [existing] = await db.select().from(assets).where(eq(assets.assetId, assetId)).limit(1)
    if (!existing) {
      return c.json({ detail: 'Asset not found' }, 404)
    }
    if (user.role !== 'superadmin' && user.tenantId && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    await db.delete(assets).where(eq(assets.assetId, assetId))

    return c.json({ message: 'Asset deleted' })
  } catch (err) {
    console.error('assets DELETE error:', err)
    return c.json({ detail: 'Failed to delete asset' }, 500)
  }
})

// ── POST /:assetId/baseline ──────────────────────────────────────
app.post('/:assetId/baseline', authMiddleware, requireRoles(...WRITE_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()

    const [existing] = await db.select().from(assets).where(eq(assets.assetId, assetId)).limit(1)
    if (!existing) {
      return c.json({ detail: 'Asset not found' }, 404)
    }
    if (user.role !== 'superadmin' && user.tenantId && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    const [updated] = await db
      .update(assets)
      .set({ baselineState: existing.osInfo, updatedAt: new Date() })
      .where(eq(assets.assetId, assetId))
      .returning()

    return c.json({ message: 'Baseline set', baseline_state: updated?.baselineState ?? null })
  } catch (err) {
    console.error('assets POST baseline error:', err)
    return c.json({ detail: 'Failed to set baseline' }, 500)
  }
})

// ── GET /:assetId/baseline ───────────────────────────────────────
app.get('/:assetId/baseline', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()

    const [asset] = await db
      .select({ assetId: assets.assetId, baselineState: assets.baselineState, updatedAt: assets.updatedAt })
      .from(assets)
      .where(eq(assets.assetId, assetId))
      .limit(1)

    if (!asset) {
      return c.json({ detail: 'Asset not found' }, 404)
    }
    if (user.role !== 'superadmin' && user.tenantId) {
      const [full] = await db.select({ tenantId: assets.tenantId }).from(assets).where(eq(assets.assetId, assetId)).limit(1)
      if (full && full.tenantId !== user.tenantId) {
        return c.json({ detail: 'Asset not found' }, 404)
      }
    }

    return c.json({ asset_id: asset.assetId, baseline_state: asset.baselineState, updated_at: asset.updatedAt })
  } catch (err) {
    console.error('assets GET baseline error:', err)
    return c.json({ detail: 'Failed to fetch baseline' }, 500)
  }
})

export default app
