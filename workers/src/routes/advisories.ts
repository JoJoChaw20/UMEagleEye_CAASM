import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, desc, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { advisories, events, assets, auditLogs } from '../db/schema'

const app = new Hono<{ Bindings: Env }>()

const STATUS_ROLES = ['ops_lead', 'security_engineer', 'mssp_analyst', 'superadmin']

// Helper: resolve tenantId from advisory via event->asset chain
async function getAdvisoryTenantId(
  db: ReturnType<typeof import('../db/client').getDb>,
  advisoryId: string,
): Promise<{ tenantId: string | null; assetId: string } | null> {
  const rows = await db
    .select({
      assetId: assets.assetId,
      tenantId: assets.tenantId,
    })
    .from(advisories)
    .innerJoin(events, eq(advisories.eventId, events.eventId))
    .innerJoin(assets, eq(events.assetId, assets.assetId))
    .where(eq(advisories.advisoryId, advisoryId))
    .limit(1)

  if (rows.length === 0 || !rows[0]) return null
  return { tenantId: rows[0].tenantId, assetId: rows[0].assetId }
}

// ── GET / ────────────────────────────────────────────────────────
app.get('/', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const page = Math.max(1, parseInt(c.req.query('page') ?? '1'))
    const limit = Math.min(200, Math.max(1, parseInt(c.req.query('limit') ?? '50')))
    const offset = (page - 1) * limit
    const status = c.req.query('status')
    const assigned_to = c.req.query('assigned_to')

    // Build conditions
    const conditions = []

    if (status) {
      conditions.push(eq(advisories.status, status as 'open' | 'acknowledged' | 'in_progress' | 'resolved'))
    }
    if (assigned_to) {
      conditions.push(eq(advisories.assignedTo, assigned_to))
    }

    // Tenant filter: join through events->assets
    if (user.role !== 'superadmin' && user.tenantId) {
      // Get asset IDs belonging to tenant
      const assetRows = await db
        .select({ assetId: assets.assetId })
        .from(assets)
        .where(eq(assets.tenantId, user.tenantId))
      const allowedAssetIds = assetRows.map((a) => a.assetId)

      if (allowedAssetIds.length === 0) {
        return c.json({ total: 0, page, limit, items: [] })
      }

      // Get event IDs belonging to those assets
      const eventRows = await db
        .select({ eventId: events.eventId })
        .from(events)
        .where(
          sql`${events.assetId} = ANY(ARRAY[${sql.join(allowedAssetIds.map(id => sql`${id}::uuid`), sql`, `)}])`,
        )
      const allowedEventIds = eventRows.map((e) => e.eventId)

      if (allowedEventIds.length === 0) {
        return c.json({ total: 0, page, limit, items: [] })
      }

      conditions.push(
        sql`${advisories.eventId} = ANY(ARRAY[${sql.join(allowedEventIds.map(id => sql`${id}::uuid`), sql`, `)}])`,
      )
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined

    const [rows, countRows] = await Promise.all([
      db
        .select()
        .from(advisories)
        .where(whereClause)
        .orderBy(desc(advisories.createdAt))
        .limit(limit)
        .offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(advisories).where(whereClause),
    ])

    return c.json({ total: countRows[0]?.count ?? 0, page, limit, items: rows })
  } catch (err) {
    console.error('advisories GET / error:', err)
    return c.json({ detail: 'Failed to fetch advisories' }, 500)
  }
})

// ── GET /:advisoryId ─────────────────────────────────────────────
app.get('/:advisoryId', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { advisoryId } = c.req.param()

    const [advisory] = await db
      .select()
      .from(advisories)
      .where(eq(advisories.advisoryId, advisoryId))
      .limit(1)

    if (!advisory) {
      return c.json({ detail: 'Advisory not found' }, 404)
    }

    // Tenant check via event->asset
    if (user.role !== 'superadmin' && user.tenantId) {
      const meta = await getAdvisoryTenantId(db, advisoryId)
      if (!meta || meta.tenantId !== user.tenantId) {
        return c.json({ detail: 'Advisory not found' }, 404)
      }
    }

    return c.json(advisory)
  } catch (err) {
    console.error('advisories GET /:advisoryId error:', err)
    return c.json({ detail: 'Failed to fetch advisory' }, 500)
  }
})

// ── PATCH /:advisoryId/status ────────────────────────────────────
const updateStatusSchema = z.object({
  status: z.enum(['open', 'acknowledged', 'in_progress', 'resolved']),
})

app.patch(
  '/:advisoryId/status',
  authMiddleware,
  requireRoles(...STATUS_ROLES),
  zValidator('json', updateStatusSchema),
  async (c) => {
    try {
      const user = c.get('user')
      const db = getDb(c.env.DATABASE_URL)
      const { advisoryId } = c.req.param()
      const { status } = c.req.valid('json')

      const [existing] = await db
        .select()
        .from(advisories)
        .where(eq(advisories.advisoryId, advisoryId))
        .limit(1)

      if (!existing) {
        return c.json({ detail: 'Advisory not found' }, 404)
      }

      // Tenant check
      if (user.role !== 'superadmin' && user.tenantId) {
        const meta = await getAdvisoryTenantId(db, advisoryId)
        if (!meta || meta.tenantId !== user.tenantId) {
          return c.json({ detail: 'Advisory not found' }, 404)
        }
      }

      const updateData: Partial<typeof advisories.$inferInsert> = { status }
      if (status === 'resolved') {
        updateData.resolvedAt = new Date()
      }

      const [updated] = await db
        .update(advisories)
        .set(updateData)
        .where(eq(advisories.advisoryId, advisoryId))
        .returning()

      // Insert audit log
      await db.insert(auditLogs).values({
        userId: user.userId,
        tenantId: user.tenantId ?? null,
        actionType: 'advisory_status_update',
        targetEntity: advisoryId,
        previousState: { status: existing.status },
        newState: { status },
      })

      return c.json(updated)
    } catch (err) {
      console.error('advisories PATCH status error:', err)
      return c.json({ detail: 'Failed to update advisory status' }, 500)
    }
  },
)

export default app
