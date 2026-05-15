import { Hono } from 'hono'
import { eq, and, desc, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb } from '../db/client'
import { events, assets } from '../db/schema'

const app = new Hono<{ Bindings: Env }>()

// ── GET / ────────────────────────────────────────────────────────
app.get('/', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const page = Math.max(1, parseInt(c.req.query('page') ?? '1'))
    const limit = Math.min(200, Math.max(1, parseInt(c.req.query('limit') ?? '50')))
    const offset = (page - 1) * limit
    const severity = c.req.query('severity')
    const type = c.req.query('type')
    const asset_id = c.req.query('asset_id')

    // Build WHERE against assets for tenant filtering
    const assetConditions = []
    if (user.role !== 'superadmin' && user.tenantId) {
      assetConditions.push(eq(assets.tenantId, user.tenantId))
    }

    // If filtering by tenant, get asset IDs first
    let allowedAssetIds: string[] | null = null
    if (assetConditions.length > 0) {
      const assetRows = await db
        .select({ assetId: assets.assetId })
        .from(assets)
        .where(and(...assetConditions))
      allowedAssetIds = assetRows.map((a) => a.assetId)
      if (allowedAssetIds.length === 0) {
        return c.json({ total: 0, page, limit, items: [] })
      }
    }

    const conditions = []
    if (allowedAssetIds) {
      conditions.push(sql`${events.assetId} = ANY(ARRAY[${sql.join(allowedAssetIds.map(id => sql`${id}::uuid`), sql`, `)}])`)
    }
    if (asset_id) {
      conditions.push(eq(events.assetId, asset_id))
    }
    if (severity) {
      conditions.push(eq(events.severity, severity as 'low' | 'medium' | 'high' | 'critical'))
    }
    if (type) {
      conditions.push(
        eq(
          events.eventType,
          type as
            | 'port_opened'
            | 'port_closed'
            | 'version_downgrade'
            | 'version_upgrade'
            | 'cve_detected'
            | 'new_device'
            | 'config_change'
            | 'new_package'
            | 'removed_package'
            | 'cti_match',
        ),
      )
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined

    const [rows, countRows] = await Promise.all([
      db.select().from(events).where(whereClause).orderBy(desc(events.timestamp)).limit(limit).offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(events).where(whereClause),
    ])

    return c.json({ total: countRows[0]?.count ?? 0, page, limit, items: rows })
  } catch (err) {
    console.error('events GET / error:', err)
    return c.json({ detail: 'Failed to fetch events' }, 500)
  }
})

// ── GET /stats/summary ───────────────────────────────────────────
app.get('/stats/summary', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    // Tenant-scoped asset IDs
    let allowedAssetIds: string[] | null = null
    if (user.role !== 'superadmin' && user.tenantId) {
      const assetRows = await db
        .select({ assetId: assets.assetId })
        .from(assets)
        .where(eq(assets.tenantId, user.tenantId))
      allowedAssetIds = assetRows.map((a) => a.assetId)
    }

    const assetFilter =
      allowedAssetIds !== null
        ? sql`${events.assetId} = ANY(ARRAY[${sql.join(allowedAssetIds.map(id => sql`${id}::uuid`), sql`, `)}])`
        : sql`1=1`

    const [totals, bySeverity, byType, unresolvedCritical] = await Promise.all([
      db.select({ total: sql<number>`count(*)::int` }).from(events).where(assetFilter),
      db
        .select({ severity: events.severity, count: sql<number>`count(*)::int` })
        .from(events)
        .where(assetFilter)
        .groupBy(events.severity),
      db
        .select({ event_type: events.eventType, count: sql<number>`count(*)::int` })
        .from(events)
        .where(assetFilter)
        .groupBy(events.eventType),
      db
        .select({ count: sql<number>`count(*)::int` })
        .from(events)
        .where(and(assetFilter, eq(events.severity, 'critical'))),
    ])

    const by_severity: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 }
    for (const row of bySeverity) {
      by_severity[row.severity] = row.count
    }

    const by_type: Record<string, number> = {}
    for (const row of byType) {
      by_type[row.event_type] = row.count
    }

    return c.json({
      total: totals[0]?.total ?? 0,
      by_severity,
      by_type,
      unresolved_critical: unresolvedCritical[0]?.count ?? 0,
    })
  } catch (err) {
    console.error('events GET stats/summary error:', err)
    return c.json({ detail: 'Failed to fetch event stats' }, 500)
  }
})

// ── GET /:eventId ────────────────────────────────────────────────
app.get('/:eventId', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { eventId } = c.req.param()

    const [event] = await db.select().from(events).where(eq(events.eventId, eventId)).limit(1)
    if (!event) {
      return c.json({ detail: 'Event not found' }, 404)
    }

    // Tenant check via asset
    if (user.role !== 'superadmin' && user.tenantId) {
      const [asset] = await db.select({ tenantId: assets.tenantId }).from(assets).where(eq(assets.assetId, event.assetId)).limit(1)
      if (!asset || asset.tenantId !== user.tenantId) {
        return c.json({ detail: 'Event not found' }, 404)
      }
    }

    return c.json(event)
  } catch (err) {
    console.error('events GET /:eventId error:', err)
    return c.json({ detail: 'Failed to fetch event' }, 500)
  }
})

// ── POST /:eventId/advisory ──────────────────────────────────────
app.post('/:eventId/advisory', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { eventId } = c.req.param()

    const [event] = await db.select().from(events).where(eq(events.eventId, eventId)).limit(1)
    if (!event) {
      return c.json({ detail: 'Event not found' }, 404)
    }

    // Tenant check via asset
    if (user.role !== 'superadmin' && user.tenantId) {
      const [asset] = await db.select({ tenantId: assets.tenantId }).from(assets).where(eq(assets.assetId, event.assetId)).limit(1)
      if (!asset || asset.tenantId !== user.tenantId) {
        return c.json({ detail: 'Event not found' }, 404)
      }
    }

    await c.env.ADVISORY_QUEUE.send({ eventId, userId: user.userId })

    return c.json({ message: 'Advisory generation queued', task_queued: true })
  } catch (err) {
    console.error('events POST advisory error:', err)
    return c.json({ detail: 'Failed to queue advisory generation' }, 500)
  }
})

export default app
