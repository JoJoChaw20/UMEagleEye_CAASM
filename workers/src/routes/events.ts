/**
 * UMEagleEye Workers — Events / Alerts routes
 * Returns snake_case + joined asset hostname/IP for the AlertsPage.
 */

import { Hono } from 'hono'
import { eq, and, desc, sql, gte, inArray } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { events, assets, advisories } from '../db/schema'
import { buildBaseline, extractPorts } from '../services/drift'

const app = new Hono<{ Bindings: Env }>()

// ── GET / ────────────────────────────────────────────────────────
app.get('/', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db   = getDb(c.env.HYPERDRIVE.connectionString)

    // Support both page/page_size (AlertsPage) and page/limit (legacy)
    const page     = Math.max(1, parseInt(c.req.query('page')      ?? '1'))
    const pageSize = Math.min(200, Math.max(1,
      parseInt(c.req.query('page_size') ?? c.req.query('limit') ?? '50')
    ))
    const offset  = (page - 1) * pageSize

    // Support both param names
    const severity  = c.req.query('severity')
    const eventType = c.req.query('event_type') ?? c.req.query('type')
    const assetId   = c.req.query('asset_id')

    // Build tenant-scoped asset ID list
    const tenantIdParam = c.req.query('tenant_id')
    const effectiveTenantId = user.role === 'superadmin'
      ? (tenantIdParam ?? undefined)
      : (user.tenantId ?? undefined)

    let allowedAssetIds: string[] | null = null
    if (effectiveTenantId) {
      const assetRows = await db
        .select({ assetId: assets.assetId })
        .from(assets)
        .where(eq(assets.tenantId, effectiveTenantId))
      allowedAssetIds = assetRows.map(a => a.assetId)
      if (allowedAssetIds.length === 0) {
        return c.json({ total: 0, page, page_size: pageSize, items: [] })
      }
    }

    const conditions = []
    if (allowedAssetIds) {
      conditions.push(sql`${events.assetId} = ANY(ARRAY[${sql.join(allowedAssetIds.map(id => sql`${id}::uuid`), sql`, `)}])`)
    }
    if (assetId)   conditions.push(eq(events.assetId, assetId))
    if (severity)  conditions.push(eq(events.severity, severity as 'low' | 'medium' | 'high' | 'critical'))
    if (eventType) {
      conditions.push(eq(events.eventType, eventType as
        'port_opened' | 'port_closed' | 'version_downgrade' | 'version_upgrade' |
        'cve_detected' | 'new_device' | 'config_change' | 'new_package' |
        'removed_package' | 'cti_match'))
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined

    const [rows, countRows] = await Promise.all([
      db
        .select({
          eventId:            events.eventId,
          assetId:            events.assetId,
          eventType:          events.eventType,
          severity:           events.severity,
          details:            events.details,
          compositeRiskScore: events.compositeRiskScore,
          timestamp:          events.timestamp,
          // joined asset fields
          assetHostname:      assets.hostname,
          assetIp:            assets.ipAddress,
        })
        .from(events)
        .leftJoin(assets, eq(events.assetId, assets.assetId))
        .where(whereClause)
        .orderBy(desc(events.timestamp))
        .limit(pageSize)
        .offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(events).where(whereClause),
    ])

    // Check which of the returned events already have an advisory
    const pageEventIds = rows.map(r => r.eventId).filter(Boolean)
    let advisoryEventIdSet = new Set<string>()
    if (pageEventIds.length > 0) {
      const advRows = await db
        .select({ eventId: advisories.eventId })
        .from(advisories)
        .where(inArray(advisories.eventId, pageEventIds))
      advisoryEventIdSet = new Set(advRows.map(a => a.eventId))
    }

    const items = rows.map(row => ({
      event_id:            row.eventId,
      asset_id:            row.assetId,
      event_type:          row.eventType,
      severity:            row.severity,
      details:             row.details,
      composite_risk_score: row.compositeRiskScore != null ? Number(row.compositeRiskScore) : null,
      timestamp:           row.timestamp,
      asset_hostname:      row.assetHostname ?? null,
      asset_ip:            row.assetIp ?? null,
      has_advisory:        advisoryEventIdSet.has(row.eventId),
    }))

    return c.json({
      total:     countRows[0]?.count ?? 0,
      page,
      page_size: pageSize,
      items,
    })
  } catch (err) {
    console.error('events GET / error:', err)
    return c.json({ detail: 'Failed to fetch events' }, 500)
  }
})

// ── GET /stats/summary ───────────────────────────────────────────
// Must be before /:eventId
app.get('/stats/summary', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db   = getDb(c.env.HYPERDRIVE.connectionString)

    const statsTenantIdParam = c.req.query('tenant_id')
    const statsEffectiveTenantId = user.role === 'superadmin'
      ? (statsTenantIdParam ?? undefined)
      : (user.tenantId ?? undefined)

    let allowedAssetIds: string[] | null = null
    let allowedEventIds: string[] | null = null
    if (statsEffectiveTenantId) {
      const assetRows = await db
        .select({ assetId: assets.assetId })
        .from(assets)
        .where(eq(assets.tenantId, statsEffectiveTenantId))
      allowedAssetIds = assetRows.map(a => a.assetId)
      if (allowedAssetIds.length === 0) {
        return c.json({
          total_alerts: 0,
          by_severity: { low: 0, medium: 0, high: 0, critical: 0 },
          by_type: {},
          unresolved_critical: 0,
          avg_risk_score: 0,
          resolution_rate: 100,
          daily_trend: [],
        })
      }
      const eventRows = await db
        .select({ eventId: events.eventId })
        .from(events)
        .where(inArray(events.assetId, allowedAssetIds))
      allowedEventIds = eventRows.map(e => e.eventId)
    }

    const assetFilter = allowedAssetIds !== null
      ? sql`${events.assetId} = ANY(ARRAY[${sql.join(allowedAssetIds.map(id => sql`${id}::uuid`), sql`, `)}])`
      : sql`1=1`

    // Advisory query scoped to the same tenant
    const advisoryQuery = allowedEventIds !== null
      ? allowedEventIds.length === 0
        ? Promise.resolve([{ total: 0, resolved: 0 }])
        : db.select({
            total:    sql<number>`count(*)::int`,
            resolved: sql<number>`count(*) filter (where status = 'resolved')::int`,
          }).from(advisories).where(inArray(advisories.eventId, allowedEventIds))
      : db.select({
          total:    sql<number>`count(*)::int`,
          resolved: sql<number>`count(*) filter (where status = 'resolved')::int`,
        }).from(advisories)

    // 7-day daily trend
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)

    const [totals, bySeverity, byType, avgRisk, dailyRaw, advisoryStats] = await Promise.all([
      db.select({ total: sql<number>`count(*)::int` }).from(events).where(assetFilter),
      db
        .select({ severity: events.severity, count: sql<number>`count(*)::int` })
        .from(events).where(assetFilter).groupBy(events.severity),
      db
        .select({ event_type: events.eventType, count: sql<number>`count(*)::int` })
        .from(events).where(assetFilter).groupBy(events.eventType),
      db
        .select({ avg: sql<number>`round(avg(composite_risk_score)::numeric, 1)` })
        .from(events)
        .where(and(assetFilter, sql`composite_risk_score IS NOT NULL`)),
      db
        .select({
          day:   sql<string>`date_trunc('day', timestamp)::date::text`,
          count: sql<number>`count(*)::int`,
        })
        .from(events)
        .where(and(assetFilter, gte(events.timestamp, sevenDaysAgo)))
        .groupBy(sql`date_trunc('day', timestamp)`)
        .orderBy(sql`date_trunc('day', timestamp)`),
      advisoryQuery,
    ])

    const by_severity: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 }
    for (const row of bySeverity) by_severity[row.severity] = row.count

    const by_type: Record<string, number> = {}
    for (const row of byType) by_type[row.event_type] = row.count

    const total_advisories = advisoryStats[0]?.total ?? 0
    const resolved_advisories = advisoryStats[0]?.resolved ?? 0
    const resolution_rate = total_advisories > 0
      ? Math.round((resolved_advisories / total_advisories) * 100)
      : 100

    // Fill missing days in trend
    const trendMap: Record<string, number> = {}
    for (const row of dailyRaw) trendMap[row.day] = row.count
    const daily_trend = []
    for (let i = 6; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400000)
      const key = d.toISOString().slice(0, 10)
      daily_trend.push({ date: key.slice(5), count: trendMap[key] ?? 0 })
    }

    return c.json({
      total_alerts:     totals[0]?.total ?? 0,
      by_severity,
      by_type,
      total_critical: by_severity.critical,
      avg_risk_score:   avgRisk[0]?.avg ?? 0,
      resolution_rate,
      daily_trend,
    })
  } catch (err) {
    console.error('events GET stats/summary error:', err)
    return c.json({ detail: 'Failed to fetch event stats' }, 500)
  }
})

// ── GET /:eventId ────────────────────────────────────────────────
app.get('/:eventId', authMiddleware, async (c) => {
  try {
    const user    = c.get('user')
    const db      = getDb(c.env.HYPERDRIVE.connectionString)
    const { eventId } = c.req.param()

    const [row] = await db
      .select({
        eventId:            events.eventId,
        assetId:            events.assetId,
        eventType:          events.eventType,
        severity:           events.severity,
        details:            events.details,
        compositeRiskScore: events.compositeRiskScore,
        timestamp:          events.timestamp,
        assetHostname:      assets.hostname,
        assetIp:            assets.ipAddress,
      })
      .from(events)
      .leftJoin(assets, eq(events.assetId, assets.assetId))
      .where(eq(events.eventId, eventId))
      .limit(1)

    if (!row) return c.json({ detail: 'Event not found' }, 404)

    if (user.role !== 'superadmin' && user.tenantId) {
      const [asset] = await db
        .select({ tenantId: assets.tenantId })
        .from(assets)
        .where(eq(assets.assetId, row.assetId))
        .limit(1)
      if (!asset || asset.tenantId !== user.tenantId) {
        return c.json({ detail: 'Event not found' }, 404)
      }
    }

    return c.json({
      event_id:            row.eventId,
      asset_id:            row.assetId,
      event_type:          row.eventType,
      severity:            row.severity,
      details:             row.details,
      composite_risk_score: row.compositeRiskScore != null ? Number(row.compositeRiskScore) : null,
      timestamp:           row.timestamp,
      asset_hostname:      row.assetHostname ?? null,
      asset_ip:            row.assetIp ?? null,
    })
  } catch (err) {
    console.error('events GET /:eventId error:', err)
    return c.json({ detail: 'Failed to fetch event' }, 500)
  }
})

// ── POST /:eventId/acknowledge ───────────────────────────────────
// Accepts a drift event as intentional: re-baselines the asset to the
// current state and removes the event so it stops appearing in alerts.
app.post('/:eventId/acknowledge', authMiddleware, requireRoles('tenant_superadmin', 'tenant_admin'), async (c) => {
  try {
    const user = c.get('user')
    const db   = getDb(c.env.HYPERDRIVE.connectionString)
    const { eventId } = c.req.param()

    const [event] = await db.select().from(events).where(eq(events.eventId, eventId)).limit(1)
    if (!event) return c.json({ detail: 'Event not found' }, 404)

    // Tenant guard
    if (user.role !== 'superadmin' && user.tenantId) {
      const [assetRow] = await db
        .select({ tenantId: assets.tenantId })
        .from(assets)
        .where(eq(assets.assetId, event.assetId))
        .limit(1)
      if (!assetRow || assetRow.tenantId !== user.tenantId) {
        return c.json({ detail: 'Event not found' }, 404)
      }
    }

    // Re-baseline the asset to its current state so this drift is no longer reported
    const [asset] = await db.select().from(assets).where(eq(assets.assetId, event.assetId)).limit(1)
    if (asset) {
      const osInfo = asset.osInfo as Record<string, unknown> | null
      const snapshot = buildBaseline({
        ports:            extractPorts(osInfo),
        osInfo,
        hostname:         asset.hostname,
        macAddress:       asset.macAddress,
        isInternetFacing: asset.isInternetFacing,
        deviceType:       asset.deviceType,
        autoSet:          false,
      })
      await db
        .update(assets)
        .set({ baselineState: snapshot, updatedAt: new Date() })
        .where(eq(assets.assetId, asset.assetId))
    }

    // Remove the acknowledged event
    await db.delete(events).where(eq(events.eventId, eventId))

    return c.json({ message: 'Event acknowledged and baseline updated' })
  } catch (err) {
    console.error('events POST acknowledge error:', err)
    return c.json({ detail: 'Failed to acknowledge event' }, 500)
  }
})

// ── POST /:eventId/advisory ──────────────────────────────────────
app.post('/:eventId/advisory', authMiddleware, requireRoles('tenant_superadmin', 'tenant_admin'), async (c) => {
  try {
    const user = c.get('user')
    const db   = getDb(c.env.HYPERDRIVE.connectionString)
    const { eventId } = c.req.param()

    const [event] = await db.select().from(events).where(eq(events.eventId, eventId)).limit(1)
    if (!event) return c.json({ detail: 'Event not found' }, 404)

    if (user.role !== 'superadmin' && user.tenantId) {
      const [asset] = await db
        .select({ tenantId: assets.tenantId })
        .from(assets)
        .where(eq(assets.assetId, event.assetId))
        .limit(1)
      if (!asset || asset.tenantId !== user.tenantId) {
        return c.json({ detail: 'Event not found' }, 404)
      }
    }

    await c.env.ADVISORY_QUEUE.send({ type: 'advisory', eventId, userId: user.userId })

    return c.json({ message: 'Advisory generation queued', task_queued: true })
  } catch (err) {
    console.error('events POST advisory error:', err)
    return c.json({ detail: 'Failed to queue advisory generation' }, 500)
  }
})

export default app
