import { Hono } from 'hono'
import { eq, and, desc, gte, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb } from '../db/client'
import { assets, events, postureMetrics } from '../db/schema'

const app = new Hono<{ Bindings: Env }>()

// ── GET /current ─────────────────────────────────────────────────
app.get('/current', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const tenantCondition =
      user.role !== 'superadmin' && user.tenantId ? eq(assets.tenantId, user.tenantId) : undefined

    // Fetch assets
    const assetRows = await db
      .select({
        assetId: assets.assetId,
        criticalityScore: assets.criticalityScore,
      })
      .from(assets)
      .where(tenantCondition)

    const total_assets = assetRows.length
    const total_critical_assets = assetRows.filter((a) => (a.criticalityScore ?? 0) >= 8).length
    const highCriticalityPercent = total_assets > 0 ? total_critical_assets / total_assets : 0

    // Fetch open events for those assets
    const assetIds = assetRows.map((a) => a.assetId)

    let criticalCount = 0
    let highCount = 0
    let topRisks: Array<{ event_id: string; severity: string; event_type: string; asset_id: string }> = []

    if (assetIds.length > 0) {
      const assetFilter = sql`${events.assetId} = ANY(ARRAY[${sql.join(assetIds.map(id => sql`${id}::uuid`), sql`, `)}])`

      const [critResult, highResult, topRiskRows] = await Promise.all([
        db
          .select({ count: sql<number>`count(*)::int` })
          .from(events)
          .where(and(assetFilter, eq(events.severity, 'critical'))),
        db
          .select({ count: sql<number>`count(*)::int` })
          .from(events)
          .where(and(assetFilter, eq(events.severity, 'high'))),
        db
          .select({
            eventId: events.eventId,
            severity: events.severity,
            eventType: events.eventType,
            assetId: events.assetId,
          })
          .from(events)
          .where(and(assetFilter, eq(events.severity, 'critical')))
          .orderBy(desc(events.timestamp))
          .limit(5),
      ])

      criticalCount = critResult[0]?.count ?? 0
      highCount = highResult[0]?.count ?? 0
      topRisks = topRiskRows.map((r) => ({
        event_id: r.eventId,
        severity: r.severity,
        event_type: r.eventType,
        asset_id: r.assetId,
      }))
    }

    // Score algorithm
    let score = 100
    const critDeduction = Math.min(criticalCount * 5, 40)
    const highDeduction = Math.min(highCount * 2, 20)
    score -= critDeduction
    score -= highDeduction
    if (highCriticalityPercent > 0.2) {
      score -= 10
    }
    score = Math.max(0, Math.min(100, score))

    return c.json({
      overall_score: score,
      total_assets,
      total_critical_assets,
      open_critical_events: criticalCount,
      top_risks: topRisks,
    })
  } catch (err) {
    console.error('posture GET /current error:', err)
    return c.json({ detail: 'Failed to compute posture' }, 500)
  }
})

// ── GET /history ─────────────────────────────────────────────────
app.get('/history', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const days = Math.min(365, Math.max(1, parseInt(c.req.query('days') ?? '30')))
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000)

    const conditions = [gte(postureMetrics.timestamp, since)]
    if (user.role !== 'superadmin' && user.tenantId) {
      conditions.push(eq(postureMetrics.tenantId, user.tenantId))
    }

    const rows = await db
      .select()
      .from(postureMetrics)
      .where(and(...conditions))
      .orderBy(postureMetrics.timestamp)

    return c.json({ days, count: rows.length, history: rows })
  } catch (err) {
    console.error('posture GET /history error:', err)
    return c.json({ detail: 'Failed to fetch posture history' }, 500)
  }
})

export default app
