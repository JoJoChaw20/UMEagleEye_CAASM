import { Hono } from 'hono'
import { eq, and, desc, gte, sql, isNull, or, ne, inArray } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb } from '../db/client'
import { assets, events } from '../db/schema'
import { isOpenEvent, postureScore } from '../lib/eventStatus'

const app = new Hono<{ Bindings: Env }>()

// ── GET /current ─────────────────────────────────────────────────
// Counts OPEN critical/high alerts (open + in_progress) — the same definition
// the Alerts page, /history and the nightly snapshot use.
app.get('/current', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const tenantIdParam = c.req.query('tenant_id')
    const effectiveTenantId = user.role === 'superadmin'
      ? (tenantIdParam ?? undefined)
      : (user.tenantId ?? undefined)
    const tenantCondition = effectiveTenantId ? eq(assets.tenantId, effectiveTenantId) : undefined

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

    let criticalCount = 0
    let highCount = 0
    let topRisks: Array<{ event_id: string; severity: string; event_type: string; asset_id: string }> = []

    if (total_assets > 0) {
      const scoped = and(tenantCondition, isOpenEvent())

      const [sevRows, topRiskRows] = await Promise.all([
        db
          .select({ severity: events.severity, count: sql<number>`count(*)::int` })
          .from(events)
          .innerJoin(assets, eq(events.assetId, assets.assetId))
          .where(and(scoped, inArray(events.severity, ['critical', 'high'])))
          .groupBy(events.severity),
        db
          .select({
            eventId: events.eventId,
            severity: events.severity,
            eventType: events.eventType,
            assetId: events.assetId,
          })
          .from(events)
          .innerJoin(assets, eq(events.assetId, assets.assetId))
          .where(and(scoped, eq(events.severity, 'critical')))
          .orderBy(desc(events.lastSeen))
          .limit(5),
      ])

      criticalCount = sevRows.find(r => r.severity === 'critical')?.count ?? 0
      highCount = sevRows.find(r => r.severity === 'high')?.count ?? 0
      topRisks = topRiskRows.map((r) => ({
        event_id: r.eventId,
        severity: r.severity,
        event_type: r.eventType,
        asset_id: r.assetId,
      }))
    }

    const score = postureScore(criticalCount, highCount, total_assets, total_critical_assets)

    // What is pulling the score down, so an analyst can explain the number
    const score_drivers = [
      { label: `${criticalCount} open critical alert${criticalCount === 1 ? '' : 's'}`, impact: -Math.min(criticalCount * 5, 40) },
      { label: `${highCount} open high alert${highCount === 1 ? '' : 's'}`, impact: -Math.min(highCount * 2, 20) },
      { label: `${Math.round(highCriticalityPercent * 100)}% of assets are high-criticality (limit 20%)`, impact: highCriticalityPercent > 0.2 ? -10 : 0 },
    ].filter(d => d.impact < 0)

    return c.json({
      overall_score: score,
      total_assets,
      total_critical_assets,
      open_critical_events: criticalCount,
      open_high_events: highCount,
      score_drivers,
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

    const raw   = c.req.query('limit') ?? c.req.query('days') ?? '14'
    const limit = Math.min(365, Math.max(1, parseInt(raw)))
    const now   = new Date()
    const since = new Date(now)
    since.setDate(since.getDate() - limit)

    const tenantIdParam = c.req.query('tenant_id')
    const effectiveTenantId = user.role === 'superadmin'
      ? (tenantIdParam ?? undefined)
      : (user.tenantId ?? undefined)
    const tenantCondition = effectiveTenantId ? eq(assets.tenantId, effectiveTenantId) : undefined

    // 2 bulk queries — no per-day loops. An alert counts on a day if it was
    // open at that day's end (raised by then, not yet closed); false positives
    // never count.
    const [allAssets, seriousEvents] = await Promise.all([
      db.select({ criticalityScore: assets.criticalityScore, createdAt: assets.createdAt })
        .from(assets)
        .where(tenantCondition),
      db.select({ severity: events.severity, firstSeen: events.firstSeen, resolvedAt: events.resolvedAt })
        .from(events)
        .innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(
          tenantCondition,
          inArray(events.severity, ['critical', 'high']),
          ne(events.status, 'false_positive'),
          or(isNull(events.resolvedAt), gte(events.resolvedAt, since)),
        )),
    ])

    const openAt = (sev: 'critical' | 'high', t: number) => seriousEvents.filter(e =>
      e.severity === sev
      && new Date(e.firstSeen).getTime() <= t
      && (!e.resolvedAt || new Date(e.resolvedAt).getTime() > t)).length

    const items = []
    for (let i = limit - 1; i >= 0; i--) {
      const dayEnd = new Date(now)
      dayEnd.setDate(dayEnd.getDate() - i)
      dayEnd.setHours(23, 59, 59, 999)
      const dayEndMs = Math.min(dayEnd.getTime(), now.getTime())

      const dayAssets   = allAssets.filter(a => a.createdAt && new Date(a.createdAt).getTime() <= dayEndMs)
      const totalAssets = dayAssets.length
      const totalCriticalAssets = dayAssets.filter(a => (a.criticalityScore ?? 0) >= 8).length
      const critCount   = openAt('critical', dayEndMs)
      const highCount   = openAt('high', dayEndMs)

      items.push({
        snapshot_id:           '00000000-0000-0000-0000-000000000000',
        overall_score:         postureScore(critCount, highCount, totalAssets, totalCriticalAssets),
        total_assets:          totalAssets,
        total_critical_assets: totalCriticalAssets,
        open_critical_events:  critCount,
        open_high_events:      highCount,
        top_risks:             [],
        timestamp:             dayEnd.toISOString(),
      })
    }

    return c.json({ items })
  } catch (err) {
    console.error('posture GET /history error:', err)
    return c.json({ detail: 'Failed to fetch posture history' }, 500)
  }
})

export default app
