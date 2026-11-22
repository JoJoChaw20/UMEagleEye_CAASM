/**
 * Weekly history (lib/weekly.ts): one record per tenant per finished week, kept in weekly_snapshots.
 *
 * The nightly job (cron/triggers.ts) records each tenant's weeks that are missing, the last
 * MAX_BACKFILL at most: on Monday the week that just ended, the first time the weeks before it
 * (reconstructed from alert dates, `backfilled`). One SQL statement per tenant computes all its
 * missing weeks, and one batch saves them: a few subrequests a night whatever the number of weeks.
 *
 * "Open when the week ended": first seen before the end, and still open, or closed after it (an
 * alert closed without a resolved date counts as closed when last updated). A reconstructed week
 * counts each alert with its severity, tier and due date of today, and cannot know devices removed
 * since; a week recorded when it ends has the numbers of that moment.
 */
import { and, desc, eq, gte, inArray, sql } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { tenants, weeklySnapshots } from '../db/schema'
import { clockStartExpr, dueAtExpr, tierExpr } from '../lib/priority'
import { KEV_ALERT } from '../lib/alertSignals'
import { addWeeks, finishedWeeks, weekBounds, weekStartOf, type WeekMetrics } from '../lib/weekly'

type DB = ReturnType<typeof getDb>

export const MAX_BACKFILL = 12

const OPEN_AT_END = sql`("events"."status" IN ('open', 'in_progress') OR COALESCE("events"."resolved_at", "events"."updated_at") >= w.e)`
const IN_WEEK = (col: string) => sql.raw(`(${col} >= w.s AND ${col} < w.e)`)

/** Metrics of the given weeks for one tenant, in one statement. `prevTotals` (live records of the week
 *  before) give devices removed. */
export async function computeWeeks(db: DB, tenantId: string, weekStarts: string[], prevTotals: Map<string, number> = new Map()): Promise<Map<string, WeekMetrics>> {
  const out = new Map<string, WeekMetrics>()
  if (!weekStarts.length) return out
  const weeks = weekStarts.map((w) => { const b = weekBounds(w); return { week_start: w, s: b.start.toISOString(), e: b.end.toISOString() } })
  const res = await db.execute(sql`
    WITH w AS (SELECT * FROM jsonb_to_recordset(${JSON.stringify(weeks)}::jsonb) AS w(week_start text, s timestamptz, e timestamptz))
    SELECT w.week_start,
      (SELECT jsonb_build_object(
          'open_end', count(*) FILTER (WHERE ${OPEN_AT_END}),
          't1', count(*) FILTER (WHERE ${OPEN_AT_END} AND ${tierExpr} = 1),
          't2', count(*) FILTER (WHERE ${OPEN_AT_END} AND ${tierExpr} = 2),
          't3', count(*) FILTER (WHERE ${OPEN_AT_END} AND ${tierExpr} = 3),
          't4', count(*) FILTER (WHERE ${OPEN_AT_END} AND ${tierExpr} = 4),
          'critical', count(*) FILTER (WHERE ${OPEN_AT_END} AND "events"."severity" = 'critical'),
          'high', count(*) FILTER (WHERE ${OPEN_AT_END} AND "events"."severity" = 'high'),
          'medium', count(*) FILTER (WHERE ${OPEN_AT_END} AND "events"."severity" = 'medium'),
          'low', count(*) FILTER (WHERE ${OPEN_AT_END} AND "events"."severity" = 'low'),
          'overdue_end', count(*) FILTER (WHERE ${OPEN_AT_END} AND ${dueAtExpr} < w.e),
          'kev_open_end', count(*) FILTER (WHERE ${OPEN_AT_END} AND ${KEV_ALERT}),
          'new', count(*) FILTER (WHERE ${IN_WEEK('"events"."first_seen"')}),
          'resolved', count(*) FILTER (WHERE "events"."status" = 'resolved' AND ${IN_WEEK('"events"."resolved_at"')}),
          'closed_other', count(*) FILTER (WHERE "events"."status" IN ('false_positive', 'accepted_risk') AND ${IN_WEEK('"events"."resolved_at"')}),
          'on_time', count(*) FILTER (WHERE "events"."status" = 'resolved' AND ${IN_WEEK('"events"."resolved_at"')} AND "events"."resolved_at" <= ${dueAtExpr}),
          'median_resolve_hours', percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch from ("events"."resolved_at" - ${clockStartExpr})) / 3600)
              FILTER (WHERE "events"."status" = 'resolved' AND ${IN_WEEK('"events"."resolved_at"')} AND "events"."resolved_at" >= ${clockStartExpr}),
          'sightings_new', count(*) FILTER (WHERE "events"."event_type" = 'cti_match' AND "events"."details"->>'match_kind' = 'sighting' AND ${IN_WEEK('"events"."first_seen"')})
        )
        FROM "events" JOIN "assets" ON "assets"."asset_id" = "events"."asset_id"
        WHERE "assets"."tenant_id" = ${tenantId}::uuid AND "events"."first_seen" < w.e) AS ev,
      (SELECT COALESCE(jsonb_object_agg(t, n), '{}'::jsonb) FROM (
          SELECT "events"."event_type"::text AS t, count(*) AS n
          FROM "events" JOIN "assets" ON "assets"."asset_id" = "events"."asset_id"
          WHERE "assets"."tenant_id" = ${tenantId}::uuid AND "events"."first_seen" < w.e AND ${OPEN_AT_END}
          GROUP BY 1) x) AS by_type,
      (SELECT count(*) FROM "assets" a WHERE a.tenant_id = ${tenantId}::uuid AND a.created_at < w.e)::int AS assets_total,
      (SELECT count(*) FROM "assets" a WHERE a.tenant_id = ${tenantId}::uuid AND a.created_at >= w.s AND a.created_at < w.e)::int AS assets_added,
      (SELECT p.overall_score FROM posture_metrics p WHERE p.tenant_id = ${tenantId}::uuid AND p.timestamp >= w.s AND p.timestamp < w.e
        ORDER BY p.timestamp DESC LIMIT 1) AS posture_score
    FROM w`)
  for (const r of res.rows as Array<{ week_start: string; ev: Record<string, number | null>; by_type: Record<string, number>; assets_total: number; assets_added: number; posture_score: number | null }>) {
    const e = r.ev ?? {}
    const n = (k: string) => Number(e[k] ?? 0)
    const resolved = n('resolved')
    const prev = prevTotals.get(addWeeks(r.week_start, -1))
    const median = e.median_resolve_hours == null ? null : Math.round(Number(e.median_resolve_hours) * 10) / 10
    out.set(r.week_start, {
      assets_total: Number(r.assets_total), assets_added: Number(r.assets_added),
      assets_removed: prev == null ? null : Math.max(0, prev + Number(r.assets_added) - Number(r.assets_total)),
      open_end: n('open_end'),
      open_by_tier: { 1: n('t1'), 2: n('t2'), 3: n('t3'), 4: n('t4') },
      open_by_severity: { critical: n('critical'), high: n('high'), medium: n('medium'), low: n('low') },
      open_by_type: Object.fromEntries(Object.entries(r.by_type ?? {}).map(([k, v]) => [k, Number(v)])),
      overdue_end: n('overdue_end'), new: n('new'), resolved, closed_other: n('closed_other'),
      median_resolve_hours: median, on_time: n('on_time'), on_time_pct: resolved ? Math.round((n('on_time') / resolved) * 100) : null,
      kev_open_end: n('kev_open_end'), sightings_new: n('sightings_new'),
      posture_score: r.posture_score == null ? null : Number(r.posture_score),
    })
  }
  return out
}

/** Record every tenant's missing finished weeks (the last MAX_BACKFILL), each tenant from its first week.
 *  A week recorded within a day of its end is "live"; later ones are reconstructed. Returns how many. */
export async function recordWeeks(db: DB, now: Date = new Date()): Promise<{ weeks: number; tenants: number; live: Array<{ tenantId: string; weekStart: string }> }> {
  const candidates = finishedWeeks(now, MAX_BACKFILL)
  const rows = await db.select({ tenantId: tenants.tenantId, createdAt: tenants.createdAt }).from(tenants)
  const have = await db.select({ tenantId: weeklySnapshots.tenantId, weekStart: weeklySnapshots.weekStart, metrics: weeklySnapshots.metrics, backfilled: weeklySnapshots.backfilled })
    .from(weeklySnapshots).where(gte(weeklySnapshots.weekStart, addWeeks(candidates[0]!, -1)))
  let weeks = 0, touched = 0
  const inserts = []
  const out: Array<{ tenantId: string; weekStart: string }> = []      // weeks recorded as they ended
  for (const t of rows) {
    const firstWeek = weekStartOf(t.createdAt)
    const mine = have.filter((h) => h.tenantId === t.tenantId)
    const missing = candidates.filter((w) => w >= firstWeek && !mine.some((h) => h.weekStart === w))
    if (!missing.length) continue
    const prevTotals = new Map(mine.filter((h) => !h.backfilled).map((h) => [h.weekStart, Number((h.metrics as WeekMetrics).assets_total)]))
    const computed = await computeWeeks(db, t.tenantId, missing, prevTotals)
    for (const [weekStart, metrics] of computed) {
      const live = now.getTime() - weekBounds(weekStart).end.getTime() < 86_400_000
      inserts.push(db.insert(weeklySnapshots).values({ tenantId: t.tenantId, weekStart, metrics, backfilled: !live })
        .onConflictDoNothing({ target: [weeklySnapshots.tenantId, weeklySnapshots.weekStart] }))
      if (live) out.push({ tenantId: t.tenantId, weekStart })
      weeks++
    }
    touched++
  }
  if (inserts.length) await db.batch(inserts as [typeof inserts[number], ...typeof inserts])
  return { weeks, tenants: touched, live: out }
}

export interface WeeklyView {
  weeks: Array<{ week_start: string; metrics: WeekMetrics; backfilled: boolean }>   // newest first
  current: { week_start: string; metrics: WeekMetrics }                              // this week so far
  baseline_week: string | null
  baseline: WeekMetrics | null
}

/** A tenant's recorded weeks (newest first), this week so far, and its baseline. */
export async function weeklyView(db: DB, tenantId: string, limit = 12): Promise<WeeklyView> {
  const now = new Date()
  const [rows, [tenant], current] = await Promise.all([
    db.select().from(weeklySnapshots).where(eq(weeklySnapshots.tenantId, tenantId)).orderBy(desc(weeklySnapshots.weekStart)).limit(limit),
    db.select({ baseline: tenants.baselineWeek }).from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1),
    computeWeeks(db, tenantId, [weekStartOf(now)]),
  ])
  const baselineWeek = tenant?.baseline ?? null
  let baseline = rows.find((r) => r.weekStart === baselineWeek)?.metrics as WeekMetrics | undefined
  if (baselineWeek && !baseline) {
    const [b] = await db.select({ metrics: weeklySnapshots.metrics }).from(weeklySnapshots)
      .where(and(eq(weeklySnapshots.tenantId, tenantId), inArray(weeklySnapshots.weekStart, [baselineWeek]))).limit(1)
    baseline = b?.metrics as WeekMetrics | undefined
  }
  const cw = weekStartOf(now)
  return {
    weeks: rows.map((r) => ({ week_start: r.weekStart, metrics: r.metrics as WeekMetrics, backfilled: r.backfilled })),
    current: { week_start: cw, metrics: current.get(cw)! },
    baseline_week: baselineWeek,
    baseline: baseline ?? null,
  }
}
