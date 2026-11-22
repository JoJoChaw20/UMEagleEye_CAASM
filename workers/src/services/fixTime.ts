/**
 * Fix-time figures for the SOC to report upward (Dashboard and Reports): the work waiting, what is
 * overdue or due in the next 7 days (in alerts and in estimated hours, lib/alertRank.ts EFFORT_HOURS),
 * how many alerts were fixed within their target, and how long fixes actually take here.
 *
 * Time to resolve is measured per alert type from the tenant's own resolved alerts (last 90 days):
 * the median, from when the fix-time clock started (first seen, or reopened) to resolved. It is shown
 * as an expectation only from MIN_RESOLVED alerts of that type: fewer would be guesswork.
 * On time: alerts resolved in the last 30 days whose resolution came before their due date (closed as
 * false positive or accepted risk is a decision, not a fix, so those are left out of both).
 */
import { and, eq, gte, sql, type SQL } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { assets, events } from '../db/schema'
import { isOpenEvent } from '../lib/eventStatus'
import { clockStartExpr, dueAtExpr, effortHoursExpr, effortKeyExpr } from '../lib/priority'
import { EFFORT_HOURS, EFFORT_LABEL, type EffortKey } from '../lib/alertRank'

type DB = ReturnType<typeof getDb>

export const MIN_RESOLVED = 10
const DAY = 86_400_000

export interface Workload { count: number; hours: number }
export interface FixTime {
  open: Workload
  overdue: Workload
  due_7d: Workload
  by_effort: Array<{ key: EffortKey; label: string; hours_each: number; open: number; hours: number; overdue: number; due_7d: number }>
  on_time_30d: { resolved: number; on_time: number; pct: number | null }
  time_to_resolve: Array<{ type: string; resolved: number; median_hours: number; reliable: boolean }>
  min_resolved: number
}

const resolvedHours = sql`extract(epoch from (${events.resolvedAt} - ${clockStartExpr})) / 3600`
const round1 = (n: unknown) => Math.round(Number(n ?? 0) * 10) / 10

/** Median hours to resolve per alert type, last 90 days, in `scope` (one type when given). */
async function timeToResolve(db: DB, scope: SQL | undefined, type?: string) {
  const rows = await db.select({
      type: events.eventType,
      n: sql<number>`count(*)::int`,
      median: sql<number>`percentile_cont(0.5) within group (order by ${resolvedHours})::float`,
    })
    .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
    .where(and(scope, eq(events.status, 'resolved'), gte(events.resolvedAt, new Date(Date.now() - 90 * DAY)),
      sql`${events.resolvedAt} >= ${clockStartExpr}`, type ? sql`${events.eventType} = ${type}` : undefined))
    .groupBy(events.eventType)
  return rows.map((r) => ({ type: String(r.type), resolved: r.n, median_hours: round1(r.median), reliable: r.n >= MIN_RESOLVED }))
    .sort((a, b) => b.resolved - a.resolved)
}

export async function fixTimeSummary(db: DB, tenantId: string | undefined): Promise<FixTime> {
  const scope = tenantId ? eq(assets.tenantId, tenantId) : undefined
  const week = sql`now() + interval '7 days'`
  const [workRows, onTime, ttr] = await Promise.all([
    db.select({
        key: sql<string>`${effortKeyExpr}`,
        open: sql<number>`count(*)::int`,
        hours: sql<number>`sum(${effortHoursExpr})::float`,
        overdue: sql<number>`count(*) filter (where now() > ${dueAtExpr})::int`,
        overdueHours: sql<number>`COALESCE(sum(${effortHoursExpr}) filter (where now() > ${dueAtExpr}), 0)::float`,
        due7: sql<number>`count(*) filter (where ${dueAtExpr} between now() and ${week})::int`,
        due7Hours: sql<number>`COALESCE(sum(${effortHoursExpr}) filter (where ${dueAtExpr} between now() and ${week}), 0)::float`,
      })
      .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(and(scope, isOpenEvent()))
      .groupBy(sql`1`),
    db.select({
        resolved: sql<number>`count(*)::int`,
        onTime: sql<number>`count(*) filter (where ${events.resolvedAt} <= ${dueAtExpr})::int`,
      })
      .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(and(scope, eq(events.status, 'resolved'), gte(events.resolvedAt, new Date(Date.now() - 30 * DAY)))),
    timeToResolve(db, scope),
  ])

  const by_effort = (Object.keys(EFFORT_HOURS) as EffortKey[]).map((key) => {
    const r = workRows.find((w) => w.key === key)
    return {
      key, label: EFFORT_LABEL[key], hours_each: EFFORT_HOURS[key],
      open: r?.open ?? 0, hours: round1(r?.hours), overdue: r?.overdue ?? 0, due_7d: r?.due7 ?? 0,
    }
  }).filter((r) => r.open > 0)
  const sum = (f: (w: typeof workRows[number]) => number) => round1(workRows.reduce((s, w) => s + Number(f(w) ?? 0), 0))
  const resolved = onTime[0]?.resolved ?? 0
  const inTime = onTime[0]?.onTime ?? 0
  return {
    open: { count: sum((w) => w.open), hours: sum((w) => w.hours) },
    overdue: { count: sum((w) => w.overdue), hours: sum((w) => w.overdueHours) },
    due_7d: { count: sum((w) => w.due7), hours: sum((w) => w.due7Hours) },
    by_effort,
    on_time_30d: { resolved, on_time: inTime, pct: resolved ? Math.round((inTime / resolved) * 100) : null },
    time_to_resolve: ttr,
    min_resolved: MIN_RESOLVED,
  }
}

/** One alert's expectation: the tenant's median for its type, when there are enough to go by. */
export async function expectedTimeToResolve(db: DB, tenantId: string | null, type: string): Promise<{ median_hours: number; resolved: number } | null> {
  if (!tenantId) return null
  const [r] = await timeToResolve(db, eq(assets.tenantId, tenantId), type)
  return r && r.reliable ? { median_hours: r.median_hours, resolved: r.resolved } : null
}
