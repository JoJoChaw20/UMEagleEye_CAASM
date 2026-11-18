/**
 * overview.ts - the overall status a person sees on the dashboard, for "how are we doing / what is going on /
 * what should we fix first" questions in the chat. Every number comes from the database with the dashboard's
 * own rules: postureScore (lib/eventStatus), agentLiveness, and the priority score (lib/priority) with the
 * dashboard's tiers (P0 direct threat intel, P1 >= 100, P2 >= 75, P3 the rest).
 *
 * Access is decided by the caller (intelRunner-style, from the signed-in user): `detail` false gives counts
 * only, with no device names (a role limited to status and score, and the Platform Superadmin).
 */
import { and, desc, eq, gte, inArray, isNull, sql } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { advisories, agents, assets, events, scanResults } from '../db/schema'
import { agentLiveness } from '../lib/agentLiveness'
import { ACTIVE_ADVISORY_STATUSES } from '../lib/advisoryScope'
import { OPEN_STATUSES, postureScore } from '../lib/eventStatus'
import { priorityExpr } from '../lib/priority'

type DB = ReturnType<typeof getDb>

/** Database reads one overview makes; counted in the chat budget before it runs. */
export const OVERVIEW_SUBREQUESTS = 6
export const TOP_PRIORITIES = 8
const DAY = 86_400_000

export interface OverviewScope { tenantId?: string; detail: boolean }

export interface PriorityItem {
  tier: 'P0' | 'P1' | 'P2' | 'P3'; priority_score: number; severity: string; alert_type: string; status: string
  device?: string; internet_facing?: boolean; what?: string; advisory?: string | null; first_seen: string | null
}

/** PURE. The dashboard's tier for an open alert (frontend components/dashboard/dashboardUtils.js operationalTier). */
export function tierOf(alertType: string, details: Record<string, unknown>, score: number): PriorityItem['tier'] {
  const directIntel = alertType === 'cti_match' ? details.match_kind !== 'watchlist' : alertType !== 'cve_detected' && Boolean(details.has_cti_match)
  if (directIntel) return 'P0'
  if (score >= 100) return 'P1'
  if (score >= 75) return 'P2'
  return 'P3'
}

const short = (v: unknown, max = 80): string => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max)

/** PURE. A one-line description of what an alert is about, from its details. */
export function alertWhat(alertType: string, d: Record<string, unknown>): string {
  if (alertType === 'cve_detected' && d.package_name) {
    const cves = Number(d.cve_count ?? 0), kev = Number(d.kev_count ?? 0)
    return short(`${d.package_name} ${d.package_version ?? ''}: ${cves || 1} CVE(s)${kev ? `, ${kev} known exploited` : ''}${d.fix_to ? `, fixed in ${d.fix_to}` : ''}`, 140)
  }
  if (d.cve_id) return short(`${d.cve_id}${d.kev ? ' (known exploited)' : ''}`)
  if (d.port) return short(`port ${d.port}/${d.protocol ?? 'tcp'}${d.service ? ` (${d.service})` : ''} open`)
  if (d.indicator) return short(`threat-intel match: ${d.indicator}`)
  if (d.missing_kb) return short(`missing Windows update ${d.missing_kb}`)
  return short(alertType.replace(/_/g, ' '))
}

export async function loadOverview(db: DB, scope: OverviewScope, now = Date.now()) {
  const assetScope = scope.tenantId ? eq(assets.tenantId, scope.tenantId) : undefined
  const open = inArray(events.status, [...OPEN_STATUSES])
  const directIntel = sql`(CASE WHEN ${events.eventType} = 'cti_match' THEN COALESCE(${events.details}->>'match_kind', '') <> 'watchlist'
    ELSE ${events.eventType} <> 'cve_detected' AND COALESCE((${events.details}->>'has_cti_match')::boolean, false) END)`

  const [assetRow, agentRows, scanRow, alertRow, advisoryRows, top] = await Promise.all([
    db.select({
      total: sql<number>`count(*)::int`,
      critical: sql<number>`count(*) filter (where ${assets.criticalityScore} >= 8)::int`,
      internet: sql<number>`count(*) filter (where COALESCE(${assets.internetFacingOverride}, ${assets.isInternetFacing}))::int`,
    }).from(assets).where(assetScope),
    db.select({ kind: agents.kind, lastHeartbeat: agents.lastHeartbeat }).from(agents)
      .where(and(scope.tenantId ? eq(agents.tenantId, scope.tenantId) : undefined, isNull(agents.retiredAt))),
    db.select({
      total: sql<number>`count(*)::int`,
      failed: sql<number>`count(*) filter (where ${scanResults.status} = 'failed')::int`,
      running: sql<number>`count(*) filter (where ${scanResults.status} in ('pending', 'running', 'queued'))::int`,
      last: sql<string | null>`max(${scanResults.completedAt})`,
    }).from(scanResults).where(and(scope.tenantId ? eq(scanResults.tenantId, scope.tenantId) : undefined, gte(scanResults.startedAt, new Date(now - 7 * DAY)))),
    db.select({
      total: sql<number>`count(*)::int`,
      critical: sql<number>`count(*) filter (where ${events.severity} = 'critical')::int`,
      high: sql<number>`count(*) filter (where ${events.severity} = 'high')::int`,
      medium: sql<number>`count(*) filter (where ${events.severity} = 'medium')::int`,
      low: sql<number>`count(*) filter (where ${events.severity} = 'low')::int`,
      newWeek: sql<number>`count(*) filter (where ${events.firstSeen} >= ${new Date(now - 7 * DAY)})::int`,
      p0: sql<number>`count(*) filter (where ${directIntel})::int`,
      p1: sql<number>`count(*) filter (where not ${directIntel} and ${priorityExpr} >= 100)::int`,
      p2: sql<number>`count(*) filter (where not ${directIntel} and ${priorityExpr} >= 75 and ${priorityExpr} < 100)::int`,
    }).from(events).innerJoin(assets, eq(events.assetId, assets.assetId)).where(and(assetScope, open)),
    db.select({ status: advisories.status, n: sql<number>`count(*)::int` }).from(advisories)
      .innerJoin(events, eq(advisories.eventId, events.eventId)).innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(assetScope).groupBy(advisories.status),
    scope.detail
      ? db.select({
          eventId: events.eventId, type: events.eventType, severity: events.severity, status: events.status, details: events.details,
          firstSeen: events.firstSeen, score: priorityExpr, hostname: assets.hostname, ip: assets.ipAddress,
          internet: sql<boolean>`COALESCE(${assets.internetFacingOverride}, ${assets.isInternetFacing})`,
          advisory: sql<string | null>`(SELECT a.advisory_id::text FROM advisories a WHERE a.event_id = ${events.eventId}
            AND a.status IN (${sql.join(ACTIVE_ADVISORY_STATUSES.map(s => sql`${s}`), sql`, `)}) ORDER BY a.created_at DESC LIMIT 1)`,
        }).from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
          .where(and(assetScope, open)).orderBy(desc(directIntel), desc(priorityExpr), desc(events.firstSeen)).limit(TOP_PRIORITIES)
      : Promise.resolve([]),
  ])
  return buildOverview({ assets: assetRow[0], agents: agentRows, scans: scanRow[0], alerts: alertRow[0], advisories: advisoryRows, top }, scope, now)
}

type Counts = Record<string, number | string | null | undefined>
export interface OverviewRows {
  assets?: Counts; agents: Array<{ kind: string | null; lastHeartbeat: Date | string | null }>; scans?: Counts; alerts?: Counts
  advisories: Array<{ status: string; n: number }>
  top: Array<{ eventId: string; type: string; severity: string; status: string; details: unknown; firstSeen: Date | string | null; score: number; hostname: string | null; ip: string; internet: boolean; advisory: string | null }>
}

const num = (v: unknown) => Number(v ?? 0) || 0
const iso = (v: unknown) => (v == null ? null : v instanceof Date ? v.toISOString() : String(v))

/** PURE. The overview from its rows: sections the dashboard shows, and the priorities to act on first. */
export function buildOverview(rows: OverviewRows, scope: OverviewScope, now = Date.now()) {
  const totalAssets = num(rows.assets?.total), criticalAssets = num(rows.assets?.critical)
  const openCritical = num(rows.alerts?.critical), openHigh = num(rows.alerts?.high)
  const live = { online: 0, degraded: 0, offline: 0 }
  for (const a of rows.agents) live[agentLiveness(a.lastHeartbeat, a.kind, now)]++
  const byStatus = Object.fromEntries(rows.advisories.map(r => [r.status, num(r.n)]))
  const activeAdvisories = ACTIVE_ADVISORY_STATUSES.reduce((n, s) => n + num(byStatus[s]), 0)
  const p0 = num(rows.alerts?.p0), p1 = num(rows.alerts?.p1), p2 = num(rows.alerts?.p2)
  const openTotal = num(rows.alerts?.total)
  return {
    scope: scope.tenantId ? 'this company' : 'all companies',
    // Stated as a value: verification reads numbers in values, not inside field names like scans_last_7_days.
    period_days: 7,
    posture_score: postureScore(openCritical, openHigh, totalAssets, criticalAssets),
    assets: { total: totalAssets, critical: criticalAssets, internet_facing: num(rows.assets?.internet) },
    agents: { total: rows.agents.length, ...live },
    scans_last_7_days: { total: num(rows.scans?.total), failed: num(rows.scans?.failed), in_progress: num(rows.scans?.running), last_completed: iso(rows.scans?.last) },
    open_alerts: { total: openTotal, critical: openCritical, high: openHigh, medium: num(rows.alerts?.medium), low: num(rows.alerts?.low), new_last_7_days: num(rows.alerts?.newWeek) },
    advisories: { active: activeAdvisories, by_status: byStatus },
    priority_tiers: { P0_investigate: p0, P1_urgent: p1, P2_high: p2, P3_routine: Math.max(0, openTotal - p0 - p1 - p2) },
    ...(scope.detail ? {
      top_priorities: rows.top.map((t): PriorityItem => {
        const d = (t.details ?? {}) as Record<string, unknown>
        return {
          tier: tierOf(t.type, d, num(t.score)), priority_score: num(t.score), severity: t.severity, alert_type: t.type, status: t.status,
          device: short(t.hostname || t.ip, 80), internet_facing: Boolean(t.internet), what: alertWhat(t.type, d),
          advisory: t.advisory ? t.advisory.slice(0, 8) : null, first_seen: iso(t.firstSeen),
        }
      }),
    } : { note: 'Counts only for this role: device names and individual alerts are not shown.' }),
    tiers_explained: 'P0 = direct threat-intelligence match (investigate now); P1 = priority score 100+ (urgent); P2 = 75-99 (high); P3 = the rest.',
  }
}
