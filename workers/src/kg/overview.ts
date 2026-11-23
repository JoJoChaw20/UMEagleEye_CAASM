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
import { dueAtExpr, priorityExpr, tierExpr } from '../lib/priority'
import { kbLabel } from '../lib/alertSignals'
import { TIER_LABEL, tierOfPriority } from '../lib/alertRank'

type DB = ReturnType<typeof getDb>

/** Database reads one overview makes; counted in the chat budget before it runs. */
export const OVERVIEW_SUBREQUESTS = 6
export const TOP_PRIORITIES = 8
const DAY = 86_400_000

export interface OverviewScope { tenantId?: string; detail: boolean }

export interface PriorityItem {
  tier: string; priority_score: number; due: string | null; severity: string; alert_type: string; status: string
  device?: string; internet_facing?: boolean; what?: string; advisory?: string | null; first_seen: string | null
}

/** PURE. The tier name of an alert's priority number (lib/alertRank.ts): Compromise, Exploited, Fix, Review. */
export function tierOf(priority: number): string {
  return TIER_LABEL[tierOfPriority(priority)]
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
  if (d.indicator_value) return short(`threat-intel match: ${d.indicator_value}${d.matched_on ? ` (${d.matched_on})` : ''}`)
  if (alertType === 'os_patch_missing' && d.platform === 'linux') return short(`${d.updates ?? '?'} Linux security update(s) waiting`)
  if (alertType === 'os_patch_missing') return short(`missing Windows update${kbLabel(d.kb) ? ` ${kbLabel(d.kb)}` : 's'}`)
  if (alertType === 'security_baseline') return short(`security baseline ${d.percent ?? '?'}% (target ${d.target ?? '?'}%), ${d.failed ?? '?'} checks failed`)
  return short(alertType.replace(/_/g, ' '))
}

export async function loadOverview(db: DB, scope: OverviewScope, now = Date.now()) {
  const assetScope = scope.tenantId ? eq(assets.tenantId, scope.tenantId) : undefined
  const open = inArray(events.status, [...OPEN_STATUSES])

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
      p0: sql<number>`count(*) filter (where ${tierExpr} = 1)::int`,
      p1: sql<number>`count(*) filter (where ${tierExpr} = 2)::int`,
      p2: sql<number>`count(*) filter (where ${tierExpr} = 3)::int`,
      overdue: sql<number>`count(*) filter (where now() > ${dueAtExpr})::int`,
    }).from(events).innerJoin(assets, eq(events.assetId, assets.assetId)).where(and(assetScope, open)),
    db.select({ status: advisories.status, n: sql<number>`count(*)::int` }).from(advisories)
      .innerJoin(events, eq(advisories.eventId, events.eventId)).innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(assetScope).groupBy(advisories.status),
    scope.detail
      ? db.select({
          eventId: events.eventId, type: events.eventType, severity: events.severity, status: events.status, details: events.details,
          firstSeen: events.firstSeen, score: priorityExpr, dueAt: dueAtExpr, hostname: assets.hostname, ip: assets.ipAddress,
          internet: sql<boolean>`COALESCE(${assets.internetFacingOverride}, ${assets.isInternetFacing})`,
          advisory: sql<string | null>`(SELECT a.advisory_id::text FROM advisories a WHERE a.event_id = ${events.eventId}
            AND a.status IN (${sql.join(ACTIVE_ADVISORY_STATUSES.map(s => sql`${s}`), sql`, `)}) ORDER BY a.created_at DESC LIMIT 1)`,
        }).from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
          .where(and(assetScope, open)).orderBy(desc(priorityExpr), desc(events.firstSeen)).limit(TOP_PRIORITIES)
      : Promise.resolve([]),
  ])
  return buildOverview({ assets: assetRow[0], agents: agentRows, scans: scanRow[0], alerts: alertRow[0], advisories: advisoryRows, top }, scope, now)
}

type Counts = Record<string, number | string | null | undefined>
export interface OverviewRows {
  assets?: Counts; agents: Array<{ kind: string | null; lastHeartbeat: Date | string | null }>; scans?: Counts; alerts?: Counts
  advisories: Array<{ status: string; n: number }>
  top: Array<{ eventId: string; type: string; severity: string; status: string; details: unknown; firstSeen: Date | string | null; score: number; dueAt?: Date | string | null; hostname: string | null; ip: string; internet: boolean; advisory: string | null }>
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
    priority_tiers: { compromise: p0, exploited: p1, fix: p2, review: Math.max(0, openTotal - p0 - p1 - p2) },
    overdue_alerts: num(rows.alerts?.overdue),
    ...(scope.detail ? {
      top_priorities: rows.top.map((t): PriorityItem => {
        const d = (t.details ?? {}) as Record<string, unknown>
        return {
          tier: tierOf(num(t.score)), priority_score: Math.round((num(t.score) % 1000) * 10) / 10, due: iso(t.dueAt),
          severity: t.severity, alert_type: t.type, status: t.status,
          device: short(t.hostname || t.ip, 80), internet_facing: Boolean(t.internet), what: alertWhat(t.type, d),
          advisory: t.advisory ? t.advisory.slice(0, 8) : null, first_seen: iso(t.firstSeen),
        }
      }),
    } : { note: 'Counts only for this role: device names and individual alerts are not shown.' }),
    tiers_explained: 'compromise = threat intelligence seen on a device (investigate within 24 hours); exploited = a CVE on CISA KEV (fix within 7 days if internet-facing, otherwise 14); fix = other vulnerabilities and exposures (15/30/90/180 days by severity); review = changes and new devices to confirm (7 days). priority_score is 0-100 within the tier; due is the fix-time target.',
  }
}
