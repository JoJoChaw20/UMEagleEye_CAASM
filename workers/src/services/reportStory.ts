/**
 * services/reportStory.ts — the facts behind the security posture report, in the order an
 * IT security admin decides in:
 *
 *   1. verdict      how bad is it, in one sentence, and the numbers that justify it
 *   2. actions      what to do first: the top fixes, ranked like the Alerts page (priorityExpr),
 *                   CVE alerts grouped into one upgrade per package and asset
 *   3. hotspots     where the risk sits: assets with the most open critical/high alerts
 *   4. changes      what changed in the reporting period (opened, closed, new devices, ports)
 *   5. progress     remediation: advisories by status, SLA breaches, unowned critical alerts
 *   6. coverage     what the numbers cannot see: assets without an SBOM, not seen recently
 *
 * Every query is scoped to one tenant (or none for the platform superadmin's all-tenant view).
 */
import { and, desc, eq, gte, inArray, lt, or, sql, type SQL } from 'drizzle-orm'
import type { DB } from '../db/client'
import { advisories, assets, events } from '../db/schema'
import { isOpenEvent } from '../lib/eventStatus'
import { priorityExpr } from '../lib/priority'
import { fixTarget } from '../lib/fixTarget'
import { ACTIVE_ADVISORY_STATUSES, advisoryInTenant } from '../lib/advisoryScope'

const SLA_HOURS = 72
const STALE_DAYS = 14

export const PERIOD_DAYS: Record<string, number> = { weekly: 7, monthly: 30, executive: 30 }

type Due = 'within 72 hours' | 'within 7 days' | 'next maintenance window'

export interface ReportAction {
  rank: number
  action: string
  asset: string
  ip: string | null
  why: string[]
  severity: string
  due: Due
  owner: string | null
  assigned: boolean
}

const label = (a: { hostname: string | null; ipAddress: string | null }) => a.hostname || a.ipAddress || 'unknown asset'
const num = (v: unknown): number | null => (v == null || v === '' || Number.isNaN(Number(v)) ? null : Number(v))

function actionText(type: string, d: Record<string, unknown>, group?: { pkg: string; to: string | null; count: number }): string {
  if (group) {
    return group.to
      ? `Upgrade ${group.pkg} to ${group.to} (fixes ${group.count} CVE${group.count === 1 ? '' : 's'})`
      : `Mitigate ${group.pkg}: no fixed version yet (${group.count} CVE${group.count === 1 ? '' : 's'})`
  }
  switch (type) {
    case 'port_opened': return `Review new open port ${d.port ?? '?'}/${d.protocol ?? 'tcp'}: close it or accept it`
    case 'new_device': return 'Identify the new device and give it an owner, or isolate it'
    case 'cti_match': return 'Investigate the threat-intelligence match on this host'
    case 'exposure': return `${String(d.title ?? 'Fix the exposure')} on port ${d.port ?? '?'}: ${String(d.fix ?? '').slice(0, 160)}`
    case 'os_patch_missing': return `Install the missing Windows updates${d.missing_kb ? ` (${String(d.missing_kb).slice(0, 40)})` : ''}`
    case 'version_downgrade': return `Check the downgrade of ${d.changed_attribute ?? 'a component'}${d.from ? ` from ${d.from} to ${d.to}` : ''}`
    case 'config_change': return `Review the configuration change${d.changed_attribute ? ` (${d.changed_attribute})` : ''}`
    default: return `Review the ${type.replace(/_/g, ' ')} alert`
  }
}

function whyAndDue(type: string, severity: string, d: Record<string, unknown>, a: { isInternetFacing: boolean | null; criticalityScore: number | null }) {
  const why: string[] = []
  const kev = d.kev === true
  const ti = type === 'cti_match' || d.has_cti_match === true
  const epss = num(d.epss_score) ?? 0
  const cvss = num(d.cvss_base_score)
  if (kev) why.push('exploited in the wild (CISA KEV)')
  if (ti) why.push('named by threat intelligence')
  if (type === 'os_patch_missing' && (num(d.exploited) ?? 0) > 0) why.push('missing fixes include exploited CVEs')
  if (epss >= 0.1) why.push(`EPSS ${Math.round(epss * 100)}%`)
  if (cvss != null && cvss >= 9) why.push(`CVSS ${cvss}`)
  if (a.isInternetFacing) why.push('internet-facing')
  if ((a.criticalityScore ?? 0) >= 8) why.push(`critical asset (${a.criticalityScore}/10)`)
  const severe = severity === 'critical' || severity === 'high'
  const due: Due = kev || ti || (type === 'os_patch_missing' && (num(d.exploited) ?? 0) > 0) ? 'within 72 hours'
    : (severe && (a.isInternetFacing || (a.criticalityScore ?? 0) >= 8)) || epss >= 0.1 || severity === 'critical' ? 'within 7 days'
    : 'next maintenance window'
  if (why.length === 0) why.push(`${severity} severity`)
  return { why, due }
}

export async function buildReportStory(db: DB, tenantId: string | undefined, reportType: string) {
  const days = PERIOD_DAYS[reportType] ?? 30
  const now = new Date()
  const since = new Date(now.getTime() - days * 86400_000)
  const slaCut = new Date(now.getTime() - SLA_HOURS * 3600_000)
  const staleCut = new Date(now.getTime() - STALE_DAYS * 86400_000)
  const af: SQL | undefined = tenantId ? eq(assets.tenantId, tenantId) : undefined
  const advTenant = tenantId ? advisoryInTenant(db, tenantId) : undefined
  const open = isOpenEvent()

  const [prio, risk, period, hotspots, coverage, advStatus, advResolved, slaList, slaTotal] = await Promise.all([
    // the open alerts in Alerts-page order (KEV, threat intel, risk, exposure, criticality)
    db.select({
      type: events.eventType, severity: events.severity, details: events.details, assignedTo: events.assignedTo,
      assetId: assets.assetId, hostname: assets.hostname, ipAddress: assets.ipAddress, owner: assets.owner,
      isInternetFacing: assets.isInternetFacing, criticalityScore: assets.criticalityScore,
    }).from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(and(af, open)).orderBy(desc(priorityExpr), desc(events.firstSeen)).limit(400),
    // how bad: one row of counts over the open alerts
    db.select({
      critical: sql<number>`count(*) FILTER (WHERE ${events.severity} = 'critical')::int`,
      high: sql<number>`count(*) FILTER (WHERE ${events.severity} = 'high')::int`,
      medium: sql<number>`count(*) FILTER (WHERE ${events.severity} = 'medium')::int`,
      low: sql<number>`count(*) FILTER (WHERE ${events.severity} = 'low')::int`,
      kev: sql<number>`count(*) FILTER (WHERE ${events.details}->>'kev' = 'true')::int`,
      threat_intel: sql<number>`count(*) FILTER (WHERE ${events.eventType} = 'cti_match' OR ${events.details}->>'has_cti_match' = 'true')::int`,
      exposed_assets: sql<number>`count(DISTINCT ${assets.assetId}) FILTER (WHERE ${assets.isInternetFacing} AND ${events.severity} IN ('critical', 'high'))::int`,
      affected_assets: sql<number>`count(DISTINCT ${assets.assetId}) FILTER (WHERE ${events.severity} IN ('critical', 'high'))::int`,
      unassigned_critical: sql<number>`count(*) FILTER (WHERE ${events.severity} = 'critical' AND ${events.assignedTo} IS NULL)::int`,
    }).from(events).innerJoin(assets, eq(events.assetId, assets.assetId)).where(and(af, open)),
    // what changed in the period
    db.select({
      opened: sql<number>`count(*) FILTER (WHERE ${events.firstSeen} >= ${since})::int`,
      closed: sql<number>`count(*) FILTER (WHERE ${events.resolvedAt} >= ${since} AND ${events.status} IN ('resolved', 'false_positive', 'accepted_risk'))::int`,
      new_devices: sql<number>`count(*) FILTER (WHERE ${events.eventType} = 'new_device' AND ${events.firstSeen} >= ${since})::int`,
      new_ports: sql<number>`count(*) FILTER (WHERE ${events.eventType} = 'port_opened' AND ${events.firstSeen} >= ${since})::int`,
      new_critical: sql<number>`count(*) FILTER (WHERE ${events.severity} = 'critical' AND ${events.firstSeen} >= ${since})::int`,
    }).from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(and(af, or(gte(events.firstSeen, since), gte(events.resolvedAt, since)))),
    // where the risk sits
    db.select({
      hostname: assets.hostname, ipAddress: assets.ipAddress, deviceType: assets.deviceType, owner: assets.owner,
      isInternetFacing: assets.isInternetFacing, criticalityScore: assets.criticalityScore,
      critical: sql<number>`count(*) FILTER (WHERE ${events.severity} = 'critical')::int`,
      high: sql<number>`count(*) FILTER (WHERE ${events.severity} = 'high')::int`,
      total: sql<number>`count(*)::int`,
      kev: sql<number>`count(*) FILTER (WHERE ${events.details}->>'kev' = 'true')::int`,
      cveChecked: sql<boolean>`EXISTS (SELECT 1 FROM sboms s WHERE s.asset_id = assets.asset_id)`,
    }).from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(and(af, open))
      .groupBy(assets.assetId)
      .orderBy(desc(sql`count(*) FILTER (WHERE ${events.details}->>'kev' = 'true')`),
        desc(sql`count(*) FILTER (WHERE ${events.severity} = 'critical')`),
        desc(sql`count(*) FILTER (WHERE ${events.severity} = 'high')`), desc(assets.criticalityScore))
      .limit(8),
    // what the report cannot see
    db.select({
      total: sql<number>`count(*)::int`,
      cve_checked: sql<number>`count(*) FILTER (WHERE EXISTS (SELECT 1 FROM sboms s WHERE s.asset_id = assets.asset_id))::int`,
      with_agent: sql<number>`count(*) FILTER (WHERE EXISTS (SELECT 1 FROM agents g WHERE g.host_asset_id = assets.asset_id))::int`,
      not_seen_recently: sql<number>`count(*) FILTER (WHERE GREATEST(${assets.lastScanned}, ${assets.inventoryCollectedAt}) < ${staleCut} OR (${assets.lastScanned} IS NULL AND ${assets.inventoryCollectedAt} IS NULL))::int`,
      no_owner: sql<number>`count(*) FILTER (WHERE NULLIF(trim(${assets.owner}), '') IS NULL)::int`,
    }).from(assets).where(af),
    // remediation progress
    db.select({ status: advisories.status, n: sql<number>`count(*)::int` }).from(advisories)
      .where(advTenant).groupBy(advisories.status),
    db.select({ n: sql<number>`count(*)::int` }).from(advisories)
      .where(and(advTenant, eq(advisories.status, 'resolved'), gte(advisories.resolvedAt, since))),
    db.select({ summary: advisories.summary, createdAt: advisories.createdAt, assignedTo: advisories.assignedTo })
      .from(advisories)
      .where(and(advTenant, inArray(advisories.status, [...ACTIVE_ADVISORY_STATUSES]), lt(advisories.createdAt, slaCut)))
      .orderBy(advisories.createdAt).limit(5),
    db.select({ n: sql<number>`count(*)::int` }).from(advisories)
      .where(and(advTenant, inArray(advisories.status, [...ACTIVE_ADVISORY_STATUSES]), lt(advisories.createdAt, slaCut))),
  ])

  // ── top actions: one per CVE package and asset, one per other alert ──
  const actions: ReportAction[] = []
  const grouped = new Map<string, { idx: number; installed: string | null; fixes: unknown[]; count: number }>()
  for (const r of prio) {
    const d = (r.details ?? {}) as Record<string, unknown>
    const pkg = r.type === 'cve_detected' && typeof d.package_name === 'string' ? d.package_name : null
    const key = pkg ? `${r.assetId}|${pkg}` : null
    if (key && grouped.has(key)) {
      const g = grouped.get(key)!
      g.fixes.push(d.fix_versions)
      g.count++
      continue
    }
    if (actions.length >= 8) continue
    const { why, due } = whyAndDue(r.type, r.severity, d, r)
    actions.push({
      rank: actions.length + 1, action: actionText(r.type, d), asset: label(r), ip: r.hostname ? r.ipAddress : null,
      why, severity: r.severity, due, owner: r.owner?.trim() || null, assigned: !!r.assignedTo,
    })
    if (key) grouped.set(key, { idx: actions.length - 1, installed: typeof d.package_version === 'string' ? d.package_version : null, fixes: [d.fix_versions], count: 1 })
  }
  for (const [key, g] of grouped) {
    const pkg = key.split('|').slice(1).join('|')
    const t = fixTarget(g.installed, g.fixes)
    actions[g.idx]!.action = actionText('cve_detected', {}, { pkg: `${pkg}${g.installed ? ` ${g.installed}` : ''}`, to: t.to, count: g.count })
  }

  // ── the verdict ──
  const r0 = risk[0] ?? { critical: 0, high: 0, medium: 0, low: 0, kev: 0, threat_intel: 0, exposed_assets: 0, affected_assets: 0, unassigned_critical: 0 }
  const cov = coverage[0] ?? { total: 0, cve_checked: 0, with_agent: 0, not_seen_recently: 0, no_owner: 0 }
  const level: 'critical' | 'elevated' | 'stable' =
    r0.kev > 0 || r0.threat_intel > 0 || r0.exposed_assets > 0 ? 'critical'
      : r0.critical > 0 || r0.high > 0 ? 'elevated' : 'stable'
  const parts: string[] = []
  if (r0.kev) parts.push(`${r0.kev} alert${r0.kev === 1 ? ' is' : 's are'} on CVEs exploited in the wild`)
  if (r0.threat_intel) parts.push(`${r0.threat_intel} match${r0.threat_intel === 1 ? 'es' : ''} threat intelligence`)
  if (r0.exposed_assets) parts.push(`${r0.exposed_assets} internet-facing asset${r0.exposed_assets === 1 ? ' has' : 's have'} critical or high alerts`)
  const headline = level === 'critical'
    ? `Act now: ${parts.join('; ')}. ${r0.critical} critical and ${r0.high} high alerts are open on ${r0.affected_assets} assets.`
    : level === 'elevated'
      ? `Needs attention: ${r0.critical} critical and ${r0.high} high alerts are open on ${r0.affected_assets} assets; none is known to be exploited or internet-facing.`
      : 'Stable: no critical or high alerts are open.'
  const blindSpot = cov.total > 0 && cov.cve_checked < cov.total
    ? `${cov.total - cov.cve_checked} of ${cov.total} assets are not CVE-checked (no SBOM), so their vulnerabilities are not in these numbers.`
    : null

  const statusCount = Object.fromEntries(advStatus.map(s => [s.status, s.n])) as Record<string, number>
  return {
    period_days: days,
    verdict: { level, headline, blind_spot: blindSpot },
    risk: r0,
    actions,
    hotspots: hotspots.map(h => ({
      asset: label(h), ip: h.hostname ? h.ipAddress : null, device_type: h.deviceType, owner: h.owner?.trim() || null,
      internet_facing: !!h.isInternetFacing, criticality: h.criticalityScore, critical: h.critical, high: h.high,
      total: h.total, kev: h.kev, cve_checked: !!h.cveChecked,
    })),
    changes: period[0] ?? { opened: 0, closed: 0, new_devices: 0, new_ports: 0, new_critical: 0 },
    progress: {
      open: statusCount.open ?? 0, acknowledged: statusCount.acknowledged ?? 0, in_progress: statusCount.in_progress ?? 0,
      resolved_in_period: advResolved[0]?.n ?? 0,
      sla_total: slaTotal[0]?.n ?? 0,
      sla_breaches: slaList.map(s => ({
        summary: s.summary, age_days: Math.floor((now.getTime() - new Date(s.createdAt).getTime()) / 86400_000), assigned: !!s.assignedTo,
      })),
      unassigned_critical: r0.unassigned_critical,
    },
    coverage: cov,
  }
}

