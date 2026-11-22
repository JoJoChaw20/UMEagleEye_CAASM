// How urgent an alert is: its tier (why it is urgent), its score (how risky, 0-100, comparable
// across alert types) and its fix-time target (when it is due). PURE: lib/priority.ts holds the
// same rules as SQL for sorting and counting, and alertRank.test.ts checks both agree.
//
//   tier 1  Compromise  threat intelligence seen on a host (indicator match or sighting) rated
//                       high or critical                                    investigate in 24 h
//   tier 2  Exploited   a CVE on CISA KEV, or a missing Windows update that fixes an exploited CVE
//                                                         7 days internet-facing, 14 days otherwise
//   tier 3  Fix         other vulnerabilities (packages, services, Windows updates), exposures,
//                       a risky port that opened              critical 15 / high 30 / medium 90 / low 180 days
//   tier 4  Review      new devices, configuration and version changes, other new ports,
//                       watchlist hits, weak threat-intel matches               review in 7 days
//
// Score: a vulnerability keeps its validated composite risk score (lib/riskScore.ts:
// 0.40 CVSS + 0.35 EPSS + 0.15 criticality + 10 if threat intel names it). Other alerts use
// 0.85 x base(severity) + 0.15 x criticality x 10, base critical 85 / high 70 / medium 50 / low 30.
// Internet-facing counts once: +15 for alerts whose severity does not already include it.
//
// Targets: CISA BOD 22-01 (KEV in two weeks), PCI DSS v4.0 6.3.3 (critical patches in a month)
// and common enterprise practice. A tenant may change any of them (tenants.sla_policy, hours).
import { RISKY_PORTS } from './exposure'

export type Tier = 1 | 2 | 3 | 4
export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type SlaKey = 'compromise' | 'kev_exposed' | 'kev' | 'critical' | 'high' | 'medium' | 'low' | 'review'

export const TIER_LABEL: Record<Tier, string> = { 1: 'Compromise', 2: 'Exploited', 3: 'Fix', 4: 'Review' }

const H = 1, D = 24
/** Default fix-time targets in hours. */
export const SLA_DEFAULTS: Record<SlaKey, number> = {
  compromise: 24 * H,
  kev_exposed: 7 * D,
  kev: 14 * D,
  critical: 15 * D,
  high: 30 * D,
  medium: 90 * D,
  low: 180 * D,
  review: 7 * D,
}
export const SLA_KEYS = Object.keys(SLA_DEFAULTS) as SlaKey[]
/** The range a tenant may set, in hours: 1 hour to 1 year. */
export const SLA_MIN_HOURS = 1
export const SLA_MAX_HOURS = 365 * D

/** A tenant's stored policy, cleaned: only known keys with whole hours in range. */
export function cleanSlaPolicy(raw: unknown): Partial<Record<SlaKey, number>> {
  const out: Partial<Record<SlaKey, number>> = {}
  if (!raw || typeof raw !== 'object') return out
  for (const k of SLA_KEYS) {
    const v = Number((raw as Record<string, unknown>)[k])
    if (Number.isInteger(v) && v >= SLA_MIN_HOURS && v <= SLA_MAX_HOURS) out[k] = v
  }
  return out
}

/** The targets in force: the tenant's own values over the defaults. */
export function slaPolicy(raw: unknown): Record<SlaKey, number> {
  return { ...SLA_DEFAULTS, ...cleanSlaPolicy(raw) }
}

export interface RankInput {
  type: string
  severity: Severity
  details: Record<string, unknown>
  compositeRiskScore: number | null
  internetFacing: boolean
  criticality: number | null
}

const SEVERE = new Set(['critical', 'high'])
// Alert types whose severity is already raised for an internet-facing asset (their producers
// add a level), so the ranking does not add internet-facing a second time.
const SEVERITY_HAS_EXPOSURE = new Set(['exposure', 'vulnerable_service', 'port_opened', 'new_device', 'config_change'])
const BASE: Record<Severity, number> = { critical: 85, high: 70, medium: 50, low: 30 }
const FIX_TYPES = new Set(['cve_detected', 'vulnerable_service', 'os_patch_missing', 'exposure'])

const isKev = (d: Record<string, unknown>) => d.kev === true || Number(d.kev_count ?? 0) > 0

export function tierOf(a: Pick<RankInput, 'type' | 'severity' | 'details'>): Tier {
  const d = a.details
  if (a.type === 'cti_match') {
    if (d.match_kind === 'watchlist') return 4
    return SEVERE.has(a.severity) ? 1 : 4
  }
  if (isKev(d) || (a.type === 'os_patch_missing' && Number(d.exploited ?? 0) > 0)) return 2
  if (FIX_TYPES.has(a.type)) return 3
  if (a.type === 'port_opened' && Number(d.port) in RISKY_PORTS) return 3
  return 4
}

const crit10 = (c: number | null) => Math.max(c ?? 5, 1) * 10

/** 0-100, comparable across alert types (before the internet-facing step). */
export function baseScore(a: RankInput): number {
  const d = a.details
  if (a.type === 'cve_detected' && a.compositeRiskScore != null) {
    // an SBOM package with nothing to install yet waits behind fixable work, unless exploited
    const noFix = d.shape === 'package' && Number(d.fixable_count ?? 1) === 0 && !isKev(d)
    return a.compositeRiskScore * (noFix ? 0.5 : 1)
  }
  if (a.type === 'vulnerable_service' && d.max_cvss != null) {
    // the composite formula on its worst CVE (no EPSS from a banner): CVSS, criticality, KEV
    return 0.40 * Number(d.max_cvss) * 10 + 0.15 * crit10(a.criticality) + (isKev(d) ? 10 : 0)
  }
  if (a.type === 'os_patch_missing') {
    // MSRC rates the missing fixes; an exploited or Critical fix counts as CVSS 9.0, otherwise 7.5
    const cvss = Number(d.exploited ?? 0) > 0 || Number(d.critical ?? 0) > 0 ? 9.0 : 7.5
    return 0.40 * cvss * 10 + 0.15 * crit10(a.criticality) + (Number(d.exploited ?? 0) > 0 ? 10 : 0)
  }
  return 0.85 * BASE[a.severity] + 0.15 * crit10(a.criticality)
}

export function rankScore(a: RankInput): number {
  const exposure = a.internetFacing && !SEVERITY_HAS_EXPOSURE.has(a.type) ? 15 : 0
  return Math.round(Math.min(100, baseScore(a) + exposure) * 10) / 10
}

/** One number to sort by, higher first: the tier dominates, the score orders within it. */
export function priorityOf(a: RankInput): number {
  return (5 - tierOf(a)) * 1000 + rankScore(a)
}

/** The tier a priority number belongs to. */
export function tierOfPriority(priority: number): Tier {
  const t = 5 - Math.floor(priority / 1000)
  return (t >= 1 && t <= 4 ? t : 4) as Tier
}

export function slaKeyOf(tier: Tier, severity: Severity, internetFacing: boolean): SlaKey {
  if (tier === 1) return 'compromise'
  if (tier === 2) return internetFacing ? 'kev_exposed' : 'kev'
  if (tier === 4) return 'review'
  return severity
}

/**
 * Estimated hands-on work to close an alert, in hours: what the SOC reports as workload ("12 hours
 * of fixes due this week"). Planning figures for one device, not measurements; the tenant's own
 * measured time to resolve (median per alert type, services/fixTime.ts) shows how long alerts
 * actually stay open.
 */
export type EffortKey = 'investigate' | 'package' | 'service' | 'windows_update' | 'exposure' | 'software' | 'review'
export const EFFORT_HOURS: Record<EffortKey, number> = {
  investigate: 4,          // a possible compromise: isolate, examine, clean up
  package: 0.5,            // update one package on one device
  service: 1,              // upgrade a network service (and check it still works)
  windows_update: 1,       // install the update, with a restart
  exposure: 0.5,           // change a setting or close a port
  software: 0.5,           // update or remove watched software
  review: 0.25,            // look at a change and accept it or open a fix
}
export const EFFORT_LABEL: Record<EffortKey, string> = {
  investigate: 'Investigate a possible compromise', package: 'Update a package', service: 'Upgrade a service',
  windows_update: 'Install a Windows update (restart)', exposure: 'Fix an exposure', software: 'Update or remove watched software',
  review: 'Review a change',
}

export function effortKeyOf(a: Pick<RankInput, 'type' | 'severity' | 'details'>): EffortKey {
  if (a.type === 'cti_match') {
    if (a.details.match_kind === 'watchlist') return 'software'
    return tierOf(a) === 1 ? 'investigate' : 'review'
  }
  if (a.type === 'cve_detected') return 'package'
  if (a.type === 'vulnerable_service') return 'service'
  if (a.type === 'os_patch_missing') return 'windows_update'
  if (a.type === 'exposure') return 'exposure'
  if (a.type === 'port_opened' && Number(a.details.port) in RISKY_PORTS) return 'exposure'
  return 'review'
}

export type DueStatus = 'on_track' | 'due_soon' | 'overdue'

/** Due date from when the clock started (first seen, or reopened), and its status at `now`:
 *  due soon in the last quarter of the window. */
export function dueOf(start: Date, hours: number, now: Date = new Date()): { dueAt: Date; status: DueStatus } {
  const dueAt = new Date(start.getTime() + hours * 3_600_000)
  const left = dueAt.getTime() - now.getTime()
  const status: DueStatus = left < 0 ? 'overdue' : left <= hours * 3_600_000 / 4 ? 'due_soon' : 'on_track'
  return { dueAt, status }
}
