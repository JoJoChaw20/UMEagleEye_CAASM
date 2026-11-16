/**
 * SBOM alerts: one per asset and vulnerable package, with its CVEs inside.
 *
 * Every CVE Grype reports is a finding (table cve_findings, no cap). The alert (events row,
 * type cve_detected, details.shape 'package') is what is triaged, assigned, advised and
 * counted: one per package on an asset, like vulnerable_service (one per device and product)
 * and os_patch_missing (one per device). It replaced one alert per CVE, which put 1,499
 * alerts on one Ubuntu machine for 149 packages and needed a cap that silently dropped CVEs.
 *
 *   key        package type + name (an upgrade that fixes some CVEs keeps the same alert,
 *              assignee and SLA age; several installed copies stay one alert)
 *   severity   the worst CVE's band, at least high when a CVE is on CISA KEV
 *   score      the highest per-CVE composite score (lib/riskScore.ts), so the validated
 *              per-CVE weights still decide; no stored per-CVE score (criticality changes)
 *   fix_to     the version that fixes every CVE that has a fix, on every installed copy
 *
 * Alerts written before this (one per CVE, no details.shape) are "legacy": the first SBOM
 * upload after the change, or scripts/db/convert-package-alerts.mjs, folds each package's
 * legacy rows into one alert, keeping the row with an advisory, an assignee or the oldest
 * age. Pure; tested in packageAlerts.test.ts.
 */
import { computeRiskScore, type Severity } from './riskScore'
import { compareVersions } from './exposure'
import { fixTarget } from './fixTarget'

export const PACKAGE_SHAPE = 'package'
export const MAX_TOP_CVES = 10
export const MAX_INSTALLED_VERSIONS = 20

export type AlertStatus = 'open' | 'in_progress' | 'resolved' | 'false_positive' | 'accepted_risk'

/** One CVE on one installed version of a package (a cve_findings row, without ids). */
export interface Finding {
  cveId: string
  advisoryId: string | null
  packageType: string | null
  packageName: string
  packageVersion: string
  severity: Severity
  cvss: number
  epss: number
  fixVersions: string[]
  cweIds: string[]
  description: string
  kev: boolean
  hasCtiMatch: boolean
  tiEventTitles: string[]
  dismissed: boolean
}

export interface TopCve { id: string; cvss: number; epss: number; kev: boolean; fix: string | null }

export interface PackageDetails {
  shape: typeof PACKAGE_SHAPE
  package_type: string | null
  package_name: string
  package_version: string                                     // oldest installed: stable between scans
  installed_versions: { version: string; cves: number }[]
  cve_count: number
  kev_count: number
  cti_count: number
  fixable_count: number
  no_fix_count: number
  max_cvss: number
  max_epss: number
  kev: boolean
  has_cti_match: boolean
  fix_to: string | null
  top_cves: TopCve[]
  ti_event_titles: string[]
  cwe_ids: string[]
}

export interface PackageSummary { severity: Severity; score: number; details: PackageDetails }

const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 }
const BY_RANK: Severity[] = ['low', 'medium', 'high', 'critical']

export const packageKey = (type: string | null | undefined, name: string) => `${(type ?? '').toLowerCase()}::${name}`
export const findingKey = (f: Pick<Finding, 'cveId' | 'packageName' | 'packageVersion'>) =>
  `${f.cveId}::${f.packageName}::${f.packageVersion}`

/** The smallest version above `installed` that fixes this CVE, or null. */
const fixFor = (installed: string, fixVersions: string[]) => fixTarget(installed, [fixVersions]).to

/**
 * The alert for one package from its findings (all the same package, at least one).
 * `criticality` is the asset's (1-10) for the composite score. Pure.
 */
export function summarisePackage(findings: Finding[], criticality: number): PackageSummary {
  if (findings.length === 0) throw new Error('summarisePackage needs at least one finding')
  const first = findings[0]!
  const cves = new Map<string, { cvss: number; epss: number; kev: boolean; cti: boolean; fix: string | null; fixable: boolean; score: number }>()
  const versions = new Map<string, { cves: Set<string>; fixLists: string[][] }>()
  const titles: string[] = []
  const cwes: string[] = []
  let rank = 0
  for (const f of findings) {
    rank = Math.max(rank, SEVERITY_RANK[f.severity])
    const score = computeRiskScore(f.cvss, f.epss, criticality, f.hasCtiMatch)
    const fix = fixFor(f.packageVersion, f.fixVersions)
    const c = cves.get(f.cveId)
    cves.set(f.cveId, c ? {
      cvss: Math.max(c.cvss, f.cvss), epss: Math.max(c.epss, f.epss), kev: c.kev || f.kev, cti: c.cti || f.hasCtiMatch,
      // the fix of the oldest copy matters most; keep the highest so every copy is covered
      fix: c.fix && fix ? (compareVersions(fix, c.fix) > 0 ? fix : c.fix) : (c.fix ?? fix),
      fixable: c.fixable || fix !== null, score: Math.max(c.score, score),
    } : { cvss: f.cvss, epss: f.epss, kev: f.kev, cti: f.hasCtiMatch, fix, fixable: fix !== null, score })
    const v = versions.get(f.packageVersion) ?? { cves: new Set<string>(), fixLists: [] }
    v.cves.add(f.cveId)
    v.fixLists.push(f.fixVersions)
    versions.set(f.packageVersion, v)
    for (const t of f.tiEventTitles) if (!titles.includes(t) && titles.length < 3) titles.push(t)
    for (const w of f.cweIds) if (!cwes.includes(w) && cwes.length < 10) cwes.push(w)
  }
  const all = [...cves.entries()]
  const kevCount = all.filter(([, c]) => c.kev).length
  if (kevCount > 0) rank = Math.max(rank, SEVERITY_RANK.high)

  const ordered = [...versions.keys()].sort(compareVersions)
  let fixTo: string | null = null
  for (const ver of ordered) {
    const to = fixTarget(ver, versions.get(ver)!.fixLists).to
    if (to && (fixTo === null || compareVersions(to, fixTo) > 0)) fixTo = to
  }
  const fixable = all.filter(([, c]) => c.fixable).length
  const top = all
    .sort(([ia, a], [ib, b]) => Number(b.kev) - Number(a.kev) || b.score - a.score || b.cvss - a.cvss || ia.localeCompare(ib))
    .slice(0, MAX_TOP_CVES)
    .map(([id, c]) => ({ id, cvss: c.cvss, epss: c.epss, kev: c.kev, fix: c.fix }))

  return {
    severity: BY_RANK[rank]!,
    score: Math.max(...all.map(([, c]) => c.score)),
    details: {
      shape: PACKAGE_SHAPE,
      package_type: first.packageType,
      package_name: first.packageName,
      package_version: ordered[0] ?? first.packageVersion,
      installed_versions: ordered.slice(0, MAX_INSTALLED_VERSIONS).map((version) => ({ version, cves: versions.get(version)!.cves.size })),
      cve_count: cves.size,
      kev_count: kevCount,
      cti_count: all.filter(([, c]) => c.cti).length,
      fixable_count: fixable,
      no_fix_count: cves.size - fixable,
      max_cvss: Math.max(...all.map(([, c]) => c.cvss)),
      max_epss: Math.max(...all.map(([, c]) => c.epss)),
      kev: kevCount > 0,
      has_cti_match: all.some(([, c]) => c.cti),
      fix_to: fixTo,
      top_cves: top,
      ti_event_titles: titles,
      cwe_ids: cwes,
    },
  }
}

// ── Legacy alerts (one per CVE) ──────────────────────────────────────────────

export const isPackageAlert = (details: unknown) => (details as { shape?: unknown } | null)?.shape === PACKAGE_SHAPE

/** The package key of any cve_detected alert, legacy or package. */
export function alertKey(details: Record<string, unknown>): string | null {
  const name = details['package_name']
  return typeof name === 'string' && name ? packageKey(details['package_type'] as string | null, name) : null
}

/** The findings a legacy alert stands for: its CVE on each installed version it lists. */
export function legacyFindings(details: Record<string, unknown>, severity: Severity): Finding[] {
  const cveId = details['cve_id']
  const name = details['package_name']
  if (typeof cveId !== 'string' || !cveId || typeof name !== 'string' || !name) return []
  const strs = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])
  const listed = Array.isArray(details['affected_versions']) ? details['affected_versions'] as { version?: unknown; fix_versions?: unknown }[] : []
  const copies = listed.filter((a) => typeof a?.version === 'string' && a.version)
    .map((a) => ({ version: a.version as string, fix: strs(a.fix_versions) }))
  if (copies.length === 0) copies.push({ version: String(details['package_version'] ?? ''), fix: strs(details['fix_versions']) })
  return copies.map((c) => ({
    cveId, advisoryId: (details['advisory_id'] as string | null) ?? null,
    packageType: (details['package_type'] as string | null) ?? null, packageName: name, packageVersion: c.version,
    severity, cvss: Number(details['cvss_base_score'] ?? 0) || 0, epss: Number(details['epss_score'] ?? 0) || 0,
    fixVersions: c.fix, cweIds: strs(details['cwe_ids']), description: String(details['description'] ?? '').slice(0, 500),
    kev: details['kev'] === true, hasCtiMatch: details['has_cti_match'] === true,
    tiEventTitles: strs(details['ti_event_titles']).slice(0, 3), dismissed: false,
  }))
}

// ── The plan for one asset ───────────────────────────────────────────────────

export interface ExistingAlert {
  eventId: string
  status: AlertStatus
  severity: Severity
  details: Record<string, unknown>
  firstSeen: Date
  assignedTo: string | null
  hasLiveAdvisory: boolean
  /** CVE ids the alert held before this run (package alerts: its findings; legacy: its cve_id). */
  knownCves: string[]
}

export interface AlertWrite {
  eventId: string
  isNew: boolean
  key: string
  severity: Severity
  score: number
  details: PackageDetails
  /** set when the status changes (new alerts are open) */
  status?: 'open' | 'in_progress'
  note?: string
}

export interface PackagePlan {
  /** package alerts to insert or refresh (packages with findings now) */
  alerts: AlertWrite[]
  /** active alerts whose package has no vulnerability left (or only dismissed ones) */
  resolve: { eventId: string; note: string }[]
  /** legacy rows folded into the kept alert of their package; move = carry its live advisory over */
  merge: { from: string; into: string; moveAdvisory: boolean }[]
  /** finding key → the alert it belongs to */
  owner: Map<string, string>
  /** findings to mark dismissed (CVEs closed as false positive / accepted risk one by one before) */
  dismiss: Set<string>
}

const STATUS_RANK: Record<AlertStatus, number> = { false_positive: 0, accepted_risk: 1, resolved: 2, open: 3, in_progress: 4 }
const active = (s: AlertStatus) => s === 'open' || s === 'in_progress'

/** The row that stays the package's alert: a package alert, then one with an advisory, one being
 *  worked on, one assigned, then the oldest (keeps the SLA age). */
export function chooseKept(rows: ExistingAlert[]): ExistingAlert {
  return [...rows].sort((a, b) =>
    Number(isPackageAlert(b.details)) - Number(isPackageAlert(a.details))
    || Number(b.hasLiveAdvisory) - Number(a.hasLiveAdvisory)
    || Number(b.status === 'in_progress') - Number(a.status === 'in_progress')
    || Number(b.assignedTo !== null) - Number(a.assignedTo !== null)
    || a.firstSeen.getTime() - b.firstSeen.getTime()
    || a.eventId.localeCompare(b.eventId))[0]!
}

/**
 * What to write for one asset. `findings` are the vulnerabilities present now (deduplicated by
 * finding key; `dismissed` as stored); `existing` every cve_detected alert of the asset. Pure.
 *
 *  - a package with findings and no alert gets a new one (open);
 *  - an open / in-progress alert is refreshed; a resolved one reopens (the fix did not take);
 *  - false positive / accepted risk stay closed unless a CVE it did not hold before is on KEV;
 *  - an active alert whose package has nothing left (or only dismissed CVEs) is resolved;
 *  - legacy rows of a package fold into one alert; CVEs a person closed one by one inside a
 *    package that is still open become dismissed findings.
 */
export function planPackageAlerts(input: {
  findings: Finding[]
  existing: ExistingAlert[]
  criticality: number
  newId: () => string
}): PackagePlan {
  const plan: PackagePlan = { alerts: [], resolve: [], merge: [], owner: new Map(), dismiss: new Set() }

  // Existing alerts by package: the kept row, the group's most active status, the CVEs it held.
  type Group = { rows: ExistingAlert[]; kept: ExistingAlert; status: AlertStatus; known: Set<string>; closedCves: Set<string> }
  const groups = new Map<string, Group>()
  const byKey = new Map<string, ExistingAlert[]>()
  for (const e of input.existing) {
    const key = alertKey(e.details)
    if (!key) continue
    byKey.set(key, [...(byKey.get(key) ?? []), e])
  }
  for (const [key, rows] of byKey) {
    const kept = chooseKept(rows)
    const status = rows.reduce<AlertStatus>((s, r) => (STATUS_RANK[r.status] > STATUS_RANK[s] ? r.status : s), 'false_positive')
    const known = new Set(rows.flatMap((r) => r.knownCves))
    // a legacy CVE someone closed as not a problem, while the package's alert stays open
    const closedCves = new Set(rows.filter((r) => !isPackageAlert(r.details) && (r.status === 'false_positive' || r.status === 'accepted_risk'))
      .map((r) => String(r.details['cve_id'] ?? '')).filter(Boolean))
    groups.set(key, { rows, kept, status, known, closedCves })
  }
  // Fold a package's other rows into its kept one (only for packages this run touches: closed
  // history of a package that is gone stays as it was).
  const fold = (g: Group) => {
    let advisoryTaken = g.kept.hasLiveAdvisory
    for (const r of g.rows) {
      if (r === g.kept) continue
      const moveAdvisory = !advisoryTaken && r.hasLiveAdvisory
      if (moveAdvisory) advisoryTaken = true
      plan.merge.push({ from: r.eventId, into: g.kept.eventId, moveAdvisory })
    }
  }

  const present = new Map<string, Finding[]>()
  for (const f of input.findings) {
    const key = packageKey(f.packageType, f.packageName)
    present.set(key, [...(present.get(key) ?? []), f])
  }

  for (const [key, all] of present) {
    const g = groups.get(key)
    const keepOpen = g && active(g.status)
    const dismissed = (f: Finding) => f.dismissed || (!!g && keepOpen === true && g.closedCves.has(f.cveId))
    for (const f of all) if (!f.dismissed && dismissed(f)) plan.dismiss.add(findingKey(f))
    const live = all.filter((f) => !dismissed(f))
    const summary = summarisePackage(live.length ? live : all, input.criticality)
    const eventId = g?.kept.eventId ?? input.newId()
    for (const f of all) plan.owner.set(findingKey(f), eventId)
    const write: AlertWrite = { eventId, isNew: !g, key, ...summary }
    if (g) fold(g)

    if (!g) {
      write.status = 'open'
    } else if (live.length === 0) {
      if (active(g.status)) plan.resolve.push({ eventId, note: 'Auto-resolved: only CVEs marked not applicable remain' })
    } else if (g.status === 'resolved') {
      write.status = 'open'
      write.note = 'Reopened: the package is still vulnerable in the latest SBOM'
    } else if (!active(g.status)) {
      const newKev = live.find((f) => f.kev && !g.known.has(f.cveId))
      if (newKev) {
        write.status = 'open'
        write.note = `Reopened: ${newKev.cveId}, new in this package, is exploited in the wild (CISA KEV)`
      }
    } else if (g.kept.status !== g.status) {
      write.status = g.status as 'open' | 'in_progress'    // a folded legacy group keeps its most active status
    }
    plan.alerts.push(write)
  }

  for (const [key, g] of groups) {
    if (!present.has(key) && active(g.status)) {
      fold(g)
      plan.resolve.push({ eventId: g.kept.eventId, note: 'Auto-resolved: no known vulnerability left in this package in the latest SBOM' })
    }
  }
  return plan
}
