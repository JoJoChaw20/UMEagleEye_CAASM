/**
 * Database side of the per-package SBOM alerts (lib/packageAlerts.ts): load what an asset
 * has, write a plan, and recompute alerts after threat intelligence or criticality change.
 * Used by the CVE ingest (routes/sbom.ts), threat-intel refresh (services/threatIntel.ts),
 * alert-score refresh (services/alertScores.ts) and scripts/db/convert-package-alerts.mjs.
 */
import { and, eq, inArray, sql, type SQL } from 'drizzle-orm'
import type { DB } from '../db/client'
import { advisories, cveFindings, events } from '../db/schema'
import type { Severity } from '../lib/riskScore'
import { sameJson } from '../lib/rescore'
import {
  findingKey, isPackageAlert, summarisePackage,
  type AlertStatus, type ExistingAlert, type Finding, type PackagePlan,
} from '../lib/packageAlerts'

// Statements per db.batch (one subrequest each); findings rows per INSERT (≈19 parameters
// each, far under Postgres' 65,535).
export const WRITE_BATCH = 300
const FINDINGS_PER_INSERT = 500

const LIVE_ADVISORY = sql`adv.status IN ('open', 'acknowledged', 'in_progress')`

/** Every cve_detected alert of an asset, with what the planner needs. One query. */
export async function loadAlerts(db: DB, assetId: string): Promise<ExistingAlert[]> {
  const res = await db.execute(sql`
    SELECT e.event_id, e.status::text AS status, e.severity::text AS severity, e.details, e.first_seen, e.assigned_to,
           EXISTS (SELECT 1 FROM advisories adv WHERE adv.event_id = e.event_id AND ${LIVE_ADVISORY}) AS live_advisory,
           COALESCE((SELECT array_agg(DISTINCT f.cve_id) FROM cve_findings f WHERE f.event_id = e.event_id), '{}') AS cves
    FROM events e WHERE e.asset_id = ${assetId} AND e.event_type = 'cve_detected'`)
  return (res.rows as Record<string, unknown>[]).map((r) => {
    const details = (r['details'] ?? {}) as Record<string, unknown>
    const cves = (r['cves'] as string[] | null) ?? []
    return {
      eventId: r['event_id'] as string, status: r['status'] as AlertStatus, severity: r['severity'] as Severity,
      details, firstSeen: new Date(r['first_seen'] as string), assignedTo: (r['assigned_to'] as string | null) ?? null,
      hasLiveAdvisory: r['live_advisory'] === true,
      knownCves: isPackageAlert(details) ? cves : [String(details['cve_id'] ?? '')].filter(Boolean),
    }
  })
}

const rowToFinding = (r: Record<string, unknown>): Finding => ({
  cveId: r['cve_id'] as string, advisoryId: (r['advisory_id'] as string | null) ?? null,
  packageType: (r['package_type'] as string | null) ?? null, packageName: r['package_name'] as string,
  packageVersion: (r['package_version'] as string) ?? '', severity: r['severity'] as Severity,
  cvss: Number(r['cvss'] ?? 0), epss: Number(r['epss'] ?? 0),
  fixVersions: (r['fix_versions'] as string[] | null) ?? [], cweIds: (r['cwe_ids'] as string[] | null) ?? [],
  description: (r['description'] as string | null) ?? '', kev: r['kev'] === true, hasCtiMatch: r['has_cti_match'] === true,
  tiEventTitles: (r['ti_event_titles'] as string[] | null) ?? [], dismissed: r['dismissed'] === true,
})

/** An asset's findings that are present now (not fixed). One query. */
export async function loadPresentFindings(db: DB, assetId: string): Promise<Finding[]> {
  const res = await db.execute(sql`
    SELECT cve_id, advisory_id, package_type, package_name, package_version, severity::text AS severity, cvss, epss,
           fix_versions, cwe_ids, description, kev, has_cti_match, ti_event_titles, dismissed
    FROM cve_findings WHERE asset_id = ${assetId} AND fixed_at IS NULL`)
  return (res.rows as Record<string, unknown>[]).map(rowToFinding)
}

/**
 * The statements that carry out a plan for one asset, in an order the foreign keys accept:
 * alerts, advisory moves and folded rows, findings (upsert), findings no longer present,
 * then resolved alerts and their advisories. `findings` are the ones the plan was made from.
 * Every present finding gets last_seen = now; any other present one is then marked fixed.
 */
export function planStatements(db: DB, assetId: string, plan: PackagePlan, findings: Finding[], now: Date): unknown[] {
  const stmts: unknown[] = []
  for (const a of plan.alerts) {
    const reopen = a.status ? { status: a.status, resolvedAt: null, resolvedBy: null, resolutionNote: a.note ?? null } : {}
    if (a.isNew) {
      stmts.push(db.insert(events).values({
        eventId: a.eventId, assetId, eventType: 'cve_detected', severity: a.severity,
        compositeRiskScore: String(a.score), details: a.details, firstSeen: now, lastSeen: now,
      }))
    } else {
      stmts.push(db.update(events).set({
        severity: a.severity, compositeRiskScore: String(a.score), details: a.details,
        lastSeen: now, occurrences: sql`${events.occurrences} + 1`, updatedAt: now, ...reopen,
      }).where(eq(events.eventId, a.eventId)))
    }
  }
  for (const m of plan.merge.filter((x) => x.moveAdvisory)) {
    stmts.push(db.update(advisories).set({ eventId: m.into })
      .where(and(eq(advisories.eventId, m.from), inArray(advisories.status, ['open', 'acknowledged', 'in_progress']))))
  }
  const folded = plan.merge.map((m) => m.from)
  for (let i = 0; i < folded.length; i += 500) stmts.push(db.delete(events).where(inArray(events.eventId, folded.slice(i, i + 500))))

  const rows = findings.flatMap((f) => {
    const eventId = plan.owner.get(findingKey(f))
    return eventId ? [{
      eventId, assetId, cveId: f.cveId.slice(0, 40), advisoryId: f.advisoryId, packageType: f.packageType,
      packageName: f.packageName.slice(0, 255), packageVersion: f.packageVersion.slice(0, 100), severity: f.severity,
      cvss: String(f.cvss), epss: String(f.epss), fixVersions: f.fixVersions, cweIds: f.cweIds,
      description: f.description.slice(0, 500), kev: f.kev, hasCtiMatch: f.hasCtiMatch, tiEventTitles: f.tiEventTitles,
      dismissed: f.dismissed || plan.dismiss.has(findingKey(f)), firstSeen: now, lastSeen: now, fixedAt: null,
    }] : []
  })
  const ex = (c: string) => sql.raw(`excluded.${c}`)
  for (let i = 0; i < rows.length; i += FINDINGS_PER_INSERT) {
    stmts.push(db.insert(cveFindings).values(rows.slice(i, i + FINDINGS_PER_INSERT)).onConflictDoUpdate({
      target: [cveFindings.assetId, cveFindings.cveId, cveFindings.packageName, cveFindings.packageVersion],
      set: {
        eventId: ex('event_id'), advisoryId: ex('advisory_id'), packageType: ex('package_type'), severity: ex('severity'),
        cvss: ex('cvss'), epss: ex('epss'), fixVersions: ex('fix_versions'), cweIds: ex('cwe_ids'), description: ex('description'),
        kev: ex('kev'), hasCtiMatch: ex('has_cti_match'), tiEventTitles: ex('ti_event_titles'),
        // a dismissal is kept; a CVE that comes back after a fix is present again
        dismissed: sql`${cveFindings.dismissed} OR excluded.dismissed`, lastSeen: ex('last_seen'), fixedAt: sql`NULL`,
      },
    }))
  }
  stmts.push(db.update(cveFindings).set({ fixedAt: now })
    .where(and(eq(cveFindings.assetId, assetId), sql`${cveFindings.fixedAt} IS NULL`, sql`${cveFindings.lastSeen} < ${now.toISOString()}`)))

  const notes = new Map<string, string[]>()
  for (const r of plan.resolve) notes.set(r.note, [...(notes.get(r.note) ?? []), r.eventId])
  for (const [note, ids] of notes) {
    stmts.push(db.update(events).set({ status: 'resolved', resolvedAt: now, updatedAt: now, resolutionNote: note })
      .where(and(inArray(events.eventId, ids), inArray(events.status, ['open', 'in_progress']))))
    // the scanner confirmed the fix: the alert's advisory is resolved too
    stmts.push(db.update(advisories).set({ status: 'resolved', resolvedAt: now })
      .where(and(inArray(advisories.eventId, ids), inArray(advisories.status, ['open', 'acknowledged', 'in_progress']))))
  }
  return stmts
}

/** Run statements in db.batch chunks (each chunk is one subrequest and one transaction). */
export async function runBatches(db: DB, stmts: unknown[]): Promise<void> {
  for (let i = 0; i < stmts.length; i += WRITE_BATCH) {
    await db.batch(stmts.slice(i, i + WRITE_BATCH) as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
  }
}

/** Which open package alerts to recompute. */
export type RecomputeScope = { tenantId: string } | { assetIds: string[] } | { eventIds: string[] }

function scopeSql(scope: RecomputeScope): SQL | null {
  const list = (ids: string[]) => sql.join(ids.map((id) => sql`${id}::uuid`), sql`, `)
  if ('tenantId' in scope) return sql`a.tenant_id = ${scope.tenantId}`
  if ('assetIds' in scope) return scope.assetIds.length ? sql`e.asset_id IN (${list(scope.assetIds)})` : null
  return scope.eventIds.length ? sql`e.event_id IN (${list(scope.eventIds)})` : null
}

/**
 * Recompute open package alerts from their present, not-dismissed findings with the asset's
 * current criticality: after threat intel changed a finding's KEV / match flags, or a rescore
 * changed criticality. Writes only alerts whose severity, score or summary moved. Returns how
 * many changed. Subrequests: 1 read + 1 per 300 changed alerts.
 */
export async function recomputePackageAlerts(db: DB, scope: RecomputeScope): Promise<number> {
  const where = scopeSql(scope)
  if (!where) return 0
  const res = await db.execute(sql`
    SELECT e.event_id, e.severity::text AS alert_severity, e.composite_risk_score::float AS stored_score, e.details AS alert_details,
           a.criticality_score AS crit, f.cve_id, f.advisory_id, f.package_type, f.package_name, f.package_version,
           f.severity::text AS severity, f.cvss, f.epss, f.fix_versions, f.cwe_ids, '' AS description, f.kev, f.has_cti_match,
           f.ti_event_titles, f.dismissed
    FROM events e
    JOIN assets a ON a.asset_id = e.asset_id
    JOIN cve_findings f ON f.event_id = e.event_id AND f.fixed_at IS NULL AND NOT f.dismissed
    WHERE e.event_type = 'cve_detected' AND e.status IN ('open', 'in_progress') AND ${where}`)
  const byEvent = new Map<string, { rows: Record<string, unknown>[] }>()
  for (const r of res.rows as Record<string, unknown>[]) {
    const id = r['event_id'] as string
    const g = byEvent.get(id) ?? { rows: [] }
    g.rows.push(r)
    byEvent.set(id, g)
  }
  const stmts: unknown[] = []
  for (const [eventId, { rows }] of byEvent) {
    const head = rows[0]!
    const s = summarisePackage(rows.map(rowToFinding), Number(head['crit'] ?? 5))
    const storedScore = head['stored_score'] == null ? null : Number(head['stored_score'])
    if (s.severity === head['alert_severity'] && storedScore !== null && Math.abs(storedScore - s.score) < 0.005
      && sameJson(s.details, head['alert_details'])) continue
    stmts.push(db.update(events).set({ severity: s.severity, compositeRiskScore: String(s.score), details: s.details, updatedAt: new Date() })
      .where(eq(events.eventId, eventId)))
  }
  await runBatches(db, stmts)
  return stmts.length
}
