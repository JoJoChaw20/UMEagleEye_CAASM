/**
 * Known-malicious packages on devices (lib/maliciousPackages.ts): raises, reopens and resolves the
 * critical `cti_match` alerts (match_kind 'malicious_package', R8).
 *
 * Runs for one device after its SBOM or its package findings arrive (queue job 'malicious_packages',
 * routes/sbom.ts), and nightly over every device's packages (CTI chain step 'malpkg', services/cti.ts),
 * because OSV adds malicious-package records every day. The nightly run asks OSV about at most
 * NIGHTLY_MAX packages and carries on from there the next night. An alert resolves when its package
 * is no longer on the device; false positives and accepted risks stay closed.
 */
import { sql } from 'drizzle-orm'
import type { getDb } from '../db/client'
import {
  MALWARE_CWES, MAL_SOURCE_ADVISORY, MAL_SOURCE_OSV, OSV_BATCH, OSV_ECOSYSTEM, malDetails, malIdsOf, malSeverity, osvQuery,
  recordScope, type MalScope as MalScopeKind, type PackageRow,
} from '../lib/maliciousPackages'

type DB = ReturnType<typeof getDb>

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
const NIGHTLY_MAX = 10 * OSV_BATCH        // 10 OSV calls per night
const NIGHTLY_CURSOR = 'malpkg:offset'
const RECORD_TTL = 30 * 24 * 3600
const MAX_RECORDS = 10                     // OSV record lookups per run (one subrequest each)

export type MalScope = { assetId: string; osv?: boolean } | { nightly: true }
export interface MalResult { checked: number; malicious: number; created: number; reopened: number; resolved: number }

const PMS = sql.raw(Object.keys(OSV_ECOSYSTEM).map((p) => `'${p}'`).join(', '))

async function packagesToCheck(db: DB, kv: KVNamespace, scope: MalScope): Promise<PackageRow[]> {
  if ('assetId' in scope) {
    const res = await db.execute(sql`
      SELECT DISTINCT package_manager AS pm, name, version, purl FROM dependencies
      WHERE asset_id = ${scope.assetId}::uuid AND package_manager IN (${PMS})`)
    return res.rows as unknown as PackageRow[]
  }
  const offset = Number(await kv.get(NIGHTLY_CURSOR)) || 0
  const res = await db.execute(sql`
    SELECT DISTINCT package_manager AS pm, name, version, purl FROM dependencies
    WHERE package_manager IN (${PMS})
    ORDER BY 1, 2, 3, 4 OFFSET ${offset} LIMIT ${NIGHTLY_MAX}`)
  const rows = res.rows as unknown as PackageRow[]
  await kv.put(NIGHTLY_CURSOR, String(rows.length < NIGHTLY_MAX ? 0 : offset + rows.length))
  return rows
}

/** OSV's MAL- ids for each package (only the ones that have some). A failed batch is logged and skipped. */
async function askOsv(rows: PackageRow[]): Promise<Array<{ p: PackageRow; ids: string[] }>> {
  const asked = rows.map((p) => ({ p, q: osvQuery(p) })).filter((x): x is { p: PackageRow; q: NonNullable<typeof x.q> } => x.q !== null)
  const out: Array<{ p: PackageRow; ids: string[] }> = []
  for (let i = 0; i < asked.length; i += OSV_BATCH) {
    const chunk = asked.slice(i, i + OSV_BATCH)
    try {
      const res = await fetch(OSV_BATCH_URL, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries: chunk.map((x) => x.q) }),
      })
      if (!res.ok) throw new Error(`OSV querybatch HTTP ${res.status}`)
      const results = ((await res.json()) as { results?: unknown[] }).results ?? []
      chunk.forEach((x, n) => {
        const ids = malIdsOf(results[n])
        if (ids.length) out.push({ p: x.p, ids })
      })
    } catch (err) {
      console.error('[malpkg] OSV batch failed:', err instanceof Error ? err.message : err)
    }
  }
  return out
}

interface MalRecord { summary: string | null; scope: MalScopeKind }

/** OSV's record: its one-line summary ("Malicious code in @ctrl/tinycolor (npm)") and whether it lists
 *  releases or the whole name (lib/maliciousPackages.ts recordScope), cached. Not looked up (over the
 *  budget, or OSV failed): the whole name, the cautious reading; the next run looks again. */
async function recordOf(kv: KVNamespace, id: string, budget: { left: number }): Promise<MalRecord> {
  const key = `malpkg:record:${id}`
  const cached = await kv.get(key)
  if (cached !== null) {
    try { return JSON.parse(cached) as MalRecord } catch { /* looked up again below */ }
  }
  if (budget.left <= 0) return { summary: null, scope: 'name' }
  budget.left--
  try {
    const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`)
    if (!res.ok) return { summary: null, scope: 'name' }
    const body = await res.json() as { summary?: unknown }
    const rec: MalRecord = { summary: String(body.summary ?? '').slice(0, 300) || null, scope: recordScope(body) }
    await kv.put(key, JSON.stringify(rec), { expirationTtl: RECORD_TTL })
    return rec
  } catch {
    return { summary: null, scope: 'name' }
  }
}

export async function checkMaliciousPackages(db: DB, kv: KVNamespace, scope: MalScope): Promise<MalResult> {
  const assetScope = 'assetId' in scope ? sql`a.asset_id = ${scope.assetId}::uuid` : sql`true`
  const rows = 'assetId' in scope && scope.osv === false ? [] : await packagesToCheck(db, kv, scope)
  const hits = await askOsv(rows)
  const budget = { left: MAX_RECORDS }

  // OSV hits: every device in scope that has that package version. A release listed by any of its
  // records is critical; a name match only is a review (lib/maliciousPackages.ts recordScope).
  const osvPkgs = []
  for (const h of hits) {
    const records = await Promise.all(h.ids.slice(0, 3).map((id) => recordOf(kv, id, budget)))
    const scope: MalScopeKind = records.some((r) => r.scope === 'version') ? 'version' : 'name'
    osvPkgs.push({ pm: h.p.pm, name: h.p.name, version: h.p.version, severity: malSeverity(scope),
      details: malDetails(h.p, h.ids, MAL_SOURCE_OSV, records.find((r) => r.summary)?.summary ?? null, scope) })
  }
  const fromOsv = osvPkgs.length ? (await db.execute(sql`
    SELECT DISTINCT ON (d.asset_id, x.details->>'indicator_value') d.asset_id::text AS asset_id, x.severity, x.details
    FROM jsonb_to_recordset(${JSON.stringify(osvPkgs)}::jsonb) AS x(pm text, name text, version text, severity text, details jsonb)
    JOIN dependencies d ON d.package_manager = x.pm AND d.name = x.name AND d.version = x.version
    JOIN assets a ON a.asset_id = d.asset_id
    WHERE ${assetScope}`)).rows as Array<{ asset_id: string; severity: string; details: Record<string, unknown> }> : []

  // The agent's own findings (Grype) for packages with embedded malicious code
  const advisories = (await db.execute(sql`
    SELECT f.asset_id::text AS asset_id, f.package_type AS pm, f.package_name AS name, f.package_version AS version,
           array_agg(DISTINCT COALESCE(f.advisory_id, f.cve_id)) AS ids, min(f.description) AS summary
    FROM cve_findings f JOIN assets a ON a.asset_id = f.asset_id
    WHERE f.fixed_at IS NULL AND f.cwe_ids && ${sql.raw(`ARRAY[${MALWARE_CWES.map((c) => `'${c}'`).join(',')}]::text[]`)} AND ${assetScope}
    GROUP BY 1, 2, 3, 4`)).rows as Array<{ asset_id: string; pm: string | null; name: string; version: string; ids: string[]; summary: string | null }>
  // Grype matched the installed version against the advisory's affected versions: a release
  const fromAdvisories = advisories.map((r) => ({
    asset_id: r.asset_id,
    severity: malSeverity('version'),
    details: malDetails({ pm: r.pm, name: r.name, version: r.version, purl: null }, r.ids, MAL_SOURCE_ADVISORY, r.summary?.slice(0, 300) || null, 'version'),
  }))

  // One alert per (asset, package version); OSV first when both name it
  const seen = new Set<string>()
  const found = [...fromOsv, ...fromAdvisories].filter((r) => {
    const k = `${r.asset_id}|${r.details.indicator_value}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })

  let created = 0
  let reopened = 0
  if (found.length) {
    const res = await db.execute(sql`
      WITH x AS (
        SELECT (r->>'asset_id')::uuid AS asset_id, (r->>'severity')::severity AS severity, r->'details' AS details
        FROM jsonb_array_elements(${JSON.stringify(found)}::jsonb) r
      ),
      ex AS (
        SELECT e.event_id, e.asset_id, e.status, e.details->>'indicator_value' AS iv FROM events e
        WHERE e.event_type = 'cti_match' AND e.details->>'match_kind' = 'malicious_package' AND e.asset_id IN (SELECT asset_id FROM x)
      ),
      ins AS (
        INSERT INTO events (asset_id, event_type, severity, details)
        SELECT x.asset_id, 'cti_match', x.severity, x.details FROM x
        WHERE NOT EXISTS (SELECT 1 FROM ex WHERE ex.asset_id = x.asset_id AND ex.iv = x.details->>'indicator_value')
        RETURNING 1
      ),
      upd AS (
        UPDATE events e SET details = e.details || x.details, severity = x.severity, last_seen = now(), updated_at = now(),
          status = CASE WHEN e.status = 'resolved' THEN 'open'::event_status ELSE e.status END,
          resolved_at = CASE WHEN e.status = 'resolved' THEN NULL ELSE e.resolved_at END,
          resolved_by = CASE WHEN e.status = 'resolved' THEN NULL ELSE e.resolved_by END,
          resolution_note = CASE WHEN e.status = 'resolved' THEN 'Reopened: the malicious package is on the device again' ELSE e.resolution_note END
        FROM ex, x
        WHERE e.event_id = ex.event_id AND ex.asset_id = x.asset_id AND ex.iv = x.details->>'indicator_value'
          AND ex.status IN ('open', 'in_progress', 'resolved')
        RETURNING (ex.status = 'resolved') AS reopened
      )
      SELECT (SELECT count(*) FROM ins)::int AS created, (SELECT count(*) FROM upd WHERE reopened)::int AS reopened`)
    const row = (res.rows[0] ?? {}) as { created?: number; reopened?: number }
    created = Number(row.created ?? 0)
    reopened = Number(row.reopened ?? 0)
  }

  // Gone from the device (neither in its SBOM nor in its open findings): resolved
  const gone = await db.execute(sql`
    UPDATE events e SET status = 'resolved', resolved_at = now(), updated_at = now(),
      resolution_note = 'Auto-resolved: the malicious package is no longer on the device'
    FROM assets a
    WHERE a.asset_id = e.asset_id AND ${assetScope}
      AND e.event_type = 'cti_match' AND e.details->>'match_kind' = 'malicious_package' AND e.status IN ('open', 'in_progress')
      AND NOT EXISTS (SELECT 1 FROM dependencies d WHERE d.asset_id = e.asset_id
                      AND d.name = e.details->>'package_name' AND d.version = e.details->>'package_version')
      AND NOT EXISTS (SELECT 1 FROM cve_findings f WHERE f.asset_id = e.asset_id AND f.fixed_at IS NULL
                      AND f.package_name = e.details->>'package_name' AND f.package_version = e.details->>'package_version')
    RETURNING e.event_id`)

  return { checked: rows.length, malicious: found.length, created, reopened, resolved: gone.rows.length }
}
