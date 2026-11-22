// EPSS (FIRST.org's probability that a CVE is exploited in the next 30 days) for the CVEs on
// devices. SBOM ingest asks for at most 300 per upload (routes/sbom.ts); the rest were stored as
// 0, which read as a real score. Now they stay NULL ("not checked yet") and this nightly step,
// one queue job in the CTI chain (services/cti.ts), fills them in and re-asks every week, since
// EPSS changes daily. The package alerts' scores follow at the nightly rescore (cron/triggers.ts).
import type { DB } from '../db/client'
import { sql } from 'drizzle-orm'

/** FIRST.org takes up to 30 CVEs per call; 30 calls stay well inside one queue job's allowance. */
export const EPSS_PER_CALL = 30
export const EPSS_MAX_PER_RUN = 900
export const EPSS_STALE_DAYS = 7

/** PURE. CVE ids split into calls of at most `size`, only real CVE ids. */
export function epssBatches(cveIds: string[], size = EPSS_PER_CALL): string[][] {
  const ids = [...new Set(cveIds.filter((id) => /^CVE-\d{4}-\d{4,}$/.test(id)))]
  const out: string[][] = []
  for (let i = 0; i < ids.length; i += size) out.push(ids.slice(i, i + size))
  return out
}

/** Ask FIRST.org for one batch. A CVE it does not know gets 0 (it has no score yet). */
async function fetchBatch(ids: string[]): Promise<Map<string, number> | null> {
  try {
    const res = await fetch(`https://api.first.org/data/v1/epss?cve=${ids.join(',')}`)
    if (!res.ok) return null
    const body = await res.json() as { data?: Array<{ cve: string; epss: string }> }
    const scores = new Map<string, number>(ids.map((id) => [id, 0]))
    for (const e of body.data ?? []) scores.set(e.cve, parseFloat(e.epss) || 0)
    return scores
  } catch {
    return null
  }
}

/**
 * Fill in and refresh EPSS on present findings: never checked first, then the oldest checks,
 * the most severe first. Returns how many CVEs were updated and how many still wait.
 */
export async function refreshEpss(db: DB, max = EPSS_MAX_PER_RUN): Promise<{ updated: number; waiting: number }> {
  const due = await db.execute(sql`
    SELECT cve_id, bool_or(epss_checked_at IS NULL) AS never, min(epss_checked_at) AS checked, max(cvss) AS cvss
    FROM cve_findings
    WHERE fixed_at IS NULL AND cve_id LIKE 'CVE-%'
      AND (epss IS NULL OR epss_checked_at IS NULL OR epss_checked_at < now() - make_interval(days => ${EPSS_STALE_DAYS}))
    GROUP BY cve_id
    ORDER BY bool_or(epss_checked_at IS NULL) DESC, min(epss_checked_at) NULLS FIRST, max(cvss) DESC
    LIMIT ${max + 1}`)
  const rows = due.rows as { cve_id: string }[]
  const ids = rows.slice(0, max).map((r) => r.cve_id)
  const found = new Map<string, number>()
  for (const batch of epssBatches(ids)) {
    const scores = await fetchBatch(batch)
    if (scores) for (const [id, v] of scores) found.set(id, v)
  }
  if (found.size === 0) return { updated: 0, waiting: rows.length }
  const values = [...found].map(([cve, epss]) => ({ cve, epss }))
  await db.execute(sql`
    UPDATE cve_findings f SET epss = v.epss, epss_checked_at = now()
    FROM jsonb_to_recordset(${JSON.stringify(values)}::jsonb) AS v(cve varchar, epss numeric)
    WHERE f.cve_id = v.cve AND f.fixed_at IS NULL`)
  return { updated: found.size, waiting: Math.max(0, rows.length - found.size) }
}
