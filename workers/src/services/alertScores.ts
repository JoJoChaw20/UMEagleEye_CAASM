import { sql, type SQL } from 'drizzle-orm'
import type { DB } from '../db/client'
import { planAlertScores, type AlertScoreRow } from '../lib/riskScore'

export type AlertScoreScope = { tenantId: string } | { assetIds: string[] }

// Rows per UPDATE: 2 parameters each, far under Postgres' 65k limit.
const WRITE_CHUNK = 1000

/**
 * Bring the risk score of open CVE alerts in `scope` in line with their asset's current
 * criticality (lib/riskScore.ts planAlertScores). Called after a rescore, so a criticality
 * change reaches the Alerts queue at once instead of at the computer's next SBOM upload.
 * Subrequests: 1 read + 1 write per 1,000 changed alerts. Returns how many changed.
 */
export async function refreshCveAlertScores(db: DB, scope: AlertScoreScope): Promise<number> {
  let where: SQL
  if ('tenantId' in scope) where = sql`a.tenant_id = ${scope.tenantId}`
  else if (scope.assetIds.length) where = sql`e.asset_id IN (${sql.join(scope.assetIds.map((id) => sql`${id}`), sql`, `)})`
  else return 0

  const res = await db.execute(sql`
    SELECT e.event_id, (e.details->>'cvss_base_score')::float AS cvss, (e.details->>'epss_score')::float AS epss,
           (e.details->>'has_cti_match')::boolean AS cti, e.composite_risk_score::float AS stored, a.criticality_score AS crit
    FROM events e JOIN assets a ON a.asset_id = e.asset_id
    WHERE e.event_type = 'cve_detected' AND e.status IN ('open', 'in_progress') AND ${where}`)
  const rows: AlertScoreRow[] = (res.rows as Array<Record<string, unknown>>).map((r) => ({
    eventId: r['event_id'] as string, cvss: r['cvss'] as number | null, epss: r['epss'] as number | null,
    ctiMatch: r['cti'] as boolean | null, stored: r['stored'] as number | null, criticality: r['crit'] as number | null,
  }))
  const changes = planAlertScores(rows)

  for (let i = 0; i < changes.length; i += WRITE_CHUNK) {
    const values = sql.join(changes.slice(i, i + WRITE_CHUNK).map((c) => sql`(${c.eventId}::uuid, ${c.score}::numeric)`), sql`, `)
    await db.execute(sql`
      UPDATE events e SET composite_risk_score = v.score, updated_at = now()
      FROM (VALUES ${values}) AS v(event_id, score)
      WHERE e.event_id = v.event_id`)
  }
  return changes.length
}
