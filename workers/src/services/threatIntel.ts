/**
 * What threat intelligence an asset's alerts may use, and keeping CVE alerts in step
 * with it.
 *
 * An indicator is MATCHABLE for an asset of tenant T when it is a global feed entry
 * (OTX, ThreatFox, CISA KEV), or an attribute of a PUBLISHED event that is T's own,
 * shared with all tenants, or a platform event; and it is marked to_ids and not on a
 * warninglist. Drafts and other tenants' private events never touch T's alerts.
 *
 * CVE alerts carry the result in their details: has_cti_match (any matchable 'cve'
 * indicator), kev (one of them is CISA KEV) and ti_event_titles (the events naming it).
 * refreshCveIntel() recomputes those after anything changes (nightly feeds, an event
 * published, unpublished, edited or deleted), both ways: a flag can also be cleared.
 */
import { and, eq, inArray, sql, type SQL } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { ctiIndicators, tiEvents } from '../db/schema'

type DB = ReturnType<typeof getDb>

export const KEV_SOURCE = 'CISA KEV'

/** SQL: indicator `c` (joined to its event `te`, LEFT JOIN) is matchable for tenant `tenant`. */
export function matchableSql(tenant: SQL): SQL {
  return sql`(c.to_ids AND c.warning IS NULL AND (
    c.ti_event_id IS NULL
    OR (te.status = 'published' AND (te.tenant_id = ${tenant} OR te.distribution IN ('all_tenants', 'platform')))
  ))`
}

export interface CveIntel { kev: boolean; titles: string[] }

/** For CVE IDs found on an asset of `tenantId`: which are named by matchable intel. */
export async function cveIntelFor(db: DB, tenantId: string | null, cveIds: string[]): Promise<Map<string, CveIntel>> {
  const out = new Map<string, CveIntel>()
  if (cveIds.length === 0) return out
  const rows = await db
    .select({ value: ctiIndicators.value, source: ctiIndicators.source, eventId: ctiIndicators.tiEventId, title: tiEvents.title })
    .from(ctiIndicators)
    .leftJoin(tiEvents, eq(tiEvents.tiEventId, ctiIndicators.tiEventId))
    .where(and(
      eq(ctiIndicators.indicatorType, 'cve'),
      inArray(ctiIndicators.value, cveIds),
      sql`${ctiIndicators.toIds} AND ${ctiIndicators.warning} IS NULL`,
      sql`(${ctiIndicators.tiEventId} IS NULL OR (${tiEvents.status} = 'published' AND (${tiEvents.tenantId} = ${tenantId} OR ${tiEvents.distribution} IN ('all_tenants', 'platform'))))`,
    ))
  for (const r of rows) {
    const cur = out.get(r.value) ?? { kev: false, titles: [] }
    if (!r.eventId && r.source === KEV_SOURCE) cur.kev = true
    if (r.title && !cur.titles.includes(r.title) && cur.titles.length < 3) cur.titles.push(r.title)
    out.set(r.value, cur)
  }
  return out
}

/** Which alerts to refresh: all, one tenant's, or one asset's. */
export type IntelScope = { all: true } | { tenantId: string } | { assetId: string }

function scopeSql(scope: IntelScope): SQL {
  if ('assetId' in scope) return sql`AND e.asset_id = ${scope.assetId}`
  if ('tenantId' in scope) return sql`AND a.tenant_id = ${scope.tenantId}`
  return sql``
}

/**
 * Recompute has_cti_match / kev / ti_event_titles on open CVE alerts in `scope`, adjust
 * their risk score by the +/-10 threat-intel bonus (routes/sbom.ts computeRiskScore),
 * and bring the alert↔indicator links (shown on the alert) in line. Returns how many
 * alerts changed.
 */
export async function refreshCveIntel(db: DB, scope: IntelScope): Promise<number> {
  const where = scopeSql(scope)
  const res = await db.execute(sql`
    WITH m AS (
      SELECT e.event_id, v.hit, v.kev, v.titles
      FROM events e
      JOIN assets a ON a.asset_id = e.asset_id
      CROSS JOIN LATERAL (
        SELECT count(c.indicator_id) > 0 AS hit,
               COALESCE(bool_or(c.ti_event_id IS NULL AND c.source = ${KEV_SOURCE}), false) AS kev,
               COALESCE(to_jsonb((array_agg(DISTINCT te.title) FILTER (WHERE te.title IS NOT NULL))[1:3]), '[]'::jsonb) AS titles
        FROM cti_indicators c
        LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
        WHERE c.indicator_type = 'cve' AND c.value = e.details->>'cve_id'
          AND ${matchableSql(sql`a.tenant_id`)}
      ) v
      WHERE e.event_type = 'cve_detected' AND e.status IN ('open', 'in_progress') ${where}
    )
    UPDATE events e SET
      details = e.details || jsonb_build_object('has_cti_match', m.hit, 'kev', m.kev, 'ti_event_titles', m.titles),
      composite_risk_score = LEAST(GREATEST(COALESCE(e.composite_risk_score, 0)
        + CASE WHEN m.hit AND NOT COALESCE((e.details->>'has_cti_match')::boolean, false) THEN 10
               WHEN NOT m.hit AND COALESCE((e.details->>'has_cti_match')::boolean, false) THEN -10
               ELSE 0 END, 0), 100),
      updated_at = now()
    FROM m
    WHERE e.event_id = m.event_id
      AND (COALESCE((e.details->>'has_cti_match')::boolean, false) IS DISTINCT FROM m.hit
        OR COALESCE((e.details->>'kev')::boolean, false) IS DISTINCT FROM m.kev
        OR COALESCE(e.details->'ti_event_titles', '[]'::jsonb) IS DISTINCT FROM m.titles)
    RETURNING 1
  `)
  await linkCveIndicators(db, scope)
  return res.rows.length
}

/** Link CVE alerts to the matchable 'cve' indicators naming their CVE, and drop links to
 *  ones that are no longer matchable (event unpublished, made private, to_ids off). */
export async function linkCveIndicators(db: DB, scope: IntelScope): Promise<void> {
  const where = scopeSql(scope)
  await db.execute(sql`
      DELETE FROM event_cti_indicators l
      USING events e, assets a, cti_indicators c
      LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
      WHERE l.event_id = e.event_id AND a.asset_id = e.asset_id AND c.indicator_id = l.indicator_id
        AND e.event_type = 'cve_detected' AND c.indicator_type = 'cve' ${where}
        AND NOT ${matchableSql(sql`a.tenant_id`)}
  `)
  await db.execute(sql`
      INSERT INTO event_cti_indicators (event_id, indicator_id)
      SELECT e.event_id, c.indicator_id
      FROM events e
      JOIN assets a ON a.asset_id = e.asset_id
      JOIN cti_indicators c ON c.indicator_type = 'cve' AND c.value = e.details->>'cve_id'
      LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
      WHERE e.event_type = 'cve_detected' ${where} AND ${matchableSql(sql`a.tenant_id`)}
      ON CONFLICT DO NOTHING
  `)
}

/** The tenants whose alerts an event can affect: its own, or every tenant when it is
 *  (or was, before an edit) shared or platform-wide. */
export function scopeForEvent(ev: { tenantId: string | null; distribution: string }, previousDistribution?: string): IntelScope {
  const wide = (d?: string) => d === 'all_tenants' || d === 'platform'
  if (!ev.tenantId || wide(ev.distribution) || wide(previousDistribution)) return { all: true }
  return { tenantId: ev.tenantId }
}
