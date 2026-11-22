/**
 * What threat intelligence an asset's alerts may use, and keeping CVE alerts in step
 * with it.
 *
 * An indicator is MATCHABLE for an asset of tenant T when it is a global feed entry
 * (OTX, ThreatFox, CISA KEV), or an attribute of a PUBLISHED event that is T's own,
 * shared with all tenants, or a platform event; and it is marked to_ids and not on a
 * warninglist. Drafts and other tenants' private events never touch T's alerts.
 *
 * CVE findings (cve_findings) carry the result: has_cti_match (any matchable 'cve'
 * indicator), kev (one of them is CISA KEV) and ti_event_titles (the events naming it); the
 * package alert sums them up (kev_count, has_cti_match...). refreshCveIntel() recomputes
 * those after anything changes (nightly feeds, an event published, unpublished, edited or
 * deleted), both ways: a flag can also be cleared.
 */
import { and, eq, inArray, sql, type SQL } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { ctiIndicators, tiEvents } from '../db/schema'
import { recomputePackageAlerts } from './packageAlerts'

type DB = ReturnType<typeof getDb>

export const KEV_SOURCE = 'CISA KEV'

/** SQL: indicator `c` (joined to its event `te`, LEFT JOIN) is matchable for tenant `tenant`. */
// An event a tenant shares with all tenants can be READ by every tenant, but raises alerts only in
// its own tenant: otherwise one tenant admin could flood every tenant with alerts (an event naming
// "Microsoft Edge" or "edu.my"). Only platform events (the superadmin's) alert every tenant.
export function matchableSql(tenant: SQL): SQL {
  return sql`(c.to_ids AND c.warning IS NULL AND (
    c.ti_event_id IS NULL
    OR (te.status = 'published' AND (te.tenant_id = ${tenant} OR te.distribution = 'platform'))
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
      sql`(${ctiIndicators.tiEventId} IS NULL OR (${tiEvents.status} = 'published' AND (${tiEvents.tenantId} = ${tenantId} OR ${tiEvents.distribution} = 'platform')))`,
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
 * Recompute has_cti_match / kev / ti_event_titles on the present CVE findings of open
 * package alerts in `scope` (cve_findings), then the alerts those changed (their counts,
 * severity and score: services/packageAlerts.ts), and bring the alert↔indicator links
 * (shown on the alert) in line. Returns how many alerts changed.
 */
export async function refreshCveIntel(db: DB, scope: IntelScope): Promise<number> {
  const where = scopeSql(scope)
  const res = await db.execute(sql`
    WITH m AS (
      SELECT f.finding_id, v.hit, v.kev, v.titles
      FROM cve_findings f
      JOIN events e ON e.event_id = f.event_id
      JOIN assets a ON a.asset_id = e.asset_id
      CROSS JOIN LATERAL (
        SELECT count(c.indicator_id) > 0 AS hit,
               COALESCE(bool_or(c.ti_event_id IS NULL AND c.source = ${KEV_SOURCE}), false) AS kev,
               COALESCE(to_jsonb((array_agg(DISTINCT te.title) FILTER (WHERE te.title IS NOT NULL))[1:3]), '[]'::jsonb) AS titles
        FROM cti_indicators c
        LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
        WHERE c.indicator_type = 'cve' AND c.value = f.cve_id
          AND ${matchableSql(sql`a.tenant_id`)}
      ) v
      WHERE f.fixed_at IS NULL AND e.event_type = 'cve_detected' AND e.status IN ('open', 'in_progress') ${where}
    )
    UPDATE cve_findings f SET has_cti_match = m.hit, kev = m.kev, ti_event_titles = m.titles
    FROM m
    WHERE f.finding_id = m.finding_id
      AND (f.has_cti_match IS DISTINCT FROM m.hit OR f.kev IS DISTINCT FROM m.kev OR f.ti_event_titles IS DISTINCT FROM m.titles)
    RETURNING f.event_id
  `)
  const changed = [...new Set((res.rows as { event_id: string }[]).map((r) => r.event_id))]
  const alerts = await recomputePackageAlerts(db, { eventIds: changed })
  await linkCveIndicators(db, scope)
  return alerts + await refreshServiceKev(db, scope)
}

/**
 * The same for vulnerable services (scan banners, services/serviceCves.ts): mark each listed CVE
 * that is on CISA KEV now, and update kev_count / kev / has_cti_match. A service that gains a KEV
 * CVE goes up to at least high, as serviceFinding() rates a new one. Without this, a CVE added to
 * KEV after the scan stayed unflagged until the next active scan. Returns how many alerts changed.
 */
export async function refreshServiceKev(db: DB, scope: IntelScope): Promise<number> {
  const where = scopeSql(scope)
  const res = await db.execute(sql`
    WITH s AS (
      SELECT e.event_id,
        (SELECT jsonb_agg(CASE WHEN EXISTS (
                  SELECT 1 FROM cti_indicators c
                  WHERE c.indicator_type = 'cve' AND c.value = x->>'id' AND c.ti_event_id IS NULL AND c.source = ${KEV_SOURCE})
                THEN x || '{"kev": true}'::jsonb ELSE x - 'kev' END ORDER BY t.ord)
         FROM jsonb_array_elements(e.details->'cves') WITH ORDINALITY AS t(x, ord)) AS cves
      FROM events e
      JOIN assets a ON a.asset_id = e.asset_id
      WHERE e.event_type = 'vulnerable_service' AND e.status IN ('open', 'in_progress')
        AND jsonb_typeof(e.details->'cves') = 'array' ${where}
    ), k AS (
      SELECT event_id, cves, (SELECT count(*) FROM jsonb_array_elements(cves) x WHERE x->>'kev' = 'true')::int AS n FROM s
    )
    UPDATE events e SET
      details = e.details || jsonb_build_object('cves', k.cves, 'kev_count', k.n, 'kev', k.n > 0, 'has_cti_match', k.n > 0),
      severity = CASE WHEN k.n > 0 AND e.severity IN ('low', 'medium') THEN 'high'::severity ELSE e.severity END,
      updated_at = now()
    FROM k
    WHERE e.event_id = k.event_id
      AND (COALESCE((e.details->>'kev_count')::int, 0) <> k.n OR (e.details->>'kev') IS DISTINCT FROM (k.n > 0)::text)
    RETURNING e.event_id
  `)
  return res.rows.length
}

/** Link package alerts to the matchable 'cve' indicators naming one of their present CVEs, and
 *  drop links to ones no longer matchable (event unpublished, made private, to_ids off) or to
 *  CVEs the package no longer has. */
export async function linkCveIndicators(db: DB, scope: IntelScope): Promise<void> {
  const where = scopeSql(scope)
  await db.execute(sql`
      DELETE FROM event_cti_indicators l
      USING events e, assets a, cti_indicators c
      LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
      WHERE l.event_id = e.event_id AND a.asset_id = e.asset_id AND c.indicator_id = l.indicator_id
        AND e.event_type = 'cve_detected' AND c.indicator_type = 'cve' ${where}
        AND (NOT ${matchableSql(sql`a.tenant_id`)}
          OR NOT EXISTS (SELECT 1 FROM cve_findings f WHERE f.event_id = e.event_id AND f.cve_id = c.value AND f.fixed_at IS NULL))
  `)
  await db.execute(sql`
      INSERT INTO event_cti_indicators (event_id, indicator_id)
      SELECT DISTINCT e.event_id, c.indicator_id
      FROM cve_findings f
      JOIN events e ON e.event_id = f.event_id
      JOIN assets a ON a.asset_id = e.asset_id
      JOIN cti_indicators c ON c.indicator_type = 'cve' AND c.value = f.cve_id
      LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
      WHERE f.fixed_at IS NULL AND e.event_type = 'cve_detected' ${where} AND ${matchableSql(sql`a.tenant_id`)}
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
