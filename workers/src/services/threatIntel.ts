/**
 * What threat intelligence an asset's alerts may use, and keeping CVE alerts in step
 * with it.
 *
 * An indicator is MATCHABLE for an asset of tenant T when it is a global feed entry
 * (ThreatFox, CISA KEV), or an attribute of a PUBLISHED event that is T's own, a platform
 * event (the MyCERT advisories, services/mycert.ts), or shared with all tenants by another
 * tenant and opted into by T (eventAlertsSql); and it is marked to_ids and not on a
 * warninglist. Drafts and other tenants' private events never touch T's alerts.
 *
 * CVE findings (cve_findings) carry the result: has_cti_match (any matchable 'cve'
 * indicator), kev (exploited in the wild: on CISA KEV, or named exploited by a published
 * platform event, i.e. a MyCERT advisory: EXPLOITED_SQL) and ti_event_titles (the events
 * naming it); the package alert sums them up (kev_count, has_cti_match...), and an exploited
 * CVE ranks in the Exploited tier (lib/alertRank.ts) whichever said so. refreshCveIntel()
 * recomputes those after anything changes (nightly feeds, an event published, unpublished,
 * edited or deleted), both ways: a flag can also be cleared.
 */
import { sql, type SQL } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { recomputePackageAlerts } from './packageAlerts'
import { MYCERT_SOURCE } from '../lib/mycert'

type DB = ReturnType<typeof getDb>

export const KEV_SOURCE = 'CISA KEV'

/**
 * SQL: CVE indicator `c` (its event `te`, LEFT JOIN) says the CVE is exploited in the wild: a CISA KEV
 * entry, or an attribute of a published platform event that lists it in exploited_cves (only MyCERT
 * advisories set it). Use it on rows already known matchable.
 */
export const EXPLOITED_SQL = sql`((c.ti_event_id IS NULL AND c.source = ${KEV_SOURCE})
  OR COALESCE(te.status = 'published' AND te.distribution = 'platform' AND c.value = ANY(te.exploited_cves), false))`

/** SQL: CVE `cveId` (an SQL text value) is exploited in the wild per CISA KEV or a published MyCERT advisory. */
export function cveExploitedSql(cveId: SQL): SQL {
  return sql`(EXISTS (SELECT 1 FROM cti_indicators c WHERE c.indicator_type = 'cve' AND c.value = ${cveId}
                        AND c.ti_event_id IS NULL AND c.source = ${KEV_SOURCE})
    OR EXISTS (SELECT 1 FROM ti_events te WHERE te.status = 'published' AND te.distribution = 'platform'
                 AND ${cveId} = ANY(te.exploited_cves)))`
}

/**
 * How long a feed's IP, domain or URL keeps raising alerts after the feed last listed it. Feeds
 * list an indicator while it is active (ThreatFox: its last 7 days), so one that has not been
 * listed for this long is most likely cleaned up or reassigned: an IP is often handed to someone
 * else within weeks, a domain lasts longer. Kept in the table (and on old alerts) until retention
 * deletes it (services/retention.ts, 90 days); it just stops matching. KEV CVEs and a tenant's own
 * event attributes do not expire. A MyCERT advisory's IPs, domains and URLs follow the same windows,
 * counted from the advisory's date (their last_seen): the advisory stays, its old addresses stop
 * matching. Its CVEs and hashes do not expire.
 */
export const FEED_FRESH_DAYS = { ip: 30, domain: 90, url: 90 } as const
// The day counts as SQL literals (constants above): bound as parameters they arrive as text,
// and "text * interval" fails (it broke the agents' list download on 22 Nov until fixed).
// A retired feed's rows stop matching at once; retention deletes them. AlienVault OTX was dropped on
// 22 Nov 2026; URLhaus and Feodo Tracker on 27 Nov 2026, when MyCERT became the main source.
export const RETIRED_SOURCES = ['AlienVault OTX', 'URLhaus', 'Feodo Tracker']
const RETIRED_LIST = sql.raw(RETIRED_SOURCES.map((s) => `'${s.replace(/'/g, "''")}'`).join(', '))
// Event attributes loaded from MyCERT (services/mycert.ts) age like feed entries.
const AGEING_EVENT_SOURCE = sql.raw(`'${MYCERT_SOURCE}'`)
/** A value still recent enough to match, for table alias `a`: a feed value listed lately, a MyCERT
 *  advisory's value within the same window of its date; an analyst's event attributes always are. */
export function freshSql(a: string): SQL {
  const t = sql.raw(a)
  return sql`((${t}.ti_event_id IS NOT NULL AND ${t}.source <> ${AGEING_EVENT_SOURCE}) OR (${t}.source NOT IN (${RETIRED_LIST})
  AND (${t}.indicator_type NOT IN ('ip', 'domain', 'url')
  OR ${t}.last_seen > now() - (CASE WHEN ${t}.indicator_type = 'ip' THEN ${sql.raw(String(Number(FEED_FRESH_DAYS.ip)))}
                                 ELSE ${sql.raw(String(Number(FEED_FRESH_DAYS.domain)))} END) * interval '1 day')))`
}
export const FEED_FRESH = freshSql('c')

/**
 * What an indicator is used for (the Threat Intelligence page), for table alias `a`:
 *   'agents'      on the agents' list, checked on the computers (sightings: lookups, connections, running
 *                 programs' file hashes), and matched against the assets' addresses and names (R5);
 *   'assets'      matched against scan, inventory and SBOM data only: CVEs, watched software, URLs on a
 *                 named host (their host against device names);
 *   'reference:<why>'  kept for lookups and context, never matched: retired (its feed was dropped),
 *                 safe_list (on a warninglist), not_for_detection (to_ids off), expired (no feed has
 *                 listed it lately), no_data (a type nothing here can see: emails).
 * Follows routes/sightings.ts and matchableSql; lib/indicatorUse.test.ts keeps them in step.
 */
export function indicatorUseSql(a: string): SQL {
  const t = sql.raw(a)
  const ipv4Host = sql.raw(`${a}.value ~ '^[A-Za-z][A-Za-z0-9+.-]*://([^/?#@]*@)?[0-9]{1,3}(\\.[0-9]{1,3}){3}([:/?#]|$)'`)
  return sql`(CASE
    WHEN ${t}.source IN (${RETIRED_LIST}) AND ${t}.ti_event_id IS NULL THEN 'reference:retired'
    WHEN ${t}.warning IS NOT NULL THEN 'reference:safe_list'
    WHEN NOT ${t}.to_ids THEN 'reference:not_for_detection'
    WHEN NOT ${freshSql(a)} THEN 'reference:expired'
    WHEN ${t}.indicator_type IN ('ip', 'domain', 'hash') THEN 'agents'
    WHEN ${t}.indicator_type = 'url' AND ${ipv4Host} THEN 'agents'
    WHEN ${t}.indicator_type IN ('cve', 'software', 'url') THEN 'assets'
    ELSE 'reference:no_data' END)`
}

/**
 * SQL: event `te` (published) raises alerts in tenant `tenant`: its own event, a platform event (the
 * superadmin's), or one another tenant shared with all tenants that `tenant` opted into: its choice
 * for that event (ti_event_alert_choices), else its default (tenants.shared_event_alerts, off).
 * Without the opt-in a shared event is only read: one tenant admin cannot flood every tenant with
 * alerts (an event naming "Microsoft Edge" or "edu.my").
 */
export function eventAlertsSql(tenant: SQL): SQL {
  return sql`(te.tenant_id = ${tenant} OR te.distribution = 'platform'
    OR (te.distribution = 'all_tenants' AND COALESCE(
      (SELECT ch.alerts FROM ti_event_alert_choices ch WHERE ch.tenant_id = ${tenant} AND ch.ti_event_id = te.ti_event_id),
      (SELECT tn.shared_event_alerts FROM tenants tn WHERE tn.tenant_id = ${tenant}),
      false)))`
}

/** SQL: indicator `c` (joined to its event `te`, LEFT JOIN) is matchable for tenant `tenant`. */
export function matchableSql(tenant: SQL): SQL {
  return sql`(c.to_ids AND c.warning IS NULL AND ${FEED_FRESH} AND (
    c.ti_event_id IS NULL
    OR (te.status = 'published' AND ${eventAlertsSql(tenant)})
  ))`
}

/** SQL: the name of the tenant that shared event `te`, when it is not `tenant` itself ("Shared by"). */
export function sharedBySql(tenant: SQL): SQL {
  return sql`(CASE WHEN te.tenant_id IS NOT NULL AND te.tenant_id IS DISTINCT FROM ${tenant}
    THEN (SELECT tn.name FROM tenants tn WHERE tn.tenant_id = te.tenant_id) END)`
}

export interface CveIntel { kev: boolean; titles: string[] }

/** For CVE IDs found on an asset of `tenantId`: which are named by matchable intel. */
export async function cveIntelFor(db: DB, tenantId: string | null, cveIds: string[]): Promise<Map<string, CveIntel>> {
  const out = new Map<string, CveIntel>()
  if (cveIds.length === 0) return out
  // Aliased c / te so the shared rule (eventAlertsSql) applies as everywhere else.
  const res = await db.execute(sql`
    SELECT c.value, c.ti_event_id AS "eventId", te.title, ${EXPLOITED_SQL} AS exploited
    FROM cti_indicators c LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
    WHERE c.indicator_type = 'cve' AND c.value IN (${sql.join(cveIds.map((v) => sql`${v}`), sql`, `)})
      AND c.to_ids AND c.warning IS NULL
      AND (c.ti_event_id IS NULL OR (te.status = 'published' AND ${eventAlertsSql(sql`${tenantId}::uuid`)}))
  `)
  const rows = res.rows as Array<{ value: string; eventId: string | null; title: string | null; exploited: boolean }>
  for (const r of rows) {
    const cur = out.get(r.value) ?? { kev: false, titles: [] }
    if (r.exploited) cur.kev = true
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
               COALESCE(bool_or(${EXPLOITED_SQL}), false) AS kev,
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
 * that is exploited now (CISA KEV or a MyCERT advisory: cveExploitedSql), and update kev_count / kev /
 * has_cti_match. A service that gains an exploited CVE goes up to at least high, as serviceFinding()
 * rates a new one. Without this, a CVE added to KEV after the scan stayed unflagged until the next
 * active scan. Returns how many alerts changed.
 */
export async function refreshServiceKev(db: DB, scope: IntelScope): Promise<number> {
  const where = scopeSql(scope)
  const res = await db.execute(sql`
    WITH s AS (
      SELECT e.event_id,
        (SELECT jsonb_agg(CASE WHEN ${cveExploitedSql(sql`x->>'id'`)}
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
