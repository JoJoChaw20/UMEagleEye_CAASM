/**
 * Threat-intel matching against assets: raises, reopens and resolves `cti_match` alerts.
 *
 *   R5  possible compromise — a PUBLIC IP of the asset, or its full hostname (or a parent
 *       domain of it), is an IP / domain indicator, or the host of a URL indicator.
 *       Private and special-use addresses never match (they exist in every network).
 *   R6  watched software — software an event watches ("MOVEit Transfer",
 *       "log4j-core@2.14.1") is installed (agent inventory) or in the SBOM.
 *
 * Indicators follow the Step 4 rules (services/threatIntel.ts matchableSql): feed
 * entries, plus published events the asset's tenant may see; to_ids on, not on a
 * warninglist. One alert per (asset, indicator type, value), whichever feeds or events
 * name it. Runs both ways: after new evidence (scan, inventory, SBOM, asset edit) for
 * the assets concerned, and after new knowledge (nightly feeds, an event change) for
 * the tenants concerned. A match that no longer holds is resolved; one that comes back
 * reopens its resolved alert; false positives and accepted risks stay closed.
 *
 * The whole reconciliation is ONE SQL statement (one subrequest), plus two for the
 * alert↔indicator links shown on the alert.
 */
import { sql, type SQL } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { matchableSql, type IntelScope } from './threatIntel'

type DB = ReturnType<typeof getDb>

export type MatchScope = IntelScope | { assetIds: string[] }

export interface MatchResult { created: number; reopened: number; resolved: number }

// RFC 1918, loopback, link-local, CGNAT, documentation, multicast, reserved
const SPECIAL_V4 = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
  '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4']
const OCTET = '(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
const IPV4_RE = `^${OCTET}(\\.${OCTET}){3}$`

function assetScope(scope: MatchScope): SQL {
  if ('assetIds' in scope) {
    return scope.assetIds.length
      ? sql`a.asset_id IN (${sql.join(scope.assetIds.map(id => sql`${id}::uuid`), sql`, `)})`
      : sql`false`
  }
  if ('assetId' in scope) return sql`a.asset_id = ${scope.assetId}::uuid`
  if ('tenantId' in scope) return sql`a.tenant_id = ${scope.tenantId}::uuid`
  return sql`true`
}

export async function matchIocs(db: DB, scope: MatchScope): Promise<MatchResult> {
  const inScope = assetScope(scope)
  const special = sql.raw(`ARRAY[${SPECIAL_V4.map(n => `'${n}'`).join(',')}]::inet[]`)
  const visibleTo = (alias: string) => matchableSql(sql.raw(`${alias}.tenant_id`))

  const res = await db.execute(sql`
    WITH s AS (
      SELECT a.asset_id, a.tenant_id, a.ip_address, a.hostname FROM assets a WHERE ${inScope}
    ),
    -- What each asset shows: public IPs, full hostnames (and their parent domains), software.
    ips AS (
      SELECT DISTINCT asset_id, tenant_id, ip FROM (
        SELECT s.asset_id, s.tenant_id, s.ip_address AS ip FROM s
        UNION ALL
        SELECT s.asset_id, s.tenant_id, ad.ip_address FROM s
        JOIN asset_addresses ad ON ad.asset_id = s.asset_id AND ad.ended_at IS NULL
      ) x
      WHERE ip ~ ${IPV4_RE} AND NOT (ip::inet <<= ANY(${special}))
    ),
    hosts AS (
      SELECT s.asset_id, s.tenant_id, lower(trim(trailing '.' from s.hostname)) AS host,
             string_to_array(lower(trim(trailing '.' from s.hostname)), '.') AS labels
      FROM s WHERE s.hostname ~ '^[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+\\.?$'
    ),
    suffixes AS (            -- mail.company.my → mail.company.my, company.my
      SELECT h.asset_id, h.tenant_id, h.host, array_to_string(h.labels[i:], '.') AS name
      FROM hosts h, generate_series(1, array_length(h.labels, 1) - 1) AS i
    ),
    soft AS (
      SELECT s.asset_id, s.tenant_id, 'software'::text AS matched_on, sw.name, sw.version FROM s
      JOIN asset_software sw ON sw.asset_id = s.asset_id
      UNION ALL
      SELECT s.asset_id, s.tenant_id, 'package', d.name, d.version FROM s
      JOIN dependencies d ON d.asset_id = s.asset_id
    ),
    url_iocs AS (
      SELECT c.*, lower(substring(c.value from '^[A-Za-z][A-Za-z0-9+.-]*://([^/:?#@]+)')) AS url_host
      FROM cti_indicators c WHERE c.indicator_type = 'url'
    ),
    hit AS (
      SELECT ips.asset_id, ips.tenant_id, c.indicator_type::text AS itype, c.value AS ivalue,
             'ip' AS matched_on, ips.ip AS observed, 'ioc' AS kind, c.source, c.ti_event_id, te.title, te.threat_level::text AS level
      FROM ips JOIN cti_indicators c ON c.indicator_type = 'ip' AND c.value = ips.ip
      LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
      WHERE ${visibleTo('ips')}
      UNION ALL
      SELECT sx.asset_id, sx.tenant_id, 'domain', c.value, 'hostname', sx.host, 'ioc', c.source, c.ti_event_id, te.title, te.threat_level::text
      FROM suffixes sx JOIN cti_indicators c ON c.indicator_type = 'domain' AND c.value = sx.name
      LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
      WHERE ${visibleTo('sx')}
      UNION ALL
      SELECT h.asset_id, h.tenant_id, 'url', c.value, 'hostname', h.host, 'ioc', c.source, c.ti_event_id, te.title, te.threat_level::text
      FROM hosts h JOIN url_iocs c ON c.url_host = h.host
      LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
      WHERE ${visibleTo('h')}
      UNION ALL
      SELECT so.asset_id, so.tenant_id, 'software', c.value, so.matched_on,
             so.name || COALESCE(' ' || so.version, ''), 'watchlist', c.source, c.ti_event_id, te.title, te.threat_level::text
      FROM soft so
      JOIN cti_indicators c ON c.indicator_type = 'software'
        AND (lower(so.name) = lower(substring(c.value from '^(@?[^@]+)'))
             OR lower(so.name) LIKE lower(substring(c.value from '^(@?[^@]+)')) || ' %')
        AND (substring(c.value from '^@?[^@]+@(.+)$') IS NULL
             OR so.version = substring(c.value from '^@?[^@]+@(.+)$')
             OR so.version LIKE substring(c.value from '^@?[^@]+@(.+)$') || '.%')
      LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
      WHERE ${visibleTo('so')}
    ),
    -- One alert per (asset, indicator): its severity is the highest any source gives it
    -- (feed entries: high; events: their threat level, one step up for IOCs).
    d AS (
      SELECT asset_id, itype, ivalue,
             min(matched_on) AS matched_on, min(observed) AS observed, min(kind) AS kind,
             (ARRAY['low', 'medium', 'high', 'critical'])[max(
               CASE WHEN ti_event_id IS NULL THEN 3
                    ELSE (CASE level WHEN 'high' THEN 4 WHEN 'medium' THEN 3 ELSE 2 END) END
               - CASE WHEN kind = 'watchlist' AND ti_event_id IS NOT NULL AND level = 'high' THEN 1 ELSE 0 END)]::severity AS severity,
             jsonb_build_object(
               'indicator_type', itype, 'indicator_value', ivalue,
               'matched_on', min(matched_on), 'observed', min(observed), 'match_kind', min(kind),
               'rule', CASE WHEN min(kind) = 'watchlist' THEN 'R6' ELSE 'R5' END,
               'sources', to_jsonb(array_agg(DISTINCT COALESCE(title, source))),
               'ti_event_titles', COALESCE(to_jsonb(array_agg(DISTINCT title) FILTER (WHERE title IS NOT NULL)), '[]'::jsonb),
               'ti_event_ids', COALESCE(to_jsonb(array_agg(DISTINCT ti_event_id) FILTER (WHERE ti_event_id IS NOT NULL)), '[]'::jsonb)
             ) AS details
      FROM hit GROUP BY asset_id, itype, ivalue
    ),
    ex AS (
      SELECT e.event_id, e.asset_id, e.status, e.details->>'indicator_type' AS itype, e.details->>'indicator_value' AS ivalue
      FROM events e JOIN assets a ON a.asset_id = e.asset_id
      WHERE e.event_type = 'cti_match' AND ${inScope}
    ),
    ins AS (
      INSERT INTO events (asset_id, event_type, severity, details)
      SELECT d.asset_id, 'cti_match', d.severity, d.details FROM d
      WHERE NOT EXISTS (SELECT 1 FROM ex WHERE ex.asset_id = d.asset_id AND ex.itype = d.itype AND ex.ivalue = d.ivalue)
      RETURNING 1
    ),
    upd AS (
      UPDATE events e SET
        details = e.details || d.details, severity = d.severity, last_seen = now(), updated_at = now(),
        status = CASE WHEN e.status = 'resolved' THEN 'open'::event_status ELSE e.status END,
        resolved_at = CASE WHEN e.status = 'resolved' THEN NULL ELSE e.resolved_at END,
        resolved_by = CASE WHEN e.status = 'resolved' THEN NULL ELSE e.resolved_by END,
        resolution_note = CASE WHEN e.status = 'resolved' THEN 'Reopened: the indicator matches this asset again' ELSE e.resolution_note END,
        occurrences = e.occurrences + CASE WHEN e.status = 'resolved' THEN 1 ELSE 0 END
      FROM ex, d
      WHERE e.event_id = ex.event_id AND ex.asset_id = d.asset_id AND ex.itype = d.itype AND ex.ivalue = d.ivalue
        AND ex.status IN ('open', 'in_progress', 'resolved')
        AND (ex.status = 'resolved' OR e.details IS DISTINCT FROM e.details || d.details OR e.severity <> d.severity)
      RETURNING (ex.status = 'resolved') AS reopened
    ),
    res AS (
      UPDATE events e SET status = 'resolved', resolved_at = now(), updated_at = now(),
        resolution_note = 'Auto-resolved: the indicator no longer matches (removed, unpublished, or the asset changed)'
      FROM ex
      WHERE e.event_id = ex.event_id AND ex.status IN ('open', 'in_progress')
        AND NOT EXISTS (SELECT 1 FROM d WHERE d.asset_id = ex.asset_id AND d.itype = ex.itype AND d.ivalue = ex.ivalue)
      RETURNING 1
    )
    SELECT (SELECT count(*) FROM ins)::int AS created,
           (SELECT count(*) FROM upd WHERE reopened)::int AS reopened,
           (SELECT count(*) FROM res)::int AS resolved
  `)
  const row = (res.rows[0] ?? {}) as Partial<MatchResult>
  await linkMatchIndicators(db, inScope)
  return { created: Number(row.created ?? 0), reopened: Number(row.reopened ?? 0), resolved: Number(row.resolved ?? 0) }
}

/** Link each open cti_match alert to the matchable indicators it is about (shown on the
 *  alert); drop links that no longer hold. */
async function linkMatchIndicators(db: DB, inScope: SQL): Promise<void> {
  const matchable = matchableSql(sql`a.tenant_id`)
  await db.execute(sql`
    DELETE FROM event_cti_indicators l
    USING events e, assets a, cti_indicators c
    LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
    WHERE l.event_id = e.event_id AND a.asset_id = e.asset_id AND c.indicator_id = l.indicator_id
      AND e.event_type = 'cti_match' AND ${inScope}
      AND (e.status NOT IN ('open', 'in_progress') OR NOT ${matchable})
  `)
  await db.execute(sql`
    INSERT INTO event_cti_indicators (event_id, indicator_id)
    SELECT e.event_id, c.indicator_id
    FROM events e
    JOIN assets a ON a.asset_id = e.asset_id
    JOIN cti_indicators c ON c.indicator_type::text = e.details->>'indicator_type' AND c.value = e.details->>'indicator_value'
    LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
    WHERE e.event_type = 'cti_match' AND e.status IN ('open', 'in_progress') AND ${inScope} AND ${matchable}
    ON CONFLICT DO NOTHING
  `)
}
