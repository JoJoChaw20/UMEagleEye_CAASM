/**
 * UMEagleEye Workers — CTI routes
 * Returns snake_case field names to match frontend expectations.
 */

import { Hono } from 'hono'
import { eq, and, or, isNull, desc, gte, ilike, ne, inArray, sql, type SQL } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb, type DB } from '../db/client'
import { CTI_INGEST_LOCK, LAST_INGEST_KEY, type LastIngest } from '../services/cti'
import { ctiIndicators, assets, assetAddresses, tiEvents, events, eventCtiIndicators } from '../db/schema'
import {
  ATTACK, buildMatrix, expandTechniques, type MatrixGroup, softwareName, softwareUsing, techniqueName, techniquesFor,
} from '../lib/attack'

const app = new Hono<{ Bindings: Env }>()

const READ_ROLES   = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner']
// The feeds are shared by every tenant, so only the platform superadmin starts an early
// run (staging has no crons, so this is how its feeds get loaded). Production loads them
// nightly at INGEST_HOUR_UTC.
const INGEST_ROLES = ['superadmin']
const INGEST_HOUR_UTC = 22     // wrangler.toml "0 22 * * *" = 06:00 MYT

/** The next nightly ingestion after `now` (exported for tests). */
export function nextIngestAt(now: Date): Date {
  const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), INGEST_HOUR_UTC))
  if (next.getTime() <= now.getTime()) next.setUTCDate(next.getUTCDate() + 1)
  return next
}

const OPEN = ['open', 'in_progress'] as const
const NO_TENANT = '00000000-0000-0000-0000-000000000000'

// The routes below are the global feeds (OTX, ThreatFox, CISA KEV). Attributes of
// threat-intel events are served by routes/tiEvents.ts, scoped to who may see them.
const FEED = isNull(ctiIndicators.tiEventId)

// IoC Feed filters from the ATT&CK tab.
// family: an ATT&CK software id (S0154) or the feed's family name.
// technique: indicators whose family uses it (or one of its sub-techniques), or whose feed named it.
export function attackConditions(family?: string, technique?: string): SQL[] {
  const out: SQL[] = []
  if (family) {
    out.push(/^S\d{4}$/i.test(family)
      ? eq(ctiIndicators.attackSoftware, family.toUpperCase())
      : ilike(ctiIndicators.malwareFamily, family))
  }
  if (technique) {
    // ids come from attack.json, never from the request, so they are safe to inline
    const techs = expandTechniques([technique])
    const soft = softwareUsing(techs)
    const named = sql`${ctiIndicators.attackTechniques} && ${sql.raw(`ARRAY[${techs.map((t) => `'${t}'`).join(',') || "''"}]::text[]`)}`
    out.push(soft.length ? or(inArray(ctiIndicators.attackSoftware, soft), named)! : named)
  }
  return out
}

// ── Helper: transform a Drizzle CTI row → snake_case ─────────────
function toSnake(row: typeof ctiIndicators.$inferSelect) {
  return {
    indicator_id:       row.indicatorId,
    source:             row.source,
    indicator_type:     row.indicatorType,
    value:              row.value,
    confidence_score:   row.confidenceScore != null ? Number(row.confidenceScore) : null,
    malware_family:     row.malwareFamily,
    attack_software:    row.attackSoftware,
    attack_software_name: softwareName(row.attackSoftware),
    technique_count:    techniquesFor(row.attackSoftware, row.attackTechniques).length,
    first_seen:         row.firstSeen,
    last_seen:          row.lastSeen,
  }
}

// Indicators linked to open match alerts on the user's assets (superadmins: any tenant).
function matchedIndicatorIds(db: DB, user: { role: string; tenantId?: string | null }) {
  return db
    .select({ id: eventCtiIndicators.indicatorId })
    .from(eventCtiIndicators)
    .innerJoin(events, eq(events.eventId, eventCtiIndicators.eventId))
    .innerJoin(assets, eq(assets.assetId, events.assetId))
    .where(and(
      eq(events.eventType, 'cti_match'),
      inArray(events.status, [...OPEN]),
      user.role === 'superadmin' ? undefined : eq(assets.tenantId, user.tenantId ?? NO_TENANT),
    ))
}

// ── GET /indicators ──────────────────────────────────────────────
app.get('/indicators', authMiddleware, async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)

    const page     = Math.max(1, parseInt(c.req.query('page')  ?? '1'))
    const limit    = Math.min(500, Math.max(1, parseInt(c.req.query('limit') ?? '100')))
    const offset   = (page - 1) * limit
    const type     = c.req.query('indicator_type') ?? c.req.query('type')
    const source   = c.req.query('source')
    const search   = (c.req.query('q') ?? c.req.query('search'))?.trim()
    const family   = c.req.query('family')?.trim()
    const technique = c.req.query('technique')?.trim().toUpperCase()
    const matched  = c.req.query('matched') === 'true'

    const conditions = [FEED, ...attackConditions(family, technique)]
    // Only indicators behind an open match alert on the user's own assets.
    if (matched) conditions.push(inArray(ctiIndicators.indicatorId, matchedIndicatorIds(db, c.get('user'))))
    if (type)   conditions.push(eq(ctiIndicators.indicatorType, type as 'ip' | 'domain' | 'hash' | 'url' | 'email' | 'cve' | 'software'))
    if (source) conditions.push(ilike(ctiIndicators.source, `%${source}%`))
    if (search) conditions.push(ilike(ctiIndicators.value, `%${search}%`))

    const whereClause = and(...conditions)

    const [rows, countRows] = await Promise.all([
      db.select().from(ctiIndicators).where(whereClause).orderBy(desc(ctiIndicators.lastSeen)).limit(limit).offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(ctiIndicators).where(whereClause),
    ])

    return c.json({
      total:  countRows[0]?.count ?? 0,
      page,
      limit,
      items:  rows.map(toSnake),
    })
  } catch (err) {
    console.error('cti GET /indicators error:', err)
    return c.json({ detail: 'Failed to fetch CTI indicators' }, 500)
  }
})

// ── GET /stats ───────────────────────────────────────────────────
app.get('/stats', authMiddleware, async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const isSuper = user.role === 'superadmin'
    const ownTenant = user.tenantId ?? NO_TENANT
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)

    const [totalResult, bySource, byType, recent7d, matchRows, eventRows, lastIngest] = await Promise.all([
      db.select({ count: sql<number>`count(*)::int` }).from(ctiIndicators).where(FEED),
      db
        .select({ source: ctiIndicators.source, count: sql<number>`count(*)::int` })
        .from(ctiIndicators)
        .where(FEED)
        .groupBy(ctiIndicators.source)
        .orderBy(desc(sql`count(*)`)),
      db
        .select({ indicator_type: ctiIndicators.indicatorType, count: sql<number>`count(*)::int` })
        .from(ctiIndicators)
        .where(FEED)
        .groupBy(ctiIndicators.indicatorType)
        .orderBy(desc(sql`count(*)`)),
      db
        .select({ count: sql<number>`count(*)::int` })
        .from(ctiIndicators)
        .where(and(FEED, gte(ctiIndicators.firstSeen, sevenDaysAgo))),
      // Open threat-intel matches on the user's assets
      db
        .select({
          open:   sql<number>`count(*)::int`,
          high:   sql<number>`count(*) FILTER (WHERE ${events.severity} IN ('critical', 'high'))::int`,
          assets: sql<number>`count(DISTINCT ${events.assetId})::int`,
        })
        .from(events)
        .innerJoin(assets, eq(assets.assetId, events.assetId))
        .where(and(
          eq(events.eventType, 'cti_match'),
          inArray(events.status, [...OPEN]),
          isSuper ? undefined : eq(assets.tenantId, ownTenant),
        )),
      // Threat-intel events this user can see (own drafts and published shared ones)
      db
        .select({
          total:     sql<number>`count(*)::int`,
          published: sql<number>`count(*) FILTER (WHERE ${tiEvents.status} = 'published')::int`,
        })
        .from(tiEvents)
        .where(isSuper ? undefined : or(
          eq(tiEvents.tenantId, ownTenant),
          and(eq(tiEvents.status, 'published'), inArray(tiEvents.distribution, ['all_tenants', 'platform'])),
        )),
      c.env.KV_CACHE.get<LastIngest>(LAST_INGEST_KEY, 'json').catch(() => null),
    ])

    const by_source: Record<string, number> = {}
    for (const row of bySource) by_source[row.source] = row.count

    const by_type: Record<string, number> = {}
    for (const row of byType) by_type[row.indicator_type] = row.count

    return c.json({
      total_indicators: totalResult[0]?.count ?? 0,  // snake_case for frontend
      by_source,
      by_type,
      recent_7d: recent7d[0]?.count ?? 0,
      matches: {
        open:   matchRows[0]?.open ?? 0,
        high:   matchRows[0]?.high ?? 0,
        assets: matchRows[0]?.assets ?? 0,
      },
      ti_events: { total: eventRows[0]?.total ?? 0, published: eventRows[0]?.published ?? 0 },
      // Feed health: each feed's count, and when it last loaded (null before the first
      // recorded run). next_ingest_at is the nightly run (production; staging has no crons).
      feeds: bySource.map((r) => ({
        source:     r.source,
        count:      r.count,
        ok:         lastIngest?.feeds?.[r.source]?.ok ?? null,
        last_ok_at: lastIngest?.feeds?.[r.source]?.last_ok_at ?? null,
      })),
      last_ingest_at: lastIngest?.at ?? null,
      next_ingest_at: nextIngestAt(new Date()).toISOString(),
      can_ingest: isSuper,
    })
  } catch (err) {
    console.error('cti GET /stats error:', err)
    return c.json({ detail: 'Failed to fetch CTI stats' }, 500)
  }
})

// ── GET /attack ─── the ATT&CK catalogue, for picking techniques on an event ──
app.get('/attack', authMiddleware, (c) => {
  c.header('Cache-Control', 'private, max-age=86400')
  return c.json({
    version: ATTACK.version,
    modified: ATTACK.modified,
    tactics: ATTACK.tactics.map(([id, short, name]) => ({ id, short, name })),
    // [id, name, tactic shortnames]
    techniques: Object.entries(ATTACK.techniques).map(([id, [name, tix]]) => [id, name, tix.map((i) => ATTACK.tactics[i]?.[1])]),
    software: Object.entries(ATTACK.software).map(([id, [name, t]]) => [id, name, t.length]),
    names: ATTACK.names,
  })
})

// ── GET /matrix ──────────────────────────────────────────────────
// MITRE ATT&CK view: techniques come from MITRE's own data for each indicator's malware
// family (lib/attack.ts), or were named by the feed or the event; never inferred from
// type or tags. CVEs (CISA KEV) are not malware and are left out. ?scope=
//   feeds    (default) the global feeds
//   matched  indicators behind open alerts on our assets (feeds and events)
//   events   our events and the published ones shared with us, one family per event
export type MatrixScope = 'feeds' | 'matched' | 'events'

/** The groups GET /matrix builds the matrix from (exported for tests). */
export async function matrixGroups(
  db: DB, scope: MatrixScope, user: { role: string; tenantId?: string | null },
): Promise<MatrixGroup[]> {
  const isSuper = user.role === 'superadmin'
  const ownTenant = user.tenantId ?? '00000000-0000-0000-0000-000000000000'
  const notCve = ne(ctiIndicators.indicatorType, 'cve')
  let groups: MatrixGroup[]

  if (scope === 'matched') {
    groups = await db
      .select({
        family:   ctiIndicators.malwareFamily,
        software: ctiIndicators.attackSoftware,
        named:    ctiIndicators.attackTechniques,
        count:    sql<number>`count(DISTINCT ${ctiIndicators.indicatorId})::int`,
      })
      .from(eventCtiIndicators)
      .innerJoin(ctiIndicators, eq(ctiIndicators.indicatorId, eventCtiIndicators.indicatorId))
      .innerJoin(events, eq(events.eventId, eventCtiIndicators.eventId))
      .innerJoin(assets, eq(assets.assetId, events.assetId))
      .where(and(
        notCve,
        inArray(events.status, ['open', 'in_progress']),
        isSuper ? undefined : eq(assets.tenantId, ownTenant),
      ))
      .groupBy(ctiIndicators.malwareFamily, ctiIndicators.attackSoftware, ctiIndicators.attackTechniques)
  } else if (scope === 'events') {
    const rows = await db
      .select({
        title:    tiEvents.title,
        family:   tiEvents.malwareFamily,
        software: tiEvents.attackSoftware,
        named:    tiEvents.attackTechniques,
        // qualified by hand: with no join drizzle writes a bare "ti_event_id", which the subquery would read as c's
        count:    sql<number>`(SELECT count(*)::int FROM cti_indicators c WHERE c.ti_event_id = ti_events.ti_event_id AND c.indicator_type <> 'cve')`,
      })
      .from(tiEvents)
      .where(isSuper ? undefined : or(
        eq(tiEvents.tenantId, ownTenant),
        and(eq(tiEvents.status, 'published'), inArray(tiEvents.distribution, ['all_tenants', 'platform'])),
      ))
      .orderBy(desc(tiEvents.updatedAt))
      .limit(500)
    groups = rows.map((r) => ({ ...r, label: r.title }))
  } else {
    groups = await db
      .select({
        family:   ctiIndicators.malwareFamily,
        software: ctiIndicators.attackSoftware,
        named:    ctiIndicators.attackTechniques,
        count:    sql<number>`count(*)::int`,
      })
      .from(ctiIndicators)
      .where(and(FEED, notCve))
      .groupBy(ctiIndicators.malwareFamily, ctiIndicators.attackSoftware, ctiIndicators.attackTechniques)
  }
  return groups
}

app.get('/matrix', authMiddleware, async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const wanted = c.req.query('scope')
    const scope: MatrixScope = wanted === 'matched' || wanted === 'events' ? wanted : 'feeds'
    const groups = await matrixGroups(db, scope, c.get('user'))
    const matrix = buildMatrix(groups)
    const extra = scope === 'events'
      ? { events_total: groups.length, events_with_attack: groups.filter((g) => techniquesFor(g.software, g.named).length > 0).length }
      : {}
    return c.json({ scope, ...matrix, ...extra })
  } catch (err) {
    console.error('cti GET /matrix error:', err)
    return c.json({ detail: 'Failed to fetch MITRE ATT&CK matrix' }, 500)
  }
})

// ── GET /lookup ──────────────────────────────────────────────────
app.get('/lookup', authMiddleware, async (c) => {
  try {
    const db    = getDb(c.env.DATABASE_URL)
    const user  = c.get('user')
    const value = c.req.query('value')?.trim()
    if (!value) return c.json({ detail: 'value query param required' }, 422)

    // Find indicator: a feed entry, else an attribute of an event this user may see
    // (own tenant's, or a published shared/platform one; superadmins see all).
    const visibleEvent = user.role === 'superadmin'
      ? sql`true`
      : sql`(${tiEvents.tenantId} = ${user.tenantId ?? null} OR (${tiEvents.status} = 'published' AND ${tiEvents.distribution} IN ('all_tenants', 'platform')))`
    const [hit] = await db
      .select({ indicator: ctiIndicators, eventTitle: tiEvents.title })
      .from(ctiIndicators)
      .leftJoin(tiEvents, eq(tiEvents.tiEventId, ctiIndicators.tiEventId))
      .where(and(eq(ctiIndicators.value, value), or(FEED, visibleEvent)))
      .orderBy(sql`${ctiIndicators.tiEventId} IS NOT NULL`)     // feed entries first
      .limit(1)
    const indicator = hit?.indicator

    // Cross-reference against internal assets (IP match only)
    let matched_internal_asset: {
      asset_id: string; hostname: string | null; ip_address: string
      criticality_score: number | null; is_internet_facing: boolean | null
    } | null = null
    try {
      // IP is no longer unique across assets. Prefer the asset whose CURRENT
      // address row holds this IP, then the most recently scanned — deterministic.
      const [asset] = await db
        .select({
          assetId:         assets.assetId,
          hostname:        assets.hostname,
          ipAddress:       assets.ipAddress,
          criticalityScore: assets.criticalityScore,
          isInternetFacing: assets.isInternetFacing,
          hasCurrentAddr:  sql<boolean>`bool_or(${assetAddresses.addressId} IS NOT NULL)`,
        })
        .from(assets)
        .leftJoin(assetAddresses, and(
          eq(assetAddresses.assetId, assets.assetId),
          isNull(assetAddresses.endedAt),
          eq(assetAddresses.ipAddress, value),
        ))
        .where(and(
          or(eq(assets.ipAddress, value), eq(assetAddresses.ipAddress, value)),
          // only the user's own tenant's assets (superadmins: any)
          user.role === 'superadmin' ? undefined : eq(assets.tenantId, user.tenantId ?? ''),
        ))
        .groupBy(assets.assetId)
        .orderBy(desc(sql`bool_or(${assetAddresses.addressId} IS NOT NULL)`), desc(assets.lastScanned))
        .limit(1)

      if (asset) {
        matched_internal_asset = {
          asset_id:         asset.assetId,
          hostname:         asset.hostname,
          ip_address:       asset.ipAddress,
          criticality_score: asset.criticalityScore,
          is_internet_facing: asset.isInternetFacing,
        }
      }
    } catch {
      // Non-IP values will not match asset IPs — expected
    }

    // Every asset an open match alert ties to this value (IP, hostname, domain or watched
    // software, as services/iocMatch.ts matched it), with the alert to open.
    const matchRows = await db
      .select({
        assetId:          assets.assetId,
        hostname:         assets.hostname,
        ipAddress:        assets.ipAddress,
        criticalityScore: assets.criticalityScore,
        eventId:          events.eventId,
        severity:         events.severity,
        observed:         sql<string | null>`${events.details}->>'observed'`,
        matchKind:        sql<string | null>`${events.details}->>'match_kind'`,
      })
      .from(events)
      .innerJoin(assets, eq(assets.assetId, events.assetId))
      .where(and(
        eq(events.eventType, 'cti_match'),
        inArray(events.status, [...OPEN]),
        sql`lower(${events.details}->>'indicator_value') = lower(${value})`,
        user.role === 'superadmin' ? undefined : eq(assets.tenantId, user.tenantId ?? NO_TENANT),
      ))
      .orderBy(desc(assets.criticalityScore))
      .limit(50)
    const matched_assets: Array<{
      asset_id: string; hostname: string | null; ip_address: string; criticality_score: number | null
      event_id: string | null; severity: string | null; observed: string | null; match_kind: string | null
    }> = matchRows.map((r) => ({
      asset_id: r.assetId, hostname: r.hostname, ip_address: r.ipAddress, criticality_score: r.criticalityScore,
      event_id: r.eventId, severity: r.severity, observed: r.observed, match_kind: r.matchKind,
    }))
    // The asset using this IP when no alert names it (a private address, or not matched yet)
    const byIp = matched_internal_asset
    if (byIp && !matched_assets.some((m) => m.asset_id === byIp.asset_id)) {
      matched_assets.push({
        asset_id: byIp.asset_id, hostname: byIp.hostname, ip_address: byIp.ip_address,
        criticality_score: byIp.criticality_score, event_id: null, severity: null, observed: value, match_kind: 'address',
      })
    }

    if (indicator) {
      return c.json({
        found: true,
        indicator: {
          ...toSnake(indicator),
          event_title: hit?.eventTitle ?? null,
          techniques: techniquesFor(indicator.attackSoftware, indicator.attackTechniques)
            .map((id) => ({ id, name: techniqueName(id) })),
        },
        matched_internal_asset,
        matched_assets,
      })
    }

    return c.json({ found: false, value, matched_internal_asset, matched_assets })
  } catch (err) {
    console.error('cti GET /lookup error:', err)
    return c.json({ detail: 'Lookup failed' }, 500)
  }
})

// ── GET /debug ───────────────────────────────────────────────────
// Live reachability test — accessible to any authenticated user.
app.get('/debug', authMiddleware, async (c) => {
  const results: Record<string, unknown> = {}

  // ── OTX ──
  try {
    const key = c.env.OTX_API_KEY
    results.otx_key_set    = !!key
    results.otx_key_length = key?.length ?? 0
    const res = await fetch(
      'https://otx.alienvault.com/api/v1/pulses/activity?limit=3&page=1',
      { headers: key ? { 'X-OTX-API-KEY': key } : {} },
    )
    results.otx_http_status = res.status
    results.otx_ok = res.ok
    if (res.ok) {
      const d = await res.json() as { count?: number; results?: Array<{ name: string; indicators: unknown[] }> }
      results.otx_total_pulses_available = d.count
      results.otx_pulses_in_response     = d.results?.length ?? 0
      results.otx_first_pulse_name       = d.results?.[0]?.name ?? null
      results.otx_first_pulse_indicators = d.results?.[0]?.indicators?.length ?? 0
    } else {
      results.otx_error_body = await res.text().catch(() => '(unreadable)')
    }
  } catch (e) {
    results.otx_fetch_exception = String(e)
  }

  // ── ThreatFox ──
  try {
    const key = c.env.THREATFOX_API_KEY
    results.threatfox_key_set    = !!key
    results.threatfox_key_length = key?.length ?? 0
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (key) headers['Auth-Key'] = key

    const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers,
      body: JSON.stringify({ query: 'get_iocs', days: 1 }),
    })
    results.threatfox_http_status = res.status
    results.threatfox_ok = res.ok
    const rawText = await res.text()
    results.threatfox_raw_response_snippet = rawText.slice(0, 300)
    if (res.ok) {
      try {
        const d = JSON.parse(rawText) as { query_status?: string; data?: unknown[] }
        results.threatfox_query_status  = d.query_status
        results.threatfox_ioc_count     = Array.isArray(d.data) ? d.data.length : `data is ${typeof d.data}`
        results.threatfox_sample_ioc    = Array.isArray(d.data) ? d.data[0] : d.data
      } catch { results.threatfox_parse_error = 'JSON.parse failed' }
    }
  } catch (e) {
    results.threatfox_fetch_exception = String(e)
  }

  return c.json(results)
})

// ── POST /ingest ─────────────────────────────────────────────────
app.post('/ingest', authMiddleware, requireRoles(...INGEST_ROLES), async (c) => {
  try {
    const lockKey  = CTI_INGEST_LOCK
    const existing = await c.env.KV_CACHE.get(lockKey)
    if (existing) {
      return c.json({ message: 'CTI ingestion already running or recently completed', queued: false })
    }

    await c.env.KV_CACHE.put(lockKey, '1', { expirationTtl: 3600 })
    await c.env.ADVISORY_QUEUE.send({ type: 'cti_ingest', triggeredBy: c.get('user').userId })

    return c.json({ message: 'CTI ingestion queued successfully', queued: true })
  } catch (err) {
    console.error('cti POST /ingest error:', err)
    return c.json({ detail: 'Failed to queue CTI ingestion' }, 500)
  }
})

export default app
