/**
 * UMEagleEye Workers — CTI routes
 * Returns snake_case field names to match frontend expectations.
 */

import { Hono } from 'hono'
import { eq, and, or, isNull, desc, gte, ilike, ne, inArray, sql, type SQL } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireAction, requirePlatformSuperadmin } from '../middleware/auth'
import { getDb, type DB } from '../db/client'
import { ACTIVE_FEEDS, CTI_INGEST_LOCK, FEED_UNITS, LAST_INGEST_KEY, feedRefresh, type LastIngest } from '../services/cti'
import { maybeHarvestMycert } from '../services/mycert'
import { MYCERT_ORIGIN, MYCERT_SOURCE } from '../lib/mycert'
import { MATCH_KINDS } from './events'
import { indicatorUseSql } from '../services/threatIntel'
import { ctiIndicators, assets, assetAddresses, tiEvents, events, eventCtiIndicators } from '../db/schema'
import {
  ATTACK, buildMatrix, expandTechniques, type MatrixGroup, softwareName, softwareUsing, techniqueName, techniquesFor,
} from '../lib/attack'

const app = new Hono<{ Bindings: Env }>()

const INGEST_HOUR_UTC = 22     // wrangler.toml "0 22 * * *" = 06:00 MYT

/** The next nightly ingestion after `now` (exported for tests). */
export function nextIngestAt(now: Date): Date {
  const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), INGEST_HOUR_UTC))
  if (next.getTime() <= now.getTime()) next.setUTCDate(next.getUTCDate() + 1)
  return next
}

const OPEN = ['open', 'in_progress'] as const
const NO_TENANT = '00000000-0000-0000-0000-000000000000'

// The routes below are the intel every tenant shares: the global feeds (ThreatFox, CISA KEV...) and
// MyCERT's advisories (platform events, services/mycert.ts). Attributes of other threat-intel events are
// served by routes/tiEvents.ts, scoped to who may see them.
const FEED = or(isNull(ctiIndicators.tiEventId), eq(ctiIndicators.source, MYCERT_SOURCE))!

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
    // why a listed value raises no alert: on the safe list (warning), or not for detection (to_ids)
    warning:            row.warning,
    to_ids:             row.toIds,
    malware_family:     row.malwareFamily,
    attack_software:    row.attackSoftware,
    attack_software_name: softwareName(row.attackSoftware),
    technique_count:    techniquesFor(row.attackSoftware, row.attackTechniques).length,
    first_seen:         row.firstSeen,
    last_seen:          row.lastSeen,
  }
}

// What each feed indicator is used for (services/threatIntel.ts indicatorUseSql)
const USE = indicatorUseSql('"cti_indicators"')
/** 'agents' | 'assets' | 'reference:<why>' as {used_for, reference_reason}. */
export function usedFor(use: string): { used_for: 'agents' | 'assets' | 'reference'; reference_reason: string | null } {
  if (use === 'agents' || use === 'assets') return { used_for: use, reference_reason: null }
  return { used_for: 'reference', reference_reason: use.startsWith('reference:') ? use.slice(10) : 'no_data' }
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
app.get('/indicators', authMiddleware, requireAction('cti.view'), async (c) => {
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
    const use      = c.req.query('use')            // agents | assets | reference

    // Every filter but the type and the use: the type chips' counts (by_type) are these split by type, so
    // they add up to the total shown; `reference` is how many reference-only ones "Show all" would add.
    const base = [FEED, ...attackConditions(family, technique)]
    // Only indicators behind an open match alert on the user's own assets.
    if (matched) base.push(inArray(ctiIndicators.indicatorId, matchedIndicatorIds(db, c.get('user'))))
    if (source) base.push(ilike(ctiIndicators.source, `%${source}%`))
    if (search) base.push(ilike(ctiIndicators.value, `%${search}%`))
    const useCond = use === 'agents' || use === 'assets' ? sql`${USE} = ${use}`
      : use === 'in_use' ? sql`${USE} IN ('agents', 'assets')`            // the Indicators tab's default
      : use === 'reference' ? sql`${USE} LIKE 'reference:%'` : undefined
    const withUse = useCond ? [...base, useCond] : base
    const conditions = type ? [...withUse, eq(ctiIndicators.indicatorType, type as 'ip' | 'domain' | 'hash' | 'url' | 'email' | 'cve' | 'software')] : withUse

    const whereClause = and(...conditions)

    const [rows, countRows, typeRows, refRows] = await Promise.all([
      db.select({ row: ctiIndicators, use: sql<string>`${USE}` }).from(ctiIndicators).where(whereClause).orderBy(desc(ctiIndicators.lastSeen)).limit(limit).offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(ctiIndicators).where(whereClause),
      db.select({ type: ctiIndicators.indicatorType, n: sql<number>`count(*)::int` }).from(ctiIndicators).where(and(...withUse)).groupBy(ctiIndicators.indicatorType),
      db.select({ n: sql<number>`count(*)::int` }).from(ctiIndicators).where(and(...base, sql`${USE} LIKE 'reference:%'`)),
    ])

    return c.json({
      total:  countRows[0]?.count ?? 0,
      page,
      limit,
      by_type: Object.fromEntries(typeRows.map((r) => [r.type, r.n])),
      reference: refRows[0]?.n ?? 0,
      items:  rows.map((r) => ({ ...toSnake(r.row), ...usedFor(r.use) })),
    })
  } catch (err) {
    console.error('cti GET /indicators error:', err)
    return c.json({ detail: 'Failed to fetch CTI indicators' }, 500)
  }
})

// ── GET /stats ───────────────────────────────────────────────────
app.get('/stats', authMiddleware, requireAction('cti.view'), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const isSuper = user.role === 'superadmin'
    const ownTenant = user.tenantId ?? NO_TENANT
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)

    const [totalResult, bySource, byType, recent7d, matchRows, eventRows, lastIngest, usageRows, outcomeRows] = await Promise.all([
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
          // R7: an agent saw its computer contact a listed domain or IP (routes/sightings.ts)
          sightings: sql<number>`count(*) FILTER (WHERE ${events.details}->>'match_kind' = 'sighting')::int`,
        })
        .from(events)
        .innerJoin(assets, eq(assets.assetId, events.assetId))
        .where(and(
          eq(events.eventType, 'cti_match'),
          inArray(events.status, [...OPEN]),
          isSuper ? undefined : eq(assets.tenantId, ownTenant),
        )),
      // Threat-intel events this user can see (own drafts and published shared ones), MyCERT's advisories
      // left out (they have their own tab and count): ours, ours published, and shared with us
      db
        .select({
          total:     sql<number>`count(*)::int`,
          published: sql<number>`count(*) FILTER (WHERE ${tiEvents.status} = 'published')::int`,
          ours:      sql<number>`count(*) FILTER (WHERE ${tiEvents.tenantId} = ${ownTenant}::uuid)::int`,
          ours_published: sql<number>`count(*) FILTER (WHERE ${tiEvents.tenantId} = ${ownTenant}::uuid AND ${tiEvents.status} = 'published')::int`,
        })
        .from(tiEvents)
        .where(and(isNull(tiEvents.origin), isSuper ? undefined : or(
          eq(tiEvents.tenantId, ownTenant),
          and(eq(tiEvents.status, 'published'), inArray(tiEvents.distribution, ['all_tenants', 'platform'])),
        ))),
      c.env.KV_CACHE.get<LastIngest>(LAST_INGEST_KEY, 'json').catch(() => null),
      // What the feed indicators are used for: checked by agents, against assets, or reference only (and why)
      db.select({ use: sql<string>`${USE}`, n: sql<number>`count(*)::int` }).from(ctiIndicators).where(FEED).groupBy(sql`1`),
      // How this tenant's threat-intel alerts ended, last 90 days: the measured precision on real data
      db.select({
          kind: sql<string>`COALESCE(${events.details}->>'match_kind', 'ioc')`,
          status: events.status,
          n: sql<number>`count(*)::int`,
        })
        .from(events).innerJoin(assets, eq(assets.assetId, events.assetId))
        .where(and(
          eq(events.eventType, 'cti_match'),
          inArray(events.status, ['resolved', 'false_positive', 'accepted_risk']),
          gte(events.resolvedAt, new Date(Date.now() - 90 * 86_400_000)),
          isSuper ? undefined : eq(assets.tenantId, ownTenant),
        ))
        .groupBy(sql`1`, events.status),
    ])
    const usage = { agents: 0, assets: 0, reference: 0, reference_reasons: {} as Record<string, number> }
    for (const r of usageRows) {
      const u = usedFor(r.use)
      usage[u.used_for] += r.n
      if (u.reference_reason) usage.reference_reasons[u.reference_reason] = (usage.reference_reasons[u.reference_reason] ?? 0) + r.n
    }
    const outcomes: Record<string, { resolved: number; false_positive: number; accepted_risk: number }> = {}
    for (const r of outcomeRows) {
      const o = (outcomes[r.kind] ??= { resolved: 0, false_positive: 0, accepted_risk: 0 })
      o[r.status as 'resolved' | 'false_positive' | 'accepted_risk'] += r.n
    }

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
        sightings: matchRows[0]?.sightings ?? 0,
      },
      ti_events: {
        total: eventRows[0]?.total ?? 0, published: eventRows[0]?.published ?? 0,
        ours: eventRows[0]?.ours ?? 0, ours_published: eventRows[0]?.ours_published ?? 0,
        shared: (eventRows[0]?.total ?? 0) - (eventRows[0]?.ours ?? 0),
      },
      // feed indicators by what they are used for (agents / assets / reference, with the reasons)
      usage,
      // closed threat-intel alerts, last 90 days, by kind (sighting, ioc, malicious_package, watchlist) and outcome
      outcomes_90d: outcomes,
      // Feed health: each feed's count, and when it last loaded (null before the first
      // recorded run). next_ingest_at is the nightly run: null on staging, which has no crons;
      // there can_ingest lets the Platform Superadmin load them (feedRefresh).
      // The feeds the nightly chain loads, in its order (a retired feed's rows are counted above, not here)
      feeds: ACTIVE_FEEDS.map((source) => ({
        source,
        // MyCERT counts advisories, not their indicators: its count is the last run's (advisories stored);
        // the others count every row they have stored, the Indicators tab's total with "Show reference-only
        // too" ticked (and its default total too: a feed's values that can no longer alert are deleted at the
        // end of each nightly update, so its rows are all in use; only MyCERT keeps reference-only values)
        count:      (source === MYCERT_SOURCE ? undefined : bySource.find((r) => r.source === source)?.count) ?? lastIngest?.feeds?.[source]?.count ?? 0,
        // what the count counts: "89 advisories", "1,805 CVEs", "92,331 indicators"
        unit:       FEED_UNITS[source] ?? ['indicator', 'indicators'],
        ok:         lastIngest?.feeds?.[source]?.ok ?? null,
        last_ok_at: lastIngest?.feeds?.[source]?.last_ok_at ?? null,
      })),
      last_ingest_at: lastIngest?.at ?? null,
      next_ingest_at: feedRefresh(c.env.APP_ENV).scheduled ? nextIngestAt(new Date()).toISOString() : null,
      can_ingest: feedRefresh(c.env.APP_ENV).manual && isSuper,
    })
  } catch (err) {
    console.error('cti GET /stats error:', err)
    return c.json({ detail: 'Failed to fetch CTI stats' }, 500)
  }
})

// ── GET /attack ─── the ATT&CK catalogue, for picking techniques on an event ──
app.get('/attack', authMiddleware, requireAction('cti.view'), (c) => {
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
      // the events the Events page lists: MyCERT's advisories are left out (their techniques count on the
      // overview, with the sources), so this view shows what that list shows
      .where(and(isNull(tiEvents.origin), isSuper ? undefined : or(
        eq(tiEvents.tenantId, ownTenant),
        and(eq(tiEvents.status, 'published'), inArray(tiEvents.distribution, ['all_tenants', 'platform'])),
      )))
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

app.get('/matrix', authMiddleware, requireAction('cti.view'), async (c) => {
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
app.get('/lookup', authMiddleware, requireAction('cti.view'), async (c) => {
  try {
    const db    = getDb(c.env.DATABASE_URL)
    const user  = c.get('user')
    const value = c.req.query('value')?.trim()
    if (!value) return c.json({ detail: 'value query param required' }, 422)
    // Feeds store domains, URLs and hashes in lower case; analysts paste them in any case, and
    // often defanged ("evil[.]com", "hxxp://"). Both spellings are looked up, so the index is used.
    const refanged = value.replace(/\[\.\]/g, '.').replace(/^hxxp/i, 'http')
    const spellings = [...new Set([value, refanged, refanged.toLowerCase()])]

    // Find indicator: a feed entry, else an attribute of an event this user may see
    // (own tenant's, or a published shared/platform one; superadmins see all).
    const visibleEvent = user.role === 'superadmin'
      ? sql`true`
      : sql`(${tiEvents.tenantId} = ${user.tenantId ?? null} OR (${tiEvents.status} = 'published' AND ${tiEvents.distribution} IN ('all_tenants', 'platform')))`
    const [hit] = await db
      .select({ indicator: ctiIndicators, eventTitle: tiEvents.title, use: sql<string>`${USE}` })
      .from(ctiIndicators)
      .leftJoin(tiEvents, eq(tiEvents.tiEventId, ctiIndicators.tiEventId))
      .where(and(inArray(ctiIndicators.value, spellings), or(FEED, visibleEvent)))
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
          eq(assetAddresses.ipAddress, refanged),
        ))
        .where(and(
          or(eq(assets.ipAddress, refanged), eq(assetAddresses.ipAddress, refanged)),
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
        sql`lower(${events.details}->>'indicator_value') = lower(${refanged})`,
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
          // what it is used for (an event's attribute: as its feed counterpart would be)
          ...usedFor(hit!.use),
          event_title: hit?.eventTitle ?? null,
          // documented for the family in ATT&CK, or inferred from its kind or role (lib/malwareKind.ts),
          // or for a KEV CVE from MITRE CTID's mappings
          techniques: techniquesFor(indicator.attackSoftware, indicator.attackTechniques).map((id) => ({
            id, name: techniqueName(id),
            how: techniquesFor(indicator.attackSoftware, []).includes(id) ? 'documented'
              : indicator.source === 'CISA KEV' ? 'mapped' : 'inferred',
          })),
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
// Live reachability test of the feeds, with the platform's API keys: the platform superadmin only.
app.get('/debug', authMiddleware, requirePlatformSuperadmin, async (c) => {
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

// ── GET /mycert ─── MyCERT's advisories and what each touches here ──
// The main source (services/mycert.ts): newest first, each with the devices and open alerts it drives in
// the viewer's tenant (superadmins: all), through the alert↔indicator links (event_cti_indicators: a CVE
// on a device, an indicator matched or seen). About 150 advisories a year: read in one query, filtered
// here. ?affecting=1 those touching a device, ?exploited=1 those naming an exploited CVE, ?q= number,
// title or CVE, ?page= and ?page_size= (default 20). summary counts them all (the tiles, the dashboard card,
// the filter chips' counts).
app.get('/mycert', authMiddleware, requireAction('cti.view'), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    // a superadmin may scope it to one tenant (the dashboard's tenant picker, ?tenant_id=)
    const picked = user.role === 'superadmin' ? c.req.query('tenant_id') : undefined
    const here = user.role === 'superadmin'
      ? (picked && /^[0-9a-f-]{36}$/i.test(picked) ? sql`a.tenant_id = ${picked}::uuid` : sql`true`)
      : sql`a.tenant_id = ${user.tenantId ?? NO_TENANT}::uuid`
    const res = await db.execute(sql`
      SELECT te.ti_event_id AS event_id, te.external_id, te.title, te.description, te.threat_level, te.published_at,
             COALESCE(te.exploited_cves, '{}') AS exploited_cves, te.source_meta, te.tags,
             (SELECT count(*)::int FROM cti_indicators c WHERE c.ti_event_id = te.ti_event_id AND c.indicator_type = 'cve') AS cve_count,
             (SELECT count(*)::int FROM cti_indicators c WHERE c.ti_event_id = te.ti_event_id AND c.indicator_type <> 'cve') AS ioc_count,
             (SELECT array_agg(c.value) FROM cti_indicators c WHERE c.ti_event_id = te.ti_event_id AND c.indicator_type = 'cve') AS cves,
             hit.devices, hit.alerts
      FROM ti_events te
      CROSS JOIN LATERAL (
        SELECT count(DISTINCT e.asset_id)::int AS devices, count(DISTINCT e.event_id)::int AS alerts
        FROM cti_indicators c
        JOIN event_cti_indicators l ON l.indicator_id = c.indicator_id
        JOIN events e ON e.event_id = l.event_id AND e.status IN ('open', 'in_progress')
        JOIN assets a ON a.asset_id = e.asset_id
        WHERE c.ti_event_id = te.ti_event_id AND ${here}
      ) hit
      WHERE te.origin = ${MYCERT_ORIGIN} AND te.status = 'published'
      ORDER BY te.published_at DESC NULLS LAST, te.external_id DESC
    `)
    type Row = {
      event_id: string; external_id: string; title: string; description: string | null; threat_level: string
      published_at: string | null; exploited_cves: string[]; source_meta: Record<string, unknown> | null; tags: string[]
      cve_count: number; ioc_count: number; cves: string[] | null; devices: number; alerts: number
    }
    const all = (res.rows as Row[]).map((r) => {
      const meta = r.source_meta ?? {}
      return {
        event_id: r.event_id,
        id: r.external_id,
        title: r.title,
        // the title without "MyCERT MA-1506: "
        headline: r.title.replace(/^MyCERT MA-\d+:\s*/, ''),
        summary: (r.description ?? '').split('\n\nSource:')[0]!.slice(0, 600),
        published_at: r.published_at,
        threat_level: r.threat_level,
        kind: meta['kind'] ?? null,
        rating: meta['rating'] ?? null,
        url: meta['url'] ?? null,
        products: Array.isArray(meta['products']) ? meta['products'] : [],
        cve_count: r.cve_count,
        exploited_cves: r.exploited_cves,
        ioc_count: r.ioc_count,
        devices: r.devices,
        alerts: r.alerts,
        _cves: r.cves ?? [],
      }
    })
    const monthAgo = Date.now() - 30 * 86_400_000
    const summary = {
      total: all.length,
      last_30d: all.filter((a) => a.published_at && new Date(a.published_at).getTime() >= monthAgo).length,
      affecting: all.filter((a) => a.devices > 0).length,
      exploited: all.filter((a) => a.exploited_cves.length > 0).length,
      exploited_affecting: all.filter((a) => a.devices > 0 && a.exploited_cves.length > 0).length,
      newest_at: all[0]?.published_at ?? null,
    }
    const q = c.req.query('q')?.trim().toLowerCase()
    const items = all.filter((a) =>
      (c.req.query('affecting') !== '1' || a.devices > 0)
      && (c.req.query('exploited') !== '1' || a.exploited_cves.length > 0)
      && (!q || a.id.toLowerCase().includes(q) || a.title.toLowerCase().includes(q) || a._cves.some((v) => v.toLowerCase() === q)))
    // one page (?page=, ?page_size= or ?limit=, default 20), and how many match the filters
    const pageSize = Math.min(200, Math.max(1, parseInt(c.req.query('page_size') ?? c.req.query('limit') ?? '20') || 20))
    const page = Math.max(1, parseInt(c.req.query('page') ?? '1') || 1)
    const shown = items.slice((page - 1) * pageSize, page * pageSize)
    return c.json({ summary, total: items.length, page, page_size: pageSize, items: shown.map(({ _cves, ...a }) => a) })
  } catch (err) {
    console.error('cti GET /mycert error:', err)
    return c.json({ detail: 'Failed to fetch MyCERT advisories' }, 500)
  }
})

// ── GET /matches/summary ─── the Matches page's counts ──
// Open threat-intel matches (cti_match alerts) in the viewer's tenant (superadmins: all, or ?tenant_id=):
// the severity chips' counts (with the kind filter applied), the kind chips' counts (with the severity
// filter applied), and how many matches and devices the current filters keep ("6 matches on 3 devices").
// The list itself is GET /events?event_type=cti_match&status=open&severity=&match_kind=&q=&page=.
app.get('/matches/summary', authMiddleware, requireAction('cti.view'), requireAction('alert.view'), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const picked = user.role === 'superadmin' ? c.req.query('tenant_id') : undefined
    const tenantCond = user.role === 'superadmin'
      ? (picked && /^[0-9a-f-]{36}$/i.test(picked) ? sql`a.tenant_id = ${picked}::uuid` : sql`true`)
      : sql`a.tenant_id = ${user.tenantId ?? NO_TENANT}::uuid`
    const list = (raw: string | undefined, allowed: readonly string[]) => (raw ?? '').split(',').map((s) => s.trim()).filter((s) => allowed.includes(s))
    const sev = list(c.req.query('severity'), ['critical', 'high', 'medium', 'low', 'info'])
    const kinds = list(c.req.query('match_kind'), MATCH_KINDS)
    const q = c.req.query('q')?.trim()
    const kind = sql`COALESCE(e.details->>'match_kind', 'ioc')`
    // on the columns of m below
    const sevCond = sev.length ? sql`severity IN (${sql.join(sev.map((s) => sql`${s}`), sql`, `)})` : sql`true`
    const kindCond = kinds.length ? sql`kind IN (${sql.join(kinds.map((k) => sql`${k}`), sql`, `)})` : sql`true`
    const res = await db.execute(sql`
      WITH m AS (
        SELECT e.event_id, e.asset_id, e.severity::text AS severity, ${kind} AS kind
        FROM events e JOIN assets a ON a.asset_id = e.asset_id
        WHERE e.event_type = 'cti_match' AND e.status IN ('open', 'in_progress') AND ${tenantCond}
          ${q ? sql`AND (a.hostname ILIKE ${'%' + q + '%'} OR a.ip_address ILIKE ${'%' + q + '%'} OR e.details->>'indicator_value' ILIKE ${'%' + q + '%'})` : sql``}
      )
      SELECT
        (SELECT COALESCE(jsonb_object_agg(severity, n), '{}'::jsonb) FROM (SELECT severity, count(*)::int AS n FROM m WHERE ${kindCond} GROUP BY 1) x) AS by_severity,
        (SELECT COALESCE(jsonb_object_agg(kind, n), '{}'::jsonb) FROM (SELECT kind, count(*)::int AS n FROM m WHERE ${sevCond} GROUP BY 1) x) AS by_kind,
        (SELECT count(*)::int FROM m WHERE ${sevCond} AND ${kindCond}) AS matches,
        (SELECT count(DISTINCT asset_id)::int FROM m WHERE ${sevCond} AND ${kindCond}) AS devices
    `)
    const r = (res.rows[0] ?? {}) as { by_severity?: Record<string, number>; by_kind?: Record<string, number>; matches?: number; devices?: number }
    return c.json({ by_severity: r.by_severity ?? {}, by_kind: r.by_kind ?? {}, matches: r.matches ?? 0, devices: r.devices ?? 0 })
  } catch (err) {
    console.error('cti GET /matches/summary error:', err)
    return c.json({ detail: 'Failed to count matches' }, 500)
  }
})

// ── POST /ingest ─── staging only: load the shared feeds now (feedRefresh) ──
app.post('/ingest', authMiddleware, requirePlatformSuperadmin, async (c) => {
  if (!feedRefresh(c.env.APP_ENV).manual) return c.json({ detail: 'Feeds load on schedule here.' }, 404)
  try {
    if (await c.env.KV_CACHE.get(CTI_INGEST_LOCK)) {
      return c.json({ message: 'A feed update is already running or ran in the last hour', queued: false })
    }
    // This request comes from the superadmin: from Malaysia, it can fetch MyCERT now (services/mycert.ts).
    const country = (c.req.raw as unknown as { cf?: { country?: string } }).cf?.country
    await maybeHarvestMycert(c.env.KV_CACHE, country, { force: true })
    // The same lock and queue job as the nightly cron (cron/triggers.ts); the consumer clears the lock.
    await c.env.KV_CACHE.put(CTI_INGEST_LOCK, '1', { expirationTtl: 3600 })
    await c.env.ADVISORY_QUEUE.send({ type: 'cti_ingest', triggeredBy: c.get('user').userId })
    return c.json({ message: 'Feed update queued', queued: true })
  } catch (err) {
    console.error('cti POST /ingest error:', err)
    return c.json({ detail: 'Failed to queue the feed update' }, 500)
  }
})

export default app
