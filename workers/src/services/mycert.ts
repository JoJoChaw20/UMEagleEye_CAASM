/**
 * MyCERT advisories as platform threat-intel events: UMEagleEye's main threat-intel source, for
 * organisations in Malaysia (27 Nov 2026).
 *
 * Nightly, first in the feed chain (services/cti.ts): read MyCERT's RSS feed (its newest 20, no
 * credentials), fetch each advisory not stored yet, parse it (lib/mycert.ts) and save it as one
 * published platform event (ti_events.origin 'mycert', external_id its number) with its CVEs and
 * indicators as attributes (source 'MyCERT'). From there the event machinery does the rest:
 *   - CVE attributes flag the CVE alerts of every tenant (services/threatIntel.ts); a CVE MyCERT says
 *     is exploited (exploited_cves) ranks like a CISA KEV one;
 *   - indicators reach the agents' sightings list and are matched against assets (iocMatch.ts); an
 *     IP, domain or URL stops matching once the advisory is older than the feed windows
 *     (FEED_FRESH_DAYS, counted from the advisory's date), CVEs and hashes do not expire;
 *   - nobody here edits or deletes such an event (no tenant: routes/tiEvents.ts canEdit).
 * MyCERT answers a Worker only while it handles a request from Malaysia or Singapore (lib/mycert.ts,
 * Harvest), never in the nightly queue job: so the pages are fetched during such a request
 * (maybeHarvestMycert, from index.ts) and the nightly step reads them from KV (mycertSourceOf).
 * Older advisories come from MyCERT's archive: scripts/mycert-backfill.ts (run on a PC in Malaysia).
 */
import { sql } from 'drizzle-orm'
import type { DB } from '../db/client'
import type { KVNamespace } from '@cloudflare/workers-types'
import {
  MYCERT_ORIGIN, MYCERT_RSS_URL, MYCERT_SOURCE, HARVEST_STALE_MS, harvestProblem, harvestUrls, mycertAdvisoryUrl, mycertRecords,
  parseMycertAdvisory, parseMycertRss, shouldHarvest, trimAdvisoryPage, type MycertAdvisory,
} from '../lib/mycert'

const HEADERS = { 'User-Agent': 'UMEagleEye-CTI/1.0 (+https://umeagleeye.csnet.my)', Accept: 'text/html,application/rss+xml,application/xml' }

// New advisories saved per nightly run. Each costs two requests (the page, the insert) of the 50 a
// queue job may make; MyCERT publishes about one a day, so the rest wait for the next night.
export const MYCERT_PER_RUN = 15

/** Fetch a MyCERT page from wherever this code runs. From a Worker it works only while it handles a
 *  request from Malaysia or Singapore (lib/mycert.ts, Harvest); scripts on a PC in Malaysia always. */
export async function fetchMycertDirect(url: string): Promise<string> {
  const res = await fetch(url, { headers: HEADERS })
  if (!res.ok) {
    // what refused it: Cloudflare's challenge ("Just a moment...", cf-mitigated: challenge), and its ray id
    const body = (await res.text().catch(() => '')).replace(/\s+/g, ' ')
    const page = /<title>([^<]{0,80})/i.exec(body)?.[1] ?? body.slice(0, 80)
    throw new Error(`MyCERT answered HTTP ${res.status} for ${url} (cf-mitigated=${res.headers.get('cf-mitigated') ?? '-'}, ray ${res.headers.get('cf-ray') ?? '-'}, page "${page}")`)
  }
  return res.text()
}

// ── Harvest (lib/mycert.ts explains why) ─────────────────────────────
// KV: when the last harvest ran, a short lock while one runs, the fetched pages by URL (RSS included),
// and the feed's advisories already stored (written by the nightly step, so a harvest fetches only new ones).
const HARVEST_AT_KEY = 'mycert:harvest_at'
const HARVEST_LOCK_KEY = 'mycert:harvest_lock'
const KNOWN_KEY = 'mycert:known'
const pageKey = (url: string) => `mycert:page:${url}`
// Agents check in every 30 seconds: each Worker instance asks KV whether a harvest is due at most this often.
const LOOK_EVERY_MS = 10 * 60_000
let lookedAt = 0

/**
 * Called for every request (index.ts, after the answer, in waitUntil): when it comes from Malaysia or
 * Singapore and the last harvest is HARVEST_EVERY_MS old, fetch the RSS feed and the pages of advisories
 * not stored yet, and keep them in KV for HARVEST_STALE_MS. `force` (Update feeds now) skips the wait.
 * Never throws: a failed harvest is logged, and the nightly step reports MyCERT as failing.
 */
export async function maybeHarvestMycert(kv: KVNamespace, country: string | null | undefined,
  opts: { force?: boolean; now?: number; fetchText?: (url: string) => Promise<string> } = {}): Promise<boolean> {
  const now = opts.now ?? Date.now()
  if (!shouldHarvest(country, null, now, true)) return false            // not from MY or SG
  if (!opts.force && now - lookedAt < LOOK_EVERY_MS) return false
  lookedAt = now
  try {
    const last = Number(await kv.get(HARVEST_AT_KEY)) || null
    if (!shouldHarvest(country, last, now, opts.force)) return false
    if (!opts.force && await kv.get(HARVEST_LOCK_KEY)) return false     // another request is harvesting
    await kv.put(HARVEST_LOCK_KEY, '1', { expirationTtl: 300 })
    const get = opts.fetchText ?? fetchMycertDirect
    const ttl = { expirationTtl: Math.round(HARVEST_STALE_MS / 1000) }

    const rss = await get(MYCERT_RSS_URL)
    const items = parseMycertRss(rss)
    if (!items.length) throw new Error('the RSS feed held no advisories')
    const known = new Set(await kv.get<string[]>(KNOWN_KEY, 'json').catch(() => null) ?? [])
    let pages = 0
    for (const url of harvestUrls(items, known)) {
      await kv.put(pageKey(url), trimAdvisoryPage(await get(url)), ttl)
      pages++
    }
    await kv.put(pageKey(MYCERT_RSS_URL), rss, ttl)
    await kv.put(HARVEST_AT_KEY, String(now))
    console.log(`[MyCERT] harvested during a request from ${country}: the feed and ${pages} new page(s)`)
    return true
  } catch (err) {
    console.error(`[MyCERT] harvest during a request from ${country} failed:`, err instanceof Error ? err.message : String(err))
    return false
  } finally {
    await kv.delete(HARVEST_LOCK_KEY).catch(() => {})
  }
}

/**
 * How the nightly step reads MyCERT: the harvested page while it is fresh, else directly (which works only
 * during a request from Malaysia, so in a queue job it fails, saying when MyCERT was last harvested).
 */
export function mycertSourceOf(kv: KVNamespace, now = Date.now()): (url: string) => Promise<string> {
  return async (url) => {
    const last = Number(await kv.get(HARVEST_AT_KEY)) || null
    if (last !== null && now - last < HARVEST_STALE_MS) {
      const cached = await kv.get(pageKey(url))
      if (cached) return cached
    }
    try {
      return await fetchMycertDirect(url)
    } catch (err) {
      throw new Error(harvestProblem(last, now, err instanceof Error ? err.message : String(err)))
    }
  }
}

/** After the nightly step: the feed's advisories now stored, so the next harvest skips their pages. */
export async function rememberKnownMycert(kv: KVNamespace, ids: string[]): Promise<void> {
  await kv.put(KNOWN_KEY, JSON.stringify(ids))
}

/** Save one advisory (insert, or update when it is stored already) in one statement. Returns its event id. */
export async function saveMycertAdvisory(db: DB, a: MycertAdvisory, listedAt: Date | null): Promise<string | null> {
  const { event: e, attributes } = mycertRecords(a, listedAt)
  // arrays go as JSON (a URL may hold commas, quotes or braces a text[] literal would need escaped)
  const textArray = (v: string[]) => sql`ARRAY(SELECT jsonb_array_elements_text(${JSON.stringify(v)}::jsonb))`
  const techniques = e.attackTechniques ? textArray(e.attackTechniques) : sql`NULL::text[]`
  const res = await db.execute(sql`
    WITH ev AS (
      INSERT INTO ti_events (tenant_id, title, description, threat_level, status, distribution, tags,
                             attack_techniques, published_at, origin, external_id, exploited_cves, source_meta)
      VALUES (NULL, ${e.title}, ${e.description}, ${e.threatLevel}::ti_threat_level, 'published', 'platform',
              ${JSON.stringify(e.tags)}::jsonb, ${techniques}, ${e.publishedAt.toISOString()}::timestamptz,
              ${MYCERT_ORIGIN}, ${e.externalId}, ${textArray(e.exploitedCves)}, ${JSON.stringify(e.sourceMeta)}::jsonb)
      ON CONFLICT (origin, external_id) WHERE origin IS NOT NULL DO UPDATE SET
        title = excluded.title, description = excluded.description, threat_level = excluded.threat_level,
        tags = excluded.tags, attack_techniques = excluded.attack_techniques, published_at = excluded.published_at,
        exploited_cves = excluded.exploited_cves, source_meta = excluded.source_meta, updated_at = now()
      RETURNING ti_event_id
    ), gone AS (
      -- an advisory MyCERT changed: values it no longer lists leave the event
      DELETE FROM cti_indicators c USING ev
      WHERE c.ti_event_id = ev.ti_event_id AND NOT (c.value = ANY(${textArray(attributes.map((r) => r.value))}))
    ), attrs AS (
      INSERT INTO cti_indicators AS c (source, indicator_type, value, tenant_id, ti_event_id, to_ids, comment, warning,
                                       attack_techniques, first_seen, last_seen)
      SELECT ${MYCERT_SOURCE}, r.indicator_type::indicator_type, r.value, NULL, ev.ti_event_id, r.to_ids, r.comment, r.warning,
             ${techniques}, ${e.publishedAt.toISOString()}::timestamptz, ${e.publishedAt.toISOString()}::timestamptz
      FROM ev, jsonb_to_recordset(${JSON.stringify(attributes)}::jsonb)
        AS r(indicator_type text, value varchar, to_ids boolean, comment text, warning varchar)
      ON CONFLICT (ti_event_id, value) WHERE ti_event_id IS NOT NULL DO UPDATE SET
        indicator_type = excluded.indicator_type, to_ids = excluded.to_ids, comment = excluded.comment,
        warning = excluded.warning, attack_techniques = excluded.attack_techniques
    )
    SELECT ti_event_id::text AS id FROM ev
  `)
  return (res.rows[0] as { id?: string } | undefined)?.id ?? null
}

export interface MycertRun { listed: number; added: number; failed: number; stored: number; knownIds: string[] }

/**
 * The nightly load: the feed's advisories not stored yet, oldest first, at most MYCERT_PER_RUN.
 * Throws when the feed cannot be read or holds no advisory (feed health shows MyCERT failing), or
 * when every new advisory failed; one bad page is logged and tried again the next night.
 */
export async function ingestMycert(db: DB, opts: { max?: number; fetchText?: (url: string) => Promise<string> } = {}): Promise<MycertRun> {
  const get = opts.fetchText ?? fetchMycertDirect
  const items = parseMycertRss(await get(MYCERT_RSS_URL))
  if (!items.length) throw new Error('MyCERT RSS feed held no advisories (has its format changed?)')

  const ids = items.map((i) => i.id)
  const known = await db.execute(sql`
    SELECT external_id FROM ti_events WHERE origin = ${MYCERT_ORIGIN}
      AND external_id IN (${sql.join(ids.map((id) => sql`${id}`), sql`, `)})`)
  const have = new Set((known.rows as { external_id: string }[]).map((r) => r.external_id))
  const todo = items.filter((i) => !have.has(i.id)).reverse().slice(0, opts.max ?? MYCERT_PER_RUN)

  let added = 0
  let failed = 0
  for (const item of todo) {
    try {
      const adv = parseMycertAdvisory(await get(item.link || mycertAdvisoryUrl(item.id)))
      if (!adv || adv.id !== item.id) throw new Error(`the page holds ${adv ? adv.id : 'no advisory'}`)
      await saveMycertAdvisory(db, adv, item.publishedAt)
      have.add(item.id)
      added++
      console.log(`[MyCERT] ${adv.id}: ${adv.cves.length} CVE(s) (${adv.exploitedCves.length} exploited), ${adv.iocs.length} indicator(s)`)
    } catch (err) {
      failed++
      console.error(`[MyCERT] ${item.id} failed:`, err instanceof Error ? err.message : String(err))
    }
  }
  if (todo.length && !added) throw new Error(`MyCERT: none of ${todo.length} new advisories could be loaded`)

  const [{ n } = { n: 0 }] = (await db.execute(sql`SELECT count(*)::int AS n FROM ti_events WHERE origin = ${MYCERT_ORIGIN}`)).rows as { n: number }[]
  return { listed: items.length, added, failed, stored: n, knownIds: ids.filter((id) => have.has(id)) }
}
