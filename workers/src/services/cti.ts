import type { KVNamespace } from '@cloudflare/workers-types'
import type { DB } from '../db/client'
import { ctiIndicators } from '../db/schema'
import { sql } from 'drizzle-orm'
import { KEV_SOURCE, refreshCveIntel } from './threatIntel'
import { matchIocs } from './iocMatch'
import { warninglistOf } from '../lib/warninglist'
import { resolveSoftware, techniqueIds } from '../lib/attack'

// Rows per INSERT statement. Every statement is one HTTP request to Neon, and a Worker
// on the free plan may make only 50 per run (cron or queue job): with 100 rows per
// statement a 7-day ThreatFox pull (about 17k rows) ran out after 43 and OTX, the CVE
// alert refresh and the asset matching all failed. 9 parameters per row: 4,000 rows is
// 36k, under Postgres' 65,535 limit, so a nightly run needs about a dozen requests.
export const BATCH_SIZE = 4000

type CtiRow = typeof ctiIndicators.$inferInsert

// Feed entries (not event attributes). Must match idx_cti_feed_value's WHERE.
const FEED_ROW = sql`ti_event_id IS NULL`

interface OtxPulse {
  indicators: Array<{ type: string; indicator: string }>
  attack_ids?: Array<string | { id?: string; name?: string; display_name?: string }>
  malware_families?: Array<string | { id?: string; display_name?: string }>
}

interface ThreatFoxIoc {
  ioc: string
  ioc_type: string
  confidence_level: number
  malware?: string             // Malpedia key, e.g. "win.cobalt_strike"
  malware_printable?: string   // e.g. "Cobalt Strike"
  malware_alias?: string | null  // comma-separated
  threat_type?: string
  tags?: string[] | null
}

// ATT&CK: no tactic is inferred from an indicator's type or tags. An indicator has
// techniques only when its malware family is ATT&CK software (MITRE documents what the
// family does) or the feed names techniques itself; see lib/attack.ts.
const FAMILY_MAX = 120
const familyName = (n: string | null | undefined) => {
  const v = n?.trim()
  return v && !/^unknown/i.test(v) ? v.slice(0, FAMILY_MAX) : null
}

function mapOtxType(t: string): 'ip' | 'domain' | 'hash' | 'url' | 'email' | null {
  const m: Record<string, 'ip' | 'domain' | 'hash' | 'url' | 'email'> = {
    'IPv4': 'ip', 'IPv6': 'ip', 'domain': 'domain', 'hostname': 'domain',
    'URL': 'url', 'FileHash-MD5': 'hash', 'FileHash-SHA256': 'hash',
    'FileHash-SHA1': 'hash', 'email': 'email',
  }
  return m[t] ?? null
}

function mapThreatFoxType(t: string): 'ip' | 'domain' | 'hash' | 'url' | null {
  if (t === 'ip:port' || t === 'ip') return 'ip'
  if (t.includes('domain')) return 'domain'
  if (t.includes('hash') || t.includes('md5') || t.includes('sha')) return 'hash'
  if (t.includes('url')) return 'url'
  return null
}

/** cti_indicators.value is varchar(512); a longer value fails its whole statement. */
export const MAX_VALUE_LENGTH = 512

/**
 * PURE: the INSERT statements for a feed's rows. One row per value (the last one wins):
 * ON CONFLICT DO UPDATE fails when one statement holds the same value twice, which OTX
 * pulses sharing an indicator would cause. Values longer than the column are left out
 * (ThreatFox lists URLs of 500+ characters; cut short they would be a different value).
 * Exported for tests.
 */
export function planUpsertChunks<T extends { value: string }>(rows: T[], size = BATCH_SIZE): T[][] {
  const byValue = new Map<string, T>()
  for (const r of rows) if (r.value.length <= MAX_VALUE_LENGTH) byValue.set(r.value, r)
  const unique = [...byValue.values()]
  const chunks: T[][] = []
  for (let i = 0; i < unique.length; i += size) chunks.push(unique.slice(i, i + size))
  return chunks
}

/** PURE: a feed row as the JSON record batchUpsert sends (exported for tests). */
export function feedRecord(r: CtiRow) {
  return {
    source: r.source, indicator_type: r.indicatorType, value: r.value, warning: r.warning ?? null,
    confidence_score: r.confidenceScore ?? null, malware_family: r.malwareFamily ?? null,
    attack_software: r.attackSoftware ?? null, attack_techniques: r.attackTechniques ?? null,
    last_seen: r.lastSeen instanceof Date ? r.lastSeen.toISOString() : r.lastSeen ?? new Date().toISOString(),
  }
}

/**
 * Upsert rows in chunks — each chunk is one INSERT … ON CONFLICT statement whose rows go
 * as ONE JSON parameter that Postgres unpacks (jsonb_to_recordset). Building the same
 * statement with drizzle's query builder cost about 0.6 s of CPU for ThreatFox's 17k
 * rows, which with the rest of the run went over the free plan's CPU limit.
 */
export async function batchUpsert(db: DB, rows: CtiRow[]): Promise<void> {
  const tooLong = rows.filter((r) => r.value.length > MAX_VALUE_LENGTH).length
  if (tooLong) console.log(`[CTI] Skipped ${tooLong} indicator(s) longer than ${MAX_VALUE_LENGTH} characters`)
  for (const chunk of planUpsertChunks(rows)) {
    await db.execute(sql`
      INSERT INTO cti_indicators AS c (source, indicator_type, value, warning, confidence_score,
                                       malware_family, attack_software, attack_techniques, last_seen)
      SELECT r.source, r.indicator_type::indicator_type, r.value, r.warning, r.confidence_score,
             r.malware_family, r.attack_software, r.attack_techniques, r.last_seen
      FROM jsonb_to_recordset(${JSON.stringify(chunk.map(feedRecord))}::jsonb) AS r(
        source varchar, indicator_type text, value varchar, warning varchar, confidence_score numeric,
        malware_family varchar, attack_software varchar, attack_techniques text[], last_seen timestamptz)
      ON CONFLICT (value) WHERE ti_event_id IS NULL     -- the feed rows' partial unique index (idx_cti_feed_value)
      DO UPDATE SET
        last_seen         = excluded.last_seen,
        -- a feed that names no family does not erase one another feed gave
        malware_family    = coalesce(excluded.malware_family, c.malware_family),
        attack_software   = CASE WHEN excluded.malware_family IS NULL THEN c.attack_software ELSE excluded.attack_software END,
        attack_techniques = coalesce(excluded.attack_techniques, c.attack_techniques),
        confidence_score  = excluded.confidence_score,
        warning           = excluded.warning`)
  }
}

// ── OTX ──────────────────────────────────────────────────────────────
export async function ingestOtx(db: DB, apiKey: string): Promise<number> {
  if (!apiKey) {
    console.log('[OTX] No API key — skipping')
    return 0
  }

  // /pulses/activity returns recent community pulses, not just subscriptions
  const res = await fetch(
    'https://otx.alienvault.com/api/v1/pulses/activity?limit=50&page=1',
    { headers: { 'X-OTX-API-KEY': apiKey } },
  )
  if (!res.ok) {
    console.error('[OTX] HTTP error:', res.status, await res.text().catch(() => ''))
    return 0
  }

  const data = await res.json() as { results?: OtxPulse[]; count?: number }
  console.log(`[OTX] ${data.results?.length ?? 0} pulses (total=${data.count ?? '?'})`)

  const rows: CtiRow[] = []
  const now = new Date()

  for (const pulse of data.results ?? []) {
    // Techniques the pulse's author tagged, and its malware families (strings or objects)
    const named = techniqueIds((pulse.attack_ids ?? []).flatMap((x) =>
      typeof x === 'string' ? [x] : [x.id, x.name, x.display_name]))
    const families = (pulse.malware_families ?? [])
      .map((f) => familyName(typeof f === 'string' ? f : f.display_name ?? f.id))
      .filter((f): f is string => !!f)
    // prefer a family ATT&CK documents
    const software = resolveSoftware(families)
    const family = (software && families.find((f) => resolveSoftware([f]) === software)) ?? families[0] ?? null

    for (const ind of pulse.indicators ?? []) {
      const itype = mapOtxType(ind.type)
      if (!itype || !ind.indicator) continue

      rows.push({
        source:          'AlienVault OTX',
        indicatorType:   itype,
        value:           ind.indicator,
        warning:         warninglistOf(itype, ind.indicator),
        confidenceScore: '0.70',
        malwareFamily:    family,
        attackSoftware:   software,
        attackTechniques: named.length ? named : null,
        lastSeen:        now,
      })
    }
  }

  if (!rows.length) { console.log('[OTX] No usable indicators'); return 0 }

  console.log(`[OTX] Upserting ${rows.length} rows in batches of ${BATCH_SIZE}`)
  await batchUpsert(db, rows)
  return rows.length
}

// ── ThreatFox ────────────────────────────────────────────────────────
export async function ingestThreatFox(db: DB, apiKey: string): Promise<number> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (apiKey) headers['Auth-Key'] = apiKey

  const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers,
    body: JSON.stringify({ query: 'get_iocs', days: 7 }),
  })

  if (!res.ok) {
    console.error('[ThreatFox] HTTP error:', res.status, await res.text().catch(() => ''))
    return 0
  }

  const data = await res.json() as { query_status?: string; data?: ThreatFoxIoc[] }
  console.log(`[ThreatFox] query_status=${data.query_status} records=${data.data?.length ?? 0}`)

  if (!data.data?.length) return 0

  const now  = new Date()
  const seen = new Set<string>()
  const rows: CtiRow[] = []

  for (const ioc of data.data) {
    const itype = mapThreatFoxType(ioc.ioc_type)
    if (!itype || !ioc.ioc) continue

    // ip:port → strip port so it can cross-ref internal asset IPs
    const value = itype === 'ip' && ioc.ioc.includes(':')
      ? (ioc.ioc.split(':')[0] ?? ioc.ioc)
      : ioc.ioc

    if (seen.has(value)) continue
    seen.add(value)

    rows.push({
      source:          'ThreatFox',
      indicatorType:   itype,
      value,
      warning:         warninglistOf(itype, value),
      confidenceScore: ((ioc.confidence_level ?? 50) / 100).toFixed(2),
      malwareFamily:   familyName(ioc.malware_printable),
      attackSoftware:  familyName(ioc.malware_printable) ? resolveSoftware([
        ioc.malware_printable,
        ...(ioc.malware_alias ?? '').split(','),
        ioc.malware?.split('.').slice(1).join('.'),    // Malpedia key without the platform
      ]) : null,
      lastSeen:        now,
    })
  }

  console.log(`[ThreatFox] Upserting ${rows.length} unique rows in batches of ${BATCH_SIZE}`)
  await batchUpsert(db, rows)
  return rows.length
}

// ── CISA Known Exploited Vulnerabilities ─────────────────────────────
// CVEs with confirmed exploitation in the wild (free JSON, no key, about 1.7k
// entries). Stored as 'cve' indicators, so /sboms/ingest-cve flags matching CVE
// alerts, and refreshCveIntel() updates the open alerts that already exist.
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
const KEV_BATCH = 500   // 7 params per row; well under Postgres' 65k parameter limit

interface KevEntry { cveID?: string; dateAdded?: string }

export async function ingestKev(db: DB): Promise<number> {
  const res = await fetch(KEV_URL, { headers: { 'User-Agent': 'UMEagleEye-CTI/1.0' } })
  if (!res.ok) {
    console.error('[KEV] HTTP error:', res.status)
    return 0
  }
  const data = await res.json() as { catalogVersion?: string; vulnerabilities?: KevEntry[] }
  const now = new Date()
  const seen = new Set<string>()
  const rows: CtiRow[] = []
  for (const v of data.vulnerabilities ?? []) {
    const id = v.cveID?.trim().toUpperCase()
    if (!id || !/^CVE-\d{4}-\d{4,}$/.test(id) || seen.has(id)) continue
    seen.add(id)
    const added = v.dateAdded ? new Date(v.dateAdded) : now
    rows.push({
      source: KEV_SOURCE,
      indicatorType: 'cve',
      value: id,
      confidenceScore: '1.00',
      firstSeen: Number.isNaN(added.getTime()) ? now : added,
      lastSeen: now,
    })
  }
  console.log(`[KEV] catalog ${data.catalogVersion ?? '?'}: ${rows.length} CVEs`)
  for (let i = 0; i < rows.length; i += KEV_BATCH) {
    await db.insert(ctiIndicators).values(rows.slice(i, i + KEV_BATCH)).onConflictDoUpdate({
      target: ctiIndicators.value,
      targetWhere: FEED_ROW,
      set: { lastSeen: sql`excluded.last_seen` },
    })
  }
  return rows.length
}

// ── Combined ─────────────────────────────────────────────────────────
/**
 * The text of a database error for the log. Workers Logs show a Neon error only as its
 * stack, which leaves out the message, so failures read as blank.
 */
export function describeError(err: unknown): string {
  if (!(err instanceof Error)) return String(err)
  const e = err as Error & { code?: string; detail?: string; hint?: string }
  return [e.message || e.name, e.code && `code ${e.code}`, e.detail, e.hint].filter(Boolean).join(' | ')
}

// ── Ingestion, one feed per queue job ────────────────────────────────
// A Worker on the free plan has a small CPU and request allowance per run: all three
// feeds in one run went over the CPU limit (2 s, killed and retried) once ThreatFox's
// 17k rows were saved. So each feed is its own queue job, which queues the next one;
// 'finish' refreshes the CVE alerts and the asset matches against the new data.
export type CtiStep = 'kev' | 'threatfox' | 'otx' | 'finish'
export const CTI_STEPS: CtiStep[] = ['kev', 'threatfox', 'otx', 'finish']
export const CTI_INGEST_LOCK = 'cti_ingest_lock'

/** The step after this one; null after 'finish' (exported for tests). */
export function nextCtiStep(step: CtiStep): CtiStep | null {
  return CTI_STEPS[CTI_STEPS.indexOf(step) + 1] ?? null
}

const FEED_OF: Record<Exclude<CtiStep, 'finish'>, { source: string; run: (db: DB, keys: FeedKeys) => Promise<number> }> = {
  kev:       { source: KEV_SOURCE,       run: (db) => ingestKev(db) },
  threatfox: { source: 'ThreatFox',      run: (db, k) => ingestThreatFox(db, k.threatFox) },
  otx:       { source: 'AlienVault OTX', run: (db, k) => ingestOtx(db, k.otx) },
}

export interface FeedKeys { otx: string; threatFox: string }

/**
 * Run one step and record it for the feed-health line. A feed that fails is recorded as
 * failed and the chain goes on. Returns the next step, or null when the run is done.
 */
export async function runIngestStep(db: DB, kv: KVNamespace, keys: FeedKeys, step: CtiStep): Promise<CtiStep | null> {
  if (step === 'finish') {
    // CVE alerts follow the refreshed feeds (KEV additions, entries that aged out).
    try {
      const flagged = await refreshCveIntel(db, { all: true })
      console.log(`[KEV] ${flagged} CVE alert(s) newly flagged`)
    } catch (err) {
      console.error('[KEV] Refreshing CVE alerts failed:', describeError(err))
    }
    // Assets against the refreshed feeds (R5/R6, services/iocMatch.ts).
    try {
      const m = await matchIocs(db, { all: true })
      console.log(`[CTI] Matches: ${m.created} new, ${m.reopened} reopened, ${m.resolved} resolved`)
    } catch (err) {
      console.error('[CTI] Matching assets failed:', describeError(err))
    }
    return null
  }
  const feed = FEED_OF[step]
  let result: { ok: boolean; count: number }
  try {
    result = { ok: true, count: await feed.run(db, keys) }
    console.log(`[CTI] ${feed.source}: ${result.count} indicator(s)`)
  } catch (err) {
    result = { ok: false, count: 0 }
    console.error(`[CTI] ${feed.source} failed:`, describeError(err))
  }
  await recordFeedResult(kv, feed.source, result)
  return nextCtiStep(step)
}

/** KV key holding the feeds' last results, shown as feed health on the Threat Intel page. */
export const LAST_INGEST_KEY = 'cti_last_ingest'

export interface LastIngest {
  at: string
  feeds: Record<string, { ok: boolean; count: number; last_ok_at: string | null }>
}

/** Remember one feed's result for the feed-health line (the other feeds' entries stay). */
export async function recordFeedResult(kv: KVNamespace, source: string, result: { ok: boolean; count: number }, now = new Date()): Promise<void> {
  const previous = await kv.get<LastIngest>(LAST_INGEST_KEY, 'json').catch(() => null)
  await kv.put(LAST_INGEST_KEY, JSON.stringify(planIngestRecord(previous, { [source]: result }, now)))
}

/**
 * PURE: the record after some feeds' results (exported for tests). A feed that failed
 * keeps the time it last loaded, so the page can say "failed, last loaded 3 days ago".
 */
export function planIngestRecord(
  previous: LastIngest | null, results: Record<string, { ok: boolean; count: number }>, now: Date,
): LastIngest {
  const at = now.toISOString()
  const feeds: LastIngest['feeds'] = { ...(previous?.feeds ?? {}) }
  for (const [source, f] of Object.entries(results)) {
    feeds[source] = { ok: f.ok, count: f.count, last_ok_at: f.ok ? at : previous?.feeds?.[source]?.last_ok_at ?? null }
  }
  return { at, feeds }
}
