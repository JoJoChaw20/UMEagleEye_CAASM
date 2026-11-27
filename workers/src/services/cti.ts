import type { KVNamespace } from '@cloudflare/workers-types'
import type { DB } from '../db/client'
import { ctiIndicators } from '../db/schema'
import { sql } from 'drizzle-orm'
import { KEV_SOURCE, RETIRED_SOURCES, refreshCveIntel } from './threatIntel'
import { matchIocs } from './iocMatch'
import { refreshEpss } from './epss'
import { checkMaliciousPackages } from './maliciousPackages'
import { DROP_SOURCE, checkPublicAddresses, ingestSpamhausDrop } from './publicAddresses'
import { CDN_CIDRS, TOP_DOMAINS_LIST, warninglistOf } from '../lib/warninglist'
import { resolveSoftware, techniqueIds, techniqueName } from '../lib/attack'
import { inferredTechniques } from '../lib/malwareKind'
import { MYCERT_SOURCE } from '../lib/mycert'
import { ingestMycert, rememberKnownMycert } from './mycert'
import { kevTechniques } from '../lib/kevAttack'

// Rows per INSERT statement. Every statement is one HTTP request to Neon, and a Worker
// on the free plan may make only 50 per run (cron or queue job): with 100 rows per
// statement a 7-day ThreatFox pull (about 17k rows) ran out after 43 and OTX, the CVE
// alert refresh and the asset matching all failed. 9 parameters per row: 4,000 rows is
// 36k, under Postgres' 65,535 limit, so a nightly run needs about a dozen requests.
export const BATCH_SIZE = 4000

type CtiRow = typeof ctiIndicators.$inferInsert

// Feed entries (not event attributes). Must match idx_cti_feed_value's WHERE.
const FEED_ROW = sql`ti_event_id IS NULL`
const RETIRED = sql.join(RETIRED_SOURCES.map((s) => sql`${s}`), sql`, `)

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

/** An OTX pulse's ATT&CK: techniques its author tagged, and its malware family, preferring one ATT&CK documents. */
export function otxPulseAttack(pulse: Pick<OtxPulse, 'attack_ids' | 'malware_families'>) {
  // attack_ids and malware_families come as strings or objects
  const named = techniqueIds((pulse.attack_ids ?? []).flatMap((x) =>
    typeof x === 'string' ? [x] : [x.id, x.name, x.display_name]))
  const families = (pulse.malware_families ?? [])
    .map((f) => familyName(typeof f === 'string' ? f : f.display_name ?? f.id))
    .filter((f): f is string => !!f)
  const software = resolveSoftware(families)
  const family = (software && families.find((f) => resolveSoftware([f]) === software)) ?? families[0] ?? null
  return { named, software, family }
}

/** A ThreatFox IOC's family, its ATT&CK software from the printable name, aliases or Malpedia key,
 *  and, when ATT&CK does not describe the family, techniques inferred from the malware's kind and the
 *  indicator's role (lib/malwareKind.ts; shown as inferred). */
export function threatFoxAttack(ioc: Pick<ThreatFoxIoc, 'malware' | 'malware_printable' | 'malware_alias' | 'threat_type'>) {
  const family = familyName(ioc.malware_printable)
  const names = [ioc.malware_printable, ...(ioc.malware_alias ?? '').split(','), ioc.malware?.split('.').slice(1).join('.')]
  const attackSoftware = family ? resolveSoftware(names) : null
  const inferred = inferredTechniques({ names: family ? [...names, ioc.malware] : [], inAttack: !!attackSoftware, role: ioc.threat_type })
    .filter((t) => techniqueName(t) !== null)
  return {
    malwareFamily:  family,
    attackSoftware,
    attackTechniques: inferred.length ? inferred : null,
  }
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
        -- a row a retired feed stored first (RETIRED_SOURCES) becomes this feed's: kept under the old
        -- name it never matched, though this feed lists it now (found 27 Nov 2026: OTX rows refreshed by ThreatFox)
        source            = CASE WHEN c.source IN (${RETIRED}) THEN excluded.source ELSE c.source END,
        last_seen         = excluded.last_seen,
        -- a feed that names no family does not erase one another feed gave
        malware_family    = coalesce(excluded.malware_family, c.malware_family),
        attack_software   = CASE WHEN excluded.malware_family IS NULL THEN c.attack_software ELSE excluded.attack_software END,
        attack_techniques = coalesce(excluded.attack_techniques, c.attack_techniques),
        -- the feed that first listed it keeps its own confidence: another feed listing the same
        -- value only raises it (OTX's flat 70% used to overwrite ThreatFox's real level)
        confidence_score  = CASE WHEN c.source = excluded.source OR c.source IN (${RETIRED}) THEN excluded.confidence_score
                                 ELSE GREATEST(c.confidence_score, excluded.confidence_score) END,
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
  // A failed fetch throws, so feed health shows the feed as failing (it used to read "ok, 0
  // indicators" for weeks when a key expired). An unset key above is a deliberate skip.
  if (!res.ok) {
    throw new Error(`OTX answered HTTP ${res.status}: ${(await res.text().catch(() => '')).slice(0, 200)}`)
  }

  const data = await res.json() as { results?: OtxPulse[]; count?: number }
  console.log(`[OTX] ${data.results?.length ?? 0} pulses (total=${data.count ?? '?'})`)

  const rows: CtiRow[] = []
  const now = new Date()

  for (const pulse of data.results ?? []) {
    const { named, software, family } = otxPulseAttack(pulse)

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
// ThreatFox's "last N days" answer. Since 11 Nov (staging) and 22 Nov (production) every API answer stops after
// about 64 KB, mid-record, whatever the window (7, 3 or 1 day) and compressed or not: ThreatFox's server ends
// its streamed (chunked) answer early. So a cut-off, empty or non-JSON answer is asked again for fewer days, and
// when every try is cut off the recent export file (a static download, the last 48 hours) is used instead; the
// feed runs nightly, so 48 hours still holds each night's new entries. A refusal (HTTP error, unknown key) is not
// retried: neither would change it.
export const THREATFOX_DAYS = [7, 3, 1]
const THREATFOX_EXPORT = (key: string) => `https://threatfox-api.abuse.ch/v2/files/exports/${encodeURIComponent(key)}/recent.json`
class ThreatFoxBadAnswer extends Error {}
type ThreatFoxAnswer = { query_status?: string; data?: ThreatFoxIoc[] }

async function readJson(res: Response, what: string): Promise<unknown> {
  // Read as text first: an empty or cut-off body otherwise fails as a bare "Unexpected end of JSON input".
  const text = await res.text().catch((err) => { throw new ThreatFoxBadAnswer(`reading the ${what} failed: ${String(err).slice(0, 120)}`) })
  const h = (k: string) => res.headers.get(k) ?? '-'
  const shape = `HTTP ${res.status}, ${h('content-type')}, ${text.length} chars, ${h('transfer-encoding') === 'chunked' ? 'streamed' : `length ${h('content-length')}`}`
  if (!text.trim()) throw new ThreatFoxBadAnswer(`an empty ${what} (${shape})`)
  try {
    return JSON.parse(text)
  } catch {
    throw new ThreatFoxBadAnswer(`${what} not JSON, probably cut off (${shape}): ...${text.slice(-60).replace(/\s+/g, ' ')}`)
  }
}

async function threatFoxIocs(apiKey: string, days: number): Promise<ThreatFoxAnswer> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (apiKey) headers['Auth-Key'] = apiKey
  const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers,
    body: JSON.stringify({ query: 'get_iocs', days }),
  })
  if (!res.ok) {
    throw new Error(`ThreatFox answered HTTP ${res.status}: ${(await res.text().catch(() => '')).slice(0, 200)}`)
  }
  return await readJson(res, 'answer') as ThreatFoxAnswer
}

/** The export file's records as the API's: the export names the value ioc_value and gives tags as one string,
 *  and holds either a list or an object of lists keyed by id. */
export function threatFoxExportIocs(raw: unknown): ThreatFoxIoc[] {
  const list = Array.isArray(raw) ? raw
    : raw && typeof raw === 'object' ? Object.values(raw as Record<string, unknown>).flat() : []
  const out: ThreatFoxIoc[] = []
  for (const r of list as Array<Record<string, unknown>>) {
    const ioc = r?.ioc ?? r?.ioc_value
    if (typeof ioc !== 'string' || typeof r.ioc_type !== 'string') continue
    const tags = Array.isArray(r.tags) ? r.tags as string[]
      : typeof r.tags === 'string' && r.tags ? r.tags.split(',').map((t) => t.trim()).filter(Boolean) : null
    out.push({
      ioc, ioc_type: r.ioc_type, confidence_level: Number(r.confidence_level ?? 50),
      malware: r.malware as string | undefined, malware_printable: r.malware_printable as string | undefined,
      malware_alias: (r.malware_alias as string | null | undefined) ?? null, threat_type: r.threat_type as string | undefined, tags,
    })
  }
  return out
}

async function threatFoxExport(apiKey: string): Promise<ThreatFoxAnswer> {
  const res = await fetch(THREATFOX_EXPORT(apiKey))
  if (!res.ok) throw new ThreatFoxBadAnswer(`export HTTP ${res.status}: ${(await res.text().catch(() => '')).slice(0, 120)}`)
  const data = threatFoxExportIocs(await readJson(res, 'export'))
  return { query_status: data.length ? 'ok' : 'no_result', data }
}

export async function ingestThreatFox(db: DB, apiKey: string): Promise<number> {
  let data: ThreatFoxAnswer | null = null
  const problems: string[] = []
  for (const days of THREATFOX_DAYS) {
    try {
      data = await threatFoxIocs(apiKey, days)
      break
    } catch (err) {
      if (!(err instanceof ThreatFoxBadAnswer)) throw err
      problems.push(`${days} days: ${err.message}`)
    }
  }
  if (!data) {
    try {
      data = await threatFoxExport(apiKey)
    } catch (err) {
      if (!(err instanceof ThreatFoxBadAnswer)) throw err
      problems.push(err.message)
    }
  }
  if (!data) throw new Error(`ThreatFox sent no usable answer: ${problems.join('; ')}`)
  if (problems.length) console.log(`[ThreatFox] used ${problems.length > THREATFOX_DAYS.length - 1 ? 'the recent export' : 'a shorter window'} after: ${problems.join('; ')}`)
  console.log(`[ThreatFox] query_status=${data.query_status} records=${data.data?.length ?? 0}`)
  // 'ok', or 'no_result' for a quiet week; anything else (e.g. 'unknown_auth_key') is a failure
  if (data.query_status && data.query_status !== 'ok' && data.query_status !== 'no_result') {
    throw new Error(`ThreatFox refused the query: ${data.query_status}`)
  }

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
      ...threatFoxAttack(ioc),
      lastSeen:        now,
    })
  }

  console.log(`[ThreatFox] Upserting ${rows.length} unique rows in batches of ${BATCH_SIZE}`)
  await batchUpsert(db, rows)
  return rows.length
}

// URLhaus and Feodo Tracker (abuse.ch) were loaded here from 22 to 27 Nov 2026 and dropped when MyCERT
// became the main source: Feodo listed about 5 addresses, most URLhaus URLs were on the warninglist.
// Their stored rows stop matching at once (threatIntel.ts RETIRED_SOURCES) and retention deletes them.

// ── CISA Known Exploited Vulnerabilities ─────────────────────────────
// CVEs with confirmed exploitation in the wild (free JSON, no key, about 1.7k
// entries). Stored as 'cve' indicators, so /sboms/ingest-cve flags matching CVE
// alerts, and refreshCveIntel() updates the open alerts that already exist.
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
const KEV_BATCH = 500   // 7 params per row; well under Postgres' 65k parameter limit

interface KevEntry { cveID?: string; dateAdded?: string }

export async function ingestKev(db: DB): Promise<number> {
  const res = await fetch(KEV_URL, { headers: { 'User-Agent': 'UMEagleEye-CTI/1.0' } })
  if (!res.ok) throw new Error(`CISA KEV answered HTTP ${res.status}`)
  const data = await res.json() as { catalogVersion?: string; vulnerabilities?: KevEntry[] }
  const now = new Date()
  const seen = new Set<string>()
  const rows: CtiRow[] = []
  for (const v of data.vulnerabilities ?? []) {
    const id = v.cveID?.trim().toUpperCase()
    if (!id || !/^CVE-\d{4}-\d{4,}$/.test(id) || seen.has(id)) continue
    seen.add(id)
    const added = v.dateAdded ? new Date(v.dateAdded) : now
    // ATT&CK: how it is exploited and what it leads to (MITRE CTID's KEV mappings, lib/kevAttack.ts)
    const techniques = kevTechniques(id).all
    rows.push({
      source: KEV_SOURCE,
      indicatorType: 'cve',
      value: id,
      confidenceScore: '1.00',
      attackTechniques: techniques.length ? techniques : null,
      firstSeen: Number.isNaN(added.getTime()) ? now : added,
      lastSeen: now,
    })
  }
  console.log(`[KEV] catalog ${data.catalogVersion ?? '?'}: ${rows.length} CVEs`)
  for (let i = 0; i < rows.length; i += KEV_BATCH) {
    await db.insert(ctiIndicators).values(rows.slice(i, i + KEV_BATCH)).onConflictDoUpdate({
      target: ctiIndicators.value,
      targetWhere: FEED_ROW,
      set: { lastSeen: sql`excluded.last_seen`, attackTechniques: sql`excluded.attack_techniques` },
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
// 'epss' fills in and refreshes EPSS on the devices' CVEs (services/epss.ts); 'finish'
// refreshes the CVE alerts and the asset matches against the new data.
// 'mycert' comes first: MyCERT's advisories are the main source (services/mycert.ts; platform events,
// not feed rows). CISA KEV and EPSS give every CVE its exploited and likelihood data, ThreatFox the bulk
// indicators the agents' sightings check, Spamhaus DROP the public-address check.
// AlienVault OTX was dropped on 22 Nov 2026, URLhaus and Feodo Tracker on 27 Nov 2026: their stored rows
// stop matching at once (RETIRED_SOURCES) and are deleted by retention.
// 'malpkg' asks OSV whether any device's package versions were since published as malware
// (services/maliciousPackages.ts; at most 10,000 a night, carrying on the next night).
// 'drop' loads Spamhaus DROP for the public-address check (services/publicAddresses.ts; kept in KV, not
// as indicator rows), and 'finish' then checks every tenant's public addresses against all of them (R11).
export type CtiStep = 'mycert' | 'kev' | 'threatfox' | 'drop' | 'epss' | 'malpkg' | 'finish'
export const CTI_STEPS: CtiStep[] = ['mycert', 'kev', 'threatfox', 'drop', 'epss', 'malpkg', 'finish']
/** The feeds the chain loads, in its order, as their `source`: the feed-health line shows these only. */
export const ACTIVE_FEEDS = [MYCERT_SOURCE, KEV_SOURCE, 'ThreatFox', DROP_SOURCE]
export const CTI_INGEST_LOCK = 'cti_ingest_lock'

/**
 * How the shared feeds get loaded here. Production: the nightly cron only (the feeds are shared by
 * every tenant, so nobody starts an early run: access-control spec, item 9). Staging has no crons, so
 * there the Platform Superadmin loads them by hand (POST /cti/ingest), or they would never refresh.
 */
export function feedRefresh(appEnv: string | undefined): { scheduled: boolean; manual: boolean } {
  const staging = appEnv === 'staging'
  return { scheduled: !staging, manual: staging }
}

/**
 * Mark stored indicators (feeds and events alike) that are on a warninglist added after they were
 * saved: IPs and URL hosts in the shared CDN ranges, domains that are exactly a top-1,000 site, and
 * domains and email addresses under gov.my, edu.my or mil.my (lib/warninglist.ts). Only rows without a
 * warning yet; returns how many were marked.
 */
export async function reflagWarninglists(db: DB): Promise<number> {
  const cidrs = JSON.stringify(CDN_CIDRS)
  const domains = JSON.stringify(TOP_DOMAINS_LIST)
  const ipHost = `substring(c.value from '^[A-Za-z][A-Za-z0-9+.-]*://((?:[0-9]{1,3}\\.){3}[0-9]{1,3})(?:[:/?#]|$)')`
  // the same rule as MY_OFFICIAL_DOMAIN, on a domain or an email's host
  const myOfficial = `(c.indicator_type IN ('domain', 'email') AND lower(trim(trailing '.' from c.value)) ~ '(^|[.@])(gov|edu|mil)\\.my$')`
  const res = await db.execute(sql`
    WITH cdn AS (SELECT array_agg(x::inet) AS r FROM jsonb_array_elements_text(${cidrs}::jsonb) x),
         top AS (SELECT array_agg(x) AS d FROM jsonb_array_elements_text(${domains}::jsonb) x)
    UPDATE cti_indicators c SET warning = CASE WHEN ${sql.raw(myOfficial)} THEN 'my-official-domain'
                                              WHEN c.indicator_type = 'domain' THEN 'top-domain' ELSE 'cdn' END
    FROM cdn, top
    WHERE c.warning IS NULL AND (
      (c.indicator_type = 'ip' AND c.value ~ '^([0-9]{1,3}\\.){3}[0-9]{1,3}$' AND c.value::inet <<= ANY(cdn.r))
      OR (c.indicator_type = 'url' AND ${sql.raw(ipHost)} IS NOT NULL AND ${sql.raw(ipHost)}::inet <<= ANY(cdn.r))
      OR (c.indicator_type = 'domain'
          AND regexp_replace(lower(trim(trailing '.' from c.value)), '^www\\.', '') = ANY(top.d))
      OR ${sql.raw(myOfficial)}
    )
    RETURNING c.indicator_id`)
  return res.rows.length
}

/** The step after this one; null after 'finish' (exported for tests). */
export function nextCtiStep(step: CtiStep): CtiStep | null {
  return CTI_STEPS[CTI_STEPS.indexOf(step) + 1] ?? null
}

const FEED_OF: Record<Exclude<CtiStep, 'finish' | 'epss' | 'malpkg' | 'drop' | 'mycert'>,{ source: string; run: (db: DB, ctx: IngestContext) => Promise<number> }> = {
  kev:       { source: KEV_SOURCE,       run: (db) => ingestKev(db) },
  threatfox: { source: 'ThreatFox',      run: (db, k) => ingestThreatFox(db, k.threatFox) },
}

export interface IngestContext {
  threatFox: string
  /** Called when threat events changed (new MyCERT advisories): the agents' cached event lists are dropped. */
  eventsChanged?: () => Promise<void>
  /** How MyCERT's pages are read (services/mycert.ts mycertSourceOf: harvested during a request from
   *  Malaysia, kept in KV); default directly. */
  fetchMycert?: (url: string) => Promise<string>
}

/**
 * Run one step and record it for the feed-health line. A feed that fails is recorded as
 * failed and the chain goes on. Returns the next step, or null when the run is done.
 */
export async function runIngestStep(db: DB, kv: KVNamespace, ctx: IngestContext, step: CtiStep): Promise<CtiStep | null> {
  if (step === 'mycert') {
    // Feed health counts the advisories stored, not indicators.
    let result: { ok: boolean; count: number }
    try {
      const r = await ingestMycert(db, { fetchText: ctx.fetchMycert })
      await rememberKnownMycert(kv, r.knownIds)
      result = { ok: true, count: r.stored }
      console.log(`[CTI] ${MYCERT_SOURCE}: ${r.listed} in the feed, ${r.added} new, ${r.failed} failed, ${r.stored} stored`)
      if (r.added) await ctx.eventsChanged?.()
    } catch (err) {
      result = { ok: false, count: 0 }
      console.error(`[CTI] ${MYCERT_SOURCE} failed:`, describeError(err))
    }
    await recordFeedResult(kv, MYCERT_SOURCE, result)
    return nextCtiStep(step)
  }
  if (step === 'finish') {
    // Stored indicators get the warninglists added since they were saved (CDN ranges, top sites):
    // a value a feed no longer lists would otherwise keep its old (empty) warning.
    try {
      const flagged = await reflagWarninglists(db)
      if (flagged) console.log(`[CTI] ${flagged} stored indicator(s) put on a warninglist`)
    } catch (err) {
      console.error('[CTI] Warninglist re-check failed:', describeError(err))
    }
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
    // The organisation's public addresses against the refreshed lists (R11).
    try {
      const r = await checkPublicAddresses(db, kv, { all: true })
      console.log(`[CTI] Public addresses: ${r.addresses} checked, ${r.listed} listed; alerts ${r.created} new, ${r.reopened} reopened, ${r.resolved} resolved`)
    } catch (err) {
      console.error('[CTI] Checking public addresses failed:', describeError(err))
    }
    return null
  }
  if (step === 'drop') {
    let result: { ok: boolean; count: number }
    try {
      result = { ok: true, count: await ingestSpamhausDrop(kv) }
      console.log(`[CTI] ${DROP_SOURCE}: ${result.count} range(s)`)
    } catch (err) {
      result = { ok: false, count: 0 }
      console.error(`[CTI] ${DROP_SOURCE} failed:`, describeError(err))
    }
    await recordFeedResult(kv, DROP_SOURCE, result)
    return nextCtiStep(step)
  }
  if (step === 'epss') {
    try {
      const r = await refreshEpss(db)
      console.log(`[EPSS] ${r.updated} CVE(s) updated, ${r.waiting} waiting for the next run`)
    } catch (err) {
      console.error('[EPSS] Refresh failed:', describeError(err))
    }
    return nextCtiStep(step)
  }
  if (step === 'malpkg') {
    try {
      const r = await checkMaliciousPackages(db, kv, { nightly: true })
      console.log(`[malpkg] ${r.checked} package(s) asked, ${r.malicious} malicious: ${r.created} new, ${r.reopened} reopened, ${r.resolved} resolved`)
    } catch (err) {
      console.error('[malpkg] Check failed:', describeError(err))
    }
    return nextCtiStep(step)
  }
  // A queued job from before a step was dropped ('otx', 'urlhaus', 'feodo'): carry on with DROP and the rest.
  if (!(step in FEED_OF)) {
    console.log(`[CTI] Step '${step}' is no longer run; going on`)
    return 'drop'
  }
  const feed = FEED_OF[step as keyof typeof FEED_OF]
  let result: { ok: boolean; count: number }
  try {
    result = { ok: true, count: await feed.run(db, ctx) }
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
