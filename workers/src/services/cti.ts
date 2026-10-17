import type { DB } from '../db/client'
import { ctiIndicators } from '../db/schema'
import { sql } from 'drizzle-orm'
import { KEV_SOURCE, refreshCveIntel } from './threatIntel'
import { matchIocs } from './iocMatch'
import { warninglistOf } from '../lib/warninglist'
import { resolveSoftware, techniqueIds } from '../lib/attack'

const BATCH_SIZE = 100   // rows per INSERT statement

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

/** Upsert rows in chunks — each chunk = one INSERT … ON CONFLICT statement. */
export async function batchUpsert(db: DB, rows: CtiRow[]): Promise<void> {
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const chunk = rows.slice(i, i + BATCH_SIZE)
    await db
      .insert(ctiIndicators)
      .values(chunk)
      .onConflictDoUpdate({
        target: ctiIndicators.value,
        targetWhere: FEED_ROW,     // the feed rows' partial unique index (idx_cti_feed_value)
        set: {
          lastSeen:        sql`excluded.last_seen`,
          // a feed that names no family does not erase one another feed gave
          malwareFamily:    sql`coalesce(excluded.malware_family, ${ctiIndicators.malwareFamily})`,
          attackSoftware:   sql`CASE WHEN excluded.malware_family IS NULL THEN ${ctiIndicators.attackSoftware} ELSE excluded.attack_software END`,
          attackTechniques: sql`coalesce(excluded.attack_techniques, ${ctiIndicators.attackTechniques})`,
          confidenceScore: sql`excluded.confidence_score`,
          warning:         sql`excluded.warning`,
        },
      })
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
export async function ingestAllFeeds(
  db: DB,
  otxKey: string,
  threatFoxKey: string,
): Promise<{ otx: number; threatfox: number; kev: number; kev_alerts: number }> {
  const [otxResult, tfResult, kevResult] = await Promise.allSettled([
    ingestOtx(db, otxKey),
    ingestThreatFox(db, threatFoxKey),
    ingestKev(db),
  ])

  const otx       = otxResult.status === 'fulfilled' ? otxResult.value : 0
  const threatfox = tfResult.status  === 'fulfilled' ? tfResult.value  : 0
  const kev       = kevResult.status === 'fulfilled' ? kevResult.value : 0

  if (otxResult.status === 'rejected') console.error('[OTX] Fatal:', otxResult.reason)
  if (tfResult.status  === 'rejected') console.error('[ThreatFox] Fatal:', tfResult.reason)
  if (kevResult.status === 'rejected') console.error('[KEV] Fatal:', kevResult.reason)

  // CVE alerts follow the refreshed feeds (KEV additions, entries that aged out).
  let kevAlerts = 0
  try {
    kevAlerts = await refreshCveIntel(db, { all: true })
  } catch (err) {
    console.error('[KEV] Refreshing CVE alerts failed:', err)
  }

  // Assets against the refreshed feeds (R5/R6, services/iocMatch.ts).
  try {
    const m = await matchIocs(db, { all: true })
    console.log(`[CTI] Matches: ${m.created} new, ${m.reopened} reopened, ${m.resolved} resolved`)
  } catch (err) {
    console.error('[CTI] Matching assets failed:', err)
  }

  console.log(`[CTI] Done — OTX: ${otx}, ThreatFox: ${threatfox}, KEV: ${kev} (${kevAlerts} alert(s) newly flagged)`)
  return { otx, threatfox, kev, kev_alerts: kevAlerts }
}
