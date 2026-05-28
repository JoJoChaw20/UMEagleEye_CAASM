import type { DB } from '../db/client'
import { ctiIndicators } from '../db/schema'
import { sql } from 'drizzle-orm'

const BATCH_SIZE = 100   // rows per INSERT statement

type CtiRow = typeof ctiIndicators.$inferInsert

interface OtxPulse {
  indicators: Array<{ type: string; indicator: string }>
  attack_ids?: Array<{ name: string; display_name: string }>
}

interface ThreatFoxIoc {
  ioc: string
  ioc_type: string
  confidence_level: number
  malware?: string
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
async function batchUpsert(db: DB, rows: CtiRow[]): Promise<void> {
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const chunk = rows.slice(i, i + BATCH_SIZE)
    await db
      .insert(ctiIndicators)
      .values(chunk)
      .onConflictDoUpdate({
        target: ctiIndicators.value,
        set: {
          lastSeen:        sql`excluded.last_seen`,
          attackTactic:    sql`excluded.attack_tactic`,
          attackTechnique: sql`excluded.attack_technique`,
          confidenceScore: sql`excluded.confidence_score`,
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
    const tactic    = pulse.attack_ids?.[0]?.name ?? null
    const technique = pulse.attack_ids?.[0]?.display_name ?? null

    for (const ind of pulse.indicators ?? []) {
      const itype = mapOtxType(ind.type)
      if (!itype || !ind.indicator) continue
      rows.push({
        source:          'AlienVault OTX',
        indicatorType:   itype,
        value:           ind.indicator,
        confidenceScore: '0.70',
        attackTactic:    tactic,
        attackTechnique: technique,
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
      confidenceScore: ((ioc.confidence_level ?? 50) / 100).toFixed(2),
      lastSeen:        now,
    })
  }

  console.log(`[ThreatFox] Upserting ${rows.length} unique rows in batches of ${BATCH_SIZE}`)
  await batchUpsert(db, rows)
  return rows.length
}

// ── Combined ─────────────────────────────────────────────────────────
export async function ingestAllFeeds(
  db: DB,
  otxKey: string,
  threatFoxKey: string,
): Promise<{ otx: number; threatfox: number }> {
  const [otxResult, tfResult] = await Promise.allSettled([
    ingestOtx(db, otxKey),
    ingestThreatFox(db, threatFoxKey),
  ])

  const otx       = otxResult.status === 'fulfilled' ? otxResult.value : 0
  const threatfox = tfResult.status  === 'fulfilled' ? tfResult.value  : 0

  if (otxResult.status === 'rejected') console.error('[OTX] Fatal:', otxResult.reason)
  if (tfResult.status  === 'rejected') console.error('[ThreatFox] Fatal:', tfResult.reason)

  console.log(`[CTI] Done — OTX: ${otx}, ThreatFox: ${threatfox}`)
  return { otx, threatfox }
}
