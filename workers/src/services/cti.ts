import type { DB } from '../db/client'
import { ctiIndicators } from '../db/schema'
import { sql } from 'drizzle-orm'

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
  if (t.includes('ip')) return 'ip'
  if (t.includes('domain')) return 'domain'
  if (t.includes('hash') || t.includes('md5') || t.includes('sha')) return 'hash'
  if (t.includes('url')) return 'url'
  return null
}

export async function ingestOtx(db: DB, apiKey: string): Promise<number> {
  if (!apiKey) return 0

  const res = await fetch('https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20', {
    headers: { 'X-OTX-API-KEY': apiKey },
  })
  if (!res.ok) return 0

  const data = await res.json() as { results: OtxPulse[] }
  let count = 0

  for (const pulse of data.results ?? []) {
    const tactic = pulse.attack_ids?.[0]?.name ?? null

    for (const ind of pulse.indicators ?? []) {
      const itype = mapOtxType(ind.type)
      if (!itype) continue

      await db
        .insert(ctiIndicators)
        .values({
          source: 'AlienVault OTX',
          indicatorType: itype,
          value: ind.indicator,
          confidenceScore: '0.70',
          attackTactic: tactic,
          lastSeen: new Date(),
        })
        .onConflictDoUpdate({
          target: ctiIndicators.value,
          set: { lastSeen: new Date(), attackTactic: tactic },
        })
      count++
    }
  }
  return count
}

export async function ingestThreatFox(db: DB, apiKey: string): Promise<number> {
  const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: 'get_iocs', days: 1 }),
  })
  if (!res.ok) return 0

  const data = await res.json() as { data?: ThreatFoxIoc[] }
  let count = 0

  for (const ioc of data.data ?? []) {
    const itype = mapThreatFoxType(ioc.ioc_type)
    if (!itype) continue

    const confidence = ((ioc.confidence_level ?? 50) / 100).toFixed(2)
    await db
      .insert(ctiIndicators)
      .values({
        source: 'ThreatFox',
        indicatorType: itype,
        value: ioc.ioc,
        confidenceScore: confidence,
        lastSeen: new Date(),
      })
      .onConflictDoUpdate({
        target: ctiIndicators.value,
        set: { lastSeen: new Date() },
      })
    count++
  }
  return count
}

export async function ingestAllFeeds(db: DB, otxKey: string, _threatFoxKey: string): Promise<void> {
  await Promise.allSettled([
    ingestOtx(db, otxKey),
    ingestThreatFox(db, _threatFoxKey),
  ])
}
