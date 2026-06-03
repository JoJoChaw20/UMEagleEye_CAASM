import type { DB } from '../db/client'
import { events } from '../db/schema'
import { eq, and, gt, sql } from 'drizzle-orm'

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

// Pause between NVD requests to respect rate limits:
// 50 req/30s with key (~100ms gap), 5 req/30s without (~700ms gap)
function delay(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms))
}

export async function fetchNvdCwe(cveId: string, apiKey?: string): Promise<string[]> {
  try {
    const headers: Record<string, string> = {}
    if (apiKey) headers['apiKey'] = apiKey

    const resp = await fetch(`${NVD_BASE}?cveId=${encodeURIComponent(cveId)}`, { headers })
    if (!resp.ok) {
      console.warn(`[nvd] ${cveId} → HTTP ${resp.status}`)
      return []
    }

    const data = await resp.json() as {
      vulnerabilities?: Array<{
        cve?: {
          weaknesses?: Array<{
            description?: Array<{ value: string }>
          }>
        }
      }>
    }

    const cweIds: string[] = []
    for (const w of data.vulnerabilities?.[0]?.cve?.weaknesses ?? []) {
      for (const d of w.description ?? []) {
        if (d.value.startsWith('CWE-')) cweIds.push(d.value)
      }
    }
    return cweIds
  } catch (err) {
    console.error(`[nvd] fetchNvdCwe error for ${cveId}:`, err)
    return []
  }
}

// Enrich cve_detected events that have no CWE data yet.
// Processes up to 30 events per call to stay within Worker CPU limits.
export async function enrichMissingCwe(db: DB, apiKey?: string): Promise<number> {
  const cutoff = new Date(Date.now() - 48 * 60 * 60 * 1000)
  const delayMs = apiKey ? 100 : 700

  const rows = await db
    .select({ eventId: events.eventId, details: events.details })
    .from(events)
    .where(and(
      eq(events.eventType, 'cve_detected'),
      gt(events.timestamp, cutoff),
      sql`(${events.details}->>'cwe_ids' IS NULL OR ${events.details}->>'cwe_ids' = '[]')`
    ))
    .limit(30)

  if (rows.length === 0) return 0

  let enriched = 0
  for (const row of rows) {
    const details = (row.details ?? {}) as Record<string, unknown>
    const cveId = details['cve_id'] as string | undefined
    if (!cveId || !cveId.startsWith('CVE-')) continue

    const cweIds = await fetchNvdCwe(cveId, apiKey)
    if (cweIds.length > 0) {
      await db.update(events)
        .set({ details: { ...details, cwe_ids: cweIds } })
        .where(eq(events.eventId, row.eventId))
      enriched++
    }

    await delay(delayMs)
  }

  return enriched
}
