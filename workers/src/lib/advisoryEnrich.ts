/**
 * advisoryEnrich.ts — free, keyless public data for a CVE, used to ground advisories.
 *
 *   NVD  https://services.nvd.nist.gov/rest/json/cves/2.0   (CVSS vector, references)
 *   OSV  https://api.osv.dev/v1/vulns/{id}                  (summary, GHSA aliases)
 *
 * Only the CVE id leaves the system: no asset, hostname, IP or tenant data. Results
 * are cached in KV (NVD allows 5 requests / 30 s without a key). Every call has a
 * short timeout and fails silently: an advisory never waits on, or breaks because of,
 * a third party.
 */
import type { KVNamespace } from '@cloudflare/workers-types'
import type { AdvisoryFacts } from './advisoryKit'

type Nvd = NonNullable<NonNullable<AdvisoryFacts['cve']>['nvd']>
type Osv = NonNullable<NonNullable<AdvisoryFacts['cve']>['osv']>
export interface CveEnrichment { nvd?: Nvd; osv?: Osv; refs: Array<{ label: string; url: string }> }

const CVE_ID = /^CVE-\d{4}-\d{4,}$/
const TIMEOUT_MS = 4000
const HIT_TTL = 3 * 24 * 3600
const MISS_TTL = 3600

async function getJson(url: string, headers: Record<string, string> = {}): Promise<unknown | null> {
  try {
    const res = await fetch(url, { headers: { Accept: 'application/json', ...headers }, signal: AbortSignal.timeout(TIMEOUT_MS) })
    if (!res.ok) return null
    return await res.json()
  } catch { return null }
}

const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : null)

function parseNvd(json: unknown): { nvd?: Nvd; refs: CveEnrichment['refs'] } {
  const cve = ((json as { vulnerabilities?: Array<{ cve?: Record<string, unknown> }> })?.vulnerabilities ?? [])[0]?.cve
  if (!cve) return { refs: [] }
  const metrics = (cve.metrics ?? {}) as Record<string, Array<{ cvssData?: Record<string, unknown> }>>
  const m = (metrics.cvssMetricV31 ?? metrics.cvssMetricV30 ?? [])[0]?.cvssData ?? {}
  const refs: CveEnrichment['refs'] = []
  for (const r of (cve.references ?? []) as Array<{ url?: string; tags?: string[] }>) {
    const tags = r.tags ?? []
    const url = str(r.url)
    if (!url || !/^https:\/\//.test(url)) continue
    if (tags.includes('Patch') || tags.includes('Vendor Advisory')) {
      let host = url
      try { host = new URL(url).hostname.replace(/^www\./, '') } catch { /* keep url */ }
      refs.push({ label: `${tags.includes('Patch') ? 'Patch' : 'Vendor'}: ${host}`, url })
    }
  }
  return {
    nvd: {
      vector: str(m.vectorString), attackVector: str(m.attackVector), complexity: str(m.attackComplexity),
      privileges: str(m.privilegesRequired), userInteraction: str(m.userInteraction), published: str(cve.published),
    },
    refs: refs.slice(0, 2),
  }
}

function parseOsv(json: unknown): Osv | undefined {
  const o = json as { summary?: string; aliases?: string[]; id?: string } | null
  if (!o || (!o.summary && !o.aliases)) return undefined
  return { summary: str(o.summary), aliases: [...(o.aliases ?? []), ...(o.id ? [o.id] : [])].filter(x => typeof x === 'string').slice(0, 6) }
}

export async function enrichCve(kv: KVNamespace | undefined, cveId: string, nvdKey?: string): Promise<CveEnrichment> {
  const empty: CveEnrichment = { refs: [] }
  if (!CVE_ID.test(cveId)) return empty
  const key = `adv:enrich:${cveId}`
  try {
    const cached = await kv?.get(key, 'json') as CveEnrichment | { miss: true } | null | undefined
    if (cached) return 'miss' in cached ? empty : cached
  } catch { /* cache is optional */ }

  const [nvdJson, osvJson] = await Promise.all([
    getJson(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`, nvdKey ? { apiKey: nvdKey } : {}),
    getJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(cveId)}`),
  ])
  const nvd = parseNvd(nvdJson)
  const result: CveEnrichment = { nvd: nvd.nvd, osv: parseOsv(osvJson), refs: nvd.refs }
  const found = !!(result.nvd || result.osv)
  try {
    await kv?.put(key, JSON.stringify(found ? result : { miss: true }), { expirationTtl: found ? HIT_TTL : MISS_TTL })
  } catch { /* ignore */ }
  return found ? result : empty
}
