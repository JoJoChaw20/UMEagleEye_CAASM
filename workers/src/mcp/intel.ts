/**
 * mcp/intel.ts — public threat-intelligence tools for the chatbot and the MCP server.
 *
 * Only a public identifier ever leaves the system: a CVE id goes to NVD, OSV and FIRST
 * (EPSS); ATT&CK and CWE answers come from the bundled MITRE data (src/data/*.json), so
 * nothing is sent at all. Each external call has a short timeout, is cached in KV and
 * fails soft: a missing source is reported as missing, never guessed.
 */
import { z } from 'zod'
import { and, eq, inArray, sql } from 'drizzle-orm'
import { assets, ctiIndicators, events } from '../db/schema'
import { enrichCve } from '../lib/advisoryEnrich'
import { ATTACK, softwareUsing, tacticsOf, techniqueName } from '../lib/attack'
import { cweList } from '../lib/cwe'
import { OPEN_STATUSES } from '../lib/eventStatus'
import { KEV_SOURCE } from '../services/threatIntel'
import type { ToolContext, ToolDef } from './tools'
import { assetScope } from './scope'

const CVE_ID = /^CVE-\d{4}-\d{4,}$/i
const EPSS_TTL = 24 * 3600

async function epssFor(ctx: ToolContext, cveId: string): Promise<{ epss: number; percentile: number; date: string | null } | null> {
  const key = `intel:epss:${cveId}`
  try {
    const cached = await ctx.env.KV_CACHE?.get(key, 'json') as { epss: number; percentile: number; date: string | null } | { miss: true } | null
    if (cached) return 'miss' in cached ? null : cached
  } catch { /* cache is optional */ }
  let out: { epss: number; percentile: number; date: string | null } | null = null
  try {
    const res = await fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`, {
      headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(4000),
    })
    if (res.ok) {
      const row = ((await res.json()) as { data?: Array<{ epss?: string; percentile?: string; date?: string }> }).data?.[0]
      if (row?.epss != null) out = { epss: Number(row.epss), percentile: Number(row.percentile ?? 0), date: row.date ?? null }
    }
  } catch { /* fail soft */ }
  try {
    await ctx.env.KV_CACHE?.put(key, JSON.stringify(out ?? { miss: true }), { expirationTtl: out ? EPSS_TTL : 3600 })
  } catch { /* ignore */ }
  return out
}

const lookupCve: ToolDef<{ cve_id: z.ZodString }> = {
  name: 'lookup_cve',
  title: 'CVE intelligence',
  description: 'Public facts about one CVE: CVSS vector and attack vector (NVD), summary and GHSA/OSV aliases (OSV), CISA KEV status, EPSS exploit probability (FIRST), patch links, and how many open alerts and assets in this organisation have it. Only the CVE id is sent to those services.',
  input: { cve_id: z.string().trim().max(20).regex(CVE_ID, 'a CVE id such as CVE-2024-3094') },
  access: 'analyst',
  async run(ctx, a) {
    const id = a.cve_id.toUpperCase()
    const [enrich, epss, kev, here] = await Promise.all([
      enrichCve(ctx.env.KV_CACHE, id, ctx.env.NVD_API_KEY),
      epssFor(ctx, id),
      ctx.db.select({ added: ctiIndicators.firstSeen }).from(ctiIndicators)
        .where(and(eq(ctiIndicators.indicatorType, 'cve'), eq(ctiIndicators.value, id), eq(ctiIndicators.source, KEV_SOURCE)))
        .limit(1),
      ctx.db.select({
        alerts: sql<number>`count(*)::int`,
        assets: sql<number>`count(DISTINCT ${events.assetId})::int`,
      }).from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(
          assetScope(ctx),
          inArray(events.status, OPEN_STATUSES),
          eq(events.eventType, 'cve_detected'),
          sql`${events.details}->>'cve_id' = ${id}`,
        )),
    ])
    return {
      cve_id: id,
      nvd: enrich.nvd ?? null,
      osv: enrich.osv ?? null,
      cisa_kev: kev[0] ? { listed: true, added: kev[0].added } : { listed: false },
      epss: epss ? { probability_30d: epss.epss, percentile: epss.percentile, date: epss.date } : null,
      references: [
        { label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${id}` },
        ...enrich.refs,
        ...(enrich.osv?.aliases ?? []).filter(x => /^GHSA-/.test(x)).slice(0, 1).map(g => ({ label: g, url: `https://github.com/advisories/${g}` })),
      ],
      in_this_organisation: { open_alerts: here[0]?.alerts ?? 0, affected_assets: here[0]?.assets ?? 0 },
      sources_missing: [!enrich.nvd && 'NVD', !enrich.osv && 'OSV', !epss && 'EPSS'].filter(Boolean),
    }
  },
}

const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/i

const attackUrl = (id: string) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`

const lookupAttack: ToolDef<{ query: z.ZodString }> = {
  name: 'lookup_attack_technique',
  title: 'MITRE ATT&CK',
  description: `A MITRE ATT&CK Enterprise technique by id (T1059, T1059.001) or by words in its name ("phishing", "credential dumping"): name, tactics, sub-techniques and how many ATT&CK software families use it. From the bundled ATT&CK ${ATTACK.version} data; nothing is sent anywhere.`,
  input: { query: z.string().trim().min(2).max(60) },
  access: 'all',
  async run(_ctx, a) {
    const q = a.query.trim()
    const describe = (id: string) => ({
      technique_id: id,
      name: techniqueName(id),
      tactics: tacticsOf(id),
      sub_techniques: Object.keys(ATTACK.techniques).filter(t => t.startsWith(`${id}.`)).slice(0, 20)
        .map(t => ({ id: t, name: techniqueName(t) })),
      software_using: softwareUsing([id]).length,
      url: attackUrl(id),
    })
    if (TECHNIQUE_ID.test(q)) {
      const id = q.toUpperCase()
      return techniqueName(id) ? describe(id) : { error: `No ATT&CK technique ${id} in version ${ATTACK.version}` }
    }
    const words = q.toLowerCase().split(/\s+/).filter(w => w.length > 1)
    const hits = Object.entries(ATTACK.techniques)
      .filter(([, [name]]) => words.every(w => name.toLowerCase().includes(w)))
      .slice(0, 10)
      .map(([id, [name]]) => ({ technique_id: id, name, tactics: tacticsOf(id), url: attackUrl(id) }))
    return { attack_version: ATTACK.version, matches: hits }
  },
}

const lookupCwe: ToolDef<{ cwe_id: z.ZodString }> = {
  name: 'lookup_cwe',
  title: 'CWE weakness',
  description: 'The name of a CWE weakness (CWE-79, 787) from the bundled MITRE CWE list, with its link. Nothing is sent anywhere.',
  input: { cwe_id: z.string().trim().max(9).regex(/^(CWE-)?\d{1,5}$/i, 'a CWE id such as CWE-79') },
  access: 'all',
  async run(_ctx, a) {
    const num = a.cwe_id.replace(/^CWE-/i, '')
    const [hit] = cweList([`CWE-${num}`])
    return hit?.name
      ? { cwe_id: `CWE-${num}`, name: hit.name, url: `https://cwe.mitre.org/data/definitions/${num}.html` }
      : { error: `CWE-${num} is not in the bundled CWE list` }
  },
}

export const INTEL_TOOLS: ToolDef[] = [lookupCve, lookupAttack, lookupCwe] as unknown as ToolDef[]
