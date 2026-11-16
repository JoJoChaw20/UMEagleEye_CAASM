/**
 * risk-reliability.ts — READ-ONLY evaluation of the composite risk score (lib/riskScore.ts)
 * against real-world exploitation: does it rank the CVEs CISA lists as exploited in the
 * wild (KEV) above the rest, better than CVSS alone? For the evaluation chapter (O3).
 *
 * Ground truth is the CISA KEV catalogue fetched at run time. The stored score already adds
 * 10 points for a threat-intel match, and KEV is one, so comparing it with KEV is partly
 * circular. The fair comparison is therefore the score WITHOUT the threat-intel bonus
 * ("composite, no CTI") against CVSS alone and EPSS alone. The strongest check is temporal:
 * CVEs CISA added to KEV only AFTER the alert was raised, which nothing in the score knew.
 *
 * Run from workers/ (reads .env.<target>; DB_TARGET must match, as in scripts/db):
 *   npx esbuild scripts/risk-reliability.ts --bundle --platform=node --format=cjs --outfile=.risk-reliability.cjs
 *   node .risk-reliability.cjs --target staging [--tenant <slug>] [--fresh-epss] [--out <dir>]
 *
 * Only SELECTs are issued; nothing is written to the database. The report holds CVE ids and
 * scores only: no hostnames, addresses or tenant names.
 */
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs'
import path from 'node:path'
import { neon } from '@neondatabase/serverless'
import { computeRiskScore } from '../src/lib/riskScore'

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`)
  return i > 0 ? process.argv[i + 1] : undefined
}
const flag = (name: string) => process.argv.includes(`--${name}`)
function die(msg: string): never { console.error(`\nERROR: ${msg}`); process.exit(1) }

const target = arg('target') ?? 'staging'
const slug = arg('tenant')
const outDir = arg('out')
const freshEpss = flag('fresh-epss')
if (!['staging', 'production'].includes(target)) die('--target must be staging or production')

const envFile = path.resolve(process.cwd(), `.env.${target}`)
if (!existsSync(envFile)) die(`${envFile} not found (run from workers/)`)
const vars: Record<string, string> = {}
for (const raw of readFileSync(envFile, 'utf8').replace(/^﻿/, '').split(/\r?\n/)) {
  const line = raw.trim(); const eq = line.indexOf('=')
  if (line && !line.startsWith('#') && eq > 0) vars[line.slice(0, eq).trim()] = line.slice(eq + 1).trim().replace(/^(['"])(.*)\1$/, '$2')
}
if (vars['DB_TARGET'] !== target) die(`${path.basename(envFile)} has DB_TARGET="${vars['DB_TARGET'] ?? ''}", not "${target}"`)
const url = vars['DATABASE_URL'] ?? die('DATABASE_URL missing')

// ── Data ───────────────────────────────────────────────────────────────────────

interface Item {
  cve: string
  cvss: number
  epss: number
  crit: number
  cti: boolean
  stored: number | null
  firstSeen: Date
  kev: boolean            // in the KEV catalogue today
  kevAdded: Date | null
}

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

async function fetchKev(): Promise<Map<string, Date>> {
  const res = await fetch(KEV_URL)
  if (!res.ok) die(`KEV download failed: HTTP ${res.status}`)
  const data = await res.json() as { catalogVersion?: string; vulnerabilities?: Array<{ cveID: string; dateAdded: string }> }
  const m = new Map<string, Date>()
  for (const v of data.vulnerabilities ?? []) m.set(v.cveID, new Date(`${v.dateAdded}T00:00:00Z`))
  console.log(`KEV catalogue ${data.catalogVersion ?? '?'}: ${m.size} CVEs`)
  return m
}

async function fetchEpss(cves: string[]): Promise<Map<string, number>> {
  const out = new Map<string, number>()
  for (let i = 0; i < cves.length; i += 50) {
    const chunk = cves.slice(i, i + 50)
    const res = await fetch(`https://api.first.org/data/v1/epss?cve=${chunk.join(',')}`)
    if (!res.ok) { console.warn(`EPSS chunk ${i / 50}: HTTP ${res.status}`); continue }
    const data = await res.json() as { data?: Array<{ cve: string; epss: string }> }
    for (const d of data.data ?? []) out.set(d.cve, parseFloat(d.epss) || 0)
  }
  return out
}

// ── Ranking metrics (ties are broken uniformly at random, so results are expectations) ──

interface Group { score: number; n: number; pos: number }
function groupsOf(xs: Array<{ s: number; y: boolean }>): Group[] {
  const m = new Map<number, Group>()
  for (const { s, y } of xs) {
    const g = m.get(s) ?? { score: s, n: 0, pos: 0 }
    g.n++; if (y) g.pos++
    m.set(s, g)
  }
  return [...m.values()].sort((a, b) => b.score - a.score)
}

/** ROC AUC by Mann-Whitney with mid-ranks (exact with ties). */
function auc(gs: Group[]): number {
  const P = gs.reduce((a, g) => a + g.pos, 0), N = gs.reduce((a, g) => a + g.n - g.pos, 0)
  if (!P || !N) return NaN
  let negBelow = N, sum = 0
  for (const g of gs) {             // high to low
    const neg = g.n - g.pos
    negBelow -= neg
    sum += g.pos * (negBelow + neg / 2)
  }
  return sum / (P * N)
}

/** Expected positives in the top k. */
function hitsAt(gs: Group[], k: number): number {
  let seen = 0, hits = 0
  for (const g of gs) {
    if (seen + g.n <= k) { seen += g.n; hits += g.pos; continue }
    hits += g.pos * (k - seen) / g.n
    break
  }
  return hits
}

/** Average precision, positives in a tie group placed at their expected ranks. */
function avgPrecision(gs: Group[]): number {
  const P = gs.reduce((a, g) => a + g.pos, 0)
  if (!P) return NaN
  let seen = 0, hits = 0, sum = 0
  for (const g of gs) {
    for (let i = 1; i <= g.pos; i++) sum += (hits + i) / (seen + i * (g.n + 1) / (g.pos + 1))
    seen += g.n; hits += g.pos
  }
  return sum / P
}

/** Share of the list worked through, in rank order, to cover a share of the positives. */
function effortFor(gs: Group[], coverage: number): number {
  const total = gs.reduce((a, g) => a + g.n, 0), P = gs.reduce((a, g) => a + g.pos, 0)
  const need = coverage * P
  let seen = 0, hits = 0
  for (const g of gs) {
    if (hits + g.pos >= need - 1e-9) return (seen + (g.pos ? g.n * (need - hits) / g.pos : 0)) / total
    seen += g.n; hits += g.pos
  }
  return 1
}

/** Mean rank percentile (0 = top of the list) of the given items under a score. */
function percentileOf(all: number[], s: number): number {
  const above = all.filter((x) => x > s).length, tied = all.filter((x) => x === s).length
  return (above + (tied - 1) / 2) / Math.max(1, all.length - 1)
}

// Seeded PRNG, so the bootstrap is repeatable
function rng(seed: number) {
  return () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 2 ** 32 }
}

// ── Main ───────────────────────────────────────────────────────────────────────

type Ranker = { key: string; label: string; score: (i: Item) => number }
const RANKERS: Ranker[] = [
  { key: 'cvss', label: 'CVSS only', score: (i) => i.cvss },
  { key: 'epss', label: 'EPSS only', score: (i) => i.epss },
  { key: 'composite_no_cti', label: 'Composite, no CTI bonus', score: (i) => computeRiskScore(i.cvss, i.epss, i.crit, false) },
  { key: 'composite', label: 'Composite as deployed', score: (i) => computeRiskScore(i.cvss, i.epss, i.crit, i.cti) },
]

async function main() {
  const sql = neon(url)
  let tenantId: string | null = null
  if (slug) {
    const [t] = await sql`SELECT tenant_id FROM tenants WHERE slug = ${slug}` as Record<string, unknown>[]
    if (!t) die(`tenant "${slug}" not found`)
    tenantId = t['tenant_id'] as string
  }
  const rows = await sql`
    SELECT e.details->>'cve_id' AS cve, (e.details->>'cvss_base_score')::float AS cvss,
           (e.details->>'epss_score')::float AS epss, COALESCE((e.details->>'has_cti_match')::boolean, false) AS cti,
           e.composite_risk_score::float AS stored, e.first_seen, a.criticality_score AS crit, e.status
    FROM events e JOIN assets a ON a.asset_id = e.asset_id
    WHERE e.event_type = 'cve_detected' AND e.details->>'cve_id' LIKE 'CVE-%'
      AND (${tenantId}::uuid IS NULL OR a.tenant_id = ${tenantId}::uuid)` as Record<string, unknown>[]
  if (!rows.length) die('no CVE alerts found')

  const kev = await fetchKev()
  const alerts: Item[] = rows.map((r) => {
    const cve = r['cve'] as string
    return {
      cve, cvss: (r['cvss'] as number) ?? 0, epss: (r['epss'] as number) ?? 0, crit: (r['crit'] as number) ?? 5,
      cti: !!r['cti'], stored: r['stored'] as number | null, firstSeen: new Date(r['first_seen'] as string),
      kev: kev.has(cve), kevAdded: kev.get(cve) ?? null,
    }
  })

  // Stored score vs the formula on today's inputs. Ingest rescores an alert on every SBOM
  // upload; closed alerts keep the score they had, and criticality may have changed since.
  const matches = (a: Item) => a.stored != null && Math.abs(a.stored - computeRiskScore(a.cvss, a.epss, a.crit, a.cti)) < 0.01
  const consistent = alerts.filter(matches).length
  const openIdx = rows.map((r, i) => (r['status'] === 'open' || r['status'] === 'in_progress' ? i : -1)).filter((i) => i >= 0)
  const openConsistent = openIdx.filter((i) => matches(alerts[i]!)).length
  // explained by criticality alone: some criticality 1-10 reproduces the stored score
  const critOnly = alerts.filter((a) => !matches(a) && a.stored != null &&
    Array.from({ length: 10 }, (_, k) => k + 1).some((c) => Math.abs(a.stored! - computeRiskScore(a.cvss, a.epss, c, a.cti)) < 0.01)).length

  // One row per CVE: the worst case across the assets it is on
  const byCve = new Map<string, Item>()
  for (const a of alerts) {
    const b = byCve.get(a.cve)
    if (!b) { byCve.set(a.cve, { ...a }); continue }
    b.cvss = Math.max(b.cvss, a.cvss); b.epss = Math.max(b.epss, a.epss); b.crit = Math.max(b.crit, a.crit)
    b.cti ||= a.cti
    if (a.firstSeen < b.firstSeen) b.firstSeen = a.firstSeen
  }
  let cves = [...byCve.values()]

  let epssNote = 'stored EPSS (as fetched at ingest; missing lookups are 0)'
  if (freshEpss) {
    const fresh = await fetchEpss(cves.map((c) => c.cve))
    cves = cves.map((c) => ({ ...c, epss: fresh.get(c.cve) ?? 0 }))
    epssNote = `EPSS fetched today from FIRST.org for ${fresh.size}/${cves.length} CVEs (later than the alerts: optimistic)`
  }

  const P = cves.filter((c) => c.kev).length
  const report: Record<string, unknown> = {
    generated: new Date().toISOString(), target, scope: slug ? 'one tenant' : 'all tenants', epss: epssNote,
    alerts: alerts.length, open_alerts: rows.filter((r) => r['status'] === 'open').length,
    unique_cves: cves.length, kev_cves: P,
    kev_share: P / cves.length,
    epss_present: cves.filter((c) => c.epss > 0).length,
    stored_matches_formula: {
      matching: consistent, of: alerts.filter((a) => a.stored != null).length,
      open_matching: openConsistent, open_of: openIdx.length, other_criticality_explains: critOnly,
    },
    rankers: {} as Record<string, unknown>,
  }

  console.log(`\n${target}${slug ? ` / ${slug}` : ''}: ${alerts.length} CVE alerts, ${cves.length} unique CVEs, ${P} in KEV (${(100 * P / cves.length).toFixed(1)}%)`)
  console.log(`EPSS: ${epssNote}; non-zero for ${report['epss_present']}/${cves.length}`)
  console.log(`Stored score equals the formula on current inputs for ${consistent}/${(report['stored_matches_formula'] as { of: number }).of} alerts (open: ${openConsistent}/${openIdx.length}); ${critOnly} of the rest match with a different criticality`)

  if (!P) {
    console.log('\nNo KEV CVEs among the findings: ranking metrics need at least one positive.')
  } else {
    const ks = [10, 25, 50, 100].filter((k) => k < cves.length)
    console.log(`\n${'Ranker'.padEnd(26)} ${'AUC'.padStart(6)} ${'AP'.padStart(6)} ${ks.map((k) => `KEV@${k}`.padStart(8)).join(' ')} ${'Effort50%'.padStart(10)} ${'Effort100%'.padStart(11)}`)
    for (const r of RANKERS) {
      const gs = groupsOf(cves.map((c) => ({ s: r.score(c), y: c.kev })))
      const m = {
        auc: auc(gs), ap: avgPrecision(gs),
        kev_at: Object.fromEntries(ks.map((k) => [k, hitsAt(gs, k)])),
        effort_50: effortFor(gs, 0.5), effort_100: effortFor(gs, 1),
      }
      ;(report['rankers'] as Record<string, unknown>)[r.key] = { label: r.label, ...m }
      console.log(`${r.label.padEnd(26)} ${m.auc.toFixed(3).padStart(6)} ${m.ap.toFixed(3).padStart(6)} ${ks.map((k) => m.kev_at[k]!.toFixed(1).padStart(8)).join(' ')} ${(100 * m.effort_50).toFixed(1).padStart(9)}% ${(100 * m.effort_100).toFixed(1).padStart(10)}%`)
    }
    console.log(`Random ranking: AUC 0.500, AP ${(P / cves.length).toFixed(3)}`)

    // Bootstrap (CVEs resampled) for AUC(composite, no CTI) − AUC(CVSS)
    const rand = rng(20261116), B = 1000, diffs: number[] = []
    const comp = RANKERS[2]!, cvss = RANKERS[0]!
    for (let b = 0; b < B; b++) {
      const s = Array.from({ length: cves.length }, () => cves[Math.floor(rand() * cves.length)]!)
      const d = auc(groupsOf(s.map((c) => ({ s: comp.score(c), y: c.kev })))) - auc(groupsOf(s.map((c) => ({ s: cvss.score(c), y: c.kev }))))
      if (!Number.isNaN(d)) diffs.push(d)
    }
    diffs.sort((a, b) => a - b)
    const ci = [diffs[Math.floor(0.025 * diffs.length)], diffs[Math.floor(0.975 * diffs.length)]]
    report['auc_gain_vs_cvss'] = { mean: diffs.reduce((a, d) => a + d, 0) / diffs.length, ci95: ci, resamples: diffs.length }
    console.log(`\nAUC gain of composite (no CTI) over CVSS: ${(report['auc_gain_vs_cvss'] as { mean: number }).mean.toFixed(3)} (95% CI ${ci[0]?.toFixed(3)} to ${ci[1]?.toFixed(3)}, ${diffs.length} bootstrap resamples)`)

    // Equal-effort comparison with the common "fix everything CVSS ≥ 7" policy (Jacobs et al.)
    const policy = cves.filter((c) => c.cvss >= 7)
    const effort = policy.length
    const kevIn = (xs: Item[]) => xs.filter((c) => c.kev).length
    const topBy = (r: Ranker) => [...cves].sort((a, b) => r.score(b) - r.score(a)).slice(0, effort)
    const eq = {
      effort: effort, effort_share: effort / cves.length,
      cvss7: { coverage: kevIn(policy) / P, efficiency: kevIn(policy) / Math.max(1, effort) },
      composite_no_cti: { coverage: kevIn(topBy(comp)) / P, efficiency: kevIn(topBy(comp)) / Math.max(1, effort) },
    }
    report['equal_effort_vs_cvss7'] = eq
    console.log(`\nPolicy "fix CVSS ≥ 7": ${effort} CVEs (${(100 * eq.effort_share).toFixed(1)}%), KEV coverage ${(100 * eq.cvss7.coverage).toFixed(1)}%, efficiency ${(100 * eq.cvss7.efficiency).toFixed(1)}%`)
    console.log(`Same effort, top by composite (no CTI): KEV coverage ${(100 * eq.composite_no_cti.coverage).toFixed(1)}%, efficiency ${(100 * eq.composite_no_cti.efficiency).toFixed(1)}%`)

    // Temporal check: added to KEV after the alert was raised
    const later = cves.filter((c) => c.kevAdded && c.kevAdded > c.firstSeen)
    const allScores = Object.fromEntries(RANKERS.map((r) => [r.key, cves.map(r.score)]))
    report['added_to_kev_after_alert'] = later.map((c) => ({
      cve: c.cve, first_seen: c.firstSeen.toISOString().slice(0, 10), kev_added: c.kevAdded!.toISOString().slice(0, 10),
      cvss: c.cvss, epss: c.epss,
      percentile: Object.fromEntries(RANKERS.slice(0, 3).map((r) => [r.key, percentileOf(allScores[r.key]!, r.score(c))])),
    }))
    console.log(`\nAdded to KEV after the alert was raised: ${later.length}`)
    for (const l of report['added_to_kev_after_alert'] as Array<{ cve: string; kev_added: string; percentile: Record<string, number> }>) {
      console.log(`  ${l.cve} (KEV ${l.kev_added}): rank percentile CVSS ${(100 * l.percentile['cvss']!).toFixed(1)}%, EPSS ${(100 * l.percentile['epss']!).toFixed(1)}%, composite ${(100 * l.percentile['composite_no_cti']!).toFixed(1)}%  (0% = top)`)
    }
  }

  if (outDir) {
    mkdirSync(outDir, { recursive: true })
    const file = path.join(outDir, `risk-reliability-${target}${freshEpss ? '-fresh-epss' : ''}.json`)
    writeFileSync(file, JSON.stringify(report, null, 2))
    console.log(`\nWrote ${file}`)
  }
}

main().catch((e) => die(e instanceof Error ? e.message : String(e)))
