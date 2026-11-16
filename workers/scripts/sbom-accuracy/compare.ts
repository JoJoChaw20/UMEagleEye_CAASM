/**
 * compare.ts — READ-ONLY accuracy of the SBOM to CVE pipeline on the labelled test set
 * (scripts/sbom-accuracy/README.md), end to end: what the agent's Syft run detected and the
 * CVE alerts UMEagleEye raised for it, against OSV.dev (official advisories from GitHub,
 * PyPI, npm, Maven and NuGet sources, aggregated by Google), not against Grype itself.
 *
 *  Detection   each planted package found at its exact version (dependencies table)
 *  Vulnerable  OSV advisories, merged by alias into one vulnerability each (a CVE, its GHSA
 *              and PYSEC ids are one); recall = vulnerabilities with an alert / all;
 *              precision = alerts that are one of the package's vulnerabilities / all alerts
 *  Clean       alerts on the clean controls (should be none)
 *
 * Run from workers/ after the VM's SBOM has been uploaded:
 *   npx esbuild scripts/sbom-accuracy/compare.ts --bundle --platform=node --format=cjs --outfile=.sbom-accuracy.cjs
 *   node .sbom-accuracy.cjs --target staging --host <hostname> [--truth <saved.json>] [--out <dir>]
 *
 * The OSV answer is saved with its date (--out), so a later run can reuse it with --truth.
 * Only SELECTs are issued on the database.
 */
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs'
import path from 'node:path'
import { neon } from '@neondatabase/serverless'

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`)
  return i > 0 ? process.argv[i + 1] : undefined
}
function die(msg: string): never { console.error(`\nERROR: ${msg}`); process.exit(1) }

const target = arg('target') ?? 'staging'
// --truth-only: fetch and save the OSV ground truth, nothing else (no database)
const truthOnly = process.argv.includes('--truth-only')
const host = arg('host') ?? (truthOnly ? '' : die('--host <hostname of the VM> is required'))
const outDir = arg('out')
const truthFile = arg('truth')
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

interface Pkg { ecosystem: string; name: string; version: string; expect: 'vulnerable' | 'clean' }
const manifest = JSON.parse(readFileSync(path.resolve('scripts/sbom-accuracy/manifest.json'), 'utf8')) as { packages: Pkg[] }

// The name Syft and Grype give a package: Maven by artifact id; names compared normalised (PEP 503 style).
const norm = (s: string) => s.toLowerCase().replace(/[-_.]+/g, '-')
const shortName = (p: Pkg) => norm(p.ecosystem === 'Maven' ? p.name.split(':')[1]! : p.name)

// ── Ground truth from OSV ──
interface Vuln { ids: string[]; summary: string }      // one vulnerability: all its ids (id + aliases)
type Truth = { fetched: string; packages: Record<string, Vuln[]> }

async function osvTruth(pkgs: Pkg[]): Promise<Truth> {
  const res = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ queries: pkgs.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }),
  })
  if (!res.ok) die(`OSV querybatch: HTTP ${res.status}`)
  const batch = await res.json() as { results: Array<{ vulns?: Array<{ id: string }> }> }
  const out: Truth = { fetched: new Date().toISOString(), packages: {} }
  for (const [i, p] of pkgs.entries()) {
    const ids = (batch.results[i]?.vulns ?? []).map((v) => v.id)
    const details = await Promise.all(ids.map(async (id) => {
      const r = await fetch(`https://api.osv.dev/v1/vulns/${id}`)
      return r.ok ? await r.json() as { id: string; aliases?: string[]; withdrawn?: string; summary?: string; details?: string } : null
    }))
    // merge advisories that share an id (CVE / GHSA / PYSEC for the same flaw)
    const groups: Vuln[] = []
    for (const d of details) {
      if (!d || d.withdrawn) continue
      const all = [d.id, ...(d.aliases ?? [])]
      const hit = groups.filter((g) => g.ids.some((x) => all.includes(x)))
      const merged: Vuln = { ids: [...new Set([...all, ...hit.flatMap((g) => g.ids)])], summary: hit[0]?.summary || d.summary || (d.details ?? '').slice(0, 100) }
      for (const g of hit) groups.splice(groups.indexOf(g), 1)
      groups.push(merged)
    }
    out.packages[`${p.ecosystem}:${p.name}@${p.version}`] = groups
  }
  return out
}

async function main() {
  const pkgs = manifest.packages
  const truth: Truth = truthFile ? JSON.parse(readFileSync(truthFile, 'utf8')) : await osvTruth(pkgs)
  if (truthOnly) {
    for (const p of pkgs) {
      const v = truth.packages[`${p.ecosystem}:${p.name}@${p.version}`] ?? []
      console.log(`${p.ecosystem.padEnd(6)} ${`${p.name} ${p.version}`.padEnd(48)} ${p.expect.padEnd(10)} ${v.length} vulnerabilities`)
    }
    if (outDir) {
      mkdirSync(outDir, { recursive: true })
      writeFileSync(path.join(outDir, `sbom-accuracy-truth-${truth.fetched.slice(0, 10)}.json`), JSON.stringify(truth, null, 2))
      console.log(`\nWrote ${outDir}`)
    }
    return
  }

  const sql = neon(url)
  const found = await sql`SELECT asset_id, hostname FROM assets WHERE hostname ILIKE ${host} OR hostname ILIKE ${host + '.%'}` as Array<{ asset_id: string; hostname: string }>
  // an exact name wins over "name.local" (the same machine as heard by mDNS)
  const exact = found.filter((a) => a.hostname.toLowerCase() === host.toLowerCase())
  const assets = exact.length === 1 ? exact : found
  if (assets.length !== 1) die(`expected one asset named "${host}", found ${assets.length}: ${assets.map((a) => a.hostname).join(', ')}`)
  const assetId = assets[0]!.asset_id
  const [sbom] = await sql`SELECT sbom_id, generated_at FROM sboms WHERE asset_id = ${assetId} ORDER BY generated_at DESC LIMIT 1` as Array<{ sbom_id: string; generated_at: string }>
  if (!sbom) die('no SBOM uploaded for this asset yet')
  const deps = await sql`SELECT name, version, package_manager FROM dependencies WHERE sbom_id = ${sbom.sbom_id}` as Array<{ name: string; version: string; package_manager: string | null }>
  // What the pipeline reports per CVE: the present findings of open SBOM package alerts
  // (lib/packageAlerts.ts), plus any old per-CVE alerts not converted yet.
  const alerts = await sql`
    SELECT f.cve_id AS id, f.package_name AS pkg, f.package_version AS ver, NULL::jsonb AS affected, e.status::text AS status
    FROM cve_findings f JOIN events e ON e.event_id = f.event_id
    WHERE f.asset_id = ${assetId} AND f.fixed_at IS NULL AND NOT f.dismissed AND e.status IN ('open', 'in_progress')
    UNION ALL
    SELECT details->>'cve_id', details->>'package_name', details->>'package_version', details->'affected_versions', status::text
    FROM events WHERE asset_id = ${assetId} AND event_type = 'cve_detected' AND status IN ('open', 'in_progress')
      AND details->>'shape' IS DISTINCT FROM 'package'` as Array<{ id: string; pkg: string; ver: string; affected: unknown; status: string }>
  const [{ n: packageAlerts }] = await sql`SELECT count(*)::int AS n FROM events WHERE asset_id = ${assetId}
    AND event_type = 'cve_detected' AND status IN ('open', 'in_progress')` as Array<{ n: number }>

  type Eco = { planted: number; detected: number; vulns: number; found: number; alerts: number; correct: number; clean_alerts: number }
  const eco: Record<string, Eco> = {}
  const rows: Record<string, unknown>[] = []
  const misses: string[] = [], wrong: string[] = []
  for (const p of pkgs) {
    const e = eco[p.ecosystem] ??= { planted: 0, detected: 0, vulns: 0, found: 0, alerts: 0, correct: 0, clean_alerts: 0 }
    e.planted++
    const detected = deps.some((d) => norm(d.name) === shortName(p) && d.version === p.version)
    if (detected) e.detected++
    const vulns = truth.packages[`${p.ecosystem}:${p.name}@${p.version}`] ?? []
    const mine = alerts.filter((a) => norm(a.pkg ?? '') === shortName(p)
      && (a.ver === p.version || JSON.stringify(a.affected ?? []).includes(`"${p.version}"`)))
    const ids = new Set(mine.map((a) => a.id))
    const found = vulns.filter((v) => v.ids.some((id) => ids.has(id)))
    const correct = mine.filter((a) => vulns.some((v) => v.ids.includes(a.id)))
    e.vulns += vulns.length; e.found += found.length; e.alerts += mine.length; e.correct += correct.length
    if (p.expect === 'clean') e.clean_alerts += mine.length
    for (const v of vulns.filter((v) => !found.includes(v))) misses.push(`${p.name} ${p.version}: ${v.ids.filter((x) => x.startsWith('CVE-'))[0] ?? v.ids[0]} ${v.summary ?? ''}`.slice(0, 140))
    for (const a of mine.filter((a) => !correct.includes(a))) wrong.push(`${p.name} ${p.version}: ${a.id}`)
    rows.push({ ecosystem: p.ecosystem, package: `${p.name} ${p.version}`, expect: p.expect, detected,
      osv_vulns: vulns.length, alerts: mine.length, found: found.length, wrong: mine.length - correct.length })
  }

  console.log(`\nAsset ${assets[0]!.hostname}: SBOM ${sbom.generated_at}, ${deps.length} packages, ${alerts.length} open CVE findings in ${packageAlerts} open SBOM alert(s); OSV truth fetched ${truth.fetched}`)
  console.table(rows)
  const sum = (k: keyof Eco) => Object.values(eco).reduce((a, e) => a + e[k], 0)
  const summary = Object.fromEntries([...Object.entries(eco), ['ALL', {
    planted: sum('planted'), detected: sum('detected'), vulns: sum('vulns'), found: sum('found'),
    alerts: sum('alerts'), correct: sum('correct'), clean_alerts: sum('clean_alerts') }]].map(([k, e]) => {
    const x = e as Eco
    return [k, { ...x, detection: x.detected / x.planted, recall: x.vulns ? x.found / x.vulns : null, precision: x.alerts ? x.correct / x.alerts : null }]
  }))
  console.log('\nBy ecosystem (detection = found at the exact version; recall over OSV vulnerabilities; precision over alerts):')
  console.table(Object.fromEntries(Object.entries(summary).map(([k, s]) => [k, {
    detected: `${s.detected}/${s.planted}`, recall: s.recall == null ? 'n/a' : `${s.found}/${s.vulns} (${(100 * s.recall).toFixed(1)}%)`,
    precision: s.precision == null ? 'n/a' : `${s.correct}/${s.alerts} (${(100 * s.precision).toFixed(1)}%)`, clean_alerts: s.clean_alerts }])))
  if (misses.length) console.log(`\nMissed (in OSV, no alert): ${misses.length}\n  ${misses.join('\n  ')}`)
  if (wrong.length) console.log(`\nAlerts OSV does not list for that version: ${wrong.length}\n  ${wrong.join('\n  ')}`)

  if (outDir) {
    mkdirSync(outDir, { recursive: true })
    const tag = assets[0]!.hostname.toLowerCase().replace(/[^a-z0-9]+/g, '-')
    writeFileSync(path.join(outDir, `sbom-accuracy-truth-${truth.fetched.slice(0, 10)}.json`), JSON.stringify(truth, null, 2))
    writeFileSync(path.join(outDir, `sbom-accuracy-${tag}.json`), JSON.stringify({ host: assets[0]!.hostname, sbom: sbom.generated_at, truth_fetched: truth.fetched, open_sbom_alerts: packageAlerts, open_cve_findings: alerts.length, summary, rows, misses, wrong }, null, 2))
    console.log(`\nWrote results to ${outDir}`)
  }
}

main().catch((e) => die(e instanceof Error ? e.message : String(e)))
