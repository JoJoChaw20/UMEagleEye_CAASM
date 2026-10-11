/**
 * compare-scorers.ts — READ-ONLY side-by-side of criticality v1 and v2 for every asset
 * of one tenant, with the reasons, plus agent coverage and endpoint posture. For
 * reviewing v2 on staging before switching, and for the report.
 *
 * Run from workers/ (reads .env.<target>; DB_TARGET must match, as in scripts/db):
 *   npx esbuild scripts/compare-scorers.ts --bundle --platform=node --format=cjs --outfile=.compare-scorers.cjs
 *   node .compare-scorers.cjs --target staging --tenant agent-v2-test [--csv scores.csv]
 *
 * Only SELECTs are issued; nothing is written to the database.
 */
import { readFileSync, existsSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { neon } from '@neondatabase/serverless'
import { agentRoleOf, scoreDetail, type ScoreInput } from '../src/lib/rescore'
import { evaluatePosture } from '../src/lib/endpointPosture'
import { summarizeCoverage } from '../src/lib/coverage'
import type { ScoringResultV2 } from '../src/lib/criticalityV2'

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`)
  return i > 0 ? process.argv[i + 1] : undefined
}
function die(msg: string): never { console.error(`\nERROR: ${msg}`); process.exit(1) }

const target = arg('target') ?? 'staging'
const slug = arg('tenant') ?? die('--tenant <slug> is required (e.g. agent-v2-test)')
const csvOut = arg('csv')
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

async function main() {
  const sql = neon(url)
  const [tenant] = await sql`SELECT tenant_id, name, criticality_model FROM tenants WHERE slug = ${slug}` as Record<string, unknown>[]
  if (!tenant) die(`tenant "${slug}" not found`)
  const rows = await sql`
    SELECT asset_id, hostname, ip_address, device_type, device_type_source, is_internet_facing, internet_facing_override,
           os_info, owner, endpoint_inventory, inventory_collected_at, criticality_score, criticality_model,
           posture_score, posture_checks, in_my_assets
    FROM assets WHERE tenant_id = ${tenant['tenant_id'] as string}` as Record<string, unknown>[]

  console.log(`\nTenant ${tenant['name']} (${slug}) on ${target}: ${rows.length} assets, active formula v${tenant['criticality_model']}\n`)

  const out = rows.map(r => {
    const input: ScoreInput = {
      deviceType: r['device_type'] as string, deviceTypeSource: r['device_type_source'] as string,
      isInternetFacing: r['is_internet_facing'] as boolean, internetFacingOverride: r['internet_facing_override'] as boolean | null,
      hostname: r['hostname'] as string | null, osInfo: r['os_info'] as Record<string, unknown> | null,
      owner: r['owner'] as string | null, agentRole: agentRoleOf(r['endpoint_inventory']),
    }
    const v1 = scoreDetail(input, 1), v2 = scoreDetail(input, 2) as ScoringResultV2
    const posture = r['endpoint_inventory'] ? evaluatePosture(r['endpoint_inventory']).score : null
    return { r, v1, v2, posture, name: (r['hostname'] as string | null) ?? (r['ip_address'] as string) }
  }).sort((a, b) => (b.v2.score - b.v1.score) - (a.v2.score - a.v1.score) || a.name.localeCompare(b.name))

  const pad = (s: unknown, n: number) => String(s ?? '').slice(0, n).padEnd(n)
  console.log(`${pad('Asset', 26)} ${pad('Type', 12)} ${pad('Source', 7)} ${pad('v1', 3)} ${pad('v2', 3)} ${pad('Δ', 3)} ${pad('Conf', 6)} ${pad('Posture', 8)} Why it differs`)
  for (const o of out) {
    const d = o.v2.score - o.v1.score
    const v1Owner = o.v1.factors.some(f => f.startsWith('unowned'))
    const why: string[] = []
    if (v1Owner) why.push('no owner no longer counts (−1)')
    if (o.v2.breakdown.role) why.push('directory service role (+2)')
    if (o.v2.unknowns.length) why.push(`unknown: ${o.v2.unknowns.join(', ')}`)
    console.log(`${pad(o.name, 26)} ${pad(o.r['device_type'], 12)} ${pad(o.r['device_type_source'], 7)} ${pad(o.v1.score, 3)} ${pad(o.v2.score, 3)} ${pad(d > 0 ? `+${d}` : d, 3)} ${pad(o.v2.confidence, 6)} ${pad(o.posture ?? 'n/a', 8)} ${why.join('; ')}`)
  }

  const changed = out.filter(o => o.v1.score !== o.v2.score)
  const avg = (k: 'v1' | 'v2') => out.length ? (out.reduce((n, o) => n + o[k].score, 0) / out.length).toFixed(2) : '-'
  const high = (k: 'v1' | 'v2') => out.filter(o => o[k].score >= 8).length
  console.log(`\nChanged: ${changed.length} of ${out.length} (up ${changed.filter(o => o.v2.score > o.v1.score).length}, down ${changed.filter(o => o.v2.score < o.v1.score).length})`)
  console.log(`Average: v1 ${avg('v1')}, v2 ${avg('v2')} · high-criticality (≥8): v1 ${high('v1')}, v2 ${high('v2')}`)
  console.log(`v2 confidence: high ${out.filter(o => o.v2.confidence === 'high').length}, medium ${out.filter(o => o.v2.confidence === 'medium').length}, low ${out.filter(o => o.v2.confidence === 'low').length}`)

  const cov = summarizeCoverage(rows.map(r => ({
    asset_id: r['asset_id'] as string, hostname: r['hostname'] as string | null, ip: r['ip_address'] as string,
    device_type: r['device_type'] as string, criticality: r['criticality_score'] as number,
    inventory_at: r['inventory_collected_at'] as string | null,
    posture_score: r['endpoint_inventory'] ? evaluatePosture(r['endpoint_inventory']).score : null,
    posture_checks: r['endpoint_inventory'] ? evaluatePosture(r['endpoint_inventory']).checks : null,
  })))
  console.log(`\nAgent coverage: ${cov.with_agent} with agent; ${cov.no_agent.count} of ${cov.agent_capable} servers/PCs without; ${cov.not_applicable} network/IoT n/a; ${cov.unidentified} unidentified`)
  console.log(`Endpoint posture: ${cov.posture.average ?? '—'} across ${cov.posture.assessed} assessed; ${cov.posture.unassessed} unassessed`)
  for (const f of cov.posture.failing) console.log(`  ${f.label}: ${f.bad} at risk, ${f.warn} to review`)

  if (csvOut) {
    const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`
    const lines = ['asset,ip,type,type_source,in_my_assets,v1,v2,delta,confidence,posture,v2_factors']
    for (const o of out) lines.push([o.name, o.r['ip_address'], o.r['device_type'], o.r['device_type_source'], o.r['in_my_assets'],
      o.v1.score, o.v2.score, o.v2.score - o.v1.score, o.v2.confidence, o.posture ?? '', o.v2.factors.join(' | ')].map(esc).join(','))
    writeFileSync(csvOut, lines.join('\n'))
    console.log(`\nWrote ${csvOut}`)
  }
}

main().catch(e => die((e as Error).message))
