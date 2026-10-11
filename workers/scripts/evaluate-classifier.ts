/**
 * evaluate-classifier.ts — READ-ONLY accuracy check of device classification against
 * a labelled set: how often the original port/OS classifier and classifier v2 (with
 * hints) get the type right, and the precision and coverage of every hint rule. This
 * is the measurement that decides whether a suggestion rule may become automatic.
 *
 * Labels: a CSV you keep OUTSIDE the repository (it identifies your devices):
 *     key,type,note
 *     0e:18:7c:8f:fd:91,mobile,Jo's iPad
 *     192.168.100.165,workstation,HMSB laptop
 * key = MAC (preferred, survives DHCP) or IPv4; type = server | workstation | network |
 * iot | mobile | unknown (unknown = you do not know either; such rows are skipped).
 *
 * Run from workers/ (reads .env.<target>; DB_TARGET must match):
 *   npx esbuild scripts/evaluate-classifier.ts --bundle --platform=node --format=cjs --outfile=.evaluate-classifier.cjs
 *   node .evaluate-classifier.cjs --target staging --tenant agent-v2-test --labels C:\path\labels.csv
 */
import { readFileSync, existsSync } from 'node:fs'
import path from 'node:path'
import { neon } from '@neondatabase/serverless'
import { applyHint, deviceTypeHint, type DeviceTypeHint } from '../src/lib/deviceHints'

const TYPES = ['server', 'workstation', 'network', 'iot', 'mobile', 'unknown']
function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`)
  return i > 0 ? process.argv[i + 1] : undefined
}
function die(msg: string): never { console.error(`\nERROR: ${msg}`); process.exit(1) }

const target = arg('target') ?? 'staging'
const slug = arg('tenant') ?? die('--tenant <slug> is required')
const labelsPath = arg('labels') ?? die('--labels <csv> is required')
if (!['staging', 'production'].includes(target)) die('--target must be staging or production')
if (!existsSync(labelsPath)) die(`${labelsPath} not found`)

const envFile = path.resolve(process.cwd(), `.env.${target}`)
if (!existsSync(envFile)) die(`${envFile} not found (run from workers/)`)
const vars: Record<string, string> = {}
for (const raw of readFileSync(envFile, 'utf8').replace(/^\uFEFF/, '').split(/\r?\n/)) {
  const line = raw.trim(); const eq = line.indexOf('=')
  if (line && !line.startsWith('#') && eq > 0) vars[line.slice(0, eq).trim()] = line.slice(eq + 1).trim().replace(/^(['"])(.*)\1$/, '$2')
}
if (vars['DB_TARGET'] !== target) die(`${path.basename(envFile)} has DB_TARGET="${vars['DB_TARGET'] ?? ''}", not "${target}"`)

const labels = new Map<string, { type: string; note: string }>()
for (const [i, raw] of readFileSync(labelsPath, 'utf8').replace(/^\uFEFF/, '').split(/\r?\n/).entries()) {
  const [key, type, ...note] = raw.split(',').map(s => s.trim())
  if (!key || (i === 0 && key.toLowerCase() === 'key')) continue
  if (!type || !TYPES.includes(type)) die(`line ${i + 1}: type must be one of ${TYPES.join(', ')}`)
  labels.set(key.toLowerCase(), { type, note: note.join(',') })
}

interface Row { name: string; truth: string; note: string; before: string; after: string; source: string; hint: DeviceTypeHint | null }

async function main() {
  const sql = neon(vars['DATABASE_URL']!)
  const [tenant] = await sql`SELECT tenant_id FROM tenants WHERE slug = ${slug}` as Record<string, unknown>[]
  if (!tenant) die(`tenant "${slug}" not found`)
  const assets = await sql`
    SELECT ip_address, mac_address, hostname, hardware_vendor, device_type, device_type_source, os_info
    FROM assets WHERE tenant_id = ${tenant['tenant_id'] as string}` as Record<string, unknown>[]

  const rows: Row[] = []
  const unmatched = new Set(labels.keys())
  for (const a of assets) {
    const mac = String(a['mac_address'] ?? '').toLowerCase()
    const ip = String(a['ip_address'] ?? '')
    const key = labels.has(mac) ? mac : labels.has(ip) ? ip : null
    if (!key) continue
    unmatched.delete(key)
    const label = labels.get(key)!
    if (label.type === 'unknown') continue
    const hint = deviceTypeHint({ hostname: a['hostname'] as string | null, mac, vendor: a['hardware_vendor'] as string | null, osInfo: a['os_info'] as Record<string, unknown> | null })
    const stored = String(a['device_type']), source = String(a['device_type_source'])
    // "Before" = what the original port/OS rules (plus hand/agent types) produced: a type
    // a hint filled automatically counts as unknown there.
    const filledByHint = source === 'auto' && !!hint?.auto && hint.type === stored
    const before = filledByHint ? 'unknown' : stored
    const after = applyHint({ deviceType: before, deviceTypeSource: source }, hint).deviceType
    rows.push({ name: (a['hostname'] as string | null) ?? ip, truth: label.type, note: label.note, before, after, source, hint })
  }
  if (!rows.length) die('no labelled asset matched (check the MACs / IPs)')

  const pct = (n: number, d: number) => (d ? `${Math.round((100 * n) / d)}%` : '—')
  const right = (k: 'before' | 'after') => rows.filter(r => r[k] === r.truth).length
  const unknown = (k: 'before' | 'after') => rows.filter(r => r[k] === 'unknown').length
  const wrong = (k: 'before' | 'after') => rows.filter(r => r[k] !== 'unknown' && r[k] !== r.truth).length

  console.log(`\nLabelled assets matched: ${rows.length}${unmatched.size ? ` (${unmatched.size} label(s) matched no asset)` : ''}\n`)
  console.log('                      correct   unknown   WRONG (classified, but incorrectly)')
  for (const k of ['before', 'after'] as const) {
    console.log(`${k === 'before' ? 'port/OS rules only ' : 'with automatic hints'}  ${pct(right(k), rows.length).padStart(7)}   ${pct(unknown(k), rows.length).padStart(7)}   ${pct(wrong(k), rows.length).padStart(7)}`)
  }

  console.log('\nHint rules (all of them, automatic or not):')
  console.log('rule                    conf    fired   correct   precision   coverage')
  const byRule = new Map<string, Row[]>()
  for (const r of rows) if (r.hint) byRule.set(r.hint.rule, [...(byRule.get(r.hint.rule) ?? []), r])
  for (const [rule, rs] of byRule) {
    // A rule that names no type (Apple device) is "correct" when the true type is one an Apple device can be.
    const ok = rs.filter(r => r.hint!.type ? r.hint!.type === r.truth : ['mobile', 'workstation', 'iot'].includes(r.truth)).length
    console.log(`${rule.padEnd(22)}  ${rs[0]!.hint!.confidence.padEnd(6)}  ${String(rs.length).padStart(5)}   ${String(ok).padStart(7)}   ${pct(ok, rs.length).padStart(9)}   ${pct(rs.length, rows.length).padStart(8)}`)
  }

  console.log('\nConfusion (rows = true type, columns = classifier v2 with automatic hints):')
  const used = TYPES.filter(t => rows.some(r => r.truth === t || r.after === t))
  console.log(`${''.padEnd(12)}${used.map(t => t.slice(0, 10).padStart(11)).join('')}`)
  for (const t of used.filter(t => rows.some(r => r.truth === t))) {
    console.log(`${t.padEnd(12)}${used.map(c => String(rows.filter(r => r.truth === t && r.after === c).length).padStart(11)).join('')}`)
  }

  const misses = rows.filter(r => r.after !== r.truth)
  if (misses.length) {
    console.log('\nNot right yet:')
    for (const r of misses) {
      console.log(`  ${r.name} (${r.note || 'no note'}): true ${r.truth}, got ${r.after}${r.hint ? ` · suggestion: ${r.hint.label} [${r.hint.rule}, ${r.hint.confidence}] from ${r.hint.evidence}` : ' · no hint'}`)
    }
  }
  console.log('\nRead the precision column with the sample size: a rule that fired 2 times proves little.')
}

main().catch(e => die((e as Error).message))
