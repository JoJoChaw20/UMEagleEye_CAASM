/**
 * backfill-attack.ts — one-off: give stored feed indicators the ATT&CK techniques of their malware's kind
 * (lib/malwareKind.ts) when ATT&CK does not describe the family, and stored KEV CVEs MITRE CTID's
 * techniques (lib/kevAttack.ts). New and re-listed indicators get them at ingest; this covers the rest.
 * Only rows without techniques and without ATT&CK software are touched. Dry run unless --apply.
 *
 *   npx esbuild scripts/db/backfill-attack.ts --bundle --platform=node --format=esm --outfile=scripts/db/.backfill-attack.mjs \
 *     "--banner:js=import { createRequire as __cr } from 'module'; const require = __cr(import.meta.url);"
 *   node scripts/db/.backfill-attack.mjs <staging|production> [--apply]
 */
import { neon } from '@neondatabase/serverless'
import { inferredTechniques } from '../../src/lib/malwareKind'
import { kevTechniques } from '../../src/lib/kevAttack'
import { techniqueName } from '../../src/lib/attack'
// @ts-expect-error plain .mjs helper
import { loadEnvFile, describe } from './lib.mjs'

const target = process.argv[2]
if (target !== 'staging' && target !== 'production') { console.error('usage: <staging|production> [--apply]'); process.exit(1) }
const apply = process.argv.includes('--apply')
const { DATABASE_URL } = loadEnvFile(target)
const sql = neon(DATABASE_URL)
console.log(`Target: ${target} (${describe(DATABASE_URL)})${apply ? '' : '  [dry run]'}`)

// 1. families: one update per family
const fams = await sql(`SELECT malware_family f, count(*)::int n FROM cti_indicators
  WHERE ti_event_id IS NULL AND malware_family IS NOT NULL AND attack_software IS NULL AND attack_techniques IS NULL
  GROUP BY 1`) as Array<{ f: string; n: number }>
let famRows = 0
const plan: Array<{ f: string; t: string[]; n: number }> = []
for (const r of fams) {
  const t = inferredTechniques({ names: [r.f], inAttack: false }).filter((x) => techniqueName(x) !== null)
  if (t.length) { plan.push({ f: r.f, t, n: r.n }); famRows += r.n }
}
console.log(`Families with inferred techniques: ${plan.length} (${famRows} indicators)`)

// 2. KEV CVEs without techniques
const kev = await sql(`SELECT value FROM cti_indicators WHERE ti_event_id IS NULL AND source = 'CISA KEV' AND attack_techniques IS NULL`) as Array<{ value: string }>
const kevPlan = kev.map((r) => ({ v: r.value, t: kevTechniques(r.value).all })).filter((r) => r.t.length)
console.log(`KEV CVEs with CTID techniques: ${kevPlan.length}`)

if (apply) {
  let done = 0
  for (const p of plan) {
    const res = await sql(`UPDATE cti_indicators SET attack_techniques = $1::text[]
      WHERE ti_event_id IS NULL AND malware_family = $2 AND attack_software IS NULL AND attack_techniques IS NULL`, [p.t, p.f])
    done += (res as unknown as { length?: number }).length ?? 0
  }
  if (kevPlan.length) {
    await sql(`UPDATE cti_indicators c SET attack_techniques = ARRAY(SELECT jsonb_array_elements_text(v.t))
      FROM jsonb_to_recordset($1::jsonb) AS v(v text, t jsonb)
      WHERE c.ti_event_id IS NULL AND c.source = 'CISA KEV' AND c.value = v.v AND c.attack_techniques IS NULL`, [JSON.stringify(kevPlan)])
  }
  const [after] = await sql(`SELECT count(*) FILTER (WHERE attack_software IS NOT NULL OR attack_techniques IS NOT NULL)::int with_attack, count(*)::int total
    FROM cti_indicators WHERE ti_event_id IS NULL`) as Array<{ with_attack: number; total: number }>
  console.log(`Applied. Feed indicators with ATT&CK now: ${after!.with_attack} of ${after!.total}`)
} else {
  console.log('Dry run: nothing written (add --apply)')
}
