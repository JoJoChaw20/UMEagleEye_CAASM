/**
 * rescore-demo.ts — in-memory rescoring + statement/chunk counting on 150 assets.
 * Run: npx esbuild scripts/rescore-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.r.cjs && node .r.cjs
 */
import { planRescore } from '../src/lib/rescore'

let pass = 0, fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  got=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`)
  ok ? pass++ : fail++
}

const CHUNK = 100
const types = ['server', 'workstation', 'network', 'iot', 'unknown'] as const

// 150 fake assets, all stored at criticality 0 so every recomputed score differs.
const rows = Array.from({ length: 150 }, (_, i) => ({
  assetId: `a${i}`,
  deviceType: types[i % types.length]!,
  isInternetFacing: i % 3 === 0,
  hostname: i % 2 === 0 ? `prod-db-${i}` : `dev-host-${i}`,
  osInfo: { ports: i % 4 === 0 ? ['22/tcp', '3389/tcp', '445/tcp'] : ['80/tcp'] } as Record<string, unknown>,
  criticalityScore: 0,
}))
const layerMap = new Map<string, number>([['a0', 1], ['a1', 2]])

const plan = planRescore(rows, layerMap)
const chunks = Math.ceil(plan.changes.length / CHUNK)
console.log(`scanned=${plan.scanned}  changed=${plan.changes.length}  statements=${plan.changes.length}  chunks(@${CHUNK})=${chunks}`)

check('scanned 150', plan.scanned, 150)
check('all 150 changed (stored 0 vs computed 1-10)', plan.changes.length, 150)
check('statements == changed', plan.changes.length, 150)
check('chunks @100 = 2', chunks, 2)
check('scores in 1..10', plan.changes.every(c => c.score >= 1 && c.score <= 10), true)

// Idempotency: write the computed scores back, rescore again → nothing to write.
const scoreById = new Map(plan.changes.map(c => [c.assetId, c.score]))
const rows2 = rows.map(r => ({ ...r, criticalityScore: scoreById.get(r.assetId) ?? r.criticalityScore }))
const plan2 = planRescore(rows2, layerMap)
check('idempotent: 0 changes on re-run', plan2.changes.length, 0)
check('idempotent: still scanned 150', plan2.scanned, 150)

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail === 0 ? 0 : 1)
