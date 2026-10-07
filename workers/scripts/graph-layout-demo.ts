/**
 * graph-layout-demo.ts — PASS/FAIL for the pure layered-by-tier layout module
 * (frontend/src/utils/graphLayout.js). No React/canvas; esbuild bundles the plain JS.
 * Run: npx esbuild scripts/graph-layout-demo.ts --bundle --platform=node \
 *        --format=cjs --outfile=.gl.cjs && node .gl.cjs
 */
// @ts-expect-error — plain JS pure module, intentionally untyped for the demo
import { layoutGraph, NODE_SEP } from '../../frontend/src/utils/graphLayout.js'

let pass = 0, fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  got=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`)
  ok ? pass++ : fail++
}

// Production-shaped graph: two single-gateway subnets + a redundant pair over one host,
// plus one isolated node.
const nodes = [
  { id: 'g0',   layer: 1, ip: '192.168.0.1' },
  { id: 'dsk',  layer: 4, ip: '192.168.0.14' },
  { id: 'g100', layer: 1, ip: '192.168.100.1' },
  { id: 'jojo', layer: 5, ip: '192.168.100.71' },
  { id: 's11',  layer: 3, ip: '142.19.0.11' },
  { id: 's12',  layer: 3, ip: '142.19.0.12' },
  { id: 'srv1', layer: 4, ip: '142.19.0.1' },
  { id: 'lonely', layer: null, ip: '10.9.9.9' },
]
const edges = [
  { source: 'g0', target: 'dsk' },
  { source: 'g100', target: 'jojo' },
  { source: 's11', target: 'srv1' },
  { source: 's12', target: 'srv1' },
]
const { pos, isolatedBandY, hasIsolated } = layoutGraph(nodes, edges, { width: 1000 })
const P = (id: string) => pos.get(id)

console.log('=== layout ===')
// (h) peers (same layer, same component) share a y
check('(h) peers s11/s12 share a row (same y)', P('s11').y === P('s12').y, true)
// y monotone with tier rank: layer1 < layer3 < layer4 < layer5
check('(h) y monotone with tier (g0 < s11 < srv1 < jojo)', [P('g0').y < P('s11').y, P('s11').y < P('srv1').y, P('srv1').y < P('jojo').y], [true, true, true])
// a host linked to two peers is horizontally BETWEEN them
check('(h) srv1 sits between its two switches', P('srv1').x >= Math.min(P('s11').x, P('s12').x) && P('srv1').x <= Math.max(P('s11').x, P('s12').x), true)
check('(h) srv1 is the barycentre of s11/s12', Math.abs(P('srv1').x - (P('s11').x + P('s12').x) / 2) < 0.5, true)

// min spacing within every row
{
  const rows = new Map<number, number[]>()
  for (const n of nodes) { const p = P(n.id); const l = rows.get(p.y) ?? []; l.push(p.x); rows.set(p.y, l) }
  let ok = true
  for (const xs of rows.values()) { xs.sort((a, b) => a - b); for (let i = 1; i < xs.length; i++) if (xs[i] - xs[i - 1] < NODE_SEP - 0.5) ok = false }
  check('(h) no two nodes in a row closer than NODE_SEP', ok, true)
}
// connected components occupy disjoint horizontal bands
{
  const comps = [['g0', 'dsk'], ['g100', 'jojo'], ['s11', 's12', 'srv1']]
  const ranges = comps.map(c => { const xs = c.map(id => P(id).x); return [Math.min(...xs), Math.max(...xs)] as [number, number] }).sort((a, b) => a[0] - b[0])
  let disjoint = true
  for (let i = 1; i < ranges.length; i++) if (ranges[i][0] <= ranges[i - 1][1]) disjoint = false
  check('(h) components occupy disjoint x-bands', disjoint, true)
}
// isolated node is in the bottom band, flagged
check('(h) isolated node flagged + below the tiers', [P('lonely').isolated, P('lonely').y >= isolatedBandY, hasIsolated], [true, true, true])

// determinism
check('(h) identical input → identical output', JSON.stringify([...layoutGraph(nodes, edges, { width: 1000 }).pos]), JSON.stringify([...pos]))

// performance: 1, 50, 300 nodes
console.log('\n=== performance ===')
function gen(n: number) {
  const ns: { id: string; layer: number | null; ip: string }[] = [{ id: 'gw', layer: 1, ip: '10.0.0.1' }]
  const es: { source: string; target: string }[] = []
  for (let i = 0; i < n - 1; i++) { const id = `h${i}`; ns.push({ id, layer: 4, ip: `10.0.${(i >> 8) & 255}.${i & 255}` }); es.push({ source: 'gw', target: id }) }
  return { ns, es }
}
for (const n of [1, 50, 300]) {
  const { ns, es } = gen(n)
  const t0 = Date.now()
  for (let k = 0; k < 20; k++) layoutGraph(ns, es, { width: 1200 })
  const ms = (Date.now() - t0) / 20
  console.log(`  ${n} nodes: ${ms.toFixed(2)} ms/run (20 runs)`) ; pass++
}

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail === 0 ? 0 : 1)
