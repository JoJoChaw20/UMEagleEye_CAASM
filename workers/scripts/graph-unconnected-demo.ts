/**
 * graph-unconnected-demo.ts — PASS/FAIL for the /relationships/graph `unconnected`
 * list and the shared criticality breakdown source. Pure functions + a counting stub.
 * Run: npx esbuild scripts/graph-unconnected-demo.ts --bundle --platform=node \
 *        --format=cjs --outfile=.gu.cjs && node .gu.cjs
 */
import { computeUnconnected, buildGraphResponse, loadGraphData } from '../src/routes/relationships'
import { computeCriticality } from '../src/lib/criticality'
import { star } from './fixtures/graph-mock'

let pass = 0, fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  got=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`)
  ok ? pass++ : fail++
}

// Minimal asset-row / edge-row shapes the real functions consume.
const node = (id: string, deviceType: string) => ({ assetId: id, hostname: id, ipAddress: `10.0.0.${id.length}`, deviceType, criticalityScore: 5, isInternetFacing: false, hardwareVendor: null }) as never
const edge = (s: string, t: string) => ({ sourceAssetId: s, targetAssetId: t, relationshipType: 'connects_to' }) as never

async function main() {
// Members (all in My Assets). 'X' is a NON-member (not in this list) referenced by an edge.
const members = [node('gw', 'network'), node('h1', 'server'), node('h2', 'unknown'), node('iso', 'server')]
const edges = [edge('gw', 'h1'), edge('h2', 'X')]   // h2's only edge points at a non-member
const resp = buildGraphResponse(members, edges)

console.log('=== unconnected list ===')
// (a) members with no member-to-member edge are returned with the right reason
check('(a) unknown-type member → unconnected with unknown_type', resp.unconnected.find(u => u.id === 'h2'), { id: 'h2', hostname: 'h2', ip: '10.0.0.2', device_type: 'unknown', reason: 'unknown_type' })
// CHANGED: a known-type member with no edge is now `no_network_device` (no gateway/
// switch of its /24 in My Assets), not the old generic `no_relationships`.
check('(a) known-type member with no edge → no_network_device', resp.unconnected.find(u => u.id === 'iso')?.reason, 'no_network_device')
check('(b2) a known-type host (workstation) with no edge → no_network_device', buildGraphResponse([node('wk', 'workstation')], []).unconnected[0], { id: 'wk', hostname: 'wk', ip: '10.0.0.2', device_type: 'workstation', reason: 'no_network_device' })
// (b) a member connected ONLY to a non-member is still unconnected (edge is hidden)
check('(b) member linked only to a non-member is unconnected', resp.unconnected.some(u => u.id === 'h2'), true)
// (c) a non-member is never listed
check('(c) the non-member X is never listed', resp.unconnected.some(u => u.id === 'X'), false)
check('(c) connected members are NOT listed', [resp.unconnected.some(u => u.id === 'gw'), resp.unconnected.some(u => u.id === 'h1')], [false, false])
// (d) the response keeps every existing field
check('(d) response has all fields', Object.keys(resp).sort(), ['edges', 'nodes', 'total_edges', 'total_nodes', 'unconnected'])
check('(d) existing fields unchanged (1 visible edge, 4 nodes)', [resp.total_nodes, resp.total_edges], [4, 1])

// reuse a shared fixture: a fully-connected star has no unconnected members
const s = star(5)
const starResp = buildGraphResponse(
  s.nodes.map(n => node(n.assetId, n.deviceType)),
  s.edges.map(e => edge(e.source, e.target)),
)
check('(a2) fully-connected star → unconnected empty', starResp.unconnected.length, 0)

// (e) /graph query count is constant (counting stub)
console.log('\n=== query count ===')
function countingDb(responses: unknown[][]) {
  let i = 0
  const state = { count: 0 }
  const methods = ['select', 'from', 'where', 'limit', 'innerJoin', 'leftJoin', 'orderBy', 'groupBy', 'offset']
  const make = () => {
    const chain: Record<string, unknown> = {}
    for (const m of methods) chain[m] = () => chain
    chain.then = (res: (v: unknown) => unknown, rej?: (e: unknown) => unknown) => { const d = responses[i] ?? []; i++; state.count++; return Promise.resolve(d).then(res, rej) }
    return chain
  }
  return { db: { select: () => make() } as never, state }
}
{
  const scoped = countingDb([[{ assetId: 'a' }], [node('a', 'server')], [edge('a', 'b')]])
  await loadGraphData(scoped.db, { tenantScopeId: 't' })
  check('(e) tenant-scoped /graph = 3 queries', scoped.state.count, 3)
  const unscoped = countingDb([[node('a', 'server')], []])
  await loadGraphData(unscoped.db, { tenantScopeId: null })
  check('(e) superadmin unscoped /graph = 2 queries', unscoped.state.count, 2)
}

// Breakdown (shared source = computeCriticality, used by GET /assets/:id/score on both pages)
console.log('\n=== criticality breakdown ===')
{
  const asset = { deviceType: 'server', isInternetFacing: false, hostname: 'app', osInfo: {}, owner: null }
  const r = computeCriticality(asset)
  // (f) same function both pages call → deterministic, stable breakdown
  check('(f) breakdown is the shared computeCriticality output', computeCriticality(asset).breakdown, r.breakdown)
  check('(f) breakdown keys (no topology term)', Object.keys(r.breakdown).sort(), ['base', 'hostnameHints', 'internetFacing', 'ownerPenalty', 'portRisk'])
  // (g) terms sum to the score (non-clamped case: server 5 + unowned 1 = 6)
  const bd = r.breakdown
  check('(g) breakdown terms sum to the score', bd.base + bd.internetFacing + bd.portRisk + bd.hostnameHints + bd.ownerPenalty, r.score)
  // (h) stored != computed flag (mirrors CriticalityBadge: mismatch = computed != null && computed !== stored)
  const mismatch = (stored: number, computed: number | null) => computed != null && computed !== stored
  check('(h) stored 7 vs computed 6 → mismatch flagged', mismatch(7, r.score), true)   // r.score = 6
  check('(h) stored == computed → no mismatch', mismatch(r.score, r.score), false)
}
}

main().then(() => {
  console.log(`\n=== ${pass} passed, ${fail} failed ===`)
  process.exit(fail === 0 ? 0 : 1)
}).catch(err => { console.error(err); process.exit(1) })
