/**
 * blast-radius-demo.ts — PASS/FAIL for the directional, hub-aware blast radius and the
 * merge topology-reparent fix. Pure functions only; mock graphs from fixtures/graph-mock.
 * Run: npx esbuild scripts/blast-radius-demo.ts --bundle --platform=node \
 *        --format=cjs --outfile=.br.cjs && node .br.cjs
 */
import {
  computeBlastRadius, DEFAULT_NODE_CAP, MAX_DEPTH_CAP, type BlastNodeInput, type BlastEdgeInput,
} from '../src/lib/blastRadius'
import { loadBlastGraph } from '../src/routes/relationships'
import { planMerge, type MergeOp, type MergeAsset, type MergeRelated } from '../src/lib/merge'
import {
  TREE, star, DUAL_GATEWAY, DEPENDS, CONNECTS_CONTROL, MIXED_TYPES, BROKEN_CHAIN,
  NON_MEMBER_START, CYCLE, line, type MockGraph,
} from './fixtures/graph-mock'

let pass = 0, fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  got=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`)
  ok ? pass++ : fail++
}

// Adapt a mock graph to the pure function inputs.
const nodesOf = (g: MockGraph): BlastNodeInput[] => g.nodes.map(n => ({
  assetId: n.assetId, hostname: n.hostname, ipAddress: n.ip, deviceType: n.deviceType,
  criticalityScore: n.criticalityScore ?? 5, inMyAssets: n.inMyAssets,
}))
const edgesOf = (g: MockGraph): BlastEdgeInput[] => g.edges.map(e => ({ source: e.source, target: e.target, type: e.type }))
const run = (g: MockGraph, startId: string, direction: 'downstream' | 'upstream' | 'both', depth = 3, options = {}) =>
  computeBlastRadius({ startId, nodes: nodesOf(g), edges: edgesOf(g), direction, depth, options })
const ids = (r: ReturnType<typeof computeBlastRadius>) => r.nodes.map(n => n.assetId).sort()

async function main() {
  // ── (a) tree: downstream/upstream direction ───────────────────────────────
  console.log('=== (a) tree direction ===')
  check('(a) downstream from core = everything below', ids(run(TREE, 'core', 'downstream', 5)),
    ['dist1', 'dist2', 'leaf1', 'leaf2', 'leaf3', 'leaf4'])
  check('(a) downstream from a leaf = empty', ids(run(TREE, 'leaf1', 'downstream')), [])
  check('(a) upstream from a leaf = its chain up', ids(run(TREE, 'leaf1', 'upstream')), ['core', 'dist1'])
  const up = run(TREE, 'leaf1', 'upstream')
  check('(a) upstream depths: dist1=1, core=2', up.nodes.map(n => [n.assetId, n.depth]).sort(), [['core', 2], ['dist1', 1]])

  // ── (b) star hub: non-transitive in both, normal downstream from the hub ───
  console.log('\n=== (b) star hub ===')
  const fromSpoke = run(star(30), 'spoke0', 'both')
  check('(b) both from a spoke returns only the hub (not 31 nodes)', ids(fromSpoke), ['hub'])
  check('(b) the hub is flagged hub=true and not expanded', fromSpoke.nodes.find(n => n.assetId === 'hub')?.hub, true)
  check('(b) downstream from the hub = all 30 spokes', run(star(30), 'hub', 'downstream').nodes.length, 30)

  // ── (c) dual gateway: reach the shared child, not the other gateway ────────
  console.log('\n=== (c) dual gateway ===')
  check('(c) downstream from gwA reaches the child', ids(run(DUAL_GATEWAY, 'gwA', 'downstream')), ['child'])
  check('(c) downstream from gwB reaches the child', ids(run(DUAL_GATEWAY, 'gwB', 'downstream')), ['child'])
  check('(c) the other gateway is never reached', run(DUAL_GATEWAY, 'gwA', 'downstream').nodes.some(n => n.assetId === 'gwB'), false)

  // ── (d) depends_on is the reverse of connects_to ───────────────────────────
  console.log('\n=== (d) depends_on reversed vs connects_to ===')
  check('(d) depends_on: downstream from db reaches app (db fails → app impacted)', ids(run(DEPENDS, 'db', 'downstream')), ['app'])
  check('(d) depends_on: downstream from app reaches nothing', ids(run(DEPENDS, 'app', 'downstream')), [])
  check('(d) connects_to control: downstream from app reaches db', ids(run(CONNECTS_CONTROL, 'app', 'downstream')), ['db'])
  check('(d) connects_to control: downstream from db reaches nothing', ids(run(CONNECTS_CONTROL, 'db', 'downstream')), [])

  // ── (e) same_subnet never traversed; unknown types reported ────────────────
  console.log('\n=== (e) edge type handling ===')
  const rE = run(MIXED_TYPES, 'a', 'both')
  check('(e) only the connects_to neighbour is reached', ids(rE), ['d'])
  check('(e) same_subnet (b) and unknown (c) are not traversed', [rE.nodes.some(n => n.assetId === 'b'), rE.nodes.some(n => n.assetId === 'c')], [false, false])
  check('(e) unknown type listed in skipped_types', rE.skippedTypes, ['mystery_link'])

  // ── (f) non-member in the middle breaks the chain ──────────────────────────
  console.log('\n=== (f) non-member in the middle ===')
  check('(f) downstream from m1 reaches nothing (gap is not a member)', ids(run(BROKEN_CHAIN, 'm1', 'downstream')), [])
  check('(f) m2 beyond the gap is unreachable', run(BROKEN_CHAIN, 'm1', 'both').nodes.some(n => n.assetId === 'm2'), false)

  // ── (g) start not a member ─────────────────────────────────────────────────
  console.log('\n=== (g) non-member start ===')
  const rG = run(NON_MEMBER_START, 'out', 'downstream')
  check('(g) empty result', rG.nodes.length, 0)
  check('(g) reason = not_in_my_assets', rG.reason, 'not_in_my_assets')

  // ── (h) cycle terminates, each node once, depths correct ───────────────────
  console.log('\n=== (h) cycle ===')
  const rH = run(CYCLE, 'a', 'downstream', 5)
  check('(h) each node once', ids(rH), ['b', 'c'])
  check('(h) depths b=1, c=2', rH.nodes.map(n => [n.assetId, n.depth]).sort(), [['b', 1], ['c', 2]])

  // ── (i) depth cap 5 and node cap with truncated ────────────────────────────
  console.log('\n=== (i) caps ===')
  const deep = run(line(8), 'n0', 'downstream', 99)   // asks for 99, clamped to MAX_DEPTH_CAP
  check('(i) depth hard-capped at 5', Math.max(...deep.nodes.map(n => n.depth)), MAX_DEPTH_CAP)
  check('(i) nodes beyond depth 5 are not reached', deep.nodes.some(n => n.assetId === 'n6' || n.assetId === 'n7'), false)
  const capped = run(star(12), 'hub', 'downstream', 3, { nodeCap: 5 })
  check('(i) node cap limits the result', capped.nodes.length, 5)
  check('(i) node cap sets truncated=true', capped.truncated, true)
  check('(i) default node cap is 200', DEFAULT_NODE_CAP, 200)

  // ── (j) route issues a constant query count regardless of graph size ───────
  console.log('\n=== (j) constant query count ===')
  // Chainable stub: every builder method returns the chain; awaiting it resolves the
  // next canned response and counts one statement. loadBlastGraph awaits exactly twice.
  function countingDb(responses: unknown[][]) {
    let i = 0
    const state = { count: 0 }
    const methods = ['select', 'from', 'where', 'limit', 'innerJoin', 'leftJoin', 'orderBy', 'groupBy', 'offset']
    const makeChain = () => {
      const chain: Record<string, unknown> = {}
      for (const m of methods) chain[m] = () => chain
      chain.then = (resolve: (v: unknown) => unknown, reject?: (e: unknown) => unknown) => {
        const data = responses[i] ?? []; i++; state.count++
        return Promise.resolve(data).then(resolve, reject)
      }
      return chain
    }
    return { db: { select: () => makeChain() } as never, state }
  }
  const startResp = [{ assetId: 's', tenantId: 't', hostname: 'h', ipAddress: '10.0.0.1', deviceType: 'server', criticalityScore: 5, inMyAssets: true }]
  const edgeResp = (n: number) => Array.from({ length: n }, (_, k) => ({
    source: `a${k}`, target: `b${k}`, type: 'connects_to',
    srcHostname: 'h', srcIp: '10.0.0.2', srcDeviceType: 'server', srcCrit: 5,
    tgtHostname: 'h', tgtIp: '10.0.0.3', tgtDeviceType: 'server', tgtCrit: 5,
  }))

  const small = countingDb([startResp, edgeResp(5)])
  await loadBlastGraph(small.db, { startId: 's', tenantScopeId: 't' })
  check('(j) 5-edge graph → exactly 2 queries', small.state.count, 2)

  const big = countingDb([startResp, edgeResp(500)])
  await loadBlastGraph(big.db, { startId: 's', tenantScopeId: 't' })
  check('(j) 500-edge graph → still exactly 2 queries', big.state.count, 2)

  // ── (k) merge reparents children of deleted topology nodes ─────────────────
  console.log('\n=== (k) merge topology reparent ===')
  const asset = (id: string): MergeAsset => ({
    assetId: id, tenantId: 't', hostname: id, ipAddress: '10.0.0.1', macAddress: null, hostKey: null,
    owner: null, deviceType: 'server', hardwareVendor: null, osInfo: {}, criticalityScore: 5,
    baselineState: null, isInternetFacing: false, source: 'scan_active', inMyAssets: true,
    lastScanned: '2026-10-01T00:00:00Z', createdAt: '2026-10-01T00:00:00Z',
  })
  const getOp = (ops: MergeOp[], k: MergeOp['k']) => ops.find(o => o.k === k)

  // Survivor S has node nodeS; loser L has node nodeL. External children are not
  // prefetched — the set-based reparent fixes them regardless; simulated below.
  const planA = planMerge(asset('S'), [asset('L')], {
    addresses: [], relationships: [],
    topologyNodes: [{ nodeId: 'nodeS', assetId: 'S' }, { nodeId: 'nodeL', assetId: 'L' }],
  } as MergeRelated)
  const repA = getOp(planA.ops, 'reparentTopology') as Extract<MergeOp, { k: 'reparentTopology' }> | undefined
  const delA = getOp(planA.ops, 'deleteTopologyNodes') as Extract<MergeOp, { k: 'deleteTopologyNodes' }> | undefined
  check('(k) survivor-with-node: deletes nodeL', delA?.ids, ['nodeL'])
  check('(k) reparent target = survivor node, deleted = [nodeL]', [repA?.survivorNodeId, repA?.deletedNodeIds], ['nodeS', ['nodeL']])

  // Survivor has NO node → one loser node moved, the rest deleted; target = moved node.
  const planB = planMerge(asset('S'), [asset('L1'), asset('L2')], {
    addresses: [], relationships: [],
    topologyNodes: [{ nodeId: 'nodeL1', assetId: 'L1' }, { nodeId: 'nodeL2', assetId: 'L2' }],
  } as MergeRelated)
  const repB = getOp(planB.ops, 'reparentTopology') as Extract<MergeOp, { k: 'reparentTopology' }> | undefined
  const moveB = getOp(planB.ops, 'moveTopologyNode') as Extract<MergeOp, { k: 'moveTopologyNode' }> | undefined
  const delB = getOp(planB.ops, 'deleteTopologyNodes') as Extract<MergeOp, { k: 'deleteTopologyNodes' }> | undefined
  check('(k) survivor-without-node: move nodeL1, delete nodeL2', [moveB?.nodeId, delB?.ids], ['nodeL1', ['nodeL2']])
  check('(k) reparent target = moved node, deleted = [nodeL2]', [repB?.survivorNodeId, repB?.deletedNodeIds], ['nodeL1', ['nodeL2']])

  // Simulate the route's reparent SQL (CASE avoids self-parent; null when no survivor)
  // over an external node set, to confirm no dangling / no self-parent remains.
  type TNode = { nodeId: string; parentNodeId: string | null }
  const applyReparent = (nodes: TNode[], op: { deletedNodeIds: string[]; survivorNodeId: string | null }): TNode[] => {
    const del = new Set(op.deletedNodeIds)
    return nodes.map(n => del.has(n.parentNodeId ?? '')
      ? { ...n, parentNodeId: op.survivorNodeId && n.nodeId === op.survivorNodeId ? null : op.survivorNodeId }
      : n)
  }
  // childX pointed at deleted nodeL; the survivor node nodeS also pointed at nodeL.
  const before: TNode[] = [{ nodeId: 'nodeS', parentNodeId: 'nodeL' }, { nodeId: 'childX', parentNodeId: 'nodeL' }]
  const after = applyReparent(before, repA!)
  check('(k) child reparented onto survivor node', after.find(n => n.nodeId === 'childX')?.parentNodeId, 'nodeS')
  check('(k) survivor node did not become its own parent (→ null)', after.find(n => n.nodeId === 'nodeS')?.parentNodeId, null)
  const survivingIds = new Set(after.map(n => n.nodeId))
  check('(k) no dangling parent remains', after.every(n => n.parentNodeId == null || survivingIds.has(n.parentNodeId)), true)
  check('(k) no self-parent remains', after.every(n => n.parentNodeId !== n.nodeId), true)
  const afterNull = applyReparent(before, { deletedNodeIds: ['nodeL'], survivorNodeId: null })
  check('(k) null survivor → children become roots (null)', afterNull.map(n => n.parentNodeId), [null, null])
}

main().then(() => {
  console.log(`\n=== ${pass} passed, ${fail} failed ===`)
  process.exit(fail === 0 ? 0 : 1)
}).catch(err => { console.error(err); process.exit(1) })
