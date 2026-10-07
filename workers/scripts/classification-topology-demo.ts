/**
 * classification-topology-demo.ts — PASS/FAIL for the classification/criticality
 * engine and the graph-only fixes, running the REAL (unchanged-behaviour) functions.
 * Run: npx esbuild scripts/classification-topology-demo.ts --bundle --platform=node \
 *        --format=cjs --outfile=.ct.cjs && node .ct.cjs
 *
 * All rules are IMPORTED from production (no mirrored copies): if a rule changes, this
 * harness changes with it. A dependency guard asserts the engine never imports topology.
 */
import { readFileSync } from 'node:fs'
import { inferDeviceType } from '../src/routes/scans'
import { resolveInternetFacing } from '../src/lib/exposure'
import { classifyAsset, resolveParent, resolveParents } from '../src/routes/topology'
import { classifyRelType } from '../src/routes/relationships'
import { computeCriticality } from '../src/lib/criticality'
import { scoreAsset, planRescore } from '../src/lib/rescore'
import { planIngest, resolveIngestDeviceType, type IngestOp, type IdentityPrefetch, type PlanHost } from '../src/lib/ingest-plan'
import { planMerge, type MergeAsset, type MergeRelated } from '../src/lib/merge'
import { computeBlastRadius } from '../src/lib/blastRadius'
import {
  S1_GATEWAY_PAIR, S2_THREE_TIER, s3Hub, S4_NAME_TRAPS, PROD_CROSS_SUBNET, TIERED_CROSS_SUBNET,
  PROD_REDUNDANT, threeGateways, DIFFERENT_SIXTEEN, type ClassScenario,
} from './fixtures/graph-mock'

let pass = 0, fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  got=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`)
  ok ? pass++ : fail++
}
const getSubnet = (ip: string) => ip.split('.').slice(0, 3).join('.')

// Run the real pipeline over a scenario → per-asset classification, parent, score.
interface Classified { id: string; hostname: string | null; dev: string; inet: boolean; nodeType: string; layer: number; parent: string | null; hasChildren: boolean; score: number }
function runScenario(scn: ClassScenario): Map<string, Classified> {
  const classified = scn.assets.map(a => {
    const dev = inferDeviceType(a.ports ?? [], a.ip, a.os ?? null, scn.gatewayReported ?? undefined)
    const inet = resolveInternetFacing(a.ip, scn.gatewayReported, a.internetFacingOverride ?? null)
    const { nodeType, layer } = classifyAsset({ hostname: a.hostname, deviceType: dev, isInternetFacing: inet } as never)
    return { a, dev, inet, nodeType, layer }
  })
  const flat = classified.map(c => ({ nodeId: c.a.id, nodeType: c.nodeType as never, layer: c.layer, ip: c.a.ip, subnet: getSubnet(c.a.ip) }))
  const parentOf = new Map<string, string | null>()
  for (const c of classified) {
    parentOf.set(c.a.id, c.layer === 1 ? null : resolveParent(flat.find(f => f.nodeId === c.a.id)!, flat.filter(f => f.nodeId !== c.a.id)))
  }
  const childCount = new Map<string, number>()
  for (const [, p] of parentOf) if (p) childCount.set(p, (childCount.get(p) ?? 0) + 1)
  const out = new Map<string, Classified>()
  for (const c of classified) {
    const score = computeCriticality({ deviceType: c.dev, isInternetFacing: c.inet, hostname: c.a.hostname, osInfo: { ports: (c.a.ports ?? []).map(p => p.port) }, owner: c.a.owner ?? null }).score
    out.set(c.a.id, { id: c.a.id, hostname: c.a.hostname, dev: c.dev, inet: c.inet, nodeType: c.nodeType, layer: c.layer, parent: parentOf.get(c.a.id) ?? null, hasChildren: (childCount.get(c.a.id) ?? 0) > 0, score })
  }
  return out
}

// ── S1: .1 end host is a workstation leaf; the two gateways are network peers above ──
console.log('=== S1 gateway pair ===')
{
  const r = runScenario(S1_GATEWAY_PAIR)
  const h1 = r.get('h1')!, gwp = r.get('gwp')!, gwb = r.get('gwb')!
  check('S1 .1 end host is a workstation', h1.dev, 'workstation')
  check('S1 .1 end host is a leaf (no children)', h1.hasChildren, false)
  check('S1 .1 end host is NOT a network/gateway node', h1.nodeType, 'host')
  check('S1 both real gateways are network', [gwp.dev, gwb.dev], ['network', 'network'])
  check('S1 gateways are peers (same layer)', gwp.layer === gwb.layer, true)
  check('S1 gateways sit above the hosts (gateway layer < host layer)', gwp.layer < h1.layer, true)
  check('S1 neither gateway is parented under the .1 host', [gwp.parent === 'h1', gwb.parent === 'h1'], [false, false])
}

// ── S2 three-tier: firewall on top, hosts are leaves ────────────────────────
console.log('\n=== S2 three-tier ===')
{
  const r = runScenario(S2_THREE_TIER)
  check('S2 firewall is the gateway root', [r.get('fw')!.nodeType, r.get('fw')!.parent], ['gateway', null])
  check('S2 servers/workstations are host leaves', [r.get('srv1')!.nodeType, r.get('srv1')!.hasChildren, r.get('ws1')!.nodeType], ['host', false, 'host'])
}

// ── S3 hub: blast radius from the hub now reaches same-subnet hosts (graph fix) ──
console.log('\n=== S3 hub + infra→host edge ===')
{
  const r = runScenario(s3Hub(30))
  check('S3 hub is the gateway root', [r.get('gw')!.nodeType, r.get('gw')!.parent], ['gateway', null])
  check('S3 a same-subnet spoke is a host leaf parented to the hub', [r.get('s0')!.nodeType, r.get('s0')!.parent], ['host', 'gw'])
  // CHANGED (legitimately): cross-subnet hosts used to be parented to the hub via the
  // old positional fallback; a host is no longer cross-subnet parented, so they are now
  // roots with no edge (and would show in the unconnected notice).
  check('S3 cross-subnet hosts rem-1/rem-2 now have NO parent', [r.get('x1')!.parent, r.get('x2')!.parent], [null, null])
}

// ── Cross-subnet: non-infra hosts get no parent; infra chains still do ──────
console.log('\n=== cross-subnet parenting (infra only) ===')
{
  const r = runScenario(PROD_CROSS_SUBNET)
  const edges = [...r.values()].filter(c => c.parent).map(c => `${c.parent}->${c.id}`).sort()
  check('(a) exactly the two same-subnet edges', edges, ['n0_1->desktop', 'n100_1->jojo'])
  check('(a) the three 142.19.0.x hosts have NO parent', [r.get('u12')!.parent, r.get('u11')!.parent, r.get('u1')!.parent], [null, null, null])
  check('(d) host WITH a network device in its /24 is parented (Step 1)', [r.get('jojo')!.parent, r.get('desktop')!.parent], ['n100_1', 'n0_1'])

  const t = runScenario(TIERED_CROSS_SUBNET)
  check('(c) core switch is the root', t.get('core')!.parent, null)
  check('(c) distribution switches parent to the core across subnets', [t.get('d1')!.parent, t.get('d2')!.parent], ['core', 'core'])
  check('(c) hosts attach to their own-subnet switch', [t.get('ha')!.parent, t.get('hb')!.parent], ['d1', 'd2'])
}

// ── Redundant links: every edge from resolveParents(...).all (primary + backups) ────
console.log('\n=== redundant parents (resolveParents.all) ===')
{
  const inferEdges = (scn: ClassScenario): string[] => {
    const flat = scn.assets.map(a => {
      const dev = inferDeviceType(a.ports ?? [], a.ip, a.os ?? null, scn.gatewayReported ?? undefined)
      const inet = resolveInternetFacing(a.ip, scn.gatewayReported, a.internetFacingOverride ?? null)
      const { nodeType, layer } = classifyAsset({ hostname: a.hostname, deviceType: dev, isInternetFacing: inet } as never)
      return { nodeId: a.id, nodeType: nodeType as never, layer, ip: a.ip, subnet: getSubnet(a.ip) }
    })
    const edges: string[] = []
    for (const n of flat) for (const p of resolveParents(n, flat.filter(f => f.nodeId !== n.nodeId)).all) edges.push(`${p}->${n.nodeId}`)
    return edges.sort()
  }

  // (a) production: server .1 links to BOTH switches; exactly 4 edges; no 142.19↔192.168
  const prod = inferEdges(PROD_REDUNDANT)
  check('(a) exactly the 4 expected edges', prod, ['g0->dsk', 'g100->jojo', 's11->srv1', 's12->srv1'])
  const net14 = new Set(['s11', 's12', 'srv1']), net192 = new Set(['g0', 'g100', 'dsk', 'jojo'])
  const crossNet = prod.some(e => { const [s, t] = e.split('->'); return (net14.has(s!) && net192.has(t!)) || (net192.has(s!) && net14.has(t!)) })
  check('(a) no edge between 142.19.x and 192.168.x', crossNet, false)

  // (f) tree vs graph: the stored parent_node_id is the single PRIMARY (lowest IP of the
  // tied set); the graph draws every tied parent.
  const flatSrv = PROD_REDUNDANT.assets.map(a => {
    const dev = inferDeviceType(a.ports ?? [], a.ip, a.os ?? null, PROD_REDUNDANT.gatewayReported ?? undefined)
    const inet = resolveInternetFacing(a.ip, PROD_REDUNDANT.gatewayReported, null)
    const { nodeType, layer } = classifyAsset({ hostname: a.hostname, deviceType: dev, isInternetFacing: inet } as never)
    return { nodeId: a.id, nodeType: nodeType as never, layer, ip: a.ip, subnet: getSubnet(a.ip) }
  })
  const srv = flatSrv.find(f => f.nodeId === 'srv1')!
  const rp = resolveParents(srv, flatSrv.filter(f => f.nodeId !== 'srv1'))
  check('(f) primary parent (tree) is a single node', typeof rp.primary === 'string', true)
  check('(f) primary is the lowest-IP tied switch (s11)', rp.primary, 's11')
  check('(f) graph parents = both switches', rp.all.slice().sort(), ['s11', 's12'])

  // (b) tiered chain within one /16 still links across subnets
  check('(b) tiered /16 edges', inferEdges(TIERED_CROSS_SUBNET), ['core->d1', 'core->d2', 'd1->ha', 'd2->hb'])
  // (c) infra in different /16s is NOT linked
  check('(c) different /16 → no cross-subnet edge', inferEdges(DIFFERENT_SIXTEEN), [])
  // (d) three equal gateways: each of 5 hosts links to all three; determinism
  const tg = threeGateways()
  const e1 = inferEdges(tg), e2 = inferEdges(tg)
  check('(d) every host links to all three switches (5×3 = 15 edges)', e1.length, 15)
  check('(d) one host has exactly 3 edges', e1.filter(e => e.endsWith('->h0')).sort(), ['gw1->h0', 'gw2->h0', 'gw3->h0'])
  check('(d) deterministic (same input → same edges)', e1, e2)
  // (e) single gateway: a host gets exactly one edge (no duplicates)
  check('(e) single-gateway subnet → one edge per host (DESKTOP)', prod.filter(e => e.endsWith('->dsk')), ['g0->dsk'])
}

// ── S4 name/position traps ──────────────────────────────────────────────────
console.log('\n=== S4 name traps ===')
{
  const r = runScenario(S4_NAME_TRAPS)
  check('S4 .254 workstation stays workstation', r.get('ws')!.dev, 'workstation')
  check('S4 .1 IoT stays iot (not promoted to network)', r.get('iot')!.dev, 'iot')
  check('S4 a .1 host WITH real network evidence is still network', r.get('net')!.dev, 'network')
  check('S4 a server named like a switch stays a server (host)', [r.get('db')!.dev, r.get('db')!.nodeType], ['server', 'host'])
  check('S4 a real switch (SNMP, no hostname) is network', r.get('sw')!.dev, 'network')
}

// ── Criticality independent of topology ─────────────────────────────────────
console.log('\n=== criticality is engine-only (no topology) ===')
{
  const base = { deviceType: 'server', isInternetFacing: false, hostname: 'app', osInfo: {}, owner: 'IT' }
  check('scoreAsset has NO topologyLayer parameter', 'topologyLayer' in base, false)
  check('a stray topology layer does not change the score', scoreAsset({ ...base, topologyLayer: 1 } as never), scoreAsset(base))
  check('breakdown has no topologyLayer key', 'topologyLayer' in computeCriticality({ ...base }).breakdown, false)
  // per-asset == bulk == create/PATCH entry point (all route through scoreAsset)
  const bulk = planRescore([{ assetId: 'A', ...base, criticalityScore: 0 }])
  check('per-asset == bulk', bulk.changes[0]?.score, scoreAsset(base))
  // deltas unchanged
  const unowned = scoreAsset({ ...base, owner: null })
  check('owner penalty still +1', unowned - scoreAsset(base), 1)
  check('internet-facing still +2', scoreAsset({ ...base, isInternetFacing: true }) - scoreAsset(base), 2)
  // S5: PATCH workstation→network is immediately correct, no topology refresh needed
  const net = scoreAsset({ deviceType: 'network', isInternetFacing: false, hostname: 'host-x', osInfo: { ports: [445] }, owner: null })
  check('S5 network score needs no topology refresh (same with/without a layer)', scoreAsset({ deviceType: 'network', isInternetFacing: false, hostname: 'host-x', osInfo: { ports: [445] }, owner: null, topologyLayer: 1 } as never), net)
  // S6: removed-from-My-Assets (no node) vs a stale node → identical (layer unused)
  check('S6 removed asset carries no layer bonus (score layer-independent)', scoreAsset({ deviceType: 'network', isInternetFacing: false, hostname: 'x', osInfo: {}, owner: null, topologyLayer: 3 } as never), scoreAsset({ deviceType: 'network', isInternetFacing: false, hostname: 'x', osInfo: {}, owner: null }))
}

// ── device_type_source rules ────────────────────────────────────────────────
console.log('\n=== device_type_source ===')
{
  const man = { deviceType: 'server', deviceTypeSource: 'manual' }
  const aut = { deviceType: 'server', deviceTypeSource: 'auto' }
  check('manual KNOWN type never changes on an active scan', resolveIngestDeviceType(man, 'network', false), { deviceType: 'server', deviceTypeSource: 'manual', corrected: false })
  // manual + UNKNOWN is not a real choice → a concrete scan result fills it and flips to auto.
  check('manual + unknown IS filled by a scan (→ auto)', resolveIngestDeviceType({ deviceType: 'unknown', deviceTypeSource: 'manual' }, 'server', false), { deviceType: 'server', deviceTypeSource: 'auto', corrected: false })
  check('manual + unknown filled by a passive scan too (→ auto)', resolveIngestDeviceType({ deviceType: 'unknown', deviceTypeSource: 'manual' }, 'server', true), { deviceType: 'server', deviceTypeSource: 'auto', corrected: false })
  check('manual + unknown + unclassified scan stays manual/unknown', resolveIngestDeviceType({ deviceType: 'unknown', deviceTypeSource: 'manual' }, 'unknown', false), { deviceType: 'unknown', deviceTypeSource: 'manual', corrected: false })
  check('auto corrected by a different non-unknown ACTIVE scan', resolveIngestDeviceType(aut, 'network', false), { deviceType: 'network', deviceTypeSource: 'auto', corrected: true })
  check('auto NOT corrected by a passive scan (no flip-flop)', resolveIngestDeviceType(aut, 'network', true), { deviceType: 'server', deviceTypeSource: 'auto', corrected: false })
  check('unknown never overwrites a known type', resolveIngestDeviceType(aut, 'unknown', false), { deviceType: 'server', deviceTypeSource: 'auto', corrected: false })
  check('passive MAY fill an unknown type', resolveIngestDeviceType({ deviceType: 'unknown', deviceTypeSource: 'auto' }, 'server', true), { deviceType: 'server', deviceTypeSource: 'auto', corrected: false })
  check('create (no existing) → auto', resolveIngestDeviceType(null, 'server', false), { deviceType: 'server', deviceTypeSource: 'auto', corrected: false })
}

// ── device_type correction keeps an auto baseline in step (no false drift) ──
console.log('\n=== scan auto-correction + baseline ===')
{
  const GLOBAL = '98:bb:cc:00:00:01'
  const NOW = new Date('2026-10-07T00:00:00Z')
  const mkPrefetch = (autoSet: boolean): IdentityPrefetch => ({
    addresses: [{ addressId: 'ad1', assetId: 'A1', networkKey: '10.0.0.0/24', ipAddress: '10.0.0.5', macAddress: GLOBAL, deviceType: 'server', lastSeen: NOW.getTime(), assetCreatedAt: NOW.getTime() }],
    assets: [{ assetId: 'A1', deviceType: 'server', deviceTypeSource: 'auto', hostKey: null, osInfo: {}, hostname: 'h', owner: null, hardwareVendor: null, macAddress: GLOBAL, source: 'scan_active', hasBaseline: true, baseline: { device_type: 'server', auto_set: autoSet, ports_known: true, snmp_sysdescr: 'x' } as never }],
  })
  const host: PlanHost = { ip: '10.0.0.5', rawMac: GLOBAL, hostname: 'h', hostKeyRaw: null, deviceType: 'network', observedOsInfo: { ports: ['22/tcp'] }, ports: [22], hardwareVendor: null, internetFacing: false, isPassive: false, tenantId: 't' }
  const setOf = (p: IdentityPrefetch) => (planIngest([host], p, { now: NOW }).perHost[0]!.ops.find(o => o.k === 'updateAsset') as Extract<IngestOp, { k: 'updateAsset' }>).set
  const auto = setOf(mkPrefetch(true))
  check('active scan corrects auto type → network', [auto.deviceType, auto.deviceTypeSource], ['network', 'auto'])
  check('auto-set baseline device_type moves with it (no false drift)', (auto.baselineState as Record<string, unknown>).device_type, 'network')
  const confirmed = setOf(mkPrefetch(false))
  check('user-confirmed baseline (auto_set=false) is NOT moved → drift will flag', confirmed.baselineState === undefined || (confirmed.baselineState as Record<string, unknown>).device_type === 'server', true)
}

// ── merge device_type + source ──────────────────────────────────────────────
console.log('\n=== merge device_type source ===')
{
  const a = (id: string, deviceType: string, deviceTypeSource: string): MergeAsset => ({
    assetId: id, tenantId: 't', hostname: id, ipAddress: '10.0.0.1', macAddress: null, hostKey: null, owner: null,
    deviceType, deviceTypeSource, hardwareVendor: null, osInfo: {}, criticalityScore: 5, baselineState: null,
    isInternetFacing: false, source: 'scan_active', inMyAssets: true, lastScanned: '2026-10-01T00:00:00Z', createdAt: '2026-10-01T00:00:00Z',
  })
  const noRel: MergeRelated = { addresses: [], relationships: [], topologyNodes: [] }
  const m1 = planMerge(a('S', 'server', 'manual'), [a('L', 'network', 'auto')], noRel).mergedFields
  check('merge: manual survivor type wins', [m1.deviceType, m1.deviceTypeSource], ['server', 'manual'])
  const m2 = planMerge(a('S', 'server', 'auto'), [a('L', 'network', 'manual')], noRel).mergedFields
  check('merge: a manual loser type is taken over an auto survivor', [m2.deviceType, m2.deviceTypeSource], ['network', 'manual'])
  const m3 = planMerge(a('S', 'server', 'auto'), [a('L', 'network', 'auto')], noRel).mergedFields
  check('merge: all-auto keeps survivor non-unknown type, source auto', [m3.deviceType, m3.deviceTypeSource], ['server', 'auto'])
}

// ── graph-only fixes ─────────────────────────────────────────────────────────
console.log('\n=== graph-only fixes ===')
{
  check('infra→host edge is connects_to (blast radius will walk it)', classifyRelType('switch', 'host'), 'connects_to')
  check('gateway→host edge is connects_to', classifyRelType('gateway', 'host'), 'connects_to')
  check('infra→infra is connects_to', classifyRelType('gateway', 'router'), 'connects_to')
  check('host→host is depends_on', classifyRelType('host', 'host'), 'depends_on')

  // resolveParent cross-subnet is INFRA-ONLY now, still deterministic (lowest layer,
  // then lowest IP) for the infra cases that remain.
  const cands = [
    { nodeId: 'p_l3', nodeType: 'switch' as never, layer: 3, ip: '10.1.0.9', subnet: '10.1.0' },
    { nodeId: 'p_l2b', nodeType: 'router' as never, layer: 2, ip: '10.1.0.3', subnet: '10.1.0' },
    { nodeId: 'p_l2a', nodeType: 'gateway' as never, layer: 2, ip: '10.1.0.2', subnet: '10.1.0' },
  ]
  // Same /16 as the candidates (10.1.*) so the cross-subnet /16 rule allows the link.
  const infraNode = { nodeId: 'n', nodeType: 'switch' as never, layer: 3, ip: '10.1.9.9', subnet: '10.1.9' }
  const first = resolveParent(infraNode, cands)
  check('(e) infra cross-subnet (same /16) picks the layer-1 tier, lowest IP', first, 'p_l2a')
  check('(e) infra cross-subnet is deterministic', resolveParent(infraNode, cands), first)
  // a non-infra node cross-subnet now gets NO parent
  const hostNode = { nodeId: 'h', nodeType: 'host' as never, layer: 5, ip: '10.9.9.9', subnet: '10.9.9' }
  check('non-infra node cross-subnet → no parent', resolveParent(hostNode, cands), null)
  // an infra node whose only cross-subnet candidates are non-infra also gets no parent
  check('infra node, only non-infra cross-subnet candidates → no parent',
    resolveParent(infraNode, [{ nodeId: 'hx', nodeType: 'host' as never, layer: 2, ip: '10.1.0.2', subnet: '10.1.0' }]), null)

  // delete reparent: children of a deleted node become roots (null), no dangling.
  type TNode = { nodeId: string; parentNodeId: string | null }
  const deletedNodeId = 'nDel'
  const after: TNode[] = [{ nodeId: 'c1', parentNodeId: deletedNodeId }, { nodeId: 'c2', parentNodeId: 'other' }]
    .map(n => n.parentNodeId === deletedNodeId ? { ...n, parentNodeId: null } : n)
  check('delete reparent: no child still points at the deleted node', after.some(n => n.parentNodeId === deletedNodeId), false)

  // end-to-end: blast radius downstream from a switch reaches its same-subnet host.
  const nodes = [
    { assetId: 'sw1', hostname: 'sw', ipAddress: '10.0.0.2', deviceType: 'network', criticalityScore: 6, inMyAssets: true },
    { assetId: 'hostA', hostname: 'a', ipAddress: '10.0.0.5', deviceType: 'server', criticalityScore: 5, inMyAssets: true },
  ]
  const edges = [{ source: 'sw1', target: 'hostA', type: classifyRelType('switch', 'host') }]
  const blast = computeBlastRadius({ startId: 'sw1', nodes, edges, direction: 'downstream' })
  check('blast radius from a switch now reaches its same-subnet host', blast.nodes.map(n => n.assetId), ['hostA'])
}

// ── Dependency guard: the engine must NEVER import topology/relationships ────
console.log('\n=== dependency guard (engine ⊥ topology) ===')
{
  const engineFiles = ['src/lib/criticality.ts', 'src/lib/rescore.ts', 'src/lib/ingest-plan.ts', 'src/routes/scans.ts']
  const forbidden = /(from\s+['"][^'"]*(topology|relationships)['"])|topologyNodes|topology_nodes|topologyLayer/
  for (const f of engineFiles) {
    const src = readFileSync(f, 'utf8')
    const hit = forbidden.test(src)
    check(`engine file does not read topology: ${f}`, hit, false)
  }
}

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail === 0 ? 0 : 1)
