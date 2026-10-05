/**
 * duplicates-demo.ts — PASS/FAIL checks for findDuplicateGroups + planMerge.
 * Run: npx esbuild scripts/duplicates-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.dup-demo.cjs && node .dup-demo.cjs
 */
import { findDuplicateGroups, type DupAsset, type DupAddress } from '../src/lib/duplicates'
import { planMerge, type MergeAsset, type MergeRelated } from '../src/lib/merge'

let pass = 0, fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  got=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`)
  ok ? pass++ : fail++
}

let seq = 0
const A = (over: Partial<DupAsset>): DupAsset => ({
  assetId: over.assetId ?? `a${seq++}`, hostname: null, ipAddress: '0.0.0.0', macAddress: null,
  source: 'scan_active', inMyAssets: false, deviceType: 'workstation', lastScanned: '2026-01-01', createdAt: '2026-01-01',
  hostKey: null, ...over,
})
const AD = (assetId: string, mac: string | null, net: string | null, ip: string): DupAddress => ({
  addressId: `ad-${assetId}-${ip}`, assetId, networkKey: net, ipAddress: ip, macAddress: mac, endedAt: null,
})

const GLOBAL = '98:bb:cc:00:00:01'   // first byte 0x98 → unicast, non-LA → global/OUI
const LOCAL = '02:00:00:00:00:aa'    // first byte 0x02 → locally administered → local
const VMWARE = '00:50:56:c0:00:08'   // VMware shared/virtual

console.log('=== findDuplicateGroups ===')

// (a) 4 assets, same GLOBAL MAC, 4 different networks, one in My Assets → SAFE,
//     the My Assets member is the suggested survivor.
{
  const assets = [
    A({ assetId: 'm', source: 'manual', inMyAssets: true, ipAddress: '10.0.0.10' }),
    A({ assetId: 's1', ipAddress: '10.1.0.10' }),
    A({ assetId: 's2', ipAddress: '10.2.0.10' }),
    A({ assetId: 's3', ipAddress: '10.3.0.10' }),
  ]
  const addrs = [
    AD('m', GLOBAL, '10.0.0.0/24', '10.0.0.10'),
    AD('s1', GLOBAL, '10.1.0.0/24', '10.1.0.10'),
    AD('s2', GLOBAL, '10.2.0.0/24', '10.2.0.10'),
    AD('s3', GLOBAL, '10.3.0.0/24', '10.3.0.10'),
  ]
  const g = findDuplicateGroups(assets, addrs)
  check('(a) one group', g.length, 1)
  check('(a) confidence safe', g[0]?.confidence, 'safe')
  check('(a) 4 assets', g[0]?.assets.length, 4)
  check('(a) survivor = My Assets member', g[0]?.suggestedSurvivorId, 'm')
}

// (b) two assets, same LOCAL MAC, same /24 → SAFE.
{
  const assets = [A({ assetId: 'b1', ipAddress: '10.0.0.5' }), A({ assetId: 'b2', ipAddress: '10.0.0.6' })]
  const addrs = [AD('b1', LOCAL, '10.0.0.0/24', '10.0.0.5'), AD('b2', LOCAL, '10.0.0.0/24', '10.0.0.6')]
  const g = findDuplicateGroups(assets, addrs)
  check('(b) one safe group', [g.length, g[0]?.confidence], [1, 'safe'])
}

// (c) same LOCAL MAC on different /24 → NOT grouped.
{
  const assets = [A({ assetId: 'c1' }), A({ assetId: 'c2' })]
  const addrs = [AD('c1', LOCAL, '10.0.0.0/24', '10.0.0.5'), AD('c2', LOCAL, '10.9.0.0/24', '10.9.0.5')]
  check('(c) no group', findDuplicateGroups(assets, addrs).length, 0)
}

// (d) VMware shared/virtual MAC on two assets (two networks) → NOT grouped.
{
  const assets = [A({ assetId: 'd1' }), A({ assetId: 'd2' })]
  const addrs = [AD('d1', VMWARE, '10.0.0.0/24', '10.0.0.5'), AD('d2', VMWARE, '10.9.0.0/24', '10.9.0.5')]
  check('(d) vmware not grouped', findDuplicateGroups(assets, addrs).length, 0)
}

// (e) two NETWORK devices, same GLOBAL MAC, different non-null networks → REVIEW.
{
  const assets = [A({ assetId: 'e1', deviceType: 'network' }), A({ assetId: 'e2', deviceType: 'network' })]
  const addrs = [AD('e1', GLOBAL, '10.0.0.0/24', '10.0.0.1'), AD('e2', GLOBAL, '10.9.0.0/24', '10.9.0.1')]
  const g = findDuplicateGroups(assets, addrs)
  check('(e) review group', [g.length, g[0]?.confidence], [1, 'review'])
}

// (f) same specific hostname, different MACs → REVIEW. NOTE: "Android-2" matches the
// generic /^android-/ filter in sanitizeHostKey and would be IGNORED (see report),
// so a non-generic hostname is used here to exercise the hostname-REVIEW path.
{
  const assets = [
    A({ assetId: 'f1', hostname: 'WEB-SRV-01', macAddress: GLOBAL }),
    A({ assetId: 'f2', hostname: 'web-srv-01', macAddress: 'aa:bb:cc:00:00:02' }),
  ]
  const addrs = [AD('f1', GLOBAL, '10.0.0.0/24', '10.0.0.5'), AD('f2', 'aa:bb:cc:00:00:02', '10.9.0.0/24', '10.9.0.5')]
  const g = findDuplicateGroups(assets, addrs)
  check('(f) hostname review', [g.length, g[0]?.confidence, g[0]?.reasons[0]], [1, 'review', 'same hostname "web-srv-01", different MACs'])
}

// (g) generic hostnames (UUID-style, real Android default android-<8+ hex>) → ignored.
{
  const assets = [
    A({ assetId: 'g1', hostname: 'android-9f3c1a2b4d5e6f70' }),  // 16 hex → real default
    A({ assetId: 'g2', hostname: 'android-9f3c1a2b4d5e6f70' }),
    A({ assetId: 'g3', hostname: '550e8400-e29b-41d4-a716-446655440000' }),
    A({ assetId: 'g4', hostname: '550e8400-e29b-41d4-a716-446655440000' }),
  ]
  check('(g) generic hostnames ignored', findDuplicateGroups(assets, []).length, 0)
}

// (g2) Short "Android-2" is SPECIFIC → two assets with it + different MACs → REVIEW.
{
  const assets = [
    A({ assetId: 'an1', hostname: 'Android-2', macAddress: GLOBAL }),
    A({ assetId: 'an2', hostname: 'android-2', macAddress: 'aa:bb:cc:00:00:03' }),
  ]
  const addrs = [AD('an1', GLOBAL, '10.0.0.0/24', '10.0.0.7'), AD('an2', 'aa:bb:cc:00:00:03', '10.9.0.0/24', '10.9.0.7')]
  const g = findDuplicateGroups(assets, addrs)
  check('(g2) Android-2 hostname review', [g.length, g[0]?.confidence, g[0]?.reasons[0]], [1, 'review', 'same hostname "android-2", different MACs'])
}

console.log('\n=== planMerge ===')

// (h) merge plan: duplicate survivor edge dropped, survivor<->loser self-loop dropped,
//     remaining edge remapped, and loser current address at same (net,ip) ended first.
{
  const survivor: MergeAsset = { assetId: 'S', tenantId: 't', hostname: 'srv', ipAddress: '10.0.0.5', macAddress: GLOBAL, hostKey: null, owner: null, deviceType: 'server', hardwareVendor: null, osInfo: { a: 1 }, criticalityScore: 5, baselineState: null, isInternetFacing: false, source: 'scan_active', inMyAssets: false, lastScanned: '2026-01-01', createdAt: '2026-01-01' }
  const loser: MergeAsset = { assetId: 'L', tenantId: 't', hostname: null, ipAddress: '10.0.0.5', macAddress: LOCAL, hostKey: null, owner: 'bob', deviceType: 'unknown', hardwareVendor: null, osInfo: { b: 2 }, criticalityScore: 7, baselineState: null, isInternetFacing: true, source: 'manual', inMyAssets: true, lastScanned: '2026-06-01', createdAt: '2025-12-01' }
  const related: MergeRelated = {
    addresses: [
      { addressId: 'sa', assetId: 'S', networkKey: '10.0.0.0/24', ipAddress: '10.0.0.5', endedAt: null, lastSeen: '2026-01-01', firstSeen: '2026-01-01' },
      { addressId: 'la', assetId: 'L', networkKey: '10.0.0.0/24', ipAddress: '10.0.0.5', endedAt: null, lastSeen: '2026-06-01', firstSeen: '2026-05-01' },
    ],
    relationships: [
      { relationshipId: 'r1', sourceAssetId: 'S', targetAssetId: 'X', relationshipType: 'connects_to' }, // survivor edge
      { relationshipId: 'r2', sourceAssetId: 'L', targetAssetId: 'X', relationshipType: 'connects_to' }, // -> dup of r1, drop
      { relationshipId: 'r3', sourceAssetId: 'S', targetAssetId: 'L', relationshipType: 'connects_to' }, // -> self-loop, drop
      { relationshipId: 'r4', sourceAssetId: 'L', targetAssetId: 'Y', relationshipType: 'connects_to' }, // -> remap to S,Y
    ],
    topologyNodes: [{ nodeId: 'ns', assetId: 'S' }, { nodeId: 'nl', assetId: 'L' }],
  }
  const plan = planMerge(survivor, [loser], related)
  check('(h) addresses ended', plan.counts.addressesEnded, 1)
  check('(h) relationships dropped', plan.counts.relationshipsDropped, 2)
  check('(h) relationships remapped', plan.counts.relationshipsMoved, 1)
  check('(h) topology dropped', plan.counts.topologyDropped, 1)
  const endIdx = plan.ops.findIndex(o => o.k === 'endAddress')
  const moveIdx = plan.ops.findIndex(o => o.k === 'moveAddresses')
  check('(h) end-before-move order', endIdx >= 0 && endIdx < moveIdx, true)
  check('(h) ended loser address', (plan.ops.find(o => o.k === 'endAddress') as { addressId: string }).addressId, 'la')
  const dropped = (plan.ops.find(o => o.k === 'deleteRelationships') as { ids: string[] }).ids.sort()
  check('(h) dropped edge ids', dropped, ['r2', 'r3'])
  check('(h) deletes losers last', plan.ops[plan.ops.length - 1]?.k, 'deleteAssets')

  // (i) field merge outcomes.
  // source = latest-scanned non-manual (loser is manual+newest, survivor scan_active) → scan_active.
  check('(i) source = latest non-manual', plan.mergedFields.source, 'scan_active')
  check('(i) inMyAssets OR (loser was a member)', plan.mergedFields.inMyAssets, true)
  check('(i) hostname coalesce (survivor non-empty wins)', plan.mergedFields.hostname, 'srv')
  check('(i) latest ip from newest last_scanned (loser)', plan.mergedFields.ipAddress, '10.0.0.5')
  check('(i) latest mac from newest last_scanned (loser)', plan.mergedFields.macAddress, LOCAL)
  check('(i) deviceType survivor non-unknown', plan.mergedFields.deviceType, 'server')
  check('(i) criticality max', plan.mergedFields.criticalityScore, 7)
  check('(i) internet-facing OR', plan.mergedFields.isInternetFacing, true)
  check('(i) os_info shallow merge', plan.mergedFields.osInfo, { a: 1, b: 2 })
}

console.log('\n=== planMerge: keep exactly ONE current address ===')
{
  const mAsset = (id: string, over: Partial<MergeAsset> = {}): MergeAsset => ({
    assetId: id, tenantId: 't', hostname: null, ipAddress: '0.0.0.0', macAddress: null, hostKey: null,
    owner: null, deviceType: 'workstation', hardwareVendor: null, osInfo: {}, criticalityScore: 1,
    baselineState: null, isInternetFacing: false, source: 'scan_active', inMyAssets: false, lastScanned: '2026-01-01', createdAt: '2026-01-01', ...over,
  })
  const mAddr = (o: Partial<import('../src/lib/merge').MergeAddress> & { addressId: string; assetId: string }): import('../src/lib/merge').MergeAddress => ({
    networkKey: null, ipAddress: '0.0.0.0', endedAt: null, lastSeen: '2026-01-01', firstSeen: '2026-01-01', ...o,
  })
  const endOps = (p: ReturnType<typeof planMerge>) => p.ops.filter(o => o.k === 'endAddress' || o.k === 'endAddressAt')
  const noRel: MergeRelated['relationships'] = []
  const noTopo: MergeRelated['topologyNodes'] = []

  // (a) survivor 1 current + 3 loser current rows on different networks → 1 current remains (latest last_seen).
  {
    const plan = planMerge(
      mAsset('S', { lastScanned: '2026-03-01' }),
      [mAsset('L1', { lastScanned: '2026-07-20' }), mAsset('L2'), mAsset('L3')],
      { addresses: [
        mAddr({ addressId: 'sa', assetId: 'S',  networkKey: 'n0', ipAddress: '10.0.0.5', lastSeen: '2026-03-01' }),
        mAddr({ addressId: 'a1', assetId: 'L1', networkKey: 'n1', ipAddress: '10.1.0.5', lastSeen: '2026-07-20' }), // latest → kept
        mAddr({ addressId: 'a2', assetId: 'L2', networkKey: 'n2', ipAddress: '10.2.0.5', lastSeen: '2026-06-01' }),
        mAddr({ addressId: 'a3', assetId: 'L3', networkKey: 'n3', ipAddress: '10.3.0.5', lastSeen: '2026-05-01' }),
      ], relationships: noRel, topologyNodes: noTopo },
    )
    const ends = endOps(plan)
    check('(a) three stale current rows ended', ends.length, 3)
    check('(a) kept the latest (a1); ended the rest', ends.map(o => o.addressId).sort(), ['a2', 'a3', 'sa'])
    check('(a) ended_at = each row last_seen', (ends.find(o => o.addressId === 'a2') as { endedAt: string }).endedAt, '2026-06-01')
    check('(a) count matches end-ops (e)', plan.counts.addressesEnded, ends.length)
  }

  // (b) last_seen tie → the survivor's own row stays current.
  {
    const plan = planMerge(
      mAsset('S', { lastScanned: '2026-07-01' }),
      [mAsset('L1', { lastScanned: '2026-07-01' })],
      { addresses: [
        mAddr({ addressId: 'sa', assetId: 'S',  networkKey: 'n0', ipAddress: '10.0.0.5', lastSeen: '2026-07-01' }),
        mAddr({ addressId: 'a1', assetId: 'L1', networkKey: 'n1', ipAddress: '10.1.0.5', lastSeen: '2026-07-01' }), // tie
      ], relationships: noRel, topologyNodes: noTopo },
    )
    const ends = endOps(plan)
    check('(b) tie → exactly one ended', ends.length, 1)
    check('(b) tie → survivor row kept, loser ended', ends[0]!.addressId, 'a1')
  }

  // (c) already-ended rows are untouched.
  {
    const plan = planMerge(
      mAsset('S', { lastScanned: '2026-07-01' }),
      [mAsset('L1', { lastScanned: '2026-06-01' })],
      { addresses: [
        mAddr({ addressId: 'sa',  assetId: 'S',  networkKey: 'n0', ipAddress: '10.0.0.5', lastSeen: '2026-07-01' }),
        mAddr({ addressId: 'old', assetId: 'L1', networkKey: 'n1', ipAddress: '10.1.0.5', lastSeen: '2026-01-01', endedAt: '2026-02-01' }),
        mAddr({ addressId: 'a1',  assetId: 'L1', networkKey: 'n2', ipAddress: '10.2.0.5', lastSeen: '2026-06-01' }),
      ], relationships: noRel, topologyNodes: noTopo },
    )
    const ends = endOps(plan)
    check('(c) only the newer current loser ended', ends.map(o => o.addressId), ['a1'])
    check('(c) already-ended row left untouched', ends.some(o => o.addressId === 'old'), false)
  }

  // (d) a colliding row is ended first (collision) and NOT double-ended by the keep-one step.
  {
    const plan = planMerge(
      mAsset('S', { lastScanned: '2026-07-01' }),
      [mAsset('L1', { lastScanned: '2026-06-01' }), mAsset('L2', { lastScanned: '2026-08-01' })],
      { addresses: [
        mAddr({ addressId: 'sa', assetId: 'S',  networkKey: 'n0', ipAddress: '10.0.0.5', lastSeen: '2026-07-01' }),
        mAddr({ addressId: 'c1', assetId: 'L1', networkKey: 'n0', ipAddress: '10.0.0.5', lastSeen: '2026-06-01' }), // collides with sa
        mAddr({ addressId: 'a2', assetId: 'L2', networkKey: 'n1', ipAddress: '10.1.0.5', lastSeen: '2026-08-01' }), // latest → kept
      ], relationships: noRel, topologyNodes: noTopo },
    )
    const collision = plan.ops.filter(o => o.k === 'endAddress')
    const stale = plan.ops.filter(o => o.k === 'endAddressAt')
    check('(d) c1 collision-ended once', collision.map(o => o.addressId), ['c1'])
    check('(d) c1 not double-ended', stale.some(o => o.addressId === 'c1'), false)
    check('(d) survivor stale row sa ended (kept a2)', stale.map(o => o.addressId), ['sa'])
    check('(d) total ended = 2', plan.counts.addressesEnded, 2)
    const ci = plan.ops.findIndex(o => o.k === 'endAddress')
    const mi = plan.ops.findIndex(o => o.k === 'moveAddresses')
    check('(d) collision end before move', ci >= 0 && ci < mi, true)
    check('(d) stale end after move', plan.ops.findIndex(o => o.k === 'endAddressAt') > mi, true)
    // (e) statement count == preview "ended" count
    check('(e) end-ops == counts.addressesEnded', endOps(plan).length, plan.counts.addressesEnded)
  }
}

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail === 0 ? 0 : 1)
