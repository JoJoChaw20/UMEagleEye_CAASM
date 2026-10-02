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
  source: 'scan_active', deviceType: 'workstation', lastScanned: '2026-01-01', createdAt: '2026-01-01',
  hostKey: null, ...over,
})
const AD = (assetId: string, mac: string | null, net: string | null, ip: string): DupAddress => ({
  addressId: `ad-${assetId}-${ip}`, assetId, networkKey: net, ipAddress: ip, macAddress: mac, endedAt: null,
})

const GLOBAL = '98:bb:cc:00:00:01'   // first byte 0x98 → unicast, non-LA → global/OUI
const LOCAL = '02:00:00:00:00:aa'    // first byte 0x02 → locally administered → local
const VMWARE = '00:50:56:c0:00:08'   // VMware shared/virtual

console.log('=== findDuplicateGroups ===')

// (a) 4 assets, same GLOBAL MAC, 4 different networks, one manual → SAFE, manual survivor.
{
  const assets = [
    A({ assetId: 'm', source: 'manual', ipAddress: '10.0.0.10' }),
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
  check('(a) survivor = manual', g[0]?.suggestedSurvivorId, 'm')
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
  const survivor: MergeAsset = { assetId: 'S', tenantId: 't', hostname: 'srv', ipAddress: '10.0.0.5', macAddress: GLOBAL, hostKey: null, owner: null, deviceType: 'server', hardwareVendor: null, osInfo: { a: 1 }, criticalityScore: 5, baselineState: null, isInternetFacing: false, source: 'scan_active', lastScanned: '2026-01-01', createdAt: '2026-01-01' }
  const loser: MergeAsset = { assetId: 'L', tenantId: 't', hostname: null, ipAddress: '10.0.0.5', macAddress: LOCAL, hostKey: null, owner: 'bob', deviceType: 'unknown', hardwareVendor: null, osInfo: { b: 2 }, criticalityScore: 7, baselineState: null, isInternetFacing: true, source: 'manual', lastScanned: '2026-06-01', createdAt: '2025-12-01' }
  const related: MergeRelated = {
    addresses: [
      { addressId: 'sa', assetId: 'S', networkKey: '10.0.0.0/24', ipAddress: '10.0.0.5', endedAt: null, lastSeen: '2026-01-01' },
      { addressId: 'la', assetId: 'L', networkKey: '10.0.0.0/24', ipAddress: '10.0.0.5', endedAt: null, lastSeen: '2026-06-01' },
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
  check('(i) source manual if any', plan.mergedFields.source, 'manual')
  check('(i) hostname coalesce (survivor non-empty wins)', plan.mergedFields.hostname, 'srv')
  check('(i) latest ip from newest last_scanned (loser)', plan.mergedFields.ipAddress, '10.0.0.5')
  check('(i) latest mac from newest last_scanned (loser)', plan.mergedFields.macAddress, LOCAL)
  check('(i) deviceType survivor non-unknown', plan.mergedFields.deviceType, 'server')
  check('(i) criticality max', plan.mergedFields.criticalityScore, 7)
  check('(i) internet-facing OR', plan.mergedFields.isInternetFacing, true)
  check('(i) os_info shallow merge', plan.mergedFields.osInfo, { a: 1, b: 2 })
}

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail === 0 ? 0 : 1)
