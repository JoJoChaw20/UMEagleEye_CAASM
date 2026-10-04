/**
 * identity-demo.ts — exercises the PURE identity functions (no DB, no test runner).
 * Run: npx esbuild scripts/identity-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.identity-demo.cjs && node .identity-demo.cjs
 * (see the report for captured output).
 */
import {
  classifyMac, sanitizeHostKey, deriveNetworkKey, matchAsset,
  type CandidateAddress, type MatcherCandidates, type MatcherInput, type MatchDecision,
} from '../src/lib/identity'
import { planIngest, chunkPlan, type PlanHost, type IngestOp } from '../src/lib/ingest-plan'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}\n      got=${JSON.stringify(actual)}  expected=${JSON.stringify(expected)}`)
  ok ? pass++ : fail++
}

const addr = (o: Partial<CandidateAddress> & { assetId: string }): CandidateAddress => ({
  addressId: o.addressId ?? `addr-${o.assetId}`,
  assetId: o.assetId,
  networkKey: o.networkKey ?? null,
  ipAddress: o.ipAddress ?? '0.0.0.0',
  macAddress: o.macAddress ?? null,
  assetDeviceType: o.assetDeviceType ?? 'workstation',
})
const NONE: MatcherCandidates = { macAddresses: [], hostKeyAssetIds: [], netIpAddresses: [] }
const run = (label: string, input: MatcherInput, cand: MatcherCandidates): MatchDecision => {
  const d = matchAsset(input, cand)
  console.log(`\n# ${label}\n  input=${JSON.stringify(input)}\n  -> ${JSON.stringify(d)}`)
  return d
}

console.log('=== classifyMac ===')
for (const m of [
  '98:48:27:CB:55:6C', '98-48-27-cb-55-6c', '9848.27cb.556c',   // global, mixed formats
  '02:11:22:33:44:55', '06:aa:bb:cc:dd:ee',                     // locally administered (random/private)
  '00:50:56:c0:00:08',                                          // VMware virtual
  '00:00:5e:00:01:2a', '00:00:0c:07:ac:10', '02:bf:ab:cd:ef:01',// VRRP / HSRP / MS-NLB
  'ff:ff:ff:ff:ff:ff', '01:00:5e:00:00:fb', '00:00:00:00:00:00',// broadcast / multicast / zero
  'nope', 'aa:bb:cc', '',                                       // invalid
]) {
  console.log(`  ${JSON.stringify(m).padEnd(22)} -> ${JSON.stringify(classifyMac(m))}`)
}

console.log('\n=== sanitizeHostKey ===')
for (const h of ['WIN-SERVER01', 'android-9f3c1a', 'localhost', 'iPhone', 'iPad',
  '550e8400-e29b-41d4-a716-446655440000', '  Lab-Router  ', '']) {
  console.log(`  ${JSON.stringify(h).padEnd(40)} -> ${JSON.stringify(sanitizeHostKey(h))}`)
}

console.log('\n=== deriveNetworkKey (always the host IP /24, gateway-independent) ===')
// Same /24 must yield the same key regardless of active/passive or gateway presence.
const activeKey  = deriveNetworkKey({ ip: '192.168.0.10' })   // active scan host
const passiveKey = deriveNetworkKey({ ip: '192.168.0.200' })  // passive host, same /24
console.log(`  active  192.168.0.10  -> ${JSON.stringify(activeKey)}`)
console.log(`  passive 192.168.0.200 -> ${JSON.stringify(passiveKey)}`)
check('netkey active==passive (same /24)', activeKey, passiveKey)
check('netkey value', activeKey, '192.168.0.0/24')
check('netkey manual -> null', deriveNetworkKey({ ip: '192.168.0.10', isManualSource: true }), null)
check('netkey IPv6 -> null', deriveNetworkKey({ ip: 'fe80::1' }), null)
check('netkey unparseable -> null', deriveNetworkKey({ ip: 'not-an-ip' }), null)
check('netkey bad octet -> null', deriveNetworkKey({ ip: '10.0.0.999' }), null)

console.log('\n=== matchAsset cases ===')

// 1. Same global MAC on a new IP -> rule 1 match.
{
  const c = classifyMac('98:48:27:cb:55:6c')
  const d = run('1) global MAC, new IP', { macClass: c.macClass, mac: c.mac, ip: '192.168.0.50', hostKey: null, networkKey: 'net1' },
    { ...NONE, macAddresses: [addr({ assetId: 'X', networkKey: 'net1', ipAddress: '192.168.0.10', macAddress: c.mac! })] })
  check('case1 rule', d.rule, 1); check('case1 assetId', d.assetId, 'X')
}

// 2. Same net+IP, different valid MAC -> rule 5 (new asset, end old address).
{
  const c = classifyMac('06:aa:bb:cc:dd:ee')
  const d = run('2) reused IP, different MAC', { macClass: c.macClass, mac: c.mac, ip: '192.168.0.20', hostKey: null, networkKey: 'net1' },
    { ...NONE, netIpAddresses: [addr({ assetId: 'Y', addressId: 'A2', networkKey: 'net1', ipAddress: '192.168.0.20', macAddress: '02:11:22:33:44:55' })] })
  check('case2 rule', d.rule, 5); check('case2 endAddressId', (d as any).endAddressId, 'A2')
}

// 3. Random (local) MAC reappears on the same network -> rule 2.
{
  const c = classifyMac('02:11:22:33:44:55')
  const d = run('3) local MAC, same network', { macClass: c.macClass, mac: c.mac, ip: '192.168.0.21', hostKey: null, networkKey: 'net1' },
    { ...NONE, macAddresses: [addr({ assetId: 'Y', addressId: 'A2', networkKey: 'net1', ipAddress: '192.168.0.20', macAddress: c.mac! })] })
  check('case3 rule', d.rule, 2); check('case3 assetId', d.assetId, 'Y')
}

// 4. CSV asset (unscoped, no MAC), then a scan of the same IP -> rule 4 (fill MAC).
{
  const c = classifyMac('aa:bb:cc:dd:ee:04')
  const d = run('4) scan fills CSV asset (unscoped, no MAC)', { macClass: c.macClass, mac: c.mac, ip: '10.0.0.30', hostKey: null, networkKey: 'net1' },
    { ...NONE, netIpAddresses: [addr({ assetId: 'Z', addressId: 'A4', networkKey: null, ipAddress: '10.0.0.30', macAddress: null })] })
  check('case4 rule', d.rule, 4); check('case4 assetId', d.assetId, 'Z')
}

// 5. Two Apple-private (locally-administered) MACs in different networks -> no match.
{
  const c = classifyMac('06:11:22:33:44:a2') // different private MAC, seen on net2
  const d = run('5) apple-private MACs, different networks', { macClass: c.macClass, mac: c.mac, ip: '192.168.1.60', hostKey: null, networkKey: 'net2' },
    { ...NONE }) // DB returns nothing for THIS mac / net2+ip
  check('case5 rule', d.rule, 6); check('case5 assetId', d.assetId, null)
}

// 6. VMware virtual MAC seen on two networks -> no match (local MAC only matches same network).
{
  const c = classifyMac('00:50:56:c0:00:08')
  const d = run('6) VMware MAC on a different network', { macClass: c.macClass, mac: c.mac, ip: '192.168.2.70', hostKey: null, networkKey: 'net2' },
    { ...NONE, macAddresses: [addr({ assetId: 'V', networkKey: 'net1', ipAddress: '192.168.1.70', macAddress: c.mac!, assetDeviceType: 'server' })] })
  check('case6 class', c.macClass, 'local'); check('case6 rule', d.rule, 6); check('case6 assetId', d.assetId, null)
}

// 7. Broadcast / multicast MAC -> treated as no MAC (invalid class), new asset.
{
  const b = classifyMac('ff:ff:ff:ff:ff:ff')
  const m = classifyMac('01:00:5e:00:00:fb')
  check('case7 broadcast invalid', b, { mac: null, macClass: 'invalid' })
  check('case7 multicast invalid', m, { mac: null, macClass: 'invalid' })
  const d = run('7) broadcast MAC -> no usable MAC', { macClass: b.macClass, mac: b.mac, ip: '192.168.0.99', hostKey: null, networkKey: 'net1' }, NONE)
  check('case7 rule', d.rule, 6)
}

// 8. Hostname-only -> never matches (no MAC, no address, no host_key record).
{
  const d = run('8) hostname only', { macClass: 'invalid', mac: null, ip: '192.168.0.88', hostKey: 'laptop-01', networkKey: 'net1' }, NONE)
  check('case8 rule', d.rule, 6)
}

// 9. Tiebreaker: two legacy assets share a global MAC. The DB wrapper orders
//    candidates by last_seen DESC then created_at ASC, so matchAsset deterministically
//    picks index 0 (the most-recently-seen asset). Here candidates are supplied in
//    that wrapper order.
{
  const c = classifyMac('98:48:27:cb:55:6c')
  const candidates: MatcherCandidates = {
    ...NONE,
    macAddresses: [
      addr({ assetId: 'RECENT', addressId: 'a-recent', networkKey: '192.168.0.0/24', ipAddress: '192.168.0.11', macAddress: c.mac! }),
      addr({ assetId: 'OLD',    addressId: 'a-old',    networkKey: '192.168.0.0/24', ipAddress: '192.168.0.12', macAddress: c.mac! }),
    ],
  }
  const d = run('9) tiebreak: duplicate global MAC -> most-recent last_seen wins',
    { macClass: c.macClass, mac: c.mac, ip: '192.168.0.11', hostKey: null, networkKey: '192.168.0.0/24' }, candidates)
  check('case9 rule', d.rule, 1); check('case9 picks most-recent', d.assetId, 'RECENT')
}

// 10. Global MAC vs an UNSCOPED manual asset on the scan network -> must match
//     (rule 1). Previously the network/server cross-network exception wrongly fired
//     against the null key and created a duplicate. Caller fills the network_key.
{
  const c = classifyMac('98:48:27:cb:55:6c')
  const d = run('10) global MAC vs unscoped manual gateway (same IP)',
    { macClass: c.macClass, mac: c.mac, ip: '192.168.0.1', hostKey: null, networkKey: '192.168.0.0/24' },
    { ...NONE, macAddresses: [addr({ assetId: 'M', addressId: 'am', networkKey: null, ipAddress: '192.168.0.1', macAddress: c.mac!, assetDeviceType: 'network' })] })
  check('case10 rule', d.rule, 1); check('case10 assetId', d.assetId, 'M')
}

// 11. Local MAC + same IP vs an unscoped manual asset -> must match (rule 2,
//     unscoped-same-IP treated as same network).
{
  const c = classifyMac('00:50:56:c0:00:08') // VMware local MAC
  const d = run('11) local MAC vs unscoped manual asset (same IP)',
    { macClass: c.macClass, mac: c.mac, ip: '192.168.217.1', hostKey: null, networkKey: '192.168.217.0/24' },
    { ...NONE, macAddresses: [addr({ assetId: 'L', addressId: 'al', networkKey: null, ipAddress: '192.168.217.1', macAddress: c.mac! })] })
  check('case11 rule', d.rule, 2); check('case11 assetId', d.assetId, 'L')
}

// 12. Local MAC + DIFFERENT IP vs an unscoped asset -> must NOT match (rule 6).
{
  const c = classifyMac('02:aa:bb:cc:dd:ee')
  const d = run('12) local MAC vs unscoped asset (different IP)',
    { macClass: c.macClass, mac: c.mac, ip: '192.168.217.9', hostKey: null, networkKey: '192.168.217.0/24' },
    { ...NONE, macAddresses: [addr({ assetId: 'L2', addressId: 'al2', networkKey: null, ipAddress: '192.168.217.5', macAddress: c.mac! })] })
  check('case12 rule', d.rule, 6); check('case12 assetId', d.assetId, null)
}

// ── In-memory batched plan: 100 hosts, constant subrequests ──
console.log('\n=== batched plan: 100 hosts (in-memory, no DB) ===')
{
  const mk = (ip: string, mac: string): PlanHost => ({
    ip, rawMac: mac, hostname: null, hostKeyRaw: null, deviceType: 'workstation',
    observedOsInfo: {}, ports: [], hardwareVendor: null, internetFacing: false, isPassive: false, tenantId: 't1',
  })
  const hosts: PlanHost[] = []
  for (let i = 0; i < 100; i++) hosts.push(mk(`10.0.1.${i}`, `02:00:00:00:0a:${i.toString(16).padStart(2, '0')}`))
  // Two hosts with the SAME global MAC → host[50] must resolve to host[0]'s new asset.
  hosts[0] = mk('10.0.0.10', '98:48:27:cb:55:60')
  hosts[50] = mk('10.0.0.60', '98:48:27:cb:55:60')
  // Two hosts, SAME IP, different local MAC → host[2] (rule 5) ends the address host[1] created in-batch.
  hosts[1] = mk('10.0.0.20', '02:00:00:00:00:01')
  hosts[2] = mk('10.0.0.20', '02:00:00:00:00:02')

  let n = 0
  const plan = planIngest(hosts, { addresses: [], assets: [] }, { newId: () => `id-${n++}` })
  const chunks = chunkPlan(plan.perHost, 100)

  console.log(`  hosts=${hosts.length}  statements=${plan.statementCount}  chunks(@100)=${chunks.length}  upsertedAssetIds=${plan.upsertedAssetIds.length}`)
  const uniqueAssets = new Set(plan.upsertedAssetIds).size
  console.log(`  unique assets=${uniqueAssets}  (one fewer than hosts: host[50] merged into host[0])`)

  // host[50] resolves to host[0]'s asset (same global MAC).
  check('batch: host50 == host0 asset', plan.perHost[50]!.assetId, plan.perHost[0]!.assetId)
  check('batch: host50 is an update (rule 1)', [plan.perHost[50]!.isNew, plan.perHost[50]!.rule], [false, 1])
  check('batch: host0 is new', plan.perHost[0]!.isNew, true)
  check('batch: 99 unique assets', uniqueAssets, 99)

  // host[2] (rule 5) ends the address host[1] created in the same batch.
  const host1AddrId = (plan.perHost[1]!.ops.find(o => o.k === 'insertAddress') as Extract<IngestOp, { k: 'insertAddress' }>).values.addressId
  const host2EndId = (plan.perHost[2]!.ops.find(o => o.k === 'endAddress') as Extract<IngestOp, { k: 'endAddress' }> | undefined)?.addressId
  check('batch: host2 is rule 5', plan.perHost[2]!.rule, 5)
  check('batch: host2 ends host1 in-batch address', host2EndId, host1AddrId)

  // Subrequests are constant regardless of host count:
  console.log(`  subrequest formula (active): 2 agent + 1 scan + 3 prefetch + 1 LLM + <=16 vendor(OUI-capped) + ${chunks.length} write chunk(s) + 1 driftBatch + 1 completion`)
}

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail === 0 ? 0 : 1)
