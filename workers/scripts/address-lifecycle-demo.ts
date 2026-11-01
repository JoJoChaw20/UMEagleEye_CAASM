/**
 * address-lifecycle-demo.ts — when a device's address stops being current, and when a
 * MAC still identifies its device. PURE (no DB). From staging, 29 Oct–1 Nov:
 *  - two sites both on 192.168.0.0/24: the lab's router took .1 (ending the home router's
 *    address), and the home router came back as a NEW asset (now rule 1-past);
 *  - a laptop that moved from the lab to home kept both addresses "current" (now one
 *    network card = one current address);
 *  - a GNS3 loopback (02:00:4c:4f:4f:50) recorded as the laptop's address (shared MACs
 *    identify nothing; migration 0020 ends the old rows).
 * Run: npx esbuild scripts/address-lifecycle-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.address-lifecycle-demo.cjs && node .address-lifecycle-demo.cjs
 */
import { addressesToEnd, matchAsset, type CandidateAddress } from '../src/lib/identity'
import { planIngest, type IdentityPrefetch, type PlanHost, type PrefetchAsset } from '../src/lib/ingest-plan'
import { planAgentAddress, primaryMac } from '../src/lib/endpointInventory'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

const LAB = '192.168.0.0/24'
const HOME = '192.168.100.0/24'
const ROUTER_A = '98:48:27:cb:55:6c'   // home-side TP-Link
const ROUTER_B = 'b0:a7:b9:c3:87:9a'   // the lab's TP-Link, also at .1
const LAPTOP = '14:13:33:c3:f6:03'

const cand = (o: Partial<CandidateAddress> & { addressId: string; assetId: string }): CandidateAddress =>
  ({ networkKey: LAB, ipAddress: '192.168.0.1', macAddress: null, assetDeviceType: 'network', ...o })

console.log('\n── rule 1-past: a global MAC whose address was ended ──')
{
  const past = [cand({ addressId: 'old-a', assetId: 'A', macAddress: ROUTER_A })]
  check('matched to the device that had it',
    matchAsset({ macClass: 'global', mac: ROUTER_A, ip: '192.168.0.1', hostKey: null, networkKey: LAB },
      { macAddresses: [], hostKeyAssetIds: [], netIpAddresses: [cand({ addressId: 'cur-b', assetId: 'B', macAddress: ROUTER_B })], pastMacAddresses: past }),
    { rule: '1-past', assetId: 'A', matchedAddressId: null })
  check('a router last seen on another network: possible duplicate, not merged (as rule 1)',
    matchAsset({ macClass: 'global', mac: ROUTER_A, ip: '10.0.0.1', hostKey: null, networkKey: '10.0.0.0/24' },
      { macAddresses: [], hostKeyAssetIds: [], netIpAddresses: [], pastMacAddresses: past }),
    { rule: '1-possible-duplicate', assetId: null, possibleDuplicateOf: 'A' })
  check('a current address still wins (rule 1)',
    matchAsset({ macClass: 'global', mac: ROUTER_A, ip: '192.168.0.1', hostKey: null, networkKey: LAB },
      { macAddresses: [cand({ addressId: 'cur-c', assetId: 'C', macAddress: ROUTER_A })], hostKeyAssetIds: [], netIpAddresses: [], pastMacAddresses: past }).rule,
    1)
  check('a private (local) MAC never matches an ended address',
    matchAsset({ macClass: 'local', mac: 'ee:89:d5:a2:89:6a', ip: '192.168.0.114', hostKey: null, networkKey: LAB },
      { macAddresses: [], hostKeyAssetIds: [], netIpAddresses: [], pastMacAddresses: [cand({ addressId: 'p', assetId: 'G', macAddress: 'ee:89:d5:a2:89:6a' })] }).rule,
    6)
}

console.log('\n── addressesToEnd ──')
{
  const rows = [
    { addressId: 'lab', assetId: 'L', networkKey: LAB, ipAddress: '192.168.0.139', macAddress: LAPTOP },
    { addressId: 'home', assetId: 'L', networkKey: HOME, ipAddress: '192.168.100.71', macAddress: LAPTOP },
    { addressId: 'eth', assetId: 'L', networkKey: '10.1.0.0/24', ipAddress: '10.1.0.5', macAddress: 'aa:bb:cc:00:00:01' },
    { addressId: 'typed', assetId: 'L', networkKey: null, ipAddress: '1.2.3.4', macAddress: LAPTOP },
    { addressId: 'phone', assetId: 'P', networkKey: HOME, ipAddress: '192.168.100.80', macAddress: '6a:00:00:00:00:01' },
  ]
  check('laptop seen at home: its lab address (same MAC) ends; Ethernet and hand-typed rows stay',
    addressesToEnd(rows, { assetId: 'L', networkKey: HOME, ip: '192.168.100.71', mac: LAPTOP, keepAddressId: 'home' }), ['lab'])
  check('the laptop taking the phone\'s IP ends the phone\'s address',
    addressesToEnd(rows, { assetId: 'L', networkKey: HOME, ip: '192.168.100.80', mac: LAPTOP }), ['lab', 'phone'])
  check('no MAC known: only another holder of the IP ends',
    addressesToEnd(rows, { assetId: 'L', networkKey: HOME, ip: '192.168.100.80', mac: null }), ['phone'])
  check('unscoped sighting (manual): nothing ends', addressesToEnd(rows, { assetId: 'L', networkKey: null, ip: '9.9.9.9', mac: LAPTOP }), [])
}

console.log('\n── scan upload: the router comes back (staging, 1 Nov) ──')
{
  const asset = (assetId: string, deviceType = 'network'): PrefetchAsset => ({
    assetId, deviceType, hostKey: null, osInfo: {}, hostname: null, owner: null, hardwareVendor: 'TP-Link', macAddress: null,
    source: 'scan_passive', deviceTypeSource: 'auto', hasBaseline: true, baseline: null, internetFacingOverride: null,
  })
  const prefetch: IdentityPrefetch = {
    addresses: [{ addressId: 'b-cur', assetId: 'B', networkKey: LAB, ipAddress: '192.168.0.1', macAddress: ROUTER_B, deviceType: 'network', lastSeen: 2, assetCreatedAt: 2 }],
    assets: [asset('A'), asset('B')],
    pastMacAddresses: [{ addressId: 'a-old', assetId: 'A', networkKey: LAB, ipAddress: '192.168.0.1', macAddress: ROUTER_A, deviceType: 'network', lastSeen: 1, assetCreatedAt: 1 }],
  }
  const host: PlanHost = {
    ip: '192.168.0.1', rawMac: ROUTER_A, hostname: null, hostKeyRaw: null, deviceType: 'network', observedOsInfo: {},
    ports: [], hardwareVendor: 'TP-Link', internetFacing: false, isPassive: true, tenantId: 't',
  }
  let n = 0
  const plan = planIngest([host], prefetch, { newId: () => `new-${++n}`, now: new Date('2026-11-01T04:25:26Z'), networkKeyFor: () => LAB })
  const ph = plan.perHost[0]!
  check('same asset as before (rule 1-past), not a new one', [ph.assetId, ph.rule, ph.isNew], ['A', '1-past', false])
  check('the lab router\'s address ends, then router A gets a new current one',
    ph.ops.filter(o => o.k === 'endAddress' || o.k === 'insertAddress').map(o => o.k === 'endAddress' ? `end ${o.addressId}` : `insert ${(o as { values: { assetId: string } }).values.assetId}`),
    ['end b-cur', 'insert A'])
  check('no new-device alert', ph.ops.some(o => o.k === 'insertEvent'), false)
}

console.log('\n── scan upload: the laptop is back home ──')
{
  const prefetch: IdentityPrefetch = {
    addresses: [
      { addressId: 'lab', assetId: 'L', networkKey: LAB, ipAddress: '192.168.0.139', macAddress: LAPTOP, deviceType: 'workstation', lastSeen: 1, assetCreatedAt: 1 },
      { addressId: 'home', assetId: 'L', networkKey: HOME, ipAddress: '192.168.100.71', macAddress: LAPTOP, deviceType: 'workstation', lastSeen: 2, assetCreatedAt: 1 },
    ],
    assets: [{ assetId: 'L', deviceType: 'workstation', hostKey: 'jojochaw', osInfo: {}, hostname: 'JoJochaw', owner: null, hardwareVendor: null,
      macAddress: LAPTOP, source: 'agent', deviceTypeSource: 'agent', hasBaseline: true, baseline: null, internetFacingOverride: null }],
  }
  const host: PlanHost = {
    ip: '192.168.100.71', rawMac: LAPTOP, hostname: 'JoJochaw', hostKeyRaw: 'JoJochaw', deviceType: 'workstation', observedOsInfo: {},
    ports: [], hardwareVendor: null, internetFacing: false, isPassive: true, tenantId: 't',
  }
  const plan = planIngest([host], prefetch, { newId: () => 'x', now: new Date(), networkKeyFor: () => HOME })
  const ops = plan.perHost[0]!.ops.filter(o => o.k === 'endAddress' || o.k === 'updateAddress' || o.k === 'insertAddress')
    .map(o => `${o.k} ${'addressId' in o ? o.addressId : ''}`.trim())
  check('home row refreshed, lab row ended', ops, ['endAddress lab', 'updateAddress home'])
  // the MAC match picks the most recently seen row: here the lab one
  const labNewer = { ...prefetch, addresses: prefetch.addresses.map(a => ({ ...a, lastSeen: a.addressId === 'lab' ? 9 : 1 })) }
  const plan2 = planIngest([host], labNewer, { newId: () => 'x', now: new Date(), networkKeyFor: () => HOME })
  check('even when the lab row was seen last: home row refreshed, no second home row',
    plan2.perHost[0]!.ops.filter(o => o.k === 'endAddress' || o.k === 'updateAddress' || o.k === 'insertAddress')
      .map(o => `${o.k} ${'addressId' in o ? o.addressId : ''}`.trim()), ['endAddress lab', 'updateAddress home'])
}

console.log('\n── agent inventory ──')
{
  const current = [
    { addressId: 'lab', assetId: 'L', networkKey: LAB, ipAddress: '192.168.0.139', macAddress: LAPTOP },
    { addressId: 'home', assetId: 'L', networkKey: HOME, ipAddress: '192.168.100.71', macAddress: LAPTOP },
    { addressId: 'loop', assetId: 'L', networkKey: '142.19.0.0/23', ipAddress: '142.19.0.1', macAddress: '02:00:4c:4f:4f:50' },
  ]
  check('inventory from home: lab row ends, home row refreshed (the loopback row is migration 0020\'s)',
    planAgentAddress('L', '192.168.100.71', LAPTOP, HOME, current).map(o => `${o.k}${'addressId' in o ? ' ' + o.addressId : ''}`),
    ['end lab', 'refresh home'])
  check('inventory from a new address at the lab: old lab row and home row end, new row inserted',
    planAgentAddress('L', '192.168.0.200', LAPTOP, LAB, current).map(o => `${o.k}${'addressId' in o ? ' ' + o.addressId : ''}`),
    ['end home', 'end lab', 'insert'])
  const inv = { identity: { hostname: 'JoJochaw' }, network: { primary_ip: '142.19.0.1', interfaces: [
    { name: 'KM-TEST', mac: '02:00:4C:4F:4F:50', ipv4: ['142.19.0.1'], physical: true },
    { name: 'Wi-Fi', mac: '14:13:33:C3:F6:03', ipv4: ['192.168.100.71'], physical: true },
  ] } }
  check('primary MAC is never a shared virtual one', primaryMac(inv as never) === '02:00:4c:4f:4f:50', false)
}

console.log(`\n${pass} passed, ${fail} failed`)
if (fail > 0) process.exit(1)
