/**
 * endpoint-inventory-demo.ts — exercises the PURE endpoint-inventory helpers (no DB).
 * Run: npx esbuild scripts/endpoint-inventory-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.endpoint-inventory-demo.cjs && node .endpoint-inventory-demo.cjs
 */
import {
  chooseBinding, deviceTypeFor, diffSoftware, identityMacs, inventoryHostKey, inventoryIps, storedInventory,
  type BindingCandidate, type InventoryPayload,
} from '../src/lib/endpointInventory'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

const inv = (over: Partial<InventoryPayload> = {}): InventoryPayload => ({
  schema: 1, platform: 'windows', collected_at: '2026-10-10T12:00:00Z',
  identity: { hostname: 'JOJOCHAW' },
  hardware: { manufacturer: 'HP', form_factor: 'laptop' },
  os: { role: 'workstation' },
  network: {
    primary_ip: '192.168.100.71',
    interfaces: [
      { name: 'Wi-Fi', mac: '14:13:33:C3:F6:03', physical: true, ipv4: ['192.168.100.71'] },
      { name: 'vEthernet (WSL)', mac: '00:15:5D:01:02:03', physical: false, ipv4: ['172.20.0.1'] },
      { name: 'Random MAC NIC', mac: '06:00:59:E5:9A:C6', physical: true, ipv4: [] },        // locally administered
      { name: 'Ethernet', mac: 'A4-BB-CC-DD-EE-01', physical: true, ipv4: ['169.254.10.10'] },
    ],
    listening: [],
  },
  software: [],
  ...over,
})
const cand = (assetId: string, o: Partial<BindingCandidate> = {}): BindingCandidate =>
  ({ assetId, inMyAssets: false, lastScanned: null, hasMac: true, ...o })
const NONE = { boundAssetId: null, macMatches: [], hostKeyMatches: [], ipMatches: [] }

// ── Identity evidence ──
check('identity MACs: physical + global only, normalised',
  identityMacs(inv()), ['14:13:33:c3:f6:03', 'a4:bb:cc:dd:ee:01'])
check('host key: lower-cased specific hostname', inventoryHostKey(inv()), 'jojochaw')
check('host key: generic name ignored', inventoryHostKey(inv({ identity: { hostname: 'localhost' } })), null)
check('IPs: primary first, link-local and virtual NICs skipped', inventoryIps(inv()), ['192.168.100.71'])

// ── Binding ──
check('bound asset wins over everything',
  chooseBinding({ ...NONE, boundAssetId: 'bound', macMatches: [cand('m')] }), { assetId: 'bound', matchedBy: 'bound' })
check('single MAC match',
  chooseBinding({ ...NONE, macMatches: [cand('m')] }), { assetId: 'm', matchedBy: 'mac' })
check('several MAC matches: My Assets member preferred',
  chooseBinding({ ...NONE, macMatches: [cand('a', { lastScanned: '2026-10-10' }), cand('mine', { inMyAssets: true })] }),
  { assetId: 'mine', matchedBy: 'mac' })
check('several MAC matches: most recently seen when none is in My Assets',
  chooseBinding({ ...NONE, macMatches: [cand('old', { lastScanned: '2026-01-01' }), cand('new', { lastScanned: '2026-10-01' })] }),
  { assetId: 'new', matchedBy: 'mac' })
check('same candidate listed twice counts once',
  chooseBinding({ ...NONE, hostKeyMatches: [cand('h'), cand('h')] }), { assetId: 'h', matchedBy: 'hostname' })
check('MAC beats hostname',
  chooseBinding({ ...NONE, macMatches: [cand('m')], hostKeyMatches: [cand('h')] }), { assetId: 'm', matchedBy: 'mac' })
check('ambiguous hostname is not used',
  chooseBinding({ ...NONE, hostKeyMatches: [cand('h1'), cand('h2')] }), null)
check('IP match only for an asset with no MAC on record',
  chooseBinding({ ...NONE, ipMatches: [cand('ip', { hasMac: false })] }), { assetId: 'ip', matchedBy: 'ip' })
check('IP held by an asset with a different MAC = another device, no match',
  chooseBinding({ ...NONE, ipMatches: [cand('ip', { hasMac: true })] }), null)
check('nothing matches → null (create a new asset)', chooseBinding(NONE), null)

// ── Device type for new assets ──
check('workstation role → workstation', deviceTypeFor(inv()), 'workstation')
check('server role → server', deviceTypeFor(inv({ os: { role: 'server' } })), 'server')
check('domain controller → server', deviceTypeFor(inv({ os: { role: 'domain_controller' } })), 'server')
check('server chassis without role → server', deviceTypeFor(inv({ os: {}, hardware: { form_factor: 'server' } })), 'server')
check('nothing known → unknown', deviceTypeFor(inv({ os: {}, hardware: {} })), 'unknown')

// ── Software diff ──
const row = (id: string, name: string, version: string | null, publisher: string | null = 'Vendor') =>
  ({ softwareId: id, name, version, publisher })
const diff = diffSoftware(
  [row('1', 'Google Chrome', '120.0'), row('2', 'Old App', '1.0'), row('3', 'Zoom', '5.0'), row('4', 'zoom', '5.0', 'vendor')],
  [{ name: 'Google Chrome', version: '120.0', publisher: 'Vendor' },
   { name: 'Zoom', version: '5.1', publisher: 'Vendor' },
   { name: 'New App', version: '2.0', publisher: null },
   { name: 'New App', version: '2.0', publisher: null }],
)
check('software diff: unchanged kept', diff.unchanged, 1)
check('software diff: version change = delete old + insert new; removed app deleted; duplicate row deleted',
  diff.deleteIds.sort(), ['2', '3', '4'])
check('software diff: inserts are de-duplicated', diff.insert.map(s => `${s.name} ${s.version}`), ['Zoom 5.1', 'New App 2.0'])
check('software diff: identical lists → nothing to do',
  diffSoftware([row('1', 'A', '1')], [{ name: 'a', version: '1', publisher: 'vendor' }]), { insert: [], deleteIds: [], unchanged: 1 })

// ── Stored blob ──
const many = Array.from({ length: 700 }, (_, i) => ({ port: i }))
const stored = storedInventory(inv({
  software: [{ name: 'A' }, { name: 'B' }],
  network: { ...inv().network, listening: many },
  patches: { hotfixes: Array.from({ length: 250 }, (_, i) => ({ id: `KB${i}` })) },
}))
check('stored blob drops software but keeps the count', ['software' in stored, stored['software_count']], [false, 2])
check('stored blob caps listening ports at 500', ((stored['network'] as { listening: unknown[] }).listening).length, 500)
check('stored blob caps hotfixes at 200', ((stored['patches'] as { hotfixes: unknown[] }).hotfixes).length, 200)

console.log(`\n${pass} passed, ${fail} failed`)
if (fail) process.exit(1)
