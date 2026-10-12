/**
 * machine-identity-demo.ts — Phase C1: machine identifiers, binding with the VM-clone
 * guard, agent-confirmed device type, agent address bookkeeping, scan rule 1-agent,
 * identifier-based duplicates and merge of inventory/software/identifiers. PURE (no DB).
 * Run: npx esbuild scripts/machine-identity-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.machine-identity-demo.cjs && node .machine-identity-demo.cjs
 */
import {
  machineIdentifiers, normalizeHardwareUuid, normalizeOsInstallId, differentHardware, hardwareUuidForms,
} from '../src/lib/machineIdentity'
import {
  bindMachine, chooseBinding, planAgentAddress, primaryMac, resolveAgentDeviceType,
  type BindingCandidate, type InventoryPayload,
} from '../src/lib/endpointInventory'
import { matchAsset, type MatcherCandidates } from '../src/lib/identity'
import { planIngest, resolveIngestDeviceType, type PlanHost } from '../src/lib/ingest-plan'
import { findDuplicateGroups, type DupAsset, type DupAddress } from '../src/lib/duplicates'
import { planMerge, type MergeAsset } from '../src/lib/merge'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

// Canonical (byte-order independent) form of the Dell UUID 4C4C4544-0044-3510-8053-B4C04F564E32.
const UUID_A = '44454c4c-4400-1035-8053-b4c04f564e32'
const UUID_B = '6f1d2a90-3c55-4b8e-9d0a-1b2c3d4e5f60'
const GUID = '9a8b7c6d-1111-2222-3333-444455556666'

// ── 1. Normalising identifiers ──
console.log('\n── identifiers ──')
check('hardware UUID lowercased, braces stripped', normalizeHardwareUuid('{4C4C4544-0044-3510-8053-B4C04F564E32}'), UUID_A)
check('same VM, Windows (WMI) and Linux (sysfs) byte orders -> one value',
  normalizeHardwareUuid('564DD698-9A35-099C-B4BB-2E973F046C77'), normalizeHardwareUuid('98d64d56-359a-9c09-b4bb-2e973f046c77'))
check('placeholder UUID caught in either byte order',
  [normalizeHardwareUuid('03000200-0400-0500-0006-000700080009'), normalizeHardwareUuid('00020003-0004-0005-0006-000700080009')], [null, null])
check('different machines stay different', normalizeHardwareUuid('564dd698-9a35-099c-b4bb-2e973f046c77') === normalizeHardwareUuid('564dd698-9a35-099c-b4bb-2e973f046c78'), false)
check('all-zero UUID dropped', normalizeHardwareUuid('00000000-0000-0000-0000-000000000000'), null)
check('all-F UUID dropped', normalizeHardwareUuid('FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'), null)
check('"To be filled by O.E.M." placeholder UUID dropped', normalizeHardwareUuid('03000200-0400-0500-0006-000700080009'), null)
check('Dell UUID without a service tag dropped', normalizeHardwareUuid('4C4C4544-0000-0000-0000-000000000000'), null)
check('non-UUID text dropped', normalizeHardwareUuid('Not Available'), null)
check('Windows MachineGuid kept', normalizeOsInstallId(GUID.toUpperCase()), GUID)
check('Linux machine-id (32 hex) kept', normalizeOsInstallId('0123456789abcdef0123456789abcdef'), '0123456789abcdef0123456789abcdef')
check('all-zero machine-id dropped', normalizeOsInstallId('00000000000000000000000000000000'), null)
check('garbage machine-id dropped', normalizeOsInstallId('xyz'), null)

const inv = (over: Partial<InventoryPayload> = {}, identity: Record<string, unknown> = {}): InventoryPayload => ({
  schema: 1, platform: 'windows', collected_at: '2026-10-11T12:00:00Z',
  identity: { hostname: 'LAPTOP-1', smbios_uuid: UUID_A, machine_guid: GUID, ...identity },
  network: {
    primary_ip: '192.168.100.71',
    interfaces: [
      { name: 'Ethernet', mac: 'A4-BB-CC-DD-EE-01', physical: true, ipv4: [] },
      { name: 'Wi-Fi', mac: '14:13:33:C3:F6:03', physical: true, ipv4: ['192.168.100.71'] },
      { name: 'vEthernet (WSL)', mac: '00:15:5D:01:02:03', physical: false, ipv4: ['172.20.0.1'] },
      { name: 'Random MAC', mac: '06:00:59:E5:9A:C6', physical: true, ipv4: [] },
    ],
  },
  software: [],
  ...over,
})
check('identifiers: hardware UUID, OS install id, every physical global MAC', machineIdentifiers(inv()), [
  { kind: 'hardware_uuid', value: UUID_A }, { kind: 'os_install_id', value: GUID },
  { kind: 'mac', value: 'a4:bb:cc:dd:ee:01' }, { kind: 'mac', value: '14:13:33:c3:f6:03' },
])
check('identifiers: placeholder UUID left out, machine_id accepted (Linux)',
  machineIdentifiers(inv({}, { smbios_uuid: '00000000-0000-0000-0000-000000000000', machine_guid: undefined, machine_id: '0123456789abcdef0123456789abcdef' })).map(i => i.kind),
  ['os_install_id', 'mac', 'mac'])
check('primary MAC = the NIC holding the primary IP (not the first NIC)', primaryMac(inv()), '14:13:33:c3:f6:03')
check('primary MAC falls back to the first physical MAC',
  primaryMac(inv({ network: { primary_ip: '10.9.9.9', interfaces: [{ mac: 'A4-BB-CC-DD-EE-01', physical: true, ipv4: [] }] } })), 'a4:bb:cc:dd:ee:01')
check('differentHardware: unknown on either side proves nothing', [differentHardware([], [UUID_A]), differentHardware([UUID_A], undefined)], [false, false])
check('differentHardware: disjoint known sets differ, overlap does not', [differentHardware([UUID_A], [UUID_B]), differentHardware([UUID_A, UUID_B], [UUID_B])], [true, false])

// ── 2. Binding ──
console.log('\n── binding (bound > hardware UUID > OS install id > MAC > hostname > IP, clone guard) ──')
const cand = (assetId: string, o: Partial<BindingCandidate> = {}): BindingCandidate =>
  ({ assetId, inMyAssets: false, lastScanned: null, hasMac: true, ...o })
const NONE = { boundAssetId: null, macMatches: [], hostKeyMatches: [], ipMatches: [] }

check('old input shape still works (bound)', chooseBinding({ ...NONE, boundAssetId: 'a1' }), { assetId: 'a1', matchedBy: 'bound' })
check('bound asset with the same hardware UUID stays bound',
  bindMachine({ ...NONE, boundAssetId: 'a1', boundHardwareUuids: [UUID_A], hardwareUuid: UUID_A }),
  { decision: { assetId: 'a1', matchedBy: 'bound' }, differentHardware: [] })
check('agent copied with a cloned VM: bound asset has other hardware -> not reused, new asset',
  bindMachine({ ...NONE, boundAssetId: 'orig', boundHardwareUuids: [UUID_A], hardwareUuid: UUID_B,
    osInstallIdMatches: [cand('orig', { hardwareUuids: [UUID_A] })],
    macMatches: [cand('orig', { hardwareUuids: [UUID_A] })], hostKeyMatches: [cand('orig', { hardwareUuids: [UUID_A] })] }),
  { decision: null, differentHardware: ['orig'] })
check('hardware UUID beats OS install id and MAC',
  bindMachine({ ...NONE, hardwareUuid: UUID_A, hardwareUuidMatches: [cand('hw')], osInstallIdMatches: [cand('os')], macMatches: [cand('mac')] }).decision,
  { assetId: 'hw', matchedBy: 'hardware_uuid' })
check('reinstalled OS (new MachineGuid) still binds by hardware UUID',
  bindMachine({ ...NONE, hardwareUuid: UUID_A, hardwareUuidMatches: [cand('pc', { hardwareUuids: [UUID_A] })] }).decision,
  { assetId: 'pc', matchedBy: 'hardware_uuid' })
check('OS install id binds when hardware is unknown on the candidate',
  bindMachine({ ...NONE, hardwareUuid: UUID_A, osInstallIdMatches: [cand('os')] }).decision, { assetId: 'os', matchedBy: 'os_install_id' })
check('cloned VM (same MachineGuid, MAC, hostname; new UUID) -> new asset, original reported',
  bindMachine({ ...NONE, hardwareUuid: UUID_B,
    osInstallIdMatches: [cand('orig', { hardwareUuids: [UUID_A] })],
    macMatches: [cand('orig', { hardwareUuids: [UUID_A] })],
    hostKeyMatches: [cand('orig', { hardwareUuids: [UUID_A] })] }),
  { decision: null, differentHardware: ['orig'] })
check('clone with a placeholder UUID cannot be told apart (binds by OS install id; documented limit)',
  bindMachine({ ...NONE, hardwareUuid: null, osInstallIdMatches: [cand('orig', { hardwareUuids: [UUID_A] })] }).decision,
  { assetId: 'orig', matchedBy: 'os_install_id' })
check('MAC binds an agentless scan asset (no hardware UUID on record)',
  bindMachine({ ...NONE, hardwareUuid: UUID_A, macMatches: [cand('scan')] }).decision, { assetId: 'scan', matchedBy: 'mac' })
check('hostname: the clone is excluded, the one compatible asset binds',
  bindMachine({ ...NONE, hardwareUuid: UUID_B, hostKeyMatches: [cand('orig', { hardwareUuids: [UUID_A] }), cand('scan')] }),
  { decision: { assetId: 'scan', matchedBy: 'hostname' }, differentHardware: ['orig'] })
check('several hardware-UUID matches (duplicates): My Assets one wins',
  bindMachine({ ...NONE, hardwareUuid: UUID_A, hardwareUuidMatches: [cand('d1'), cand('d2', { inMyAssets: true })] }).decision,
  { assetId: 'd2', matchedBy: 'hardware_uuid' })

// ── 3. Device type ──
console.log('\n── device type (manual > agent > auto) ──')
check('manual known type is never changed by the agent', resolveAgentDeviceType({ deviceType: 'server', deviceTypeSource: 'manual' }, 'workstation'),
  { deviceType: 'server', deviceTypeSource: 'manual', changed: false })
check('manual unknown is filled by the agent', resolveAgentDeviceType({ deviceType: 'unknown', deviceTypeSource: 'manual' }, 'workstation'),
  { deviceType: 'workstation', deviceTypeSource: 'agent', changed: true })
check('scan guess corrected by the agent', resolveAgentDeviceType({ deviceType: 'server', deviceTypeSource: 'auto' }, 'workstation'),
  { deviceType: 'workstation', deviceTypeSource: 'agent', changed: true })
check('same type from scan becomes "confirmed by agent"', resolveAgentDeviceType({ deviceType: 'workstation', deviceTypeSource: 'auto' }, 'workstation'),
  { deviceType: 'workstation', deviceTypeSource: 'agent', changed: true })
check('agent reporting unknown changes nothing', resolveAgentDeviceType({ deviceType: 'server', deviceTypeSource: 'auto' }, 'unknown'),
  { deviceType: 'server', deviceTypeSource: 'auto', changed: false })
check('active scan never flips an agent-confirmed type', resolveIngestDeviceType({ deviceType: 'workstation', deviceTypeSource: 'agent' }, 'server', false),
  { deviceType: 'workstation', deviceTypeSource: 'agent', corrected: false })
check('active scan still corrects an auto type (unchanged)', resolveIngestDeviceType({ deviceType: 'workstation', deviceTypeSource: 'auto' }, 'server', false),
  { deviceType: 'server', deviceTypeSource: 'auto', corrected: true })

// ── 4. Addresses ──
console.log('\n── agent address bookkeeping ──')
const NET = '192.168.100.0/24'
const row = (addressId: string, assetId: string, ipAddress: string, networkKey: string | null = NET, macAddress: string | null = null) =>
  ({ addressId, assetId, networkKey, ipAddress, macAddress })
check('same IP: refresh, fill MAC', planAgentAddress('me', '192.168.100.71', 'aa', NET, [row('r1', 'me', '192.168.100.71')]),
  [{ k: 'refresh', addressId: 'r1', macAddress: 'aa', networkKey: NET }])
check('unscoped manual row with the same IP: refresh and scope it', planAgentAddress('me', '192.168.100.71', 'aa', NET, [row('r1', 'me', '192.168.100.71', null, 'bb')]),
  [{ k: 'refresh', addressId: 'r1', macAddress: 'bb', networkKey: NET }])
check('DHCP change: end old address on this network, insert new; other networks untouched',
  planAgentAddress('me', '192.168.100.80', 'aa', NET, [row('r1', 'me', '192.168.100.71'), row('r2', 'me', '10.0.0.5', '10.0.0.0/24')]),
  [{ k: 'end', addressId: 'r1' }, { k: 'insert', networkKey: NET, ipAddress: '192.168.100.80', macAddress: 'aa' }])
check('IP reused: another asset\'s hold on it is ended first',
  planAgentAddress('me', '192.168.100.80', 'aa', NET, [row('r9', 'other', '192.168.100.80')]),
  [{ k: 'end', addressId: 'r9' }, { k: 'insert', networkKey: NET, ipAddress: '192.168.100.80', macAddress: 'aa' }])

// ── 5. Scan rule 1-agent ──
console.log('\n── scan matching: MAC the agent reported ──')
const C0: MatcherCandidates = { macAddresses: [], hostKeyAssetIds: [], netIpAddresses: [] }
check('global MAC only known from the agent -> its asset (rule 1-agent)',
  matchAsset({ macClass: 'global', mac: 'a4:bb:cc:dd:ee:01', ip: '192.168.100.90', hostKey: null, networkKey: NET }, { ...C0, agentMacAssetIds: ['laptop'] }),
  { rule: '1-agent', assetId: 'laptop', matchedAddressId: null })
check('a current address with the MAC still wins (rule 1 unchanged)',
  matchAsset({ macClass: 'global', mac: 'a4:bb:cc:dd:ee:01', ip: '192.168.100.90', hostKey: null, networkKey: NET },
    { ...C0, macAddresses: [{ addressId: 'x', assetId: 'scanned', networkKey: NET, ipAddress: '192.168.100.90', macAddress: 'a4:bb:cc:dd:ee:01', assetDeviceType: 'workstation' }], agentMacAssetIds: ['laptop'] }).rule,
  1)
check('a locally administered MAC never uses agent identifiers',
  matchAsset({ macClass: 'local', mac: '06:00:59:e5:9a:c6', ip: '192.168.100.90', hostKey: null, networkKey: NET }, { ...C0, agentMacAssetIds: ['laptop'] }).rule,
  6)

const host = (ip: string, mac: string): PlanHost => ({
  ip, rawMac: mac, hostname: null, hostKeyRaw: null, deviceType: 'workstation', observedOsInfo: {}, ports: [],
  hardwareVendor: null, internetFacing: false, isPassive: false, tenantId: 't1',
})
const laptop = {
  assetId: 'laptop', deviceType: 'workstation', deviceTypeSource: 'agent', hostKey: null, osInfo: {}, hostname: 'LAPTOP-1', owner: null,
  hardwareVendor: null, macAddress: '14:13:33:c3:f6:03', source: 'agent', hasBaseline: true, baseline: null, internetFacingOverride: null,
}
let n = 0
const plan = planIngest([host('192.168.100.90', 'A4:BB:CC:DD:EE:01')], {
  addresses: [{ addressId: 'wifi', assetId: 'laptop', networkKey: NET, ipAddress: '192.168.100.71', macAddress: '14:13:33:c3:f6:03', deviceType: 'workstation', lastSeen: 1, assetCreatedAt: 1 }],
  assets: [laptop],
  agentMacs: [{ mac: 'a4:bb:cc:dd:ee:01', assetId: 'laptop' }],
}, { newId: () => `id-${n++}`, now: new Date('2026-10-11T00:00:00Z') })
const ph = plan.perHost[0]!
check('laptop scanned on its Ethernet MAC is the same asset, not a new one', [ph.rule, ph.assetId, ph.isNew], ['1-agent', 'laptop', false])
check('its address moves to the Ethernet IP; type stays agent-confirmed',
  [ph.ops.map(o => o.k), (ph.ops[0] as { set: Record<string, unknown> }).set.deviceTypeSource],
  [['updateAsset', 'endAddress', 'insertAddress'], 'agent'])
const planNoAgent = planIngest([host('192.168.100.90', 'A4:BB:CC:DD:EE:01')], { addresses: [], assets: [] }, { newId: () => `id-${n++}` })
check('without the agent identifier the same scan creates a new asset (old behaviour)', [planNoAgent.perHost[0]!.rule, planNoAgent.perHost[0]!.isNew], [6, true])

// ── 6. Duplicates ──
console.log('\n── duplicates with machine identifiers ──')
const dAsset = (assetId: string, o: Partial<DupAsset> = {}): DupAsset => ({
  assetId, hostname: null, ipAddress: '192.168.100.1', macAddress: null, source: 'scan_active', inMyAssets: false,
  deviceType: 'workstation', lastScanned: null, createdAt: null, ...o,
})
const dAddr = (assetId: string, mac: string | null, ip = '192.168.100.1'): DupAddress =>
  ({ addressId: `ad-${assetId}-${ip}`, assetId, networkKey: NET, ipAddress: ip, macAddress: mac, endedAt: null })
const groupsOf = (gs: ReturnType<typeof findDuplicateGroups>) => gs.map(g => ({ c: g.confidence, ids: g.assets.map(a => a.assetId).sort(), reasons: g.reasons }))

check('same hardware UUID -> safe', groupsOf(findDuplicateGroups([dAsset('a'), dAsset('b')], [], undefined, [
  { assetId: 'a', kind: 'hardware_uuid', value: UUID_A }, { assetId: 'b', kind: 'hardware_uuid', value: UUID_A }])),
  [{ c: 'safe', ids: ['a', 'b'], reasons: [`same hardware UUID ${UUID_A}`] }])
check('same OS installation, different hardware -> review (cloned VM)', groupsOf(findDuplicateGroups([dAsset('a'), dAsset('b')], [], undefined, [
  { assetId: 'a', kind: 'os_install_id', value: GUID }, { assetId: 'b', kind: 'os_install_id', value: GUID },
  { assetId: 'a', kind: 'hardware_uuid', value: UUID_A }, { assetId: 'b', kind: 'hardware_uuid', value: UUID_B }])).map(g => g.c),
  ['review'])
check('same OS installation, hardware unknown on one -> safe', groupsOf(findDuplicateGroups([dAsset('a'), dAsset('b')], [], undefined, [
  { assetId: 'a', kind: 'os_install_id', value: GUID }, { assetId: 'b', kind: 'os_install_id', value: GUID },
  { assetId: 'a', kind: 'hardware_uuid', value: UUID_A }])).map(g => g.c),
  ['safe'])
check('agent-reported Ethernet MAC seen on a separate scan asset -> safe',
  groupsOf(findDuplicateGroups([dAsset('agent'), dAsset('scan')], [dAddr('agent', '14:13:33:c3:f6:03', '192.168.100.71'), dAddr('scan', 'a4:bb:cc:dd:ee:01', '192.168.100.90')], undefined, [
    { assetId: 'agent', kind: 'mac', value: 'a4:bb:cc:dd:ee:01' }])),
  [{ c: 'safe', ids: ['agent', 'scan'], reasons: ['MAC a4:bb:cc:dd:ee:01 reported by the agent on this machine'] }])
check('shared global MAC but different hardware UUIDs -> review (clone kept its MAC)',
  groupsOf(findDuplicateGroups([dAsset('a'), dAsset('b')], [dAddr('a', 'a4:bb:cc:dd:ee:01', '192.168.100.71'), dAddr('b', 'a4:bb:cc:dd:ee:01', '192.168.100.72')], undefined, [
    { assetId: 'a', kind: 'hardware_uuid', value: UUID_A }, { assetId: 'b', kind: 'hardware_uuid', value: UUID_B }])).map(g => [g.c, g.reasons[0]]),
  [['review', 'same global MAC a4:bb:cc:dd:ee:01, but the hardware UUIDs differ']])
const legacyA = [dAsset('a'), dAsset('b')], legacyAd = [dAddr('a', 'a4:bb:cc:dd:ee:01', '192.168.100.71'), dAddr('b', 'a4:bb:cc:dd:ee:01', '192.168.100.72')]
check('no identifiers -> exactly the old result', findDuplicateGroups(legacyA, legacyAd, undefined, []), findDuplicateGroups(legacyA, legacyAd))

// ── 7. Merge ──
console.log('\n── merge keeps inventory, software, identifiers, agent binding ──')
const mAsset = (assetId: string, o: Partial<MergeAsset> = {}): MergeAsset => ({
  assetId, tenantId: 't1', hostname: null, ipAddress: '192.168.100.1', macAddress: null, hostKey: null, owner: null,
  deviceType: 'workstation', deviceTypeSource: 'auto', hardwareVendor: null, osInfo: {}, criticalityScore: 3, baselineState: null,
  isInternetFacing: false, source: 'scan_active', inMyAssets: false, lastScanned: null, createdAt: null, ...o,
})
const related = { addresses: [], relationships: [], topologyNodes: [] }
const m = planMerge(
  mAsset('survivor', { inMyAssets: true }),
  [mAsset('agentAsset', { source: 'agent', deviceType: 'server', deviceTypeSource: 'agent', endpointInventory: { schema: 1 }, inventoryCollectedAt: '2026-10-11T10:00:00Z' })],
  related)
check('the agent\'s inventory moves to the survivor', [m.mergedFields.endpointInventory, m.mergedFields.inventoryCollectedAt], [{ schema: 1 }, '2026-10-11T10:00:00Z'])
check('agent-confirmed type beats the survivor\'s scan guess', [m.mergedFields.deviceType, m.mergedFields.deviceTypeSource], ['server', 'agent'])
const ks = m.ops.find(o => o.k === 'keepSoftware')
check('software of the newest inventory is kept and moved', ks, { k: 'keepSoftware', keepAssetId: 'agentAsset', dropAssetIds: ['survivor'], survivorId: 'survivor' })
const kinds = m.ops.map(o => o.k)
check('identifiers and agent binding move before the losers are deleted',
  [kinds.includes('moveIdentifiers'), kinds.includes('moveAgentBinding'), kinds.indexOf('moveAgentBinding') < kinds.indexOf('deleteAssets'), kinds.indexOf('moveIdentifiers') < kinds.indexOf('deleteAssets')],
  [true, true, true, true])
const m2 = planMerge(
  mAsset('s', { endpointInventory: { v: 'old' }, inventoryCollectedAt: '2026-10-01T00:00:00Z' }),
  [mAsset('l', { endpointInventory: { v: 'new' }, inventoryCollectedAt: '2026-10-11T00:00:00Z' })], related)
check('two inventories: the newer one wins', [m2.mergedFields.endpointInventory, (m2.ops.find(o => o.k === 'keepSoftware') as { keepAssetId: string }).keepAssetId], [{ v: 'new' }, 'l'])
const m3 = planMerge(mAsset('s', { deviceType: 'iot', deviceTypeSource: 'manual' }), [mAsset('l', { deviceType: 'server', deviceTypeSource: 'agent' })], related)
check('manual type still beats agent-confirmed', [m3.mergedFields.deviceType, m3.mergedFields.deviceTypeSource], ['iot', 'manual'])
const m4 = planMerge(mAsset('s'), [mAsset('l')], related)
check('no inventories: fields untouched, survivor keeps (no) software', ['endpointInventory' in m4.mergedFields, (m4.ops.find(o => o.k === 'keepSoftware') as { keepAssetId: string }).keepAssetId], [false, 's'])

// ── 8. Rows stored before byte-order normalisation keep matching ──
console.log('\n── upgrade: hardware UUIDs stored in the old (raw) spelling ──')
const RAW_OLD = '4c4c4544-0044-3510-8053-b4c04f564e32'           // as stored before the change
check('bound asset with the raw stored UUID stays bound to the canonical incoming one',
  bindMachine({ ...NONE, boundAssetId: 'pc', boundHardwareUuids: [RAW_OLD], hardwareUuid: UUID_A }).decision,
  { assetId: 'pc', matchedBy: 'bound' })
check('OS-install-id candidate with the raw UUID is not mistaken for a clone',
  bindMachine({ ...NONE, hardwareUuid: UUID_A, osInstallIdMatches: [cand('pc', { hardwareUuids: [RAW_OLD] })] }),
  { decision: { assetId: 'pc', matchedBy: 'os_install_id' }, differentHardware: [] })
check('lookup covers both spellings', hardwareUuidForms(UUID_A).sort(), [UUID_A, RAW_OLD].sort())
check('duplicates: raw row on one asset + canonical row on another = same hardware (safe)',
  groupsOf(findDuplicateGroups([dAsset('a'), dAsset('b')], [], undefined, [
    { assetId: 'a', kind: 'hardware_uuid', value: RAW_OLD }, { assetId: 'b', kind: 'hardware_uuid', value: UUID_A }])).map(g => g.c),
  ['safe'])

console.log(`\n${pass} passed, ${fail} failed`)
if (fail > 0) process.exit(1)
