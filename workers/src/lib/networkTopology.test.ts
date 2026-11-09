import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { assetIndex, deviceAssets, linkRows, planLocations, topologySchema, type CrawlHost } from './networkTopology'

// The GNS3 lab's crawl (agent-gui/tests/fixtures/gns3): R1 - SW1 - SW2, PC-D on SW2 Gi0/3.
const devices = [
  { address: '10.99.0.1', label: 'R1', interfaces: [{ index: 1, name: 'Gi0/0', mac: '0C:59:A9:EF:00:00' }],
    addresses: [{ ip: '10.99.0.1' }, { ip: '10.10.1.1' }] },
  { address: '10.10.99.2', label: 'SW1', interfaces: [{ index: 18, name: 'Vl99', mac: '0C:37:FC:DE:80:63' }],
    addresses: [{ ip: '10.10.99.2' }] },
  { address: '10.10.99.3', label: 'SW2', interfaces: [{ index: 18, name: 'Vl99', mac: '0C:7C:50:61:80:63' }],
    addresses: [{ ip: '10.10.99.3' }] },
]
const host = (ip: string, mac: string, extra: Partial<CrawlHost> = {}): CrawlHost =>
  ({ ip, mac, vlan: null, interface: 'Gi0/1', seen_by: ['R1'], device: null, location: null, ...extra })

test('a cable seen from both ends is one row with both protocols', () => {
  const rows = linkRows([
    { a: { device: 'R1', port: 'Gi0/1' }, b: { device: 'SW1', port: 'Gi0/0' }, protocols: ['cdp'] },
    { a: { device: 'SW1', port: 'Gi0/0' }, b: { device: 'R1', port: 'Gi0/1' }, protocols: ['lldp', 'cdp'] },
    { a: { device: 'SW2', port: 'Gi0/0' }, b: { device: 'SW1', port: 'Gi0/1' }, protocols: ['lldp'] },
  ])
  assert.deepEqual(rows, [
    { aName: 'R1', aPort: 'Gi0/1', bName: 'SW1', bPort: 'Gi0/0', protocols: ['cdp', 'lldp'] },
    { aName: 'SW1', aPort: 'Gi0/1', bName: 'SW2', bPort: 'Gi0/0', protocols: ['lldp'] },
  ])
})

test('polled devices are found by address, then by MAC', () => {
  const index = assetIndex([
    { assetId: 'r1', ip: '10.10.1.1', mac: null },                    // R1 known by another address
    { assetId: 'sw1', ip: '10.10.99.2', mac: '0c:37:fc:de:80:63' },
    { assetId: 'sw2', ip: '10.10.99.30', mac: '0c-7c-50-61-80-63' },  // SW2's address changed
  ])
  assert.deepEqual(Object.fromEntries(deviceAssets(devices, index)), { R1: 'r1', SW1: 'sw1', SW2: 'sw2' })
})

test('locations go to the hosts, by MAC first, never to the polled devices', () => {
  const index = assetIndex([
    { assetId: 'pcd', ip: '10.10.1.99', mac: '00:50:79:66:68:04' },  // DHCP gave PC-D a new address
    { assetId: 'pca', ip: '10.10.10.11', mac: null },
    { assetId: 'sw1', ip: '10.10.99.2', mac: null },
  ])
  const devicesByLabel = new Map([['SW1', 'sw1'], ['SW2', 'sw2']])
  const plan = planLocations([
    host('10.10.1.41', '00:50:79:66:68:04', { vlan: 1, location: { switch: 'SW2', port: 'Gi0/3', vlan: 1, ambiguous: false } }),
    host('10.10.10.11', '00:50:79:66:68:00', { vlan: 10, interface: 'Gi0/1.10' }),
    host('10.10.99.2', '0C:37:FC:DE:80:63', { device: 'SW1' }),
    host('10.10.20.99', '00:50:79:66:68:09'),                      // no asset yet: nothing to store
  ], index, devicesByLabel, 'agent-1', '2026-11-08T11:21:00Z')
  assert.deepEqual(plan, [
    { assetId: 'pcd', location: { switch: 'SW2', switch_asset_id: 'sw2', port: 'Gi0/3', vlan: 1, ambiguous: false,
      router: 'R1', interface: 'Gi0/1', agent_id: 'agent-1', seen_at: '2026-11-08T11:21:00Z' } },
    { assetId: 'pca', location: { switch: null, switch_asset_id: null, port: null, vlan: 10, ambiguous: false,
      router: 'R1', interface: 'Gi0/1.10', agent_id: 'agent-1', seen_at: '2026-11-08T11:21:00Z' } },
  ])
})

test('an asset with two addresses keeps the entry with a switch port', () => {
  const index = assetIndex([{ assetId: 'srv', ip: '10.0.0.5', mac: '00:00:00:00:00:05' }])
  const plan = planLocations([
    host('10.0.0.5', '00:00:00:00:00:05', { location: { switch: 'SW9', port: 'Gi1/0/5', vlan: 5, ambiguous: false } }),
    host('10.0.1.5', '00:00:00:00:00:05', { vlan: 6 }),
  ], index, new Map(), 'a', 't')
  assert.equal(plan.length, 1)
  assert.equal(plan[0]!.location.port, 'Gi1/0/5')
})

test('the agent upload of the GNS3 lab is what the server takes', () => {
  // Written by the agent's tests (agent-gui/tests/test_netagent_service.py) from its real
  // topology_payload of the recorded lab: the two sides agree on the format.
  const raw = JSON.parse(readFileSync(join(process.cwd(), '..', 'agent-gui', 'tests', 'fixtures', 'gns3', 'topology-upload.json'), 'utf8'))
  const parsed = topologySchema.safeParse(raw)
  assert.ok(parsed.success, parsed.success ? '' : JSON.stringify(parsed.error.issues.slice(0, 3)))
  const body = parsed.data!
  assert.deepEqual(body.devices.map((d) => d.label), ['R1', 'SW1', 'SW2'])
  assert.equal(linkRows(body.links).length, 2)
  const index = assetIndex([
    { assetId: 'r1', ip: '10.99.0.1', mac: null }, { assetId: 'sw2', ip: '10.10.99.3', mac: null },
    { assetId: 'pcd', ip: '10.10.1.41', mac: null }, { assetId: 'pcb', ip: '10.10.10.12', mac: null },
  ])
  const devicesByLabel = deviceAssets(body.devices, index)
  const plan = Object.fromEntries(planLocations(body.hosts as CrawlHost[], index, devicesByLabel, 'a', 't').map((p) => [p.assetId, p.location]))
  assert.deepEqual([plan.pcd!.switch, plan.pcd!.switch_asset_id, plan.pcd!.port, plan.pcd!.vlan], ['SW2', 'sw2', 'Gi0/3', 1])
  assert.deepEqual([plan.pcb!.port, plan.pcb!.vlan, plan.pcb!.interface], [null, 10, 'Gi0/1.10'])
  assert.equal(plan.r1, undefined)
})

test("a crawl's networks: the subnets of the routers' and switches' own addresses, the lowest address as gateway", async () => {
  const { crawlSubnets } = await import('./networkTopology')
  // The GNS3 lab (9 Nov): R1 on the agent link and its VLAN subinterfaces, the switches' VLAN 99 SVIs
  const r1 = { addresses: [
    { ip: '10.99.0.1', prefix: 24, network: '10.99.0.0/24' }, { ip: '10.10.1.1', prefix: 24, network: '10.10.1.0/24' },
    { ip: '10.10.10.1', prefix: 24, network: '10.10.10.0/24' }, { ip: '10.10.99.1', prefix: 24, network: '10.10.99.0/24' },
    { ip: '1.1.1.1', prefix: 32, network: '1.1.1.1/32' }, { ip: '127.0.0.1', prefix: 8, network: '127.0.0.0/8' },
  ] }
  const sw1 = { addresses: [{ ip: '10.10.99.2', prefix: 24, network: '10.10.99.0/24' }, { ip: '10.10.5.5', prefix: null, network: null }] }
  assert.deepEqual(crawlSubnets([sw1, r1]), [
    { subnet: '10.10.1.0/24', gateway: '10.10.1.1' }, { subnet: '10.10.10.0/24', gateway: '10.10.10.1' },
    { subnet: '10.10.99.0/24', gateway: '10.10.99.1' }, { subnet: '10.99.0.0/24', gateway: '10.99.0.1' },
  ])
})
