import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildNetworkMap, measuredEdges, type MapDevice, type MapHost, type MapLink } from './networkMap'

// The GNS3 lab as the network agent stored it: R1 routes; SW1 and SW2 are switches.
const devices: MapDevice[] = [
  { asset_id: 'r1', ip: '10.99.0.1', network_device: { label: 'R1', os: 'Cisco IOS', version: '15.9(3)M12',
    addresses: [{ ip: '10.99.0.1' }, { ip: '10.10.1.1' }, { ip: '10.10.10.1' }] } },
  { asset_id: 'sw1', ip: '10.10.99.2', network_device: { label: 'SW1', vlans: [1, 10, 20, 99], interfaces: [{ trunk: true }] } },
  { asset_id: 'sw2', ip: '10.10.99.3', network_device: { label: 'SW2', name: 'SW2.lab.local', vlans: [1, 10, 20, 99] } },
]
const links: MapLink[] = [
  { a_name: 'R1', a_port: 'Gi0/1', a_asset_id: 'r1', b_name: 'SW1', b_port: 'Gi0/0', b_asset_id: 'sw1', protocols: ['cdp', 'lldp'] },
  { a_name: 'SW1', a_port: 'Gi0/1', a_asset_id: 'sw1', b_name: 'SW2', b_port: 'Gi0/0', b_asset_id: null, protocols: ['lldp'] },
]
const host = (id: string, ip: string, location: Partial<MapHost['location']>): MapHost => ({
  asset_id: id, label: id.toUpperCase(), ip, mac: null, device_type: 'workstation', criticality: 3,
  location: { switch: null, switch_asset_id: null, port: null, vlan: null, router: 'R1', interface: null, ...location },
})
const hosts: MapHost[] = [
  host('pcd', '10.10.1.41', { switch: 'SW2', switch_asset_id: 'sw2', port: 'Gi0/3', vlan: 1, interface: 'Gi0/1' }),
  host('pca', '10.10.10.11', { vlan: 10, interface: 'Gi0/1.10' }),
  host('pcb', '10.10.10.12', { vlan: 10, interface: 'Gi0/1.10' }),
  host('srv', '10.10.20.21', { vlan: 20, interface: 'Gi0/1.20' }),
  host('sw1', '10.10.99.2', { vlan: 99 }),                               // a polled device: not a host
]

test('the lab becomes a tree from its router down to each device', () => {
  const map = buildNetworkMap(devices, links, hosts)
  const by = Object.fromEntries(map.nodes.map((n) => [n.id, n]))
  assert.deepEqual([by.r1!.kind, by.sw1!.kind, by.sw2!.kind], ['router', 'switch', 'switch'])
  assert.deepEqual([by.r1!.parent, by.sw1!.parent, by.sw2!.parent, by.pcd!.parent], [null, 'r1', 'sw1', 'sw2'])
  assert.deepEqual([by.r1!.depth, by.sw2!.depth, by.pcd!.depth], [0, 2, 3])
  assert.equal(by.r1!.detail, 'Cisco IOS 15.9(3)M12')
  // devices with no switch port: one VLAN group per VLAN under the router
  const vlan10 = map.nodes.find((n) => n.kind === 'vlan' && n.vlan === 10)!
  assert.equal(vlan10.parent, 'r1')
  assert.deepEqual([by.pca!.parent, by.pcb!.parent], [vlan10.id, vlan10.id])
  assert.equal(map.nodes.filter((n) => n.kind === 'vlan').length, 2)
  // the cable to SW2 is matched by name although its asset was not known on the link
  const cable = map.edges.find((e) => e.kind === 'cable' && e.to === 'sw2')!
  assert.deepEqual([cable.from_port, cable.to_port, cable.tree], ['Gi0/1', 'Gi0/0', true])
  assert.equal(map.edges.find((e) => e.to === 'pcd')!.from_port, 'Gi0/3')
  assert.equal(map.nodes.filter((n) => n.id === 'sw1').length, 1)
})

test('a far end nobody read is a neighbour, and a loop is not a tree edge', () => {
  const map = buildNetworkMap(devices, [...links,
    { a_name: 'SW2', a_port: 'Gi0/1', a_asset_id: 'sw2', b_name: 'R1', b_port: 'Gi0/2', b_asset_id: 'r1', protocols: ['cdp'] },
    { a_name: 'SW2', a_port: 'Gi1/0', a_asset_id: 'sw2', b_name: 'AP-3.corp', b_port: 'eth0', b_asset_id: null, protocols: ['lldp'] },
  ], [])
  const ap = map.nodes.find((n) => n.label === 'AP-3.corp')!
  assert.deepEqual([ap.kind, ap.parent], ['neighbour', 'sw2'])
  const cables = map.edges.filter((e) => e.kind === 'cable')
  assert.equal(cables.filter((e) => e.tree).length, 3)                      // R1-SW1, R1-SW2, SW2-AP
  assert.equal(cables.filter((e) => !e.tree).length, 1)                     // the loop's last cable
})

test('measured edges go downstream between assets, through VLAN groups', () => {
  const edges = measuredEdges(buildNetworkMap(devices, links, hosts))
  const set = new Set(edges.map((e) => `${e.source}>${e.target}`))
  for (const want of ['r1>sw1', 'sw1>sw2', 'sw2>pcd', 'r1>pca', 'r1>pcb', 'r1>srv']) assert.ok(set.has(want), want)
  assert.equal(edges.length, 6)
})

test('an empty map is empty', () => {
  assert.deepEqual(buildNetworkMap([], [], []), { nodes: [], edges: [] })
})
