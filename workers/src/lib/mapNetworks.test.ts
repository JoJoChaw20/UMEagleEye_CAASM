import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildMapNetworks, placeMeasured, type AssetAlerts, type NetAddress, type NetAgent } from './mapNetworks'
import type { MapNode } from './networkMap'

const at = '2026-11-11T08:00:00Z'
const addr = (asset_id: string, ip: string, extra: Partial<NetAddress> = {}): NetAddress => ({
  asset_id, network_key: '192.168.36.0/24', ip, mac: null, last_seen: at, label: asset_id, device_type: null,
  criticality: null, in_my_assets: false, measured: false, ...extra,
})
const agent = (agent_id: string, extra: Partial<NetAgent> = {}): NetAgent => ({
  agent_id, name: agent_id, kind: 'host', networks: ['192.168.36.0/24'], default_gateway: '192.168.36.2',
  host_asset_id: null, listens: true, scans: true, ...extra,
})
const alerts = (a: Partial<AssetAlerts>): AssetAlerts => ({
  cve_open: 0, cve_critical: 0, cve_high: 0, kev: 0, exposure_open: 0, exposure_severity: null, ...a,
})

test('a network has its gateway, the agents watching it and its devices, most important first', () => {
  const nets = buildMapNetworks(
    [addr('gw', '192.168.36.2', { mac: '00:50:56:e1:2a:07' }), addr('printer', '192.168.36.9'),
      addr('ubuntu', '192.168.36.50'), addr('win', '192.168.36.60')],
    [agent('a-ubuntu', { host_asset_id: 'ubuntu', scans: false }), agent('a-win', { host_asset_id: 'win' })],
    [{ subnet: '192.168.36.0/24', gateway_ip: '192.168.36.2', gateway_mac: '00-50-56-E1-2A-07', at }],
    new Map([['printer', alerts({ cve_open: 3, cve_critical: 1 })]]),
  )
  assert.equal(nets.length, 1)
  const n = nets[0]!
  assert.deepEqual({ ...n.gateway, device: undefined }, { ip: '192.168.36.2', mac: '00:50:56:e1:2a:07', asset_id: 'gw', label: 'gw', device: undefined })
  assert.deepEqual([n.gateway!.device!.asset_id, n.gateway!.device!.ip], ['gw', '192.168.36.2'])   // its details, like any device's
  assert.equal(n.coverage, 'watched')
  assert.deepEqual(n.agents.map((a) => a.agent_id), ['a-ubuntu', 'a-win'])
  // the gateway is drawn as the gateway, not again as a device; agents' computers first, then alerts
  assert.deepEqual(n.devices.map((d) => d.asset_id), ['ubuntu', 'win', 'printer'])
  assert.deepEqual([n.device_count, n.devices[0]!.agent, n.devices[2]!.agent], [3, 'host', null])
})

test('an agent network with nothing found yet still shows, and a network nobody watches says so', () => {
  const nets = buildMapNetworks(
    [addr('phone', '192.168.0.147', { network_key: '192.168.0.0/24' })],
    [agent('lab', { networks: ['10.0.0.0/24'], default_gateway: '10.0.0.1' }),
      agent('galaxy', { kind: 'mobile', networks: [], default_gateway: null, host_asset_id: 'phone' })],
    [], new Map(),
  )
  assert.deepEqual(nets.map((n) => n.key), ['10.0.0.0/24', '192.168.0.0/24'])     // watched first
  const [lab, home] = nets
  assert.deepEqual([lab!.device_count, lab!.gateway?.ip, lab!.coverage], [0, '10.0.0.1', 'watched'])
  assert.deepEqual([home!.coverage, home!.agents, home!.phones.map((p) => p.name)], ['none', [], ['galaxy']])
  assert.equal(home!.devices[0]!.agent, 'mobile')
})

test('two gateways with different MACs at one address in one range are flagged, not merged silently', () => {
  const nets = buildMapNetworks(
    [addr('x', '192.168.0.10', { network_key: '192.168.0.0/24' })],
    [agent('home', { networks: ['192.168.0.0/24'], default_gateway: '192.168.0.1' })],
    [{ subnet: '192.168.0.0/24', gateway_ip: '192.168.0.1', gateway_mac: 'aa:aa:aa:aa:aa:01', at: '2026-11-10T00:00:00Z' },
      { subnet: '192.168.0.0/24', gateway_ip: '192.168.0.1', gateway_mac: 'bb:bb:bb:bb:bb:02', at: '2026-11-11T00:00:00Z' }],
    new Map(),
  )
  assert.deepEqual(nets[0]!.gateway_macs, ['bb:bb:bb:bb:bb:02', 'aa:aa:aa:aa:aa:01'])   // newest first
  assert.equal(nets[0]!.gateway!.mac, 'bb:bb:bb:bb:bb:02')
})

test('an agent reporting a wider range watches the narrower network it overlaps, and coverage follows its roles', () => {
  const nets = buildMapNetworks(
    [addr('d', '172.16.4.9', { network_key: '172.16.4.0/24' })],
    [agent('wide', { networks: ['172.16.0.0/16'], default_gateway: '172.16.0.1', listens: true, scans: false })],
    [], new Map(),
  )
  assert.deepEqual(nets.map((n) => [n.key, n.coverage]), [['172.16.4.0/24', 'listen_only']])
  assert.equal(nets[0]!.gateway, null)                       // its gateway is outside this range
})

test('devices on measured switch ports are counted, and the list is capped', () => {
  const many = Array.from({ length: 520 }, (_, i) => addr(`d${i}`, `10.1.${Math.floor(i / 250)}.${(i % 250) + 1}`,
    { network_key: '10.1.0.0/16', measured: i < 5 }))
  const [n] = buildMapNetworks(many, [], [], new Map())
  assert.deepEqual([n!.device_count, n!.devices.length, n!.measured_count], [520, 500, 5])
})

const node = (id: string, kind: MapNode['kind'], ip: string | null, parent: string | null, asset_id: string | null = id): MapNode => ({
  id, kind, label: id, asset_id, ip, mac: null, device_type: null, detail: null, vlan: null, criticality: null,
  seen_at: at, parent, depth: parent ? 1 : 0,
})

test('a measured tree goes into the network its router is on, and the ranges seen only through it fold in', () => {
  const nets = buildMapNetworks(
    [addr('ubuntu', '10.99.0.50', { network_key: '10.99.0.0/24' }), addr('R1', '10.99.0.1', { network_key: '10.99.0.0/24', measured: true }),
      addr('SW1', '10.10.99.2', { network_key: '10.10.99.0/24', measured: true }),
      addr('pc1', '10.10.10.11', { network_key: '10.10.10.0/24', measured: true }),
      addr('pc2', '10.10.20.21', { network_key: '10.10.20.0/24', measured: true }),
      addr('lonely', '10.10.20.99', { network_key: '10.10.20.0/24' })],             // not in the tree: 10.10.20 stays
    [agent('ubuntu-agent', { networks: ['10.99.0.0/24'], default_gateway: '10.99.0.1', host_asset_id: 'ubuntu' })], [], new Map(),
  )
  const tree = [node('R1', 'router', '10.99.0.1', null), node('SW1', 'switch', '10.10.99.2', 'R1'),
    node('pc1', 'device', '10.10.10.11', 'SW1'), node('pc2', 'device', '10.10.20.21', 'SW1')]
  const placed = placeMeasured(nets, tree)
  const home = placed.find((n) => n.key === '10.99.0.0/24')!
  assert.deepEqual(home.measured_roots, ['R1'])
  assert.deepEqual(home.subnets.sort(), ['10.10.10.0/24', '10.10.99.0/24'])
  assert.deepEqual(placed.map((n) => n.key).sort(), ['10.10.20.0/24', '10.99.0.0/24'])
  assert.equal(home.device_count, 3)                          // ubuntu (R1 is its gateway) and the folded subnets' 2
  assert.deepEqual(home.devices.map((d) => d.asset_id).sort(), ['SW1', 'pc1', 'ubuntu'])
})

test('a measured tree no agent network holds gets a network of its own', () => {
  const placed = placeMeasured([], [node('core', 'switch', '172.20.0.2', null), node('x', 'device', null, 'core')])
  assert.deepEqual(placed.map((n) => [n.key, n.title, n.measured_roots]), [['measured:core', 'core', ['core']]])
})

test('a network the laptop left names the agent, when it was there last and where it is now', () => {
  const laptop = agent('jo', { name: 'jo agent', networks: ['192.168.100.0/24'] })
  const nets = buildMapNetworks(
    [addr('pc', '10.179.40.9', { network_key: '10.179.32.0/19' }), addr('home-tv', '192.168.100.5', { network_key: '192.168.100.0/24' }),
      addr('cafe', '172.16.0.4', { network_key: '172.16.0.0/24' })],
    [laptop], [], new Map(),
    [{ agent_id: 'jo', subnet: '10.179.32.0/19', at: '2026-11-13T10:00:00Z' }, { agent_id: 'jo', subnet: '10.179.32.0/19', at: '2026-11-13T12:09:14Z' },
      { agent_id: 'jo', subnet: '192.168.100.0/24', at: '2026-11-13T16:00:00Z' }, { agent_id: 'removed', subnet: '172.16.0.0/24', at }],
  )
  const by = Object.fromEntries(nets.map((n) => [n.key, n]))
  assert.deepEqual(by['10.179.32.0/19']!.left, { agent_id: 'jo', name: 'jo agent', at: '2026-11-13T12:09:14Z', now_on: '192.168.100.0/24' })
  assert.equal(by['192.168.100.0/24']!.left, null, 'watched now: nothing left')
  assert.equal(by['172.16.0.0/24']!.left, null, 'an agent since removed is not named')
})
