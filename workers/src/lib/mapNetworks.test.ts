import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildMapNetworks, type AssetAlerts, type NetAddress, type NetAgent } from './mapNetworks'

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
  assert.deepEqual(n.gateway, { ip: '192.168.36.2', mac: '00:50:56:e1:2a:07', asset_id: 'gw', label: 'gw' })
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
