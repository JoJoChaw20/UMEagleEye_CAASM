import { test } from 'node:test'
import assert from 'node:assert/strict'
import { chooseAgent, contains, countIn, coverageOf, parseCidr, type RouteAgent } from './agentRouting'

const agent = (over: Partial<RouteAgent>): RouteAgent => ({
  agent_id: 'a', name: 'a', online: true, scanner: null, passive: null, networks: [], local_ip: null,
  busy: false, last_heartbeat: '2026-11-07T12:00:00Z', ...over,
})

test('ranges and containment', () => {
  assert.equal(parseCidr('192.168.36.77/24')!.text, '192.168.36.0/24')
  assert.equal(parseCidr('10.0.0.5')!.prefix, 32)
  assert.equal(parseCidr('300.1.1.1'), null)
  assert.equal(parseCidr('10.0.0.0/33'), null)
  assert.ok(contains(parseCidr('192.168.36.0/24')!, parseCidr('192.168.36.50')!))
  assert.ok(!contains(parseCidr('192.168.36.0/24')!, parseCidr('192.168.0.0/16')!))
  assert.equal(countIn('192.168.36.0/24', ['192.168.36.1', '192.168.37.1', 'junk']), 1)
})

test('the agent on the network scans it; the most specific network wins', () => {
  const lab = agent({ agent_id: 'lab', name: 'lab-win11', networks: ['192.168.36.0/24', '192.168.217.0/24'] })
  const wide = agent({ agent_id: 'wide', name: 'core', networks: ['192.168.0.0/16'] })
  const d = chooseAgent('192.168.36.0/24', [wide, lab])
  assert.deepEqual([d.agent_id, d.on_link], ['lab', true])
  assert.match(d.reason, /lab-win11 is on 192\.168\.36\.0\/24; 1 other agent is on it too/)
  assert.equal(chooseAgent('192.168.36.50', [lab]).agent_id, 'lab')            // one address of it
})

test('a busy or quiet agent loses a tie', () => {
  const nets = ['192.168.36.0/24']
  const busy = agent({ agent_id: 'busy', networks: nets, busy: true, last_heartbeat: '2026-11-07T12:00:30Z' })
  const free = agent({ agent_id: 'free', networks: nets })
  assert.equal(chooseAgent('192.168.36.0/24', [busy, free]).agent_id, 'free')
  const older = agent({ agent_id: 'older', networks: nets, last_heartbeat: '2026-11-07T11:59:00Z' })
  assert.equal(chooseAgent('192.168.36.0/24', [older, free]).agent_id, 'free')
})

test('offline agents and agents whose Scanner role is off are never chosen', () => {
  const nets = ['192.168.36.0/24']
  const off = agent({ agent_id: 'off', networks: nets, online: false })
  const noScan = agent({ agent_id: 'noscan', networks: nets, scanner: false })
  const d = chooseAgent('192.168.36.0/24', [off, noScan])
  assert.equal(d.agent_id, null)
  assert.match(d.reason, /No online agent runs dashboard scans/)
})

test('an older agent is taken to be on the /24 around its address, and the reason says so', () => {
  const old = agent({ agent_id: 'old', name: 'agent-test-ubuntu', local_ip: '192.168.36.50' })
  const d = chooseAgent('192.168.36.0/24', [old])
  assert.equal(d.agent_id, 'old')
  assert.match(d.reason, /taken from its address/)
})

test('no agent on the network: never scanned through a router unless an agent is picked', () => {
  const home = agent({ agent_id: 'home', name: 'test-agent-windows', networks: ['192.168.0.0/24'] })
  const d = chooseAgent('10.10.0.0/24', [home])
  assert.deepEqual([d.agent_id, d.routed], [null, [{ agent_id: 'home', name: 'test-agent-windows' }]])
  assert.match(d.reason, /through a router/)
})

test('a range spanning several agents networks is refused with the networks to scan', () => {
  const a1 = agent({ agent_id: '1', networks: ['10.0.1.0/24'] })
  const a2 = agent({ agent_id: '2', networks: ['10.0.2.0/24'] })
  const d = chooseAgent('10.0.0.0/16', [a2, a1])
  assert.equal(d.agent_id, null)
  assert.deepEqual(d.networks, ['10.0.1.0/24', '10.0.2.0/24'])
})

test('coverage of a network', () => {
  const nets = ['192.168.36.0/24']
  const sensor = agent({ agent_id: 's', name: 's', networks: nets, passive: true, scanner: false })
  const both = agent({ agent_id: 'b', name: 'b', networks: nets, passive: true })
  const away = agent({ agent_id: 'x', name: 'x', networks: ['10.0.0.0/24'], passive: true })
  assert.equal(coverageOf('192.168.36.0/24', [sensor])!.state, 'listen_only')
  assert.equal(coverageOf('192.168.36.0/24', [agent({ agent_id: 'q', networks: nets })])!.state, 'scan_only')
  const c = coverageOf('192.168.36.0/24', [sensor, both, away])!
  assert.deepEqual([c.state, c.duplicate_sensors, c.scanners.map((s) => s.agent_id)], ['covered', true, ['b']])
  assert.equal(coverageOf('172.16.0.0/24', [sensor])!.state, 'no_agent')
  // on it but not checking in: not the same as no agent at all
  const gone = coverageOf('192.168.36.0/24', [agent({ name: 'ubuntu', networks: nets, passive: true, online: false })])!
  assert.equal(gone.state, 'offline')
  assert.deepEqual(gone.offline.map((o) => o.name), ['ubuntu'])
})

test('an agent reporting late still covers its network; the card says it is late', () => {
  const nets = ['192.168.36.0/24']
  const late = agent({ agent_id: 'u', name: 'ubuntu', networks: nets, passive: true, online: false, liveness: 'degraded' })
  const c = coverageOf('192.168.36.0/24', [late])!
  assert.equal(c.state, 'covered')
  assert.equal(c.late, true)
  assert.deepEqual(c.sensors, [{ agent_id: 'u', name: 'ubuntu', late: true }])
  const mixed = coverageOf('192.168.36.0/24', [late, agent({ agent_id: 'w', name: 'win', networks: nets, passive: true })])!
  assert.equal(mixed.late, false, 'one agent on time: the network is not late')
  // a scan still goes only to an online agent
  assert.equal(chooseAgent('192.168.36.0/24', [late]).agent_id, null)
})
