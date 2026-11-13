import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildCrawls, buildNetworks } from './discoveryNetworks'

const crawl = {
  scanId: 'c1', agentId: 'netagent', scanType: 'snmp', subnet: 'snmp-crawl', status: 'completed', hostsDiscovered: 5,
  startedAt: '2026-11-09T13:26:48Z', completedAt: '2026-11-09T13:27:00Z',
  networkInfo: { crawl: { devices: 3, links: 2, located: 1, subnets: [{ subnet: '10.99.0.0/24', gateway: '10.99.0.1' }, { subnet: '10.10.1.0/24', gateway: '10.10.1.1' }] } },
}
const failed = { ...crawl, scanId: 'c2', status: 'failed', startedAt: '2026-11-09T13:40:00Z', completedAt: null,
  networkInfo: { crawl: { devices: 0, subnets: [] } } }
const passive = {
  scanId: 'p1', agentId: 'ubuntu', scanType: 'passive', subnet: 'arp-discovery', status: 'completed', hostsDiscovered: 2,
  startedAt: '2026-11-09T13:00:00Z', completedAt: '2026-11-09T13:01:00Z', networkInfo: { lan_subnet: '10.99.0.0/24' },
}

test("a crawl adds its hosts to each network it reached, but its time and agent stay the crawl's", () => {
  const nets = buildNetworks([crawl, failed, passive], new Map([['c1', ['10.99.0.10', '10.99.0.20', '10.10.1.41']]]), [])
  const by = Object.fromEntries(nets.map((n) => [n.subnet, n]))
  assert.deepEqual(Object.keys(by).sort(), ['10.10.1.0/24', '10.99.0.0/24'])
  // a network a computer agent is on: its own card, mapped by the network agent too
  const lab = by['10.99.0.0/24']!
  assert.equal(lab.crawl_only, false)
  assert.deepEqual(lab.agent_ids, ['ubuntu'])
  assert.deepEqual(lab.mapped_by, ['netagent'])
  assert.equal(lab.latest_agent_id, 'ubuntu', 'Scan this network goes to the computer agent, never the network agent')
  assert.equal(lab.latest_at, '2026-11-09T13:01:00.000Z', 'the crawl does not make it look newer')
  assert.equal(lab.hosts_24h, 2)
  // a network only the crawl reached: shown inside the crawl's card
  const far = by['10.10.1.0/24']!
  assert.equal(far.crawl_only, true)
  assert.deepEqual(far.agent_ids, [])
  assert.equal(far.latest_agent_id, null)
  assert.equal(far.gateway, '10.10.1.1')
  assert.equal(far.hosts_24h, 1)
  assert.equal(far.latest_at, '2026-11-09T13:27:00.000Z')
})

test('a network agent appears once, with its newest crawl and every network its crawls reached', () => {
  const older = { ...crawl, scanId: 'c0', startedAt: '2026-11-09T12:00:00Z', completedAt: '2026-11-09T12:01:00Z',
    networkInfo: { crawl: { devices: 2, links: 1, subnets: [{ subnet: '10.10.20.0/24', gateway: '10.10.20.1' }] } } }
  const [one, ...rest] = buildCrawls([failed, crawl, older, passive])
  assert.equal(rest.length, 0)
  assert.equal(one!.agent_id, 'netagent')
  assert.equal(one!.crawls, 3)
  assert.deepEqual(one!.latest, { scan_id: 'c2', at: '2026-11-09T13:40:00.000Z', status: 'failed' })
  assert.deepEqual(one!.last_crawl, { scan_id: 'c1', at: '2026-11-09T13:27:00.000Z', devices: 3, links: 2, located: 1 })
  assert.deepEqual(one!.subnets.map((s) => s.subnet), ['10.10.1.0/24', '10.10.20.0/24', '10.99.0.0/24'])
})
