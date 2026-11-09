import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildNetworks } from './discoveryNetworks'

test("a network agent's crawl puts every network it reached on the Networks list", () => {
  const crawl = {
    scanId: 'c1', agentId: 'netagent', scanType: 'snmp', subnet: 'snmp-crawl', status: 'completed', hostsDiscovered: 5,
    startedAt: '2026-11-09T13:26:48Z', completedAt: '2026-11-09T13:27:00Z',
    networkInfo: { crawl: { devices: 3, subnets: [{ subnet: '10.10.1.0/24', gateway: '10.10.1.1' }, { subnet: '10.99.0.0/24', gateway: '10.99.0.1' }] } },
  }
  const failed = { ...crawl, scanId: 'c0', status: 'failed', startedAt: '2026-11-09T13:10:00Z', completedAt: null,
    networkInfo: { crawl: { devices: 0, subnets: [] } } }
  const passive = {
    scanId: 'p1', agentId: 'ubuntu', scanType: 'passive', subnet: 'arp-discovery', status: 'completed', hostsDiscovered: 2,
    startedAt: '2026-11-09T13:20:00Z', completedAt: '2026-11-09T13:21:00Z', networkInfo: { lan_subnet: '192.168.36.0/24' },
  }
  const nets = buildNetworks([crawl, failed, passive], new Map([['c1', ['10.99.0.10', '10.99.0.20', '10.10.1.41']]]), [])
  const by = Object.fromEntries(nets.map((n) => [n.subnet, n]))
  assert.deepEqual(Object.keys(by).sort(), ['10.10.1.0/24', '10.99.0.0/24', '192.168.36.0/24'])
  assert.deepEqual(by['10.99.0.0/24']!.last_crawl, { scan_id: 'c1', at: '2026-11-09T13:27:00.000Z', agent_id: 'netagent', devices: 3 })
  assert.equal(by['10.99.0.0/24']!.gateway, '10.99.0.1')
  assert.equal(by['10.99.0.0/24']!.hosts_24h, 2)
  assert.equal(by['10.10.1.0/24']!.hosts_24h, 1)
  assert.equal(by['192.168.36.0/24']!.last_crawl, null)
})
