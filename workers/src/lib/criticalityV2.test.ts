import { test } from 'node:test'
import assert from 'node:assert/strict'
import { computeCriticalityV2, type ScoringInputV2 } from './criticalityV2'

const server: ScoringInputV2 = { deviceType: 'server', isInternetFacing: false, hostname: 'app01', osInfo: { ports: [22, 443] } }

test('the base score follows the device type; an unidentified type scores 3 and is reported as unknown', () => {
  const base = (deviceType: string) => computeCriticalityV2({ ...server, deviceType }).score
  assert.deepEqual(['network', 'server', 'iot', 'workstation', 'mobile', 'unknown', 'toaster'].map(base), [6, 5, 4, 3, 3, 3, 3])
  const r = computeCriticalityV2({ ...server, deviceType: 'toaster' })
  assert.equal(r.details[0]!.label, 'Unidentified device (type not identified)')
  assert.deepEqual(r.unknowns, ['device type'])
  assert.equal(r.confidence, 'low')
})

test('every factor names its source, and confidence follows how the facts were obtained', () => {
  assert.deepEqual(computeCriticalityV2({ ...server, deviceTypeSource: 'agent' }).details[0],
    { label: 'Server (confirmed by agent)', points: 5, source: 'agent' })
  assert.equal(computeCriticalityV2({ ...server, deviceTypeSource: 'manual' }).details[0]!.label, 'Server (set by hand)')
  assert.equal(computeCriticalityV2({ ...server, deviceTypeSource: 'auto' }).details[0]!.label, 'Server (inferred from scans)')
  const hinted = computeCriticalityV2({ ...server, deviceTypeHint: { type: 'server', label: 'Server', confidence: 'high', auto: true, evidence: 'SSH and HTTPS' } })
  assert.equal(hinted.details[0]!.label, 'Server (inferred from SSH and HTTPS)')
  assert.equal(computeCriticalityV2({ ...server, deviceTypeSource: 'agent' }).confidence, 'high')
  assert.equal(computeCriticalityV2({ ...server, deviceTypeSource: 'manual' }).confidence, 'high')
  assert.equal(computeCriticalityV2(server).confidence, 'medium')
})

test('a never-port-scanned asset is unknown (low confidence), not an asset with no services', () => {
  const r = computeCriticalityV2({ ...server, deviceTypeSource: 'agent', osInfo: {} })
  assert.equal(r.breakdown.portRisk, 0)
  assert.deepEqual(r.unknowns, ['open ports (no active scan yet)'])
  assert.equal(r.confidence, 'low')
  // an empty scan result is known: no services
  assert.equal(computeCriticalityV2({ ...server, deviceTypeSource: 'agent', osInfo: { ports: [] } }).confidence, 'high')
})

test('a directory service adds 2, from the agent or from Kerberos plus LDAP seen by a scan', () => {
  assert.equal(computeCriticalityV2({ ...server, agentRole: 'domain_controller' }).breakdown.role, 2)
  assert.equal(computeCriticalityV2({ ...server, osInfo: { ports: [53, 88, 389, 445] } }).breakdown.role, 2)
  assert.equal(computeCriticalityV2({ ...server, osInfo: { ports: [88, 636] } }).breakdown.role, 2)
  assert.equal(computeCriticalityV2({ ...server, osInfo: { ports: [88] } }).breakdown.role, 0)
  assert.equal(computeCriticalityV2({ ...server, osInfo: { ports: [389] } }).breakdown.role, 0)
})

test('internet-facing adds 2 and says whether an analyst confirmed it', () => {
  const inferred = computeCriticalityV2({ ...server, isInternetFacing: true })
  const confirmed = computeCriticalityV2({ ...server, isInternetFacing: true, internetFacingOverride: true })
  assert.equal(inferred.breakdown.internetFacing, 2)
  assert.deepEqual([inferred.details[1]!.source, confirmed.details[1]!.source], ['inferred', 'analyst'])
})

test('at most two high-risk services count; the others are named but not scored', () => {
  const r = computeCriticalityV2({ ...server, osInfo: { ports: [21, 23, 3389, 3389] } })
  assert.equal(r.breakdown.portRisk, 2)
  const label = r.details.find((d) => d.label.startsWith('Reachable high-risk'))!.label
  assert.match(label, /FTP 21, Telnet 23/)
  assert.match(label, /also RDP 3389, not counted \(at most \+2\)/)
})

test('a reachable database adds 1 and ten or more open ports add 1', () => {
  assert.equal(computeCriticalityV2({ ...server, osInfo: { ports: [5432] } }).breakdown.portRisk, 1)
  assert.equal(computeCriticalityV2({ ...server, osInfo: { ports: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] } }).breakdown.portRisk, 1)
  assert.equal(computeCriticalityV2({ ...server, osInfo: { ports: [1, 2, 3, 4, 5, 6, 7, 8, 9] } }).breakdown.portRisk, 0)
})

test('ports stored in any ingest format are read: numbers, "445/tcp" strings and { port } objects', () => {
  const r = computeCriticalityV2({ ...server, osInfo: { ports: ['445/tcp', { port: 3389 }, 'junk', -1, 5432] } })
  assert.equal(r.breakdown.portRisk, 3)
})

test('hostname hints add for production, database and perimeter names and subtract for non-production', () => {
  const h = (hostname: string) => computeCriticalityV2({ ...server, hostname }).breakdown.hostnameHints
  assert.equal(h('prod-db-01'), 2)
  assert.equal(h('core-fw'), 1)
  assert.equal(h('dev-web'), -1)
  assert.equal(h('lab-gw'), 0)
  assert.equal(h('product01'), 0)   // whole words only
})

test('the score stays between 1 and 10 and is the sum of the breakdown otherwise', () => {
  const max = computeCriticalityV2({
    deviceType: 'network', isInternetFacing: true, hostname: 'prod-core-db', agentRole: 'domain_controller',
    osInfo: { ports: [21, 23, 3306, 88, 389, 1, 2, 3, 4, 5] },
  })
  assert.equal(max.score, 10)
  const r = computeCriticalityV2({ ...server, hostname: 'dev-app', osInfo: { ports: [3389, 5432] } })
  const b = r.breakdown
  assert.equal(r.score, b.base + b.role + b.internetFacing + b.portRisk + b.hostnameHints)
  assert.equal(r.score, 5 + 1 + 1 - 1)
  assert.equal(r.factors.length, r.details.length)
})

test('ownership and agent-listed ports never change importance (only scan-observed facts count)', () => {
  const plain = computeCriticalityV2(server).score
  const withExtras = computeCriticalityV2({ ...server, osInfo: { ports: [22, 443], listening_ports: [3389, 445, 5900] } } as ScoringInputV2).score
  assert.equal(withExtras, plain)
})
