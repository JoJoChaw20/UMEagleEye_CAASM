import test from 'node:test'
import assert from 'node:assert/strict'
import { extractAdvisory, extractAgent, extractAsset, extractEvent, extractScan, safeDelta } from './extract'
import { containsSecret } from './redact'

const T = '11111111-1111-1111-1111-111111111111'

test('an agent key hash never reaches the graph', () => {
  const d = extractAgent({ agent_id: 'a1', tenant_id: T, name: 'n', kind: 'host', status: 'online', api_key_hash: 'HASHVALUE', config: { secret: 'x' } })
  assert.ok(!JSON.stringify(d).includes('HASHVALUE'))
  assert.ok(!JSON.stringify(d).includes('secret'))
})

test('a row with no tenant produces nothing', () => {
  assert.deepEqual(extractAsset({ asset_id: 'a', tenant_id: null, ip_address: '10.0.0.1' }).nodes, [])
  assert.deepEqual(extractEvent({ event_id: 'e', tenant_id: null }).nodes, [])
})

test('an advisory takes the tenant of its alert asset', () => {
  const d = extractAdvisory({ advisory_id: 'abcdef1234', tenant_id: T, event_id: 'e1', asset_id: 'x', summary: 's', recommended_action: 'r', status: 'open', severity: 'high', event_type: 'cve_detected', hostname: 'h', ip_address: '10.0.0.1' })
  assert.equal(d.nodes[0].tenantId, T)
  assert.equal(d.nodes[0].props.active, true)
  assert.equal(d.nodes[0].props.shortId, 'abcdef12')
})

test('a CVE node is keyed per tenant', () => {
  const d = extractEvent({ event_id: 'e', tenant_id: T, asset_id: 'x', event_type: 'cve_detected', severity: 'high', status: 'open', ip_address: '10.0.0.1', timestamp: '2026-01-01T00:00:00Z', details: { cve_id: 'cve-2024-1234' } })
  assert.ok(d.nodes.some(n => n.key === `cve:${T}:CVE-2024-1234`))
})

test('a closed alert is not counted as open', () => {
  const d = extractEvent({ event_id: 'e', tenant_id: T, asset_id: 'x', event_type: 'new_device', severity: 'low', status: 'resolved', ip_address: '10.0.0.1', timestamp: '2026-01-01T00:00:00Z', details: {} })
  assert.equal(d.nodes[0].props.open, false)
})

test('final review: an alert on an asset with no IP does not print "(null)"', () => {
  const alert = { event_id: 'e', tenant_id: T, asset_id: 'x', event_type: 'new_device', severity: 'low', status: 'open', hostname: 'web-01', timestamp: '2026-01-01T00:00:00Z', details: {} }
  const body = extractEvent({ ...alert, ip_address: null }).nodes[0].body
  assert.ok(!body.includes('null'), body)
  assert.ok(!body.includes('()'), body)
  assert.match(body, /on web-01\. Raised/)
  assert.match(extractEvent({ ...alert, ip_address: '10.0.0.1' }).nodes[0].body, /on web-01 \(10\.0\.0\.1\)\. Raised/)
})

test('an advisory on an asset with no IP does not print "(null)"', () => {
  const adv = { advisory_id: 'abcdef1234', tenant_id: T, event_id: 'e1', asset_id: 'x', summary: 's', recommended_action: 'r', status: 'open', severity: 'high', event_type: 'cve_detected', hostname: 'web-01' }
  const body = extractAdvisory({ ...adv, ip_address: null }).nodes[0].body
  assert.ok(!body.includes('null'), body)
  assert.ok(!body.includes('()'), body)
  assert.match(body, /on web-01\. Summary/)
  assert.match(extractAdvisory({ ...adv, ip_address: '10.0.0.1' }).nodes[0].body, /on web-01 \(10\.0\.0\.1\)\. Summary/)
})

test('a secret pasted into an allowed field blocks the node', () => {
  const d = extractScan({ scan_id: 's', tenant_id: T, scan_type: 'active', status: 'failed', hosts_discovered: 0, started_at: '2026-01-01T00:00:00Z', failure_reason: 'connect postgresql://admin:hunter2@db/x failed' })
  const safe = safeDelta(d)
  assert.equal(safe.nodes.length, 0)
  assert.equal(safe.blocked, 1)
})

test('secret patterns catch literals, not references', () => {
  assert.ok(containsSecret('password = "correct-horse-battery"'))
  assert.ok(containsSecret('sk-abcdefghijklmnopqrstuvwxyz123456'))
  assert.ok(!containsSecret('apiKey = env.DEEPSEEK_API_KEY'))
  assert.ok(!containsSecret('Device web-01, IP 10.0.0.1'))
})
