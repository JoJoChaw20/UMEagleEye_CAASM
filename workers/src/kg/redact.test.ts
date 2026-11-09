import test from 'node:test'
import assert from 'node:assert/strict'
import { containsSecret } from './redact'
import {
  extractAgent, extractAsset, extractEvent, extractScan, extractTiEvent, safeDelta, type Row,
} from './extract'

const T = '11111111-1111-1111-1111-111111111111'
const SECRETS = { api_key_hash: 'APIKEYHASH-9f3', password_hash: 'PASSHASH-77c', totp_secret: 'TOTPSECRET-JBSWY3DP', enrolment_token: 'ENROLTOKEN-abc' }

// Every extractor, fed a row carrying every secret column: none may copy one to its output.
test('no extractor copies a secret column, whatever the row', () => {
  const rows: Array<[string, (r: Row) => { nodes: unknown[]; edges: unknown[] }, Row]> = [
    ['asset', extractAsset, { asset_id: 'a1', tenant_id: T, hostname: 'web-01', ip_address: '10.0.0.1', ...SECRETS }],
    ['agent', extractAgent, { agent_id: 'g1', tenant_id: T, name: 'n', kind: 'host', status: 'online', ...SECRETS }],
    ['event', extractEvent, { event_id: 'e1', asset_id: 'a1', tenant_id: T, event_type: 'x', severity: 'high', status: 'open', ...SECRETS }],
    ['scan', extractScan, { scan_id: 's1', tenant_id: T, scan_type: 'active', status: 'done', ...SECRETS }],
    ['ti_event', extractTiEvent, { ti_event_id: 't1', tenant_id: T, title: 'x', threat_level: 'low', status: 'open', ...SECRETS }],
  ]
  for (const [name, fn, row] of rows) {
    const out = JSON.stringify(fn(row))
    assert.ok(out.length > 2, `${name} produced output`)
    for (const v of Object.values(SECRETS)) assert.ok(!out.includes(v), `${name} leaked ${v}`)
  }
})

test('a user row never becomes an asset node carrying credentials', () => {
  const out = JSON.stringify(extractAsset({ asset_id: 'a1', tenant_id: T, hostname: 'h', email: 'a@b.c', password_hash: '$2b$10$abcdefghijklmnopqrstuv', totp_secret: 'JBSWY3DPEHPK3PXP' }))
  assert.ok(!out.includes('$2b$'))
  assert.ok(!out.includes('JBSWY3DP'))
})

test('each secret pattern is blocked', () => {
  const samples = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'AKIAABCDEFGHIJKLMNOP',
    'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
    'xoxb-1234567890-abcdefghij',
    'postgres://user:pass@host/db',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw.abcdefghijk',
    "api_key: 'abcdefghijklmnop'",
  ]
  for (const s of samples) assert.ok(containsSecret(s), s)
})

test('a blocked node takes its edges with it and leaves the rest', () => {
  const ok = extractAsset({ asset_id: 'a1', tenant_id: T, hostname: 'web-01' })
  const bad = extractScan({ scan_id: 's1', tenant_id: T, scan_type: 'active', status: 'failed', failure_reason: 'AKIAABCDEFGHIJKLMNOP leaked' })
  const safe = safeDelta({ nodes: [...ok.nodes, ...bad.nodes], edges: [{ from: bad.nodes[0]!.key, to: ok.nodes[0]!.key, relation: 'X', tenantId: T }] })
  assert.deepEqual(safe.nodes.map(n => n.key), [ok.nodes[0]!.key])
  assert.equal(safe.edges.length, 0)
  assert.equal(safe.blocked, 1)
})
