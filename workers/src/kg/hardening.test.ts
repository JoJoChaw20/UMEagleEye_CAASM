import test from 'node:test'
import assert from 'node:assert/strict'
import { clip, extractEvent, extractRelationship, extractScan, safeDelta } from './extract'
import { containsSecret } from './redact'
import { countNodes } from './retrieve'
import { accessFor } from './access'
import { refreshProblems } from './problems'
import type { Q } from './store'
import type { Env } from '../types'

const T = '11111111-1111-1111-1111-111111111111'

test('clip never leaves half an emoji', () => {
  const out = clip('a'.repeat(199) + '\u{1F600}' + 'b', 200)
  assert.ok(!/[\ud800-\udbff](?![\udc00-\udfff])/.test(out))
  assert.equal(out, 'a'.repeat(199) + '...')
  assert.equal(clip('\ud83d lone'), '� lone')
})

test('a secret cut by the length limit still blocks the node', () => {
  const d = extractScan({ scan_id: 's', tenant_id: T, scan_type: 'active', status: 'failed', started_at: '2026-01-01T00:00:00Z', failure_reason: `${'x'.repeat(190)} password=SuperSecret12345` })
  assert.equal(safeDelta(d).nodes.length, 0)
})

test('a relationship to another company device produces nothing', () => {
  const row = { relationship_id: 'r', tenant_id: T, source_asset_id: 'a', target_asset_id: 'b', relationship_type: 'connects_to', source_label: 'web', target_label: 'OTHER-CO-HOST' }
  assert.equal(extractRelationship({ ...row, target_tenant_id: '99999999-9999-9999-9999-999999999999' }).nodes.length, 0)
  assert.equal(extractRelationship({ ...row, target_tenant_id: null }).nodes.length, 0)
  assert.equal(extractRelationship({ ...row, target_tenant_id: T }).nodes.length, 1)
})

test('an object under an allowed alert key is not copied, a list of versions is', () => {
  const d = extractEvent({
    event_id: 'e', asset_id: 'a', tenant_id: T, event_type: 'cve', severity: 'high', status: 'open',
    details: { cve_id: 'CVE-2024-0001', description: { nested: 'TOPSECRETSUB' }, fix_versions: ['1.2.3', '1.2.4'] },
  })
  const out = JSON.stringify(d)
  assert.ok(!out.includes('TOPSECRETSUB'))
  assert.ok(out.includes('1.2.3, 1.2.4'))
})

test('unquoted, URL, bearer and key-format secrets are blocked', () => {
  const blocked = [
    'password=SuperSecret12345', 'Password: SuperSecret12345', 'api_key=abcdef0123456789abcd', 'token=abcdef0123456789abcdef',
    'mysql://admin:hunter2hunter@db/x', 'https://admin:s3cretpass@host.example/x',
    'Authorization: Bearer abcdef0123456789ABCDEF', `api key ${'ab12'.repeat(16)}`, `install code: ${'0f'.repeat(32)}`,
  ]
  for (const s of blocked) assert.ok(containsSecret(s), s)
})

test('normal text, references and SHA-256 indicators are not blocked', () => {
  const fine = [
    'password: required for login', 'apiKey = env.DEEPSEEK_API_KEY', 'Authorization header missing', 'token expired',
    `sha256: ${'ab12'.repeat(16)}`, `Threat indicator ${'e3b0c442'.repeat(8)} of type FileHash-SHA256`,
    'http://example.com:8080/path', 'Connection to 10.0.0.5:22 refused',
  ]
  for (const s of fine) assert.ok(!containsSecret(s), s)
})

test('more than six filters is an error, not a silently inflated count', async () => {
  let queried = false
  const q: Q = async () => { queried = true; return [{ total: 5 }] }
  const a = accessFor({ role: 'tenant_admin', tenantId: T })
  const where = Object.fromEntries(['a', 'b', 'c', 'd', 'e', 'f', 'g'].map(k => [k, 1]))
  const r = await countNodes(q, a, { type: 'asset', where })
  assert.ok('error' in r)
  assert.equal(queried, false)
  assert.ok(!('error' in await countNodes(q, a, { type: 'asset', where: { a: 1 } })))
})

test('refresh removes indicators no alert points at, as it does CVEs', async () => {
  const sqls: string[] = []
  const q: Q = async text => { sqls.push(text); return text.includes('count(*) FILTER') ? [{ assets: 0, my_assets: 0, critical: 0, advisories: 0 }] : [] }
  await refreshProblems(q, {} as Env, T)
  assert.ok(sqls.find(s => s.includes('DELETE FROM kg_nodes n'))!.includes("n.type IN ('cve', 'indicator')"))
})
