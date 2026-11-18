import test from 'node:test'
import assert from 'node:assert/strict'
import { intelRunner, intelTenant } from './intelRunner'
import type { Env } from '../types'

const T = '11111111-1111-1111-1111-111111111111'
const env = { DATABASE_URL: 'postgres://never-used' } as unknown as Env

test('intel tenant comes from the user, never the model; the superadmin only with a valid picked tenant', () => {
  assert.equal(intelTenant({ userId: 'u', role: 'tenant_user', tenantId: T, actions: [] }, 'ffffffff-ffff-ffff-ffff-ffffffffffff'), T)
  assert.equal(intelTenant({ userId: 'u', role: 'superadmin', tenantId: null, actions: [] }, T), T)
  assert.equal(intelTenant({ userId: 'u', role: 'superadmin', tenantId: null, actions: [] }, "x' OR 1=1"), undefined)
  assert.equal(intelTenant({ userId: 'u', role: 'tenant_user', tenantId: null, actions: [] }, T), undefined)
})

test('intel runner refuses unknown tools, roles without access and bad arguments before any database use', async () => {
  const viewer = intelRunner(env, { userId: 'u', role: 'tenant_user', tenantId: T, actions: ['chatbot.use', 'asset.view'] }, null)
  assert.match(JSON.stringify(await viewer('lookup_cve', { cve_id: 'CVE-2024-3094' })), /cannot use that lookup/)
  const analyst = intelRunner(env, { userId: 'u', role: 'tenant_superadmin', tenantId: T, actions: [] }, null)
  assert.match(JSON.stringify(await analyst('lookup_cve', { cve_id: 'not-a-cve' })), /Invalid arguments/)
  assert.match(JSON.stringify(await analyst('lookup_cve', { cve_id: 'CVE-2024-3094', extra: 1 })), /Invalid arguments/)
  assert.match(JSON.stringify(await analyst('nope' as never, {})), /Unknown lookup/)
})

test('intel runner answers bundled CWE and ATT&CK lookups with no network or database', async () => {
  const run = intelRunner(env, { userId: 'u', role: 'tenant_user', tenantId: T, actions: ['chatbot.use'] }, null)
  const cwe = await run('lookup_cwe', { cwe_id: 'CWE-79' }) as { url?: string }
  assert.equal(cwe.url, 'https://cwe.mitre.org/data/definitions/79.html')
  const attack = await run('lookup_attack_technique', { query: 'T1190' }) as { url?: string }
  assert.equal(attack.url, 'https://attack.mitre.org/techniques/T1190/')
})
