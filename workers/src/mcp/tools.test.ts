import test from 'node:test'
import assert from 'node:assert/strict'
import { toolsFor, type ToolUser } from './tools'
import { PRESETS } from '../lib/actions'

const T = '11111111-1111-1111-1111-111111111111'
const user = (role: string, actions: readonly string[]): ToolUser => ({ userId: 'u1', role, tenantId: T, actions })
const preset = (k: string) => PRESETS.find(p => p.key === k)!.actions
const names = (u: ToolUser, actions = true) => toolsFor(u, { actions }).map(t => t.name)

test('the superadmin never gets the proposing tool', () => {
  // The same write keys give a tenant user the tool, so it is the role that blocks it, not the list
  const analyst = preset('analyst')
  assert.ok(analyst.includes('advisory.close_via_chat'))
  assert.ok(names(user('tenant_user', analyst)).includes('resolve_advisory'))
  const n = names({ userId: 'u', role: 'superadmin', tenantId: null, actions: analyst })
  assert.ok(n.length > 0, 'the superadmin still gets the read tools')
  assert.ok(!n.includes('resolve_advisory'))
})

test('a user with no actions gets no tools', () => {
  assert.deepEqual(names(user('tenant_user', [])), [])
})

test('a user with only chatbot.use gets only the tools open to everyone', () => {
  const n = names(user('tenant_user', ['chatbot.use']))
  assert.deepEqual(n.sort(), ['get_cve_coverage', 'get_security_overview', 'lookup_attack_technique', 'lookup_cwe'])
})

test('the viewer preset gets the analyst tools but not the proposing tool', () => {
  const n = names(user('tenant_user', preset('viewer')))
  assert.ok(n.includes('search_assets'))
  assert.ok(!n.includes('resolve_advisory'))
})

test('the analyst preset gets the proposing tool', () => {
  assert.ok(names(user('tenant_user', preset('analyst'))).includes('resolve_advisory'))
})
