import { test } from 'node:test'
import assert from 'node:assert/strict'
import { policyChangeActions, tenantPatchRefusal } from './policyChange'

test('plain setting needs configure only', () =>
  assert.deepEqual(policyChangeActions({ settings: { inventory_interval: 3600 } }), ['agent.configure']))

test('role toggle or role setting needs roles.assign', () => {
  assert.ok(policyChangeActions({ roles: { scanner: false } }).includes('agent.roles.assign'))
  assert.ok(policyChangeActions({ settings: { passive: true } }).includes('agent.roles.assign'))
  assert.ok(policyChangeActions({ settings: { network_poll: false } }).includes('agent.roles.assign'))
})

test('sightings needs sightings.enable', () =>
  assert.ok(policyChangeActions({ settings: { sightings: true } }).includes('agent.sightings.enable')))

test('an empty change still needs configure, and an empty roles object adds nothing', () => {
  assert.deepEqual(policyChangeActions({}), ['agent.configure'])
  assert.deepEqual(policyChangeActions({ roles: {} }), ['agent.configure'])
})

const T = 't1'
const platform = { role: 'superadmin', tenantId: undefined, actions: [] }
const owner = { role: 'tenant_superadmin', tenantId: T, actions: [] }
const member = (actions: string[]) => ({ role: 'tenant_user', tenantId: T, actions })

test('the Platform Superadmin may only switch a tenant on or off', () => {
  assert.equal(tenantPatchRefusal(platform, T, { is_active: false }), null)
  assert.equal(tenantPatchRefusal(platform, T, { name: 'x' })?.detail,
    'The Platform Superadmin can view tenants but cannot make changes inside them.')
  assert.equal(tenantPatchRefusal(platform, T, { allow_local_scans: true })?.status, 403)
})

test('the Tenant Superadmin renames and sets the scan policy of their own tenant, nothing else', () => {
  assert.equal(tenantPatchRefusal(owner, T, { name: 'x', auto_investigate_new_devices: true }), null)
  assert.equal(tenantPatchRefusal(owner, T, { is_active: false })?.detail, 'Only the Platform Superadmin can do this.')
  assert.equal(tenantPatchRefusal(owner, 'other', { name: 'x' })?.status, 403)
})

test('a tenant user needs the scan policy action, and can never rename', () => {
  const missing = tenantPatchRefusal(member([]), T, { allow_local_scans: false })
  assert.equal(missing?.missing_action, 'settings.scan_policy.edit')
  assert.equal(missing?.detail, 'You do not have the "Change scan policy" action. Ask your Tenant Superadmin to grant it.')
  const holder = member(['settings.view', 'settings.scan_policy.edit'])
  assert.equal(tenantPatchRefusal(holder, T, { allow_local_scans: false }), null)
  assert.equal(tenantPatchRefusal(holder, T, { name: 'x' })?.detail, 'Only the Tenant Superadmin can do this.')
  assert.equal(tenantPatchRefusal(holder, 'other', { allow_local_scans: false })?.status, 403)
})
