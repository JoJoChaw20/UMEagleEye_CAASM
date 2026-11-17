import { test } from 'node:test'
import assert from 'node:assert/strict'
import { actionChanges, addRefusal, parseActionList } from './userAdmin'

const A = 'tenant-a', B = 'tenant-b'
const platform = { userId: 'p', role: 'superadmin', tenantId: null }
const ownerA = { userId: 'oa', role: 'tenant_superadmin', tenantId: A }

test('a tenant superadmin cannot take the platform superadmin or another tenant\'s accounts', () => {
  assert.equal(addRefusal(ownerA, platform, A), 'superadmin')
  assert.equal(addRefusal(ownerA, { userId: 'b1', role: 'tenant_user', tenantId: B }, A), 'other_tenant')
  assert.equal(addRefusal(ownerA, { userId: 'ob', role: 'tenant_superadmin', tenantId: B }, A), 'other_tenant')
  assert.equal(addRefusal(ownerA, { userId: 'x', role: 'tenant_superadmin', tenantId: null }, A), 'tenant_superadmin')
})

test('a tenant superadmin adds accounts without a tenant, or already theirs, never a tenant superadmin', () => {
  const free = { userId: 'f', role: 'tenant_user', tenantId: null }
  assert.equal(addRefusal(ownerA, free, A), null)
  assert.equal(addRefusal(ownerA, { ...free, tenantId: A }, A), null)
  assert.equal(addRefusal(ownerA, ownerA, A), 'tenant_superadmin')
})

test('the platform superadmin takes no account from another tenant, no superadmin and no tenant superadmin', () => {
  assert.equal(addRefusal(platform, { userId: 'b1', role: 'tenant_user', tenantId: B }, A), 'other_tenant')
  assert.equal(addRefusal(platform, { userId: 'f', role: 'tenant_user', tenantId: null }, A), null)
  assert.equal(addRefusal(platform, { userId: 'p2', role: 'superadmin', tenantId: null }, A), 'superadmin')
  assert.equal(addRefusal(platform, { userId: 'ob', role: 'tenant_superadmin', tenantId: B }, A), 'other_tenant')
  assert.equal(addRefusal(platform, { userId: 'oa', role: 'tenant_superadmin', tenantId: A }, A), 'tenant_superadmin')
})

test('parseActionList closes requirements and reports unknown keys', () => {
  assert.deepEqual(parseActionList(['alert.manage']), { ok: true, actions: ['alert.view', 'alert.manage'] })
  assert.deepEqual(parseActionList(['asset.veiw', 'x']), { ok: false, unknown: ['asset.veiw', 'x'] })
  assert.deepEqual(parseActionList('asset.view'), { ok: false, unknown: ['asset.view'] })
})

test('parseActionList accepts an empty list and reports non-string items', () => {
  assert.deepEqual(parseActionList([]), { ok: true, actions: [] })
  assert.deepEqual(parseActionList(['asset.view', 3]), { ok: false, unknown: ['3'] })
})

test('actionChanges lists what was added and removed', () => {
  assert.deepEqual(actionChanges(['asset.view', 'alert.view'], ['alert.view', 'alert.manage']),
    { added: ['alert.manage'], removed: ['asset.view'] })
  assert.deepEqual(actionChanges([], []), { added: [], removed: [] })
})

test('the platform superadmin may promote a member of the same tenant (interim provisioning)', () => {
  assert.equal(addRefusal(platform, { userId: 'a1', role: 'tenant_user', tenantId: A }, A), null)
})
