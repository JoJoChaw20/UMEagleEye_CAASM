import { test } from 'node:test'
import assert from 'node:assert/strict'
import { addRefusal, mayGrantRole } from './userAdmin'

const A = 'tenant-a', B = 'tenant-b'
const platform = { userId: 'p', role: 'superadmin', tenantId: null }
const ownerA = { userId: 'oa', role: 'tenant_superadmin', tenantId: A }

test('a tenant superadmin cannot take the platform superadmin or another tenant\'s accounts', () => {
  assert.equal(addRefusal(ownerA, platform, A), 'superadmin')
  assert.equal(addRefusal(ownerA, { userId: 'b1', role: 'tenant_admin', tenantId: B }, A), 'other_tenant')
  assert.equal(addRefusal(ownerA, { userId: 'ob', role: 'tenant_superadmin', tenantId: B }, A), 'other_tenant')
  assert.equal(addRefusal(ownerA, { userId: 'x', role: 'tenant_superadmin', tenantId: null }, A), 'tenant_superadmin')
})

test('a tenant superadmin adds accounts without a tenant, or already theirs, but makes no tenant superadmin', () => {
  const free = { userId: 'f', role: 'business_owner', tenantId: null }
  assert.equal(addRefusal(ownerA, free, A), null)
  assert.equal(addRefusal(ownerA, { ...free, tenantId: A }, A), null)
  assert.equal(addRefusal(ownerA, free, A, 'tenant_superadmin'), 'role')
  assert.equal(mayGrantRole(ownerA, 'tenant_superadmin'), false)
  assert.equal(mayGrantRole(ownerA, 'tenant_admin'), true)
})

test('the platform superadmin moves accounts between tenants, but not another platform superadmin', () => {
  assert.equal(addRefusal(platform, { userId: 'b1', role: 'tenant_admin', tenantId: B }, A), null)
  assert.equal(addRefusal(platform, { userId: 'p2', role: 'superadmin', tenantId: null }, A), 'superadmin')
  assert.equal(mayGrantRole(platform, 'tenant_superadmin'), true)
})
