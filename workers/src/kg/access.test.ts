import test from 'node:test'
import assert from 'node:assert/strict'
import { accessFor, accessSql } from './access'

const T = '11111111-1111-1111-1111-111111111111'

test('company staff never get platform nodes', () => {
  const params: unknown[] = []
  const sql = accessSql(accessFor({ role: 'tenant_admin', tenantId: T }), 'n', params)
  assert.ok(!sql.includes("'platform'"))
  assert.deepEqual(params, [T])
})

test('a business owner is limited to role group all', () => {
  const sql = accessSql(accessFor({ role: 'business_owner', tenantId: T }), 'n', [])
  assert.ok(sql.includes("n.role_group = 'all'"))
})

test('a superadmin with no company picked sees shared knowledge only', () => {
  const params: unknown[] = []
  const sql = accessSql(accessFor({ role: 'superadmin' }), 'n', params)
  assert.ok(sql.includes("'platform'"))
  assert.ok(!sql.includes('n.tenant_id = $'))
  assert.deepEqual(params, [])
})

test('a superadmin with a picked company sees that company', () => {
  const params: unknown[] = []
  accessSql(accessFor({ role: 'superadmin' }, T), 'n', params)
  assert.deepEqual(params, [T])
})

test('a user with no company sees nothing', () => {
  assert.equal(accessSql(accessFor({ role: 'tenant_admin' }), 'n', []), 'false')
})

test('a non-superadmin cannot pick another company', () => {
  const other = '22222222-2222-2222-2222-222222222222'
  const params: unknown[] = []
  accessSql(accessFor({ role: 'tenant_admin', tenantId: T }, other), 'n', params)
  assert.deepEqual(params, [T])
})
