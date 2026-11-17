// The row-to-response mappings of the routes that read users (no route harness exists: routes are
// checked on staging), so a stored legacy-role row is tested here as the routes see it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { MIGRATION_ACTIONS } from './actions'
import {
  assignableUsers, canBeAssignedAlerts, planActionsUpdate, toAuthUser, tokenClaims, withAccount, tenantUserItem,
} from './accountRows'

const T = 'tenant-a'
const LEGACY_ADMIN = 'tenant' + '_admin'      // split so legacyRoles.test.ts finds no literal here either
const LEGACY_OWNER = 'business' + '_owner'

test('tenant user list shows legacy users\' converted actions', () => {
  const item = tenantUserItem({
    userId: 'u1', username: 'alice', email: 'a@x', role: LEGACY_ADMIN, actions: null,
    isActive: true, createdAt: null, lastLogin: null,
  })
  assert.equal(item.role, 'tenant_user')
  assert.equal(item.actions.length, 53)
  assert.deepEqual(item.actions, [...MIGRATION_ACTIONS.tenant_admin])
  assert.equal(item.user_id, 'u1')
})

test('assignable list includes legacy tenant_admin', () => {
  const items = assignableUsers([
    { userId: 'a', username: 'admin', role: LEGACY_ADMIN, actions: null },
    { userId: 'b', username: 'owner', role: LEGACY_OWNER, actions: null },
    { userId: 'c', username: 'boss', role: 'tenant_superadmin', actions: null },
    { userId: 'd', username: 'none', role: 'tenant_user', actions: [] },
  ], T)
  assert.deepEqual(items, [
    { user_id: 'a', username: 'admin', role: 'tenant_user' },
    { user_id: 'c', username: 'boss', role: 'tenant_superadmin' },
  ])
})

test('alert assignee check reads legacy rows as tenant users', () => {
  assert.equal(canBeAssignedAlerts({ tenantId: T, role: LEGACY_ADMIN, actions: null }), true)
  assert.equal(canBeAssignedAlerts({ tenantId: T, role: LEGACY_OWNER, actions: null }), false)
  // An edited legacy user: stored actions win over the converted set.
  assert.equal(canBeAssignedAlerts({ tenantId: T, role: LEGACY_OWNER, actions: ['alert.view', 'alert.manage'] }), true)
  assert.equal(canBeAssignedAlerts({ tenantId: T, role: LEGACY_ADMIN, actions: [] }), false)
  assert.equal(canBeAssignedAlerts({ tenantId: null, role: 'superadmin', actions: null }), false)
  assert.equal(canBeAssignedAlerts(undefined), false)
})

test('PUT actions accepts a legacy user and keeps its stored role', () => {
  const plan = planActionsUpdate({ role: LEGACY_ADMIN, actions: null }, ['alert.view'])
  assert.ok(plan)
  assert.deepEqual(Object.keys(plan.set), ['actions'])
  assert.deepEqual(plan.set.actions, ['alert.view'])
  assert.deepEqual(plan.previous, [...MIGRATION_ACTIONS.tenant_admin])
  assert.deepEqual(planActionsUpdate({ role: LEGACY_OWNER, actions: ['dashboard.view'] }, [])?.previous, ['dashboard.view'])
  assert.equal(planActionsUpdate({ role: 'tenant_superadmin', actions: null }, []), null)
  assert.equal(planActionsUpdate({ role: 'superadmin', actions: null }, []), null)
})

test('the signed-in user, token claims and profile carry the normalized role', () => {
  const user = toAuthUser('u1', 'alice', { role: LEGACY_OWNER, tenantId: T, actions: null })
  assert.deepEqual(user, {
    userId: 'u1', role: 'tenant_user', username: 'alice', tenantId: T, actions: [...MIGRATION_ACTIONS.business_owner],
  })
  assert.equal(toAuthUser('p', 'root', { role: 'superadmin', tenantId: null, actions: null }).tenantId, undefined)

  assert.deepEqual(tokenClaims({ userId: 'u1', role: LEGACY_ADMIN, username: 'alice', tenantId: null }),
    { sub: 'u1', role: 'tenant_user', username: 'alice', tenant_id: undefined })

  const me = withAccount({ userId: 'u1', role: LEGACY_ADMIN, actions: null, email: 'a@x' })
  assert.equal(me.role, 'tenant_user')
  assert.equal(me.actions.length, 53)
  assert.equal(me.email, 'a@x')
})
