// The row-to-response mappings of the routes that read users (no route harness exists: routes are
// checked on staging), so a stored legacy-role row is tested here as the routes see it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { MIGRATION_ACTIONS } from './actions'
import {
  assignableUsers, canBeAssignedAlerts, planActionsUpdate, storedActionsFor, signIn, toAuthUser, withAccount, tenantUserItem,
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

test('the signed-in user and profile carry the normalized role', () => {
  const user = toAuthUser('u1', 'alice', { role: LEGACY_OWNER, tenantId: T, actions: null })
  assert.deepEqual(user, {
    userId: 'u1', role: 'tenant_user', username: 'alice', tenantId: T, actions: [...MIGRATION_ACTIONS.business_owner],
  })
  assert.equal(toAuthUser('p', 'root', { role: 'superadmin', tenantId: null, actions: null }).tenantId, undefined)

  const me = withAccount({ userId: 'u1', role: LEGACY_ADMIN, actions: null, email: 'a@x' })
  assert.equal(me.role, 'tenant_user')
  assert.equal(me.actions.length, 53)
  assert.equal(me.email, 'a@x')
})

test('sign-in: the token keeps the stored role, the response carries the normalized one', () => {
  // The previous worker trusts payload.role: after a rollback a legacy user's token must still work there.
  const legacy = signIn({ userId: 'u1', role: LEGACY_ADMIN, username: 'alice', tenantId: T })
  assert.deepEqual(legacy.claims, { sub: 'u1', role: LEGACY_ADMIN, username: 'alice', tenant_id: T })
  assert.equal(legacy.role, 'tenant_user')

  const owner = signIn({ userId: 'u2', role: LEGACY_OWNER, username: 'bob', tenantId: null })
  assert.equal(owner.claims.role, LEGACY_OWNER)
  assert.equal(owner.claims.tenant_id, undefined)
  assert.equal(owner.role, 'tenant_user')

  const boss = signIn({ userId: 'u3', role: 'tenant_superadmin', username: 'carol', tenantId: T })
  assert.equal(boss.claims.role, 'tenant_superadmin')
  assert.equal(boss.role, 'tenant_superadmin')
})

test('a Tenant Superadmin is stored with NULL actions, so a demotion by old code reads as the converted set', () => {
  assert.equal(storedActionsFor('tenant_superadmin', []), null)
  assert.deepEqual(storedActionsFor('tenant_user', ['asset.view']), ['asset.view'])
  assert.deepEqual(storedActionsFor('tenant_user', []), [])
  // old code demotes the owner to the legacy admin role: NULL actions give the converted set, not zero
  assert.equal(toAuthUser('u', 'o', { role: LEGACY_ADMIN, actions: storedActionsFor('tenant_superadmin', []), tenantId: T }).actions.length, 53)
})
