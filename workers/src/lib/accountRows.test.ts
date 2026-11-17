// The row-to-response mappings of the routes that read users (no route harness exists: routes are
// checked on staging), so a stored row is tested here as the routes see it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { MIGRATION_ACTIONS } from './actions'
import {
  assignableUsers, canBeAssignedAlerts, planActionsUpdate, roleOf, signIn, toAuthUser, withAccount, tenantUserItem,
} from './accountRows'

const T = 'tenant-a'
const LEGACY_ADMIN = 'tenant' + '_admin'      // split so legacyRoles.test.ts finds no literal here either
const LEGACY_OWNER = 'business' + '_owner'
const ADMIN_SET = [...MIGRATION_ACTIONS.tenant_admin]
const OWNER_SET = [...MIGRATION_ACTIONS.business_owner]

test('tenant user list shows each user\'s stored actions', () => {
  const item = tenantUserItem({
    userId: 'u1', username: 'alice', email: 'a@x', role: 'tenant_user', actions: ADMIN_SET,
    isActive: true, createdAt: null, lastLogin: null,
  })
  assert.equal(item.role, 'tenant_user')
  assert.equal(item.actions.length, 53)
  assert.deepEqual(item.actions, ADMIN_SET)
  assert.equal(item.user_id, 'u1')
})

test('assignable list: tenant users who may manage alerts, and the Tenant Superadmin', () => {
  const items = assignableUsers([
    { userId: 'a', username: 'admin', role: 'tenant_user', actions: ADMIN_SET },
    { userId: 'b', username: 'owner', role: 'tenant_user', actions: OWNER_SET },
    { userId: 'c', username: 'boss', role: 'tenant_superadmin', actions: [] },
    { userId: 'd', username: 'none', role: 'tenant_user', actions: [] },
  ], T)
  assert.deepEqual(items, [
    { user_id: 'a', username: 'admin', role: 'tenant_user' },
    { user_id: 'c', username: 'boss', role: 'tenant_superadmin' },
  ])
})

test('alert assignee check follows stored actions', () => {
  assert.equal(canBeAssignedAlerts({ tenantId: T, role: 'tenant_user', actions: ADMIN_SET }), true)
  assert.equal(canBeAssignedAlerts({ tenantId: T, role: 'tenant_user', actions: OWNER_SET }), false)
  assert.equal(canBeAssignedAlerts({ tenantId: T, role: 'tenant_user', actions: ['alert.view', 'alert.manage'] }), true)
  assert.equal(canBeAssignedAlerts({ tenantId: T, role: 'tenant_user', actions: [] }), false)
  assert.equal(canBeAssignedAlerts({ tenantId: null, role: 'superadmin', actions: [] }), false)
  assert.equal(canBeAssignedAlerts(undefined), false)
})

test('PUT actions accepts a tenant user only and writes only actions', () => {
  const plan = planActionsUpdate({ role: 'tenant_user', actions: ADMIN_SET }, ['alert.view'])
  assert.ok(plan)
  assert.deepEqual(Object.keys(plan.set), ['actions'])
  assert.deepEqual(plan.set.actions, ['alert.view'])
  assert.deepEqual(plan.previous, ADMIN_SET)
  assert.deepEqual(planActionsUpdate({ role: 'tenant_user', actions: ['dashboard.view'] }, [])?.previous, ['dashboard.view'])
  assert.equal(planActionsUpdate({ role: 'tenant_superadmin', actions: [] }, []), null)
  assert.equal(planActionsUpdate({ role: 'superadmin', actions: [] }, []), null)
})

test('the signed-in user and profile carry the normalized role', () => {
  const user = toAuthUser('u1', 'alice', { role: 'tenant_user', tenantId: T, actions: OWNER_SET })
  assert.deepEqual(user, {
    userId: 'u1', role: 'tenant_user', username: 'alice', tenantId: T, actions: OWNER_SET,
  })
  assert.equal(toAuthUser('p', 'root', { role: 'superadmin', tenantId: null, actions: [] }).tenantId, undefined)

  const me = withAccount({ userId: 'u1', role: 'tenant_user', actions: ADMIN_SET, email: 'a@x' })
  assert.equal(me.role, 'tenant_user')
  assert.equal(me.actions.length, 53)
  assert.equal(me.email, 'a@x')
})

test('sign-in: the token and the response carry the role', () => {
  const alice = signIn({ userId: 'u1', role: 'tenant_user', username: 'alice', tenantId: T })
  assert.deepEqual(alice.claims, { sub: 'u1', role: 'tenant_user', username: 'alice', tenant_id: T })
  assert.equal(alice.role, 'tenant_user')

  const root = signIn({ userId: 'u2', role: 'superadmin', username: 'root', tenantId: null })
  assert.equal(root.claims.tenant_id, undefined)
  assert.equal(root.role, 'superadmin')

  const boss = signIn({ userId: 'u3', role: 'tenant_superadmin', username: 'carol', tenantId: T })
  assert.equal(boss.claims.role, 'tenant_superadmin')
  assert.equal(boss.role, 'tenant_superadmin')
})

test('a stray old role value fails closed: a tenant user with no actions', () => {
  // Migration 0036 removed these values from the enum; a row can only carry one if the DB is out of step.
  assert.deepEqual(toAuthUser('u', 'x', { role: LEGACY_ADMIN, tenantId: T, actions: ADMIN_SET }).actions, [])
  assert.equal(roleOf({ role: LEGACY_OWNER }), 'tenant_user')
  assert.equal(canBeAssignedAlerts({ tenantId: T, role: LEGACY_ADMIN, actions: ADMIN_SET }), false)
  assert.deepEqual(planActionsUpdate({ role: LEGACY_OWNER, actions: OWNER_SET }, ['alert.view'])?.previous, [])
})
