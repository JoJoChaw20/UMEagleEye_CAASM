import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Hono } from 'hono'
import { requireAction, requireOwnTenant, requireTenantSuperadmin } from './guards'
import type { AuthUser } from '../types'

const user = (over: Partial<AuthUser>): AuthUser => ({
  userId: 'u1', username: 'u', role: 'tenant_user', tenantId: 't1', actions: [], ...over,
})

// A tiny app: stub user, then the guard, then a 200 handler. No database.
function appWith(u: AuthUser, guard: ReturnType<typeof requireAction> | typeof requireTenantSuperadmin | typeof requireOwnTenant, path = '/x') {
  const app = new Hono()
  app.use('*', async (c, next) => { c.set('user', u); await next() })
  app.get(path, guard as never, (c) => c.json({ ok: true }))
  return app
}

test('requireAction passes for a tenant_user holding the key', async () => {
  const res = await appWith(user({ actions: ['asset.edit'] }), requireAction('asset.edit')).request('/x')
  assert.equal(res.status, 200)
})

test('requireAction 403 names the missing action', async () => {
  const res = await appWith(user({}), requireAction('asset.edit')).request('/x')
  assert.equal(res.status, 403)
  assert.deepEqual(await res.json(), {
    detail: 'You do not have the "Edit assets" action. Ask your Tenant Superadmin to grant it.',
    missing_action: 'asset.edit',
  })
})

test('requireAction passes when only the second key is held', async () => {
  const res = await appWith(user({ actions: ['asset.delete'] }), requireAction('asset.edit', 'asset.delete')).request('/x')
  assert.equal(res.status, 200)
})

test('superadmin is refused on a write action and allowed on a read action', async () => {
  const sa = user({ role: 'superadmin', tenantId: undefined })
  const denied = await appWith(sa, requireAction('asset.edit')).request('/x')
  assert.equal(denied.status, 403)
  assert.equal(((await denied.json()) as { detail: string }).detail,
    'The Platform Superadmin can view tenants but cannot make changes inside them.')
  const allowed = await appWith(sa, requireAction('asset.view')).request('/x')
  assert.equal(allowed.status, 200)
})

test('requireTenantSuperadmin checks the :tenantId of the route', async () => {
  const ts = user({ role: 'tenant_superadmin', tenantId: 't1' })
  const app = appWith(ts, requireTenantSuperadmin, '/t/:tenantId')
  assert.equal((await app.request('/t/t1')).status, 200)
  assert.equal((await app.request('/t/t2')).status, 403)
  const res = await appWith(user({}), requireTenantSuperadmin, '/t/:tenantId').request('/t/t1')
  assert.equal(res.status, 403)
  assert.equal(((await res.json()) as { detail: string }).detail, 'Only the Tenant Superadmin can do this.')
})

test('requireOwnTenant lets the Platform Superadmin through and holds everyone else to their own tenant', async () => {
  const sa = user({ role: 'superadmin', tenantId: undefined })
  assert.equal((await appWith(sa, requireOwnTenant, '/t/:tenantId').request('/t/t2')).status, 200)
  const app = appWith(user({ actions: ['settings.view'] }), requireOwnTenant, '/t/:tenantId')
  assert.equal((await app.request('/t/t1')).status, 200)
  const res = await app.request('/t/t2')
  assert.equal(res.status, 403)
  assert.equal(((await res.json()) as { detail: string }).detail, 'You can only access your own tenant.')
})
