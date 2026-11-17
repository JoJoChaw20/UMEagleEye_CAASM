import { createMiddleware } from 'hono/factory'
import type { Env, AuthUser } from '../types'
import { decide, refusalMessage, type ActionKey, type Decision } from '../lib/actions'

export function hasAction(user: AuthUser, key: ActionKey): boolean {
  return decide(user, key).ok
}

// Passes when the user may do at least one of the listed actions.
export function requireAction(first: ActionKey, ...rest: ActionKey[]) {
  return createMiddleware<{ Bindings: Env }>(async (c, next) => {
    const user = c.get('user')
    if (!user) return c.json({ detail: 'Unauthorized' }, 401)
    // The refusal names the first key, so its decision supplies the reason.
    const firstDecision = decide(user, first)
    if (firstDecision.ok || rest.some((key) => decide(user, key).ok)) {
      await next()
      return
    }
    const refused = firstDecision as Exclude<Decision, { ok: true }>
    return c.json({ detail: refusalMessage(refused.reason, first), missing_action: first }, 403)
  })
}

// The Tenant Superadmin of the tenant in the route (:tenantId), or of any tenant when the route has none.
export const requireTenantSuperadmin = createMiddleware<{ Bindings: Env }>(async (c, next) => {
  const user = c.get('user')
  if (!user) return c.json({ detail: 'Unauthorized' }, 401)
  const tenantId = c.req.param('tenantId')
  if (user.role === 'tenant_superadmin' && (tenantId === undefined || user.tenantId === tenantId)) {
    await next()
    return
  }
  return c.json({ detail: 'Only the Tenant Superadmin can do this.' }, 403)
})

export const requirePlatformSuperadmin = createMiddleware<{ Bindings: Env }>(async (c, next) => {
  const user = c.get('user')
  if (!user) return c.json({ detail: 'Unauthorized' }, 401)
  if (user.role !== 'superadmin') return c.json({ detail: 'Only the Platform Superadmin can do this.' }, 403)
  await next()
})

// Holds tenant users and the Tenant Superadmin to the tenant in the route (:tenantId). The Platform
// Superadmin passes: it sees every tenant, and the action guard before this one limits it to reading.
export const requireOwnTenant = createMiddleware<{ Bindings: Env }>(async (c, next) => {
  const user = c.get('user')
  if (!user) return c.json({ detail: 'Unauthorized' }, 401)
  if (user.role === 'superadmin' || (user.tenantId && user.tenantId === c.req.param('tenantId'))) {
    await next()
    return
  }
  return c.json({ detail: 'You can only access your own tenant.' }, 403)
})
