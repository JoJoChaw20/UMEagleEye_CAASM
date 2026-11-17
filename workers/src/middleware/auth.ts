import { createMiddleware } from 'hono/factory'
import type { Env, AuthUser } from '../types'
import { verifyToken } from '../lib/auth'
import { getDb } from '../db/client'
import { users } from '../db/schema'
import { eq } from 'drizzle-orm'

declare module 'hono' {
  interface ContextVariableMap {
    user: AuthUser
  }
}

export const authMiddleware = createMiddleware<{ Bindings: Env }>(async (c, next) => {
  const authHeader = c.req.header('Authorization')
  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ detail: 'Missing or invalid Authorization header' }, 401)
  }

  const token = authHeader.slice(7)
  const payload = await verifyToken(token, c.env.JWT_SECRET_KEY)
  if (!payload) {
    return c.json({ detail: 'Token expired or invalid' }, 401)
  }

  // Role, tenant, active flag and actions are read fresh on every request, not trusted from the
  // token, so a change by an administrator (or a deactivation) takes effect at once.
  const db = getDb(c.env.DATABASE_URL)
  const [row] = await db
    .select({ role: users.role, tenantId: users.tenantId, isActive: users.isActive, actions: users.actions })
    .from(users)
    .where(eq(users.userId, payload.sub))
    .limit(1)
  if (!row || !row.isActive) {
    return c.json({ detail: 'Your account is deactivated. Contact your Tenant Superadmin.' }, 401)
  }

  const user: AuthUser = {
    userId: payload.sub,
    role: row.role,
    username: payload.username,
    tenantId: row.tenantId ?? undefined,
    actions: row.actions ?? [],
  }
  c.set('user', user)

  // Every role but the platform superadmin sees one tenant. An account with no tenant
  // (made by Google sign-in for an unknown email, or left over when its tenant was
  // deleted) would otherwise pass routes that filter by tenant only when one is set, and
  // read every tenant's data. It may use its own account endpoints (/auth/...) and
  // nothing else until an admin adds it to a tenant.
  if (user.role !== 'superadmin' && !user.tenantId && !/^\/api\/v1\/auth\//.test(c.req.path)) {
    return c.json({ detail: 'Your account is not part of an organisation yet. Ask your administrator to add you.' }, 403)
  }

  await next()
})

// Enforce that user has one of the listed roles (exact match).
export function requireRoles(...roles: string[]) {
  return createMiddleware<{ Bindings: Env }>(async (c, next) => {
    const user = c.get('user')
    if (!user) return c.json({ detail: 'Unauthorized' }, 401)
    if (!roles.includes(user.role)) {
      return c.json({
        detail: `Insufficient permissions: role '${user.role}' is not allowed here (requires: ${roles.join(', ')})`,
      }, 403)
    }
    await next()
  })
}

// Allow superadmin platform-wide, or allow ownTenantRoles when the user's tenantId
// matches the :tenantId route parameter.
export function requireTenantAccess(platformRoles: string[], ownTenantRoles: string[]) {
  return createMiddleware<{ Bindings: Env }>(async (c, next) => {
    const user = c.get('user')
    if (!user) return c.json({ detail: 'Unauthorized' }, 401)

    if (platformRoles.includes(user.role)) {
      await next()
      return
    }

    if (ownTenantRoles.includes(user.role)) {
      const tenantId = c.req.param('tenantId')
      if (tenantId && user.tenantId === tenantId) {
        await next()
        return
      }
    }

    return c.json({
      detail: `Insufficient permissions: role '${user.role}' cannot access this tenant `
        + `(requires: ${platformRoles.join(', ')} platform-wide, or ${ownTenantRoles.join(', ')} within your own tenant)`,
    }, 403)
  })
}

// Permission guards live in guards.ts (no database or crypto imports, so they can be unit tested).
export { hasAction, requireAction, requireTenantSuperadmin, requirePlatformSuperadmin } from './guards'
