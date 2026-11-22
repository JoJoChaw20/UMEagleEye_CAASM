import { createMiddleware } from 'hono/factory'
import type { Env, AuthUser } from '../types'
import { verifyToken } from '../lib/auth'
import { toAuthUser } from '../lib/accountRows'
import { isMfaExempt } from '../lib/mfaFlow'
import { isDeactivated, sessionGate } from '../lib/sessionGate'
import { flipIfDue } from '../services/deactivation'
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
    .select({ role: users.role, tenantId: users.tenantId, isActive: users.isActive, actions: users.actions,
      username: users.username, mfaEnabled: users.mfaEnabled, sessionsValidAfter: users.sessionsValidAfter,
      scheduledDeactivationAt: users.scheduledDeactivationAt })
    .from(users)
    .where(eq(users.userId, payload.sub))
    .limit(1)
  if (!row) {
    return c.json({ detail: 'Your account is deactivated. Contact your Tenant Superadmin.' }, 401)
  }
  const refused = sessionGate(payload, row, c.req.path, new Date(), isMfaExempt(c.env, row.username, row.role))
  if (refused) {
    if (isDeactivated(row)) await flipIfDue(db, payload.sub)
    return c.json(refused.body, refused.status)
  }

  // The row's role and actions, normalized (lib/accountRows.ts).
  const user: AuthUser = toAuthUser(payload.sub, payload.username, row)
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

// Permission guards live in guards.ts (no database or crypto imports, so they can be unit tested).
export { hasAction, requireAction, requireOwnTenant, requireTenantSuperadmin, requirePlatformSuperadmin } from './guards'
