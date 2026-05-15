import { createMiddleware } from 'hono/factory'
import type { Env, AuthUser } from '../types'
import { verifyToken } from '../lib/auth'

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

  c.set('user', {
    userId: payload.sub,
    role: payload.role,
    username: payload.username,
    tenantId: payload.tenant_id,
  })

  await next()
})

export function requireRoles(...roles: string[]) {
  return createMiddleware<{ Bindings: Env }>(async (c, next) => {
    const user = c.get('user')
    if (!user) return c.json({ detail: 'Unauthorized' }, 401)
    if (!roles.includes(user.role)) {
      return c.json({ detail: 'Insufficient permissions' }, 403)
    }
    await next()
  })
}
