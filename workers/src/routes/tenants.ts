import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, count, and, ne } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles, requireTenantAccess } from '../middleware/auth'
import { getDb } from '../db/client'
import { tenants, users, assets } from '../db/schema'

const router = new Hono<{ Bindings: Env }>()

// ── Middleware combos ─────────────────────────────────────────────
const superadminOnly      = [authMiddleware, requireRoles('superadmin')] as const
// superadmin platform-wide OR tenant_superadmin for their own tenant
const tenantAdminAccess   = [authMiddleware, requireTenantAccess(['superadmin'], ['tenant_superadmin'])] as const
// superadmin platform-wide OR tenant_superadmin / tenant_admin for their own tenant
const tenantViewAccess    = [authMiddleware, requireTenantAccess(['superadmin'], ['tenant_superadmin', 'tenant_admin'])] as const

// ── GET / — List all tenants (superadmin only) ────────────────────
router.get('/', ...superadminOnly, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const rows = await db.select().from(tenants)
  return c.json({
    tenants: rows.map((t) => ({
      tenant_id: t.tenantId,
      name: t.name,
      slug: t.slug,
      is_active: t.isActive,
      created_at: t.createdAt,
    })),
  })
})

// ── POST / — Create tenant (superadmin only) ──────────────────────
router.post(
  '/',
  ...superadminOnly,
  zValidator('json', z.object({
    name: z.string().min(1).max(100),
    slug: z.string().min(1).max(50).regex(/^[a-z0-9-]+$/, 'Slug must be lowercase kebab-case'),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { name, slug } = c.req.valid('json')

    const [existing] = await db.select().from(tenants).where(eq(tenants.slug, slug)).limit(1)
    if (existing) return c.json({ detail: 'Slug already in use' }, 409)

    const tenantRows = await db.insert(tenants).values({ name, slug }).returning()
    const tenant = tenantRows[0]
    if (!tenant) return c.json({ detail: 'Failed to create tenant' }, 500)

    return c.json({
      tenant_id: tenant.tenantId,
      name: tenant.name,
      slug: tenant.slug,
      is_active: tenant.isActive,
      created_at: tenant.createdAt,
    }, 201)
  }
)

// ── GET /:tenantId — Single tenant with counts ────────────────────
// superadmin sees any; tenant_superadmin + tenant_admin see own
router.get('/:tenantId', ...tenantViewAccess, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const { tenantId } = c.req.param()

  const [tenant] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
  if (!tenant) return c.json({ detail: 'Tenant not found' }, 404)

  const [userCountRow] = await db
    .select({ value: count() })
    .from(users)
    .where(eq(users.tenantId, tenantId))

  const [assetCountRow] = await db
    .select({ value: count() })
    .from(assets)
    .where(and(eq(assets.tenantId, tenantId), eq(assets.source, 'manual')))

  return c.json({
    tenant_id: tenant.tenantId,
    name: tenant.name,
    slug: tenant.slug,
    is_active: tenant.isActive,
    created_at: tenant.createdAt,
    user_count: Number(userCountRow?.value ?? 0),
    asset_count: Number(assetCountRow?.value ?? 0),
  })
})

// ── PATCH /:tenantId — Update tenant ─────────────────────────────
// superadmin: name + is_active; tenant_superadmin: name only (own tenant)
router.patch(
  '/:tenantId',
  authMiddleware,
  async (c, next) => {
    const user = c.get('user')
    if (user.role === 'superadmin') return next()
    if (user.role === 'tenant_superadmin' && user.tenantId === c.req.param('tenantId')) return next()
    return c.json({ detail: 'Insufficient permissions' }, 403)
  },
  zValidator('json', z.object({
    name: z.string().min(1).max(100).optional(),
    is_active: z.boolean().optional(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId } = c.req.param()
    const user = c.get('user')
    const updates = c.req.valid('json')

    const [existing] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
    if (!existing) return c.json({ detail: 'Tenant not found' }, 404)

    const updateData: Record<string, unknown> = {}
    if (updates.name !== undefined) updateData.name = updates.name
    // only superadmin can toggle tenant is_active
    if (updates.is_active !== undefined && user.role === 'superadmin') {
      updateData.isActive = updates.is_active
    }

    const updatedRows = await db.update(tenants).set(updateData).where(eq(tenants.tenantId, tenantId)).returning()
    const updated = updatedRows[0]
    if (!updated) return c.json({ detail: 'Tenant not found' }, 404)

    return c.json({
      tenant_id: updated.tenantId,
      name: updated.name,
      slug: updated.slug,
      is_active: updated.isActive,
    })
  }
)

// ── DELETE /:tenantId — Deactivate tenant (superadmin only) ───────
router.delete('/:tenantId', ...superadminOnly, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const { tenantId } = c.req.param()

  const [existing] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
  if (!existing) return c.json({ detail: 'Tenant not found' }, 404)

  await db.update(tenants).set({ isActive: false }).where(eq(tenants.tenantId, tenantId))

  return c.json({ ok: true })
})

// ── GET /:tenantId/users — List users in tenant ───────────────────
// superadmin sees any; tenant_superadmin + tenant_admin see own
router.get('/:tenantId/users', ...tenantViewAccess, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const { tenantId } = c.req.param()

  const [tenant] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
  if (!tenant) return c.json({ detail: 'Tenant not found' }, 404)

  const rows = await db.select({
    userId: users.userId,
    username: users.username,
    email: users.email,
    role: users.role,
    isActive: users.isActive,
    createdAt: users.createdAt,
    lastLogin: users.lastLogin,
  }).from(users).where(eq(users.tenantId, tenantId))

  return c.json({
    users: rows.map((u) => ({
      user_id: u.userId,
      username: u.username,
      email: u.email,
      role: u.role,
      is_active: u.isActive,
      created_at: u.createdAt,
      last_login: u.lastLogin,
    })),
  })
})

// ── POST /:tenantId/users — Assign existing user to tenant ────────
// superadmin platform-wide; tenant_superadmin for own tenant
// Accepts user_id (UUID) or username for lookup
router.post(
  '/:tenantId/users',
  ...tenantAdminAccess,
  zValidator('json', z.object({
    user_id:  z.string().uuid().optional(),
    username: z.string().min(1).optional(),
  }).refine(d => d.user_id || d.username, { message: 'Either user_id or username is required' })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId } = c.req.param()
    const { user_id, username } = c.req.valid('json')

    const [tenant] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
    if (!tenant) return c.json({ detail: 'Tenant not found' }, 404)

    let resolvedId = user_id
    if (!resolvedId && username) {
      const [found] = await db.select().from(users).where(eq(users.username, username)).limit(1)
      if (!found) return c.json({ detail: `No user found with username "${username}"` }, 404)
      resolvedId = found.userId
    }

    const [user] = await db.select().from(users).where(eq(users.userId, resolvedId!)).limit(1)
    if (!user) return c.json({ detail: 'User not found' }, 404)

    await db.update(users).set({ tenantId }).where(eq(users.userId, resolvedId!))

    return c.json({ ok: true, user_id: resolvedId, username: user.username, tenant_id: tenantId })
  }
)

// ── POST /:tenantId/users/invite — Create or assign user by email ──
// superadmin platform-wide; tenant_superadmin for own tenant
router.post(
  '/:tenantId/users/invite',
  ...tenantAdminAccess,
  zValidator('json', z.object({
    email: z.string().email(),
    username: z.string().min(3).max(100).optional(),
    role: z.enum(['tenant_superadmin', 'tenant_admin', 'business_owner']).optional(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId } = c.req.param()
    const { email, username, role } = c.req.valid('json')

    const [tenant] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
    if (!tenant) return c.json({ detail: 'Tenant not found' }, 404)

    const [existing] = await db.select().from(users).where(eq(users.email, email)).limit(1)
    if (existing) {
      await db.update(users).set({ tenantId }).where(eq(users.userId, existing.userId))
      return c.json({
        ok: true,
        user_id: existing.userId,
        username: existing.username,
        email: existing.email,
        role: existing.role,
        action: 'assigned',
      })
    }

    const uname = username ?? (email.split('@')[0] ?? email).toLowerCase().replace(/[^a-z0-9_]/g, '_')
    const inserted = await db.insert(users).values({
      username: uname,
      email,
      passwordHash: 'google_oauth_no_password',
      role: role ?? 'business_owner',
      tenantId,
    }).returning()

    const newUser = inserted[0]
    if (!newUser) return c.json({ detail: 'Failed to create user' }, 500)

    return c.json({
      ok: true,
      user_id: newUser.userId,
      username: newUser.username,
      email: newUser.email,
      role: newUser.role,
      action: 'created',
    }, 201)
  }
)

// ── PATCH /:tenantId/users/:userId/role — Change user role ────────
// superadmin: any tenant; tenant_superadmin: own tenant only
// Neither can elevate to superadmin
router.patch(
  '/:tenantId/users/:userId/role',
  authMiddleware,
  async (c, next) => {
    const user = c.get('user')
    if (user.role === 'superadmin') return next()
    if (user.role === 'tenant_superadmin' && user.tenantId === c.req.param('tenantId')) return next()
    return c.json({ detail: 'Insufficient permissions' }, 403)
  },
  zValidator('json', z.object({
    role: z.enum(['tenant_superadmin', 'tenant_admin', 'business_owner']),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId, userId } = c.req.param()
    const { role } = c.req.valid('json')
    const caller = c.get('user')

    const [target] = await db
      .select()
      .from(users)
      .where(and(eq(users.userId, userId), eq(users.tenantId, tenantId)))
      .limit(1)

    if (!target) return c.json({ detail: 'User not found in this tenant' }, 404)

    // Prevent tenant_superadmin from reassigning another tenant_superadmin's role
    if (target.role === 'tenant_superadmin' && caller.role !== 'superadmin') {
      return c.json({ detail: 'Only superadmin can reassign a tenant superadmin role' }, 403)
    }

    // tenant_superadmin can only assign tenant_admin or business_owner — not tenant_superadmin
    if (caller.role === 'tenant_superadmin' && role === 'tenant_superadmin') {
      return c.json({ detail: 'Tenant superadmin cannot assign the tenant superadmin role' }, 403)
    }

    // Enforce 1 tenant_superadmin per tenant: demote existing one first
    if (role === 'tenant_superadmin') {
      await db.update(users)
        .set({ role: 'tenant_admin' })
        .where(and(
          eq(users.tenantId, tenantId),
          eq(users.role, 'tenant_superadmin'),
          ne(users.userId, userId),
        ))
    }

    await db.update(users).set({ role }).where(eq(users.userId, userId))

    return c.json({ ok: true, user_id: userId, role })
  }
)

// ── PATCH /:tenantId/users/:userId/deactivate — Deactivate user ───
// tenant_superadmin: own tenant; superadmin: any
router.patch(
  '/:tenantId/users/:userId/deactivate',
  ...tenantAdminAccess,
  zValidator('json', z.object({
    is_active: z.boolean(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId, userId } = c.req.param()
    const { is_active } = c.req.valid('json')

    const [target] = await db
      .select()
      .from(users)
      .where(and(eq(users.userId, userId), eq(users.tenantId, tenantId)))
      .limit(1)

    if (!target) return c.json({ detail: 'User not found in this tenant' }, 404)

    const caller = c.get('user')
    if (caller.role !== 'superadmin') {
      if (target.userId === caller.userId) return c.json({ detail: 'Cannot deactivate your own account' }, 403)
      if (target.role === 'tenant_superadmin') return c.json({ detail: 'Cannot deactivate another tenant superadmin' }, 403)
    }

    await db.update(users).set({ isActive: is_active }).where(eq(users.userId, userId))

    return c.json({ ok: true, user_id: userId, is_active })
  }
)

export default router
