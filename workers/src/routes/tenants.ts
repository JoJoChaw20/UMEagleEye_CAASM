import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, count } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { tenants, users, assets } from '../db/schema'

const router = new Hono<{ Bindings: Env }>()

// All tenant routes require superadmin
const superadminOnly = [authMiddleware, requireRoles('superadmin')] as const

// ── GET / — List all tenants ──────────────────────────────────────
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

// ── POST / — Create tenant ────────────────────────────────────────
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

    // Check slug uniqueness
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
router.get('/:tenantId', ...superadminOnly, async (c) => {
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
    .where(eq(assets.tenantId, tenantId))

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
router.patch(
  '/:tenantId',
  ...superadminOnly,
  zValidator('json', z.object({
    name: z.string().min(1).max(100).optional(),
    is_active: z.boolean().optional(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId } = c.req.param()
    const updates = c.req.valid('json')

    const [existing] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
    if (!existing) return c.json({ detail: 'Tenant not found' }, 404)

    const updateData: Record<string, unknown> = {}
    if (updates.name !== undefined) updateData.name = updates.name
    if (updates.is_active !== undefined) updateData.isActive = updates.is_active

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

// ── DELETE /:tenantId — Soft delete ──────────────────────────────
router.delete('/:tenantId', ...superadminOnly, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const { tenantId } = c.req.param()

  const [existing] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
  if (!existing) return c.json({ detail: 'Tenant not found' }, 404)

  await db.update(tenants).set({ isActive: false }).where(eq(tenants.tenantId, tenantId))

  return c.json({ ok: true })
})

// ── GET /:tenantId/users — List users in tenant ───────────────────
router.get('/:tenantId/users', ...superadminOnly, async (c) => {
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
router.post(
  '/:tenantId/users',
  ...superadminOnly,
  zValidator('json', z.object({
    user_id: z.string().uuid(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId } = c.req.param()
    const { user_id } = c.req.valid('json')

    const [tenant] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
    if (!tenant) return c.json({ detail: 'Tenant not found' }, 404)

    const [user] = await db.select().from(users).where(eq(users.userId, user_id)).limit(1)
    if (!user) return c.json({ detail: 'User not found' }, 404)

    await db.update(users).set({ tenantId }).where(eq(users.userId, user_id))

    return c.json({ ok: true, user_id, tenant_id: tenantId })
  }
)

// ── POST /:tenantId/users/invite — Create or assign user by email ──
router.post(
  '/:tenantId/users/invite',
  ...superadminOnly,
  zValidator('json', z.object({
    email: z.string().email(),
    username: z.string().min(3).max(100).optional(),
    role: z.enum(['ops_lead', 'security_engineer', 'business_owner', 'mssp_analyst']).optional(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId } = c.req.param()
    const { email, username, role } = c.req.valid('json')

    const [tenant] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
    if (!tenant) return c.json({ detail: 'Tenant not found' }, 404)

    // If user with this email already exists, just assign them
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

    // Create new Google-only account (no password — user must sign in via Google)
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

export default router
