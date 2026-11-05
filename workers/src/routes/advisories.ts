import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, desc, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { advisories, events, assets, auditLogs, users } from '../db/schema'
import { advisoryScope } from '../lib/advisoryScope'

const app = new Hono<{ Bindings: Env }>()

const READ_ROLES   = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner']
const STATUS_ROLES = ['tenant_superadmin', 'tenant_admin']

// Helper: resolve tenantId from advisory via event->asset chain
async function getAdvisoryTenantId(
  db: ReturnType<typeof import('../db/client').getDb>,
  advisoryId: string,
): Promise<{ tenantId: string | null; assetId: string } | null> {
  const rows = await db
    .select({
      assetId: assets.assetId,
      tenantId: assets.tenantId,
    })
    .from(advisories)
    .innerJoin(events, eq(advisories.eventId, events.eventId))
    .innerJoin(assets, eq(events.assetId, assets.assetId))
    .where(eq(advisories.advisoryId, advisoryId))
    .limit(1)

  if (rows.length === 0 || !rows[0]) return null
  return { tenantId: rows[0].tenantId, assetId: rows[0].assetId }
}

// ── GET / ────────────────────────────────────────────────────────
app.get('/', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const page = Math.max(1, parseInt(c.req.query('page') ?? '1'))
    const limit = Math.min(200, Math.max(1, parseInt(c.req.query('limit') ?? '50')))
    const offset = (page - 1) * limit
    const status = c.req.query('status')
    const assigned_to = c.req.query('assigned_to')

    // Build conditions
    const conditions = []

    if (status) {
      conditions.push(eq(advisories.status, status as 'open' | 'acknowledged' | 'in_progress' | 'resolved'))
    }
    if (assigned_to) {
      conditions.push(eq(advisories.assignedTo, assigned_to))
    }

    // Tenant filter through the alert's asset, as a subquery (lib/advisoryScope.ts)
    const scope = advisoryScope(db, user, c.req.query('tenant_id'))
    if (scope) conditions.push(scope)

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined

    const [rows, countRows] = await Promise.all([
      db
        .select({
          advisory: advisories,
          assignedToUsername: users.username,
          assignedToEmail: users.email,
        })
        .from(advisories)
        .leftJoin(users, eq(advisories.assignedTo, users.userId))
        .where(whereClause)
        .orderBy(desc(advisories.createdAt))
        .limit(limit)
        .offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(advisories).where(whereClause),
    ])

    return c.json({
      total: countRows[0]?.count ?? 0,
      page,
      limit,
      items: rows.map(({ advisory, assignedToUsername, assignedToEmail }) => ({
        ...advisory,
        assignedToName: assignedToUsername ?? assignedToEmail ?? null,
        assignedToEmail: assignedToEmail ?? null,
      })),
    })
  } catch (err) {
    console.error('advisories GET / error:', err)
    return c.json({ detail: 'Failed to fetch advisories' }, 500)
  }
})

// ── GET /:advisoryId ─────────────────────────────────────────────
app.get('/:advisoryId', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { advisoryId } = c.req.param()

    const [row] = await db
      .select({
        advisory: advisories,
        assignedToUsername: users.username,
        assignedToEmail: users.email,
      })
      .from(advisories)
      .leftJoin(users, eq(advisories.assignedTo, users.userId))
      .where(eq(advisories.advisoryId, advisoryId))
      .limit(1)

    if (!row) {
      return c.json({ detail: 'Advisory not found' }, 404)
    }
    const advisory = row.advisory

    // Tenant check via event->asset (fails closed for an account without a tenant)
    if (user.role !== 'superadmin') {
      const meta = await getAdvisoryTenantId(db, advisoryId)
      if (!meta || !user.tenantId || meta.tenantId !== user.tenantId) {
        return c.json({ detail: 'Advisory not found' }, 404)
      }
    }

    return c.json({
      ...advisory,
      assignedToName: row.assignedToUsername ?? row.assignedToEmail ?? null,
      assignedToEmail: row.assignedToEmail ?? null,
    })
  } catch (err) {
    console.error('advisories GET /:advisoryId error:', err)
    return c.json({ detail: 'Failed to fetch advisory' }, 500)
  }
})

// ── PATCH /:advisoryId/status ────────────────────────────────────
const updateStatusSchema = z.object({
  status: z.enum(['open', 'acknowledged', 'in_progress', 'resolved']),
  assigned_to: z.string().uuid().nullable().optional(),
})

app.patch(
  '/:advisoryId/status',
  authMiddleware,
  requireRoles(...STATUS_ROLES),
  zValidator('json', updateStatusSchema),
  async (c) => {
    try {
      const user = c.get('user')
      const db = getDb(c.env.DATABASE_URL)
      const { advisoryId } = c.req.param()
      const { status, assigned_to } = c.req.valid('json')

      const [existing] = await db
        .select()
        .from(advisories)
        .where(eq(advisories.advisoryId, advisoryId))
        .limit(1)

      if (!existing) {
        return c.json({ detail: 'Advisory not found' }, 404)
      }

      // Tenant check (fails closed for an account without a tenant)
      if (user.role !== 'superadmin') {
        const meta = await getAdvisoryTenantId(db, advisoryId)
        if (!meta || !user.tenantId || meta.tenantId !== user.tenantId) {
          return c.json({ detail: 'Advisory not found' }, 404)
        }
      }

      const updateData: Partial<typeof advisories.$inferInsert> = { status }
      if (assigned_to !== undefined) {
        if (assigned_to === null) {
          updateData.assignedTo = null
        } else {
          const meta = await getAdvisoryTenantId(db, advisoryId)
          if (!meta) return c.json({ detail: 'Advisory not found' }, 404)

          const [assignee] = await db
            .select({ userId: users.userId, tenantId: users.tenantId })
            .from(users)
            .where(eq(users.userId, assigned_to))
            .limit(1)

          if (!assignee || (user.role !== 'superadmin' && assignee.tenantId !== meta.tenantId)) {
            return c.json({ detail: 'Assignee is not a member of this advisory tenant' }, 400)
          }
          updateData.assignedTo = assigned_to
        }
      }
      if (status === 'resolved') {
        updateData.resolvedAt = new Date()
      }

      const [updated] = await db
        .update(advisories)
        .set(updateData)
        .where(eq(advisories.advisoryId, advisoryId))
        .returning()

      // Insert audit log
      await db.insert(auditLogs).values({
        userId: user.userId,
        tenantId: user.tenantId ?? null,
        actionType: 'advisory_status_update',
        targetEntity: advisoryId,
        previousState: { status: existing.status },
        newState: { status },
      })

      return c.json(updated)
    } catch (err) {
      console.error('advisories PATCH status error:', err)
      return c.json({ detail: 'Failed to update advisory status' }, 500)
    }
  },
)

export default app
