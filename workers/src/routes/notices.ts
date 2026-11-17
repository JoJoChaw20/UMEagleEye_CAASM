// In-app notices of the caller's tenant (ownership changes, transfer requests, checklists).
import { Hono } from 'hono'
import { and, desc, eq, isNull, or } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb } from '../db/client'
import { tenantNotices } from '../db/schema'
import { noticeVisible } from '../lib/notices'

const router = new Hono<{ Bindings: Env }>()

// Both routes act only on the caller's own tenant and own notices (listed in SELF_SERVICE, lib/routeGuard.test.ts).

// ── GET / — The caller's unexpired, undismissed notices: tenant-wide ones plus their own ──
router.get('/', authMiddleware, async (c) => {
  try {
    const me = c.get('user')
    if (!me.tenantId) return c.json([])
    const db = getDb(c.env.DATABASE_URL)
    const rows = await db.select().from(tenantNotices)
      .where(and(
        eq(tenantNotices.tenantId, me.tenantId), isNull(tenantNotices.dismissedAt),
        or(isNull(tenantNotices.userId), eq(tenantNotices.userId, me.userId)),
      ))
      .orderBy(desc(tenantNotices.createdAt)).limit(100)
    const now = new Date()
    return c.json(rows.filter((r) => noticeVisible(r, me, now)).map((r) => ({
      notice_id: r.noticeId, kind: r.kind, body: r.body, created_at: r.createdAt,
      expires_at: r.expiresAt, personal: r.userId !== null,
    })))
  } catch (err) {
    console.error('notices list error:', err)
    return c.json({ detail: 'Failed to load notices' }, 500)
  }
})

// ── POST /:id/dismiss — Dismiss one of the caller's own notices (tenant-wide ones expire instead) ──
router.post('/:id/dismiss', authMiddleware, async (c) => {
  try {
    const me = c.get('user')
    const id = c.req.param('id')
    const NOT_FOUND = { detail: 'Notice not found' }
    if (!me.tenantId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return c.json(NOT_FOUND, 404)
    const db = getDb(c.env.DATABASE_URL)
    const rows = await db.update(tenantNotices).set({ dismissedAt: new Date() })
      .where(and(
        eq(tenantNotices.noticeId, id), eq(tenantNotices.userId, me.userId), eq(tenantNotices.tenantId, me.tenantId),
        isNull(tenantNotices.dismissedAt),
      )).returning({ noticeId: tenantNotices.noticeId })
    if (!rows.length) return c.json(NOT_FOUND, 404)
    return c.json({ ok: true })
  } catch (err) {
    console.error('notice dismiss error:', err)
    return c.json({ detail: 'Failed to dismiss the notice' }, 500)
  }
})

export default router
