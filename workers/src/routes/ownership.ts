// Tenant ownership handover, Path A: a planned transfer from the owner to an active user of the tenant.
import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { and, eq, inArray, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireTenantSuperadmin } from '../middleware/auth'
import { getDb } from '../db/client'
import { ownershipTransfers, tenantRecoveryPlans, tenants, users } from '../db/schema'
import { HOURS_72, ownershipChangedNotice, validateTransfer } from '../lib/ownership'
import { ownershipView, transferMessage } from '../lib/ownershipView'
import { isUniqueViolation } from '../lib/fkViolation'
import { audit } from '../services/audit'
import { stepUp } from '../services/mfaStepUp'
import { sendMail } from '../services/mailer'
import { acceptTransfer, closeRequestNotice, postNotice, settleOwnership } from '../services/ownership'

const router = new Hono<{ Bindings: Env }>()

// Routes for the recipient (a Tenant user) cannot use requireTenantSuperadmin: they check in the handler
// that the caller belongs to :tenantId and is the transfer's recipient (and are on the allowlist in
// lib/routeGuard.test.ts).
const NOT_OPEN = 'This request is no longer open.'
const CHANGED = 'Ownership changed. Reload and try again.'
const CHECKLIST = "Security checklist for the new Tenant Superadmin: review every user's actions; choose a new successor and recovery approvers; reassign alerts and advisories assigned to the former owner."
const today = () => new Date().toISOString().slice(0, 10)

async function pendingTransfer(db: ReturnType<typeof getDb>, tenantId: string) {
  const [t] = await db.select().from(ownershipTransfers)
    .where(and(eq(ownershipTransfers.tenantId, tenantId), eq(ownershipTransfers.status, 'pending'))).limit(1)
  return t
}

// ── GET /:tenantId/ownership — Who owns the tenant, and what concerns the caller ──
router.get(
  '/:tenantId/ownership',
  authMiddleware,
  async (c) => {
    try {
      const { tenantId } = c.req.param()
      const me = c.get('user')
      if (!me.tenantId || me.tenantId !== tenantId) return c.json({ detail: 'You can only access your own tenant.' }, 403)
      const db = getDb(c.env.DATABASE_URL)
      await settleOwnership(db, tenantId)
      const [owner] = await db.select({ userId: users.userId, username: users.username }).from(users)
        .where(and(eq(users.tenantId, tenantId), eq(users.role, 'tenant_superadmin'))).limit(1)
      if (!owner) return c.json({ detail: 'This tenant has no owner.' }, 404)
      const transfer = (await pendingTransfer(db, tenantId)) ?? null
      const [plan] = await db.select().from(tenantRecoveryPlans).where(eq(tenantRecoveryPlans.tenantId, tenantId)).limit(1)
      const ids = [owner.userId, transfer?.fromUserId, transfer?.toUserId, plan?.successorId, plan?.approver1Id, plan?.approver2Id]
        .filter((x): x is string => !!x)
      const rows = await db.select({ userId: users.userId, username: users.username }).from(users).where(inArray(users.userId, ids))
      const names = Object.fromEntries(rows.map((r) => [r.userId, r.username]))
      return c.json(ownershipView({ owner, transfer, plan: plan ?? null, names }, me.userId))
    } catch (err) {
      console.error('ownership get error:', err)
      return c.json({ detail: 'Failed to load ownership' }, 500)
    }
  }
)

// ── POST /:tenantId/ownership/transfer — Owner starts a planned transfer (step-up) ──
const afterSchema = z.object({
  mode: z.string(), actions: z.array(z.string()).optional(), deactivate_on: z.string().datetime().optional(),
})
router.post(
  '/:tenantId/ownership/transfer',
  authMiddleware,
  requireTenantSuperadmin,
  zValidator('json', z.object({
    to_user_id: z.string().uuid(), after: afterSchema, password: z.string().optional(), code: z.string(),
  })),
  async (c) => {
    try {
      const { tenantId } = c.req.param()
      const body = c.req.valid('json')
      const caller = c.get('user')
      const db = getDb(c.env.DATABASE_URL)
      await settleOwnership(db, tenantId)

      const [to] = await db.select().from(users)
        .where(and(eq(users.userId, body.to_user_id), eq(users.tenantId, tenantId))).limit(1)
      if (!to) return c.json({ detail: 'User not found in this tenant' }, 404)
      const now = new Date()
      const after = { mode: body.after.mode, actions: body.after.actions, deactivateOn: body.after.deactivate_on ? new Date(body.after.deactivate_on) : null }
      const bad = validateTransfer({ ownerId: caller.userId, toUser: to, tenantId, after, now })
      if (bad) return c.json({ detail: bad }, 400)
      if (await pendingTransfer(db, tenantId)) return c.json({ detail: 'A transfer is already pending. Cancel it first.' }, 409)

      const [me] = await db.select().from(users).where(eq(users.userId, caller.userId)).limit(1)
      if (!me) return c.json({ detail: 'User not found' }, 404)
      const refused = await stepUp(c, db, me, { password: body.password, code: body.code })
      if (refused) return refused

      const expiresAt = new Date(now.getTime() + HOURS_72)
      let transferId: string
      try {
        const [row] = await db.insert(ownershipTransfers).values({
          tenantId, fromUserId: caller.userId, toUserId: to.userId, afterMode: after.mode,
          afterActions: after.mode === 'deactivate_now' ? [] : (after.actions ?? []),
          deactivateOn: after.mode === 'deactivate_on' ? after.deactivateOn : null, expiresAt,
        }).returning({ transferId: ownershipTransfers.transferId })
        transferId = row!.transferId
      } catch (err) {
        if (!isUniqueViolation(err)) throw err
        return c.json({ detail: 'A transfer is already pending. Cancel it first.' }, 409)   // unique index: one pending per tenant
      }
      const [tenant] = await db.select({ name: tenants.name }).from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
      const message = transferMessage(me.username, tenant?.name ?? 'this tenant', after.mode, after.deactivateOn ?? null)
      await postNotice(db, tenantId, to.userId, 'transfer_request', message, expiresAt)
      await audit(db, c, {
        userId: caller.userId, tenantId, actionType: 'ownership.transfer_requested', targetEntity: to.userId,
        newState: { transfer_id: transferId, after_mode: after.mode, expires_at: expiresAt.toISOString() },
      })
      await sendMail(c.env, { to: to.email, subject: 'Ownership transfer request', text: `${message} You have 72 hours to accept or decline.` })
      return c.json({ transfer_id: transferId, expires_at: expiresAt.toISOString() }, 201)
    } catch (err) {
      console.error('ownership transfer error:', err)
      return c.json({ detail: 'Failed to start the transfer' }, 500)
    }
  }
)

// ── DELETE /:tenantId/ownership/transfer — Owner cancels before acceptance ──
router.delete(
  '/:tenantId/ownership/transfer',
  authMiddleware,
  requireTenantSuperadmin,
  async (c) => {
    try {
      const { tenantId } = c.req.param()
      const caller = c.get('user')
      const db = getDb(c.env.DATABASE_URL)
      const [row] = await db.update(ownershipTransfers).set({ status: 'cancelled', decidedAt: sql`now()` })
        .where(and(
          eq(ownershipTransfers.tenantId, tenantId), eq(ownershipTransfers.status, 'pending'),
          eq(ownershipTransfers.fromUserId, caller.userId), sql`${ownershipTransfers.expiresAt} > now()`,
        )).returning({ transferId: ownershipTransfers.transferId, toUserId: ownershipTransfers.toUserId, createdAt: ownershipTransfers.createdAt })
      if (!row) return c.json({ detail: NOT_OPEN }, 409)
      await closeRequestNotice(db, tenantId, row.toUserId, row.createdAt)
      await audit(db, c, {
        userId: caller.userId, tenantId, actionType: 'ownership.transfer_cancelled', targetEntity: row.toUserId,
        newState: { transfer_id: row.transferId },
      })
      return c.json({ ok: true })
    } catch (err) {
      console.error('ownership cancel error:', err)
      return c.json({ detail: 'Failed to cancel the transfer' }, 500)
    }
  }
)

// ── POST /:tenantId/ownership/transfer/accept — Recipient accepts (step-up); ownership swaps ──
router.post(
  '/:tenantId/ownership/transfer/accept',
  authMiddleware,
  zValidator('json', z.object({ password: z.string().optional(), code: z.string() })),
  async (c) => {
    try {
      const { tenantId } = c.req.param()
      const { password, code } = c.req.valid('json')
      const caller = c.get('user')
      if (!caller.tenantId || caller.tenantId !== tenantId) return c.json({ detail: 'You can only access your own tenant.' }, 403)
      const db = getDb(c.env.DATABASE_URL)
      await settleOwnership(db, tenantId)
      const t = await pendingTransfer(db, tenantId)
      if (!t || t.toUserId !== caller.userId) return c.json({ detail: NOT_OPEN }, 409)

      const [me] = await db.select().from(users).where(eq(users.userId, caller.userId)).limit(1)
      if (!me) return c.json({ detail: 'User not found' }, 404)
      const refused = await stepUp(c, db, me, { password, code })
      if (refused) return refused

      const after = { mode: t.afterMode, actions: t.afterActions, deactivateOn: t.deactivateOn }
      const { done } = await acceptTransfer(db, t, after)
      if (!done) {
        const again = await pendingTransfer(db, tenantId)
        return c.json({ detail: again && again.transferId === t.transferId ? CHANGED : NOT_OPEN }, 409)
      }
      const [former] = await db.select().from(users).where(eq(users.userId, t.fromUserId)).limit(1)
      const note = ownershipChangedNotice(former?.username ?? '', me.username, today())
      await postNotice(db, tenantId, null, 'ownership_changed', note)
      await postNotice(db, tenantId, me.userId, 'owner_checklist', CHECKLIST)
      await audit(db, c, {
        userId: caller.userId, tenantId, actionType: 'ownership.transferred', targetEntity: t.fromUserId,
        previousState: { owner: t.fromUserId }, newState: { owner: me.userId, transfer_id: t.transferId, after_mode: t.afterMode },
      })
      for (const to of [former?.email, me.email]) {
        if (to) await sendMail(c.env, { to, subject: 'Tenant ownership changed', text: note })
      }
      return c.json({ ok: true })
    } catch (err) {
      console.error('ownership accept error:', err)
      return c.json({ detail: 'Failed to accept the transfer' }, 500)
    }
  }
)

// ── POST /:tenantId/ownership/transfer/decline — Recipient declines ──
router.post(
  '/:tenantId/ownership/transfer/decline',
  authMiddleware,
  async (c) => {
    try {
      const { tenantId } = c.req.param()
      const caller = c.get('user')
      if (!caller.tenantId || caller.tenantId !== tenantId) return c.json({ detail: 'You can only access your own tenant.' }, 403)
      const db = getDb(c.env.DATABASE_URL)
      const [row] = await db.update(ownershipTransfers).set({ status: 'declined', decidedAt: sql`now()` })
        .where(and(
          eq(ownershipTransfers.tenantId, tenantId), eq(ownershipTransfers.status, 'pending'),
          eq(ownershipTransfers.toUserId, caller.userId), sql`${ownershipTransfers.expiresAt} > now()`,
        )).returning({ transferId: ownershipTransfers.transferId, fromUserId: ownershipTransfers.fromUserId, createdAt: ownershipTransfers.createdAt })
      if (!row) return c.json({ detail: NOT_OPEN }, 409)
      await closeRequestNotice(db, tenantId, caller.userId, row.createdAt)
      await audit(db, c, {
        userId: caller.userId, tenantId, actionType: 'ownership.transfer_declined', targetEntity: row.fromUserId,
        newState: { transfer_id: row.transferId },
      })
      return c.json({ ok: true })
    } catch (err) {
      console.error('ownership decline error:', err)
      return c.json({ detail: 'Failed to decline the transfer' }, 500)
    }
  }
)

export default router
