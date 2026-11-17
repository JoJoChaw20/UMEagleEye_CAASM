// Tenant ownership handover, Path A: a planned transfer from the owner to an active user of the tenant.
import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { and, eq, inArray, isNull, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requirePlatformSuperadmin, requireTenantSuperadmin } from '../middleware/auth'
import { getDb } from '../db/client'
import { ownershipRecoveries, ownershipTransfers, tenantRecoveryPlans, tenants, users } from '../db/schema'
import {
  HOURS_72, RECOVERY_DISPUTED_NOTICE, RECOVERY_REASONS, RECOVERY_REASON_LABELS,
  approverSlot, ownerChecklist, ownershipChangedNotice, ownershipNoticeExpiry, recoveryNext, validateRecoveryPlan, validateTransfer,
} from '../lib/ownership'
import { ownershipView, transferMessage } from '../lib/ownershipView'
import { isNotNullViolation, isOwnerIndexViolation, isUniqueViolation } from '../lib/fkViolation'
import { isDeactivated } from '../lib/sessionGate'
import { audit } from '../services/audit'
import { stepUp } from '../services/mfaStepUp'
import { sendMail } from '../services/mailer'
import {
  acceptTransfer, closeRequestNotice, closeStaleRecovery, completeRecovery, openRecovery, postNotice, restoreOwnership, settleOwnership,
} from '../services/ownership'
import { planOwnerInvite } from '../services/ownerInvite'

const router = new Hono<{ Bindings: Env }>()

// Routes for the recipient (a Tenant user) cannot use requireTenantSuperadmin: they check in the handler
// that the caller belongs to :tenantId and is the transfer's recipient (and are on the allowlist in
// lib/routeGuard.test.ts).
const NOT_OPEN = 'This request is no longer open.'
const CHANGED = 'Ownership changed. Reload and try again.'
const CHECKLIST = ownerChecklist(false)
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
      await settleOwnership(db, tenantId, c.env)
      const [owner] = await db.select({ userId: users.userId, username: users.username }).from(users)
        .where(and(eq(users.tenantId, tenantId), eq(users.role, 'tenant_superadmin'))).limit(1)
      if (!owner) return c.json({ detail: 'This tenant has no owner.' }, 404)
      const transfer = (await pendingTransfer(db, tenantId)) ?? null
      const [plan] = await db.select().from(tenantRecoveryPlans).where(eq(tenantRecoveryPlans.tenantId, tenantId)).limit(1)
      const recovery = (await openRecovery(db, tenantId)) ?? null
      const ids = [owner.userId, transfer?.fromUserId, transfer?.toUserId, plan?.successorId, plan?.approver1Id, plan?.approver2Id, recovery?.successorId]
        .filter((x): x is string => !!x)
      const rows = await db.select({ userId: users.userId, username: users.username }).from(users).where(inArray(users.userId, ids))
      const names = Object.fromEntries(rows.map((r) => [r.userId, r.username]))
      return c.json(ownershipView({ owner, transfer, plan: plan ?? null, recovery, names }, me.userId))
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
      await settleOwnership(db, tenantId, c.env)

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
      await settleOwnership(db, tenantId, c.env)
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
      await postNotice(db, tenantId, null, 'ownership_changed', note, ownershipNoticeExpiry())
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

// ═══ Path B: emergency recovery ═══
// Successor and approvers are Tenant users, so these routes check in the handler that the caller belongs to
// :tenantId and holds the role (allowlisted in lib/routeGuard.test.ts), except the plan, which is the owner's.
const NOT_APPROVER = 'You are not a recovery approver for this request.'
const own = (c: any, tenantId: string) => {
  const u = c.get('user')
  return u.tenantId && u.tenantId === tenantId ? u : null
}
const WRONG_TENANT = 'You can only access your own tenant.'
const stepSchema = { password: z.string().optional(), code: z.string() }

async function loadMe(db: ReturnType<typeof getDb>, userId: string) {
  const [me] = await db.select().from(users).where(eq(users.userId, userId)).limit(1)
  return me
}

// ── PUT /:tenantId/ownership/recovery-plan — Owner names the successor and two approvers (step-up) ──
router.put(
  '/:tenantId/ownership/recovery-plan',
  authMiddleware,
  requireTenantSuperadmin,
  zValidator('json', z.object({
    successor_id: z.string().uuid(), approver_ids: z.array(z.string().uuid()).length(2), ...stepSchema,
  })),
  async (c) => {
    try {
      const { tenantId } = c.req.param()
      const body = c.req.valid('json')
      const caller = c.get('user')
      const db = getDb(c.env.DATABASE_URL)
      await settleOwnership(db, tenantId, c.env)
      const ids = [body.successor_id, ...body.approver_ids]
      const found = await db.select().from(users).where(and(eq(users.tenantId, tenantId), inArray(users.userId, ids)))
      const byId = new Map(found.map((u) => [u.userId, u]))
      const [successor, a1, a2] = ids.map((id) => byId.get(id))
      if (!successor || !a1 || !a2) {
        if (new Set(ids).size !== 3) return c.json({ detail: 'The successor and the two approvers must be three different users' }, 400)
        return c.json({ detail: 'User not found in this tenant' }, 404)
      }
      const bad = validateRecoveryPlan({ ownerId: caller.userId, successor, approvers: [a1, a2], tenantId })
      if (bad) return c.json({ detail: bad }, 400)
      if (await openRecovery(db, tenantId)) return c.json({ detail: 'A recovery is open. The plan cannot change now.' }, 409)

      const me = await loadMe(db, caller.userId)
      if (!me) return c.json({ detail: 'User not found' }, 404)
      const refused = await stepUp(c, db, me, { password: body.password, code: body.code })
      if (refused) return refused

      const [prev] = await db.select().from(tenantRecoveryPlans).where(eq(tenantRecoveryPlans.tenantId, tenantId)).limit(1)
      const set = { successorId: successor.userId, approver1Id: a1.userId, approver2Id: a2.userId, updatedAt: sql`now()` }
      await db.insert(tenantRecoveryPlans).values({ tenantId, ...set })
        .onConflictDoUpdate({ target: tenantRecoveryPlans.tenantId, set })
      await audit(db, c, {
        userId: caller.userId, tenantId, actionType: 'ownership.recovery_plan_set', targetEntity: tenantId,
        previousState: prev ? { successor: prev.successorId, approvers: [prev.approver1Id, prev.approver2Id] } : null,
        newState: { successor: successor.userId, approvers: [a1.userId, a2.userId] },
      })
      return c.json({ ok: true })
    } catch (err) {
      console.error('recovery plan error:', err)
      return c.json({ detail: 'Failed to save the recovery plan' }, 500)
    }
  }
)

// ── POST /:tenantId/ownership/recovery — The successor starts an emergency recovery (step-up) ──
router.post(
  '/:tenantId/ownership/recovery',
  authMiddleware,
  zValidator('json', z.object({ reason: z.enum(RECOVERY_REASONS), ...stepSchema })),
  async (c) => {
    try {
      const { tenantId } = c.req.param()
      const body = c.req.valid('json')
      const caller = own(c, tenantId)
      if (!caller) return c.json({ detail: WRONG_TENANT }, 403)
      const db = getDb(c.env.DATABASE_URL)
      await settleOwnership(db, tenantId, c.env)

      const [plan] = await db.select().from(tenantRecoveryPlans).where(eq(tenantRecoveryPlans.tenantId, tenantId)).limit(1)
      if (!plan || plan.successorId !== caller.userId) return c.json({ detail: 'Only the successor in the recovery plan can start a recovery.' }, 403)
      const { successorId, approver1Id, approver2Id } = plan
      if (!successorId || !approver1Id || !approver2Id) return c.json({ detail: 'The recovery plan is not complete.' }, 409)
      const people = await db.select().from(users).where(and(eq(users.tenantId, tenantId),
        inArray(users.userId, [successorId, approver1Id, approver2Id])))
      const [owner] = await db.select().from(users)
        .where(and(eq(users.tenantId, tenantId), eq(users.role, 'tenant_superadmin'))).limit(1)
      const byId = new Map(people.map((u) => [u.userId, u]))
      const [successor, a1, a2] = [successorId, approver1Id, approver2Id].map((id) => byId.get(id))
      if (!owner || !successor || !a1 || !a2) return c.json({ detail: 'The recovery plan is not complete.' }, 409)
      const bad = validateRecoveryPlan({ ownerId: owner.userId, successor, approvers: [a1, a2], tenantId })
      if (bad) return c.json({ detail: bad }, 409)
      if (await openRecovery(db, tenantId)) return c.json({ detail: 'A recovery is already open.' }, 409)

      const refused = await stepUp(c, db, successor, { password: body.password, code: body.code })
      if (refused) return refused

      const expiresAt = new Date(Date.now() + HOURS_72)
      let recoveryId: string
      try {
        const [row] = await db.insert(ownershipRecoveries).values({
          tenantId, successorId: successor.userId, formerOwnerId: owner.userId, reason: body.reason, expiresAt,
        }).returning({ recoveryId: ownershipRecoveries.recoveryId })
        recoveryId = row!.recoveryId
      } catch (err) {
        if (!isUniqueViolation(err)) throw err
        return c.json({ detail: 'A recovery is already open.' }, 409)   // unique index: one open recovery per tenant
      }
      const [tenant] = await db.select({ name: tenants.name }).from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
      const label = RECOVERY_REASON_LABELS[body.reason]
      const message = `${successor.username} asked to take over ${tenant?.name ?? 'this tenant'} as Tenant Superadmin after ${owner.username} (reason: ${label}). Approve within 72 hours if this is right.`
      const heads = `An emergency recovery of ${tenant?.name ?? 'this tenant'} was started by ${successor.username} (reason: ${label}). It needs two approvals.`
      await postNotice(db, tenantId, owner.userId, 'recovery_started', heads, expiresAt)
      await sendMail(c.env, { to: owner.email, subject: 'An emergency recovery of your tenant was started', text: heads })
      for (const a of [a1, a2]) {
        await postNotice(db, tenantId, a.userId, 'recovery_request', message, expiresAt)
        await sendMail(c.env, { to: a.email, subject: 'Emergency ownership recovery needs your approval', text: message })
      }
      await audit(db, c, {
        userId: caller.userId, tenantId, actionType: 'ownership.recovery_requested', targetEntity: owner.userId,
        newState: { recovery_id: recoveryId, reason: body.reason, expires_at: expiresAt.toISOString() },
      })
      return c.json({ recovery_id: recoveryId, expires_at: expiresAt.toISOString() }, 201)
    } catch (err) {
      console.error('recovery start error:', err)
      return c.json({ detail: 'Failed to start the recovery' }, 500)
    }
  }
)

// ── POST /:tenantId/ownership/recovery/approve — A recovery approver confirms (step-up) ──
router.post(
  '/:tenantId/ownership/recovery/approve',
  authMiddleware,
  zValidator('json', z.object(stepSchema)),
  async (c) => {
    try {
      const { tenantId } = c.req.param()
      const body = c.req.valid('json')
      const caller = own(c, tenantId)
      if (!caller) return c.json({ detail: WRONG_TENANT }, 403)
      const db = getDb(c.env.DATABASE_URL)
      await settleOwnership(db, tenantId, c.env)
      const r = await openRecovery(db, tenantId)
      if (!r) return c.json({ detail: NOT_OPEN }, 409)
      const [plan] = await db.select().from(tenantRecoveryPlans).where(eq(tenantRecoveryPlans.tenantId, tenantId)).limit(1)
      const slot = plan ? approverSlot(plan, caller.userId, r.successorId) : null
      if (!slot) return c.json({ detail: NOT_APPROVER }, 403)
      const action = slot === 'approver1' ? 'approve1' : 'approve2'
      if ((slot === 'approver1' ? r.approver1At : r.approver2At)) return c.json({ detail: 'You have already approved this request.' }, 409)
      const now = new Date()
      const next = recoveryNext(r, action, now)
      if (!next) return c.json({ detail: NOT_OPEN }, 409)

      const me = await loadMe(db, caller.userId)
      if (!me) return c.json({ detail: 'User not found' }, 404)
      const refused = await stepUp(c, db, me, { password: body.password, code: body.code })
      if (refused) return refused

      // Guarded on the other slot being as read, so two approvals landing together cannot both see "one missing".
      const mine = slot === 'approver1' ? ownershipRecoveries.approver1At : ownershipRecoveries.approver2At
      const other = slot === 'approver1' ? ownershipRecoveries.approver2At : ownershipRecoveries.approver1At
      const otherAt = slot === 'approver1' ? r.approver2At : r.approver1At
      const recorded = await db.update(ownershipRecoveries).set({
        approver1At: next.approver1At, approver2At: next.approver2At, status: next.status === 'complete_now' ? 'awaiting_approval' : next.status,
        holdUntil: next.holdUntil,
      }).where(and(
        eq(ownershipRecoveries.recoveryId, r.recoveryId), eq(ownershipRecoveries.status, 'awaiting_approval'), isNull(mine),
        otherAt ? eq(other, otherAt) : isNull(other), sql`${ownershipRecoveries.expiresAt} > now()`,
      )).returning({ recoveryId: ownershipRecoveries.recoveryId })
      if (recorded.length !== 1) return c.json({ detail: CHANGED }, 409)
      await audit(db, c, {
        userId: caller.userId, tenantId, actionType: 'ownership.recovery_approved', targetEntity: r.recoveryId,
        newState: { slot, status: next.status },
      })

      if (next.status === 'complete_now') {
        const { done } = await completeRecovery(db, { ...r, approver1At: next.approver1At, approver2At: next.approver2At }, c.env, c)
        if (!done) {
          await closeStaleRecovery(db, r)
          return c.json({ detail: CHANGED }, 409)
        }
        return c.json({ ok: true, status: 'completed' })
      }
      if (next.status === 'on_hold' && next.holdUntil) {
        const [former] = await db.select().from(users).where(eq(users.userId, r.formerOwnerId)).limit(1)
        const [succ] = await db.select({ username: users.username }).from(users).where(eq(users.userId, r.successorId)).limit(1)
        const message = `Both recovery approvers confirmed an emergency recovery: ${succ?.username ?? 'the successor'} will become Tenant Superadmin on ${next.holdUntil.toISOString().slice(0, 10)} unless you cancel. Sign in and cancel with your password and MFA code if this is wrong.`
        await postNotice(db, tenantId, r.formerOwnerId, 'recovery_hold', message, next.holdUntil)
        if (former) await sendMail(c.env, { to: former.email, subject: 'Your tenant ownership will move in 72 hours', text: message })
      }
      return c.json({ ok: true, status: next.status })
    } catch (err) {
      console.error('recovery approve error:', err)
      return c.json({ detail: 'Failed to approve the recovery' }, 500)
    }
  }
)

// ── POST /:tenantId/ownership/recovery/cancel — The current owner stops a recovery (step-up) ──
router.post(
  '/:tenantId/ownership/recovery/cancel',
  authMiddleware,
  zValidator('json', z.object(stepSchema)),
  async (c) => {
    try {
      const { tenantId } = c.req.param()
      const body = c.req.valid('json')
      const caller = own(c, tenantId)
      if (!caller) return c.json({ detail: WRONG_TENANT }, 403)
      const db = getDb(c.env.DATABASE_URL)
      await settleOwnership(db, tenantId, c.env)
      const r = await openRecovery(db, tenantId)
      if (!r || r.formerOwnerId !== caller.userId) return c.json({ detail: NOT_OPEN }, 409)
      const next = recoveryNext(r, 'cancel_by_owner', new Date())
      if (!next) return c.json({ detail: NOT_OPEN }, 409)

      const me = await loadMe(db, caller.userId)
      if (!me) return c.json({ detail: 'User not found' }, 404)
      const refused = await stepUp(c, db, me, { password: body.password, code: body.code })
      if (refused) return refused

      const [moved] = await db.update(ownershipRecoveries).set({ status: next.status })
        .where(and(eq(ownershipRecoveries.recoveryId, r.recoveryId), eq(ownershipRecoveries.status, r.status)))
        .returning({ recoveryId: ownershipRecoveries.recoveryId })
      if (!moved) return c.json({ detail: NOT_OPEN }, 409)
      const text = RECOVERY_DISPUTED_NOTICE
      const [plan] = await db.select().from(tenantRecoveryPlans).where(eq(tenantRecoveryPlans.tenantId, tenantId)).limit(1)
      const targets = [r.successorId, plan?.approver1Id, plan?.approver2Id].filter((x): x is string => !!x)
      const rows = await db.select({ userId: users.userId, email: users.email }).from(users).where(inArray(users.userId, targets))
      for (const t of rows) {
        await postNotice(db, tenantId, t.userId, 'recovery_disputed', text)
        await sendMail(c.env, { to: t.email, subject: 'Emergency ownership recovery stopped', text })
      }
      await audit(db, c, {
        userId: caller.userId, tenantId, actionType: 'ownership.recovery_disputed',
        targetEntity: r.recoveryId, newState: { status: next.status },
      })
      return c.json({ ok: true, status: next.status })
    } catch (err) {
      console.error('recovery cancel error:', err)
      return c.json({ detail: 'Failed to cancel the recovery' }, 500)
    }
  }
)

// -- POST /:tenantId/ownership/restore: Path C, the Platform Superadmin restores ownership (step-up) --
// Demotes and suspends the current owner, if any, then invites the named person as Tenant Superadmin through the
// shared owner-invite code (services/ownerInvite.ts), all in one batch (services/ownership.ts restoreOwnership).
// The step-up is the Platform Superadmin's own password and MFA code. The Platform Superadmin gains no tenant access.
router.post(
  '/:tenantId/ownership/restore',
  authMiddleware,
  requirePlatformSuperadmin,
  zValidator('json', z.object({
    email: z.string().email(), username: z.string().min(3).max(100).optional(),
    password: z.string().optional(), code: z.string(),
  })),
  async (c) => {
    try {
      const { tenantId } = c.req.param()
      const body = c.req.valid('json')
      const caller = c.get('user')
      const db = getDb(c.env.DATABASE_URL)

      const plan = await planOwnerInvite(db, caller, tenantId, body.email, body.username, true)
      if (!plan.ok) return c.json({ detail: plan.error.detail }, plan.error.status)
      if (plan.existing && isDeactivated(plan.existing)) {
        return c.json({ detail: 'That account is deactivated. Choose an active account or a new email.' }, 409)
      }
      const [former] = await db.select({ userId: users.userId, username: users.username, email: users.email }).from(users)
        .where(and(eq(users.tenantId, tenantId), eq(users.role, 'tenant_superadmin'))).limit(1)

      const [me] = await db.select().from(users).where(eq(users.userId, caller.userId)).limit(1)
      if (!me) return c.json({ detail: 'User not found' }, 404)
      const refused = await stepUp(c, db, me, { password: body.password, code: body.code })
      if (refused) return refused

      let result
      try {
        result = await restoreOwnership(db, c, {
          tenantId, platformUserId: caller.userId, email: body.email, plan, formerOwner: former ?? null,
        }, c.env)
      } catch (err) {
        // The batch rolled back. An owner appeared / the demote no longer matched: reload. A username or email clash: say so.
        if (isUniqueViolation(err) && !isOwnerIndexViolation(err)) {
          return c.json({ detail: 'That username or email is already used by another account.' }, 409)
        }
        if (!isOwnerIndexViolation(err) && !isNotNullViolation(err)) throw err
        return c.json({ detail: CHANGED }, 409)
      }
      if (!result.done || !result.newOwner) return c.json({ detail: CHANGED }, 409)
      return c.json({
        ok: true, user_id: result.newOwner.userId, username: result.newOwner.username, email: result.newOwner.email,
        action: plan.existing ? 'assigned' : 'created',
      }, 201)
    } catch (err) {
      console.error('ownership restore error:', err)
      return c.json({ detail: 'Failed to restore ownership' }, 500)
    }
  }
)

export default router
