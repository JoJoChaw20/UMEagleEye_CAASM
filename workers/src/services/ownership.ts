// Tenant ownership handover, DB side (rules are in lib/ownership.ts, response shape in lib/ownershipView.ts).
import { and, eq, gt, gte, inArray, isNotNull, isNull, lte, or, sql, type SQL } from 'drizzle-orm'
import type { Context } from 'hono'
import type { DB } from '../db/client'
import type { Env } from '../types'
import {
  enrolmentTokens, ownershipRecoveries, ownershipTransfers, tenantNotices, tenantRecoveryPlans, users,
} from '../db/schema'
import {
  completionEffects, ownerChecklist, ownershipChangedNotice, recoveryNext, swapStatements, type AfterChoice,
} from '../lib/ownership'
import { audit } from './audit'
import { sendMail } from './mailer'

/**
 * Settles what time alone decides: pending transfers past expires_at become 'expired'; an open recovery
 * past its approval window expires, and one whose 72-hour hold ended (or whose approvals are in but
 * completion did not finish) is completed. `env`, when given, lets a completion send its emails.
 */
export async function settleOwnership(db: DB, tenantId: string, env?: Env): Promise<void> {
  await settleRecovery(db, tenantId, env)
  const expired = await db.update(ownershipTransfers).set({ status: 'expired', decidedAt: sql`now()` })
    .where(and(
      eq(ownershipTransfers.tenantId, tenantId), eq(ownershipTransfers.status, 'pending'),
      lte(ownershipTransfers.expiresAt, sql`now()`),
    )).returning({ toUserId: ownershipTransfers.toUserId, createdAt: ownershipTransfers.createdAt })
  for (const t of expired) await closeRequestNotice(db, tenantId, t.toUserId, t.createdAt)
}

/** Ends the recipient's open 'transfer_request' notice (created at or after the transfer) once the transfer is no longer pending. */
export async function closeRequestNotice(db: DB, tenantId: string, toUserId: string, transferCreatedAt: Date) {
  try {
    await db.update(tenantNotices).set({ expiresAt: sql`now()` })
      .where(requestNoticeWhere(tenantId, toUserId, transferCreatedAt))
  } catch (err) {
    console.error('closing transfer_request notice failed:', err)
  }
}

function requestNoticeWhere(tenantId: string, toUserId: string, transferCreatedAt: Date) {
  return and(
    eq(tenantNotices.tenantId, tenantId), eq(tenantNotices.userId, toUserId), eq(tenantNotices.kind, 'transfer_request'),
    gte(tenantNotices.createdAt, transferCreatedAt), or(isNull(tenantNotices.expiresAt), gt(tenantNotices.expiresAt, sql`now()`)),
  )
}

/** `userId` null = every user of the tenant. A failed write is logged, never thrown. */
export async function postNotice(
  db: DB, tenantId: string, userId: string | null, kind: string, body: string, expiresAt: Date | null = null,
) {
  try {
    await db.insert(tenantNotices).values({ tenantId, userId, kind, body, expiresAt })
  } catch (err) {
    console.error(`notice ${kind} failed:`, err)
  }
}

/**
 * Accept + swap as ONE batch (one transaction). Order:
 *  1. lock both users (FOR UPDATE);
 *  2. flip the transfer to 'accepted', only if it is still pending, unexpired, for this recipient, AND the
 *     sender is still the owner and the recipient still an active tenant_user (so the flip never
 *     commits without the swap);
 *  3. demote, guarded by "this transaction made the flip" (decided_at = now());
 *  4. promote (no-ops unless the tenant has no owner, i.e. unless the demote happened);
 *  5. clear both users from the recovery plan, same guard.
 * done = the flip, demote and promote each returned 1 row; otherwise nothing changed.
 */
export async function acceptTransfer(
  db: DB, t: { transferId: string; tenantId: string; fromUserId: string; toUserId: string; createdAt: Date }, after: AfterChoice,
): Promise<{ done: boolean }> {
  const { transferId, tenantId, fromUserId, toUserId } = t
  const flipped = sql`exists (select 1 from ownership_transfers where transfer_id = ${transferId}
    and status = 'accepted' and decided_at = now())`
  const [lock, demote, promote] = swapStatements(tenantId, fromUserId, toUserId, after, flipped)
  const stateOk = sql`exists (select 1 from users where user_id = ${fromUserId} and tenant_id = ${tenantId}
      and role = 'tenant_superadmin')
    and exists (select 1 from users where user_id = ${toUserId} and tenant_id = ${tenantId}
      and role = 'tenant_user' and is_active = true)`
  const flip = db.update(ownershipTransfers).set({ status: 'accepted', decidedAt: sql`now()` })
    .where(and(
      eq(ownershipTransfers.transferId, transferId), eq(ownershipTransfers.status, 'pending'),
      eq(ownershipTransfers.toUserId, toUserId), sql`${ownershipTransfers.expiresAt} > now()`, stateOk,
    )).returning({ transferId: ownershipTransfers.transferId })
  const clearPlan = clearPlanStatement(db, tenantId, fromUserId, toUserId, flipped)
  const closeNotice = db.update(tenantNotices).set({ expiresAt: sql`now()` })
    .where(and(requestNoticeWhere(tenantId, toUserId, t.createdAt), flipped))
  const res = await db.batch([
    lock.build(db), flip, demote.build(db), promote.build(db), clearPlan, closeNotice,
  ] as any) as unknown as unknown[][]
  const [, f, d, p] = res
  return { done: f!.length === 1 && d!.length === 1 && p!.length === 1 }
}

/** Removes both users from the tenant's recovery-plan positions, only where `guard` holds. */
function clearPlanStatement(db: DB, tenantId: string, a: string, b: string, guard: SQL) {
  const nullIfMember = (col: string) => sql`case when ${sql.raw(col)} in (${a}::uuid, ${b}::uuid) then null else ${sql.raw(col)} end`
  return db.update(tenantRecoveryPlans).set({
    successorId: nullIfMember('successor_id'), approver1Id: nullIfMember('approver1_id'),
    approver2Id: nullIfMember('approver2_id'), updatedAt: sql`now()`,
  }).where(and(eq(tenantRecoveryPlans.tenantId, tenantId), guard))
}

export type OpenRecovery = typeof ownershipRecoveries.$inferSelect

/** The tenant's open recovery (awaiting approval or on hold), if any. */
export async function openRecovery(db: DB, tenantId: string): Promise<OpenRecovery | undefined> {
  const [r] = await db.select().from(ownershipRecoveries).where(and(
    eq(ownershipRecoveries.tenantId, tenantId), inArray(ownershipRecoveries.status, ['awaiting_approval', 'on_hold']),
  )).limit(1)
  return r
}

/** Former owner still owner and successor still an active tenant_user: what a completion needs. */
function recoveryStateOk(r: OpenRecovery) {
  return sql`exists (select 1 from users where user_id = ${r.formerOwnerId} and tenant_id = ${r.tenantId}
      and role = 'tenant_superadmin')
    and exists (select 1 from users where user_id = ${r.successorId} and tenant_id = ${r.tenantId}
      and role = 'tenant_user' and is_active = true)`
}

/**
 * Emergency completion as ONE batch (one transaction), so a concurrent change leaves nothing half-done:
 *  1. lock both users (FOR UPDATE);
 *  2. flip the recovery to 'completed' (completed_at = now()) only if it is still open, both approvals are in,
 *     the approval window / hold allows it, the former owner is still the owner and the successor still an
 *     active Tenant user;
 *  3. every other statement is guarded by "this transaction made the flip" (completed_at = now(); now() is the
 *     transaction start): demote with deactivate_now (former owner suspended), promote, sessions_valid_after = now()
 *     for the former owner, delete unused enrolment tokens (uses = 0), clear both users from the plan, cancel a
 *     transfer still pending in the tenant (it would block the new owner, who cannot cancel it).
 * done = flip, demote and promote each returned 1 row; otherwise nothing changed. On success the notices, audit
 * and emails follow outside the batch.
 */
export async function completeRecovery(db: DB, r: OpenRecovery, env?: Env, c: Context | null = null): Promise<{ done: boolean }> {
  const { recoveryId, tenantId, formerOwnerId, successorId } = r
  const flipped = sql`exists (select 1 from ownership_recoveries where recovery_id = ${recoveryId}
    and status = 'completed' and completed_at = now())`
  const [lock, demote, promote] = swapStatements(tenantId, formerOwnerId, successorId, { mode: 'deactivate_now' }, flipped)
  const flip = db.update(ownershipRecoveries).set({ status: 'completed', completedAt: sql`now()` })
    .where(and(
      eq(ownershipRecoveries.recoveryId, recoveryId),
      sql`((${ownershipRecoveries.status} = 'awaiting_approval' and ${ownershipRecoveries.expiresAt} > now())
        or (${ownershipRecoveries.status} = 'on_hold' and ${ownershipRecoveries.holdUntil} <= now()))`,
      isNotNull(ownershipRecoveries.approver1At), isNotNull(ownershipRecoveries.approver2At), recoveryStateOk(r),
    )).returning({ recoveryId: ownershipRecoveries.recoveryId })
  const signOut = db.update(users).set({ sessionsValidAfter: sql`now()` })
    .where(and(eq(users.userId, formerOwnerId), flipped))
  const revokeTokens = db.delete(enrolmentTokens)
    .where(and(eq(enrolmentTokens.tenantId, tenantId), eq(enrolmentTokens.uses, 0), flipped))
  const clearPlan = clearPlanStatement(db, tenantId, formerOwnerId, successorId, flipped)
  const dropTransfer = db.update(ownershipTransfers).set({ status: 'cancelled', decidedAt: sql`now()` })
    .where(and(eq(ownershipTransfers.tenantId, tenantId), eq(ownershipTransfers.status, 'pending'), flipped))
  const res = await db.batch([
    lock.build(db), flip, demote.build(db), promote.build(db), signOut, revokeTokens, clearPlan, dropTransfer,
  ] as any) as unknown as unknown[][]
  const [, f, d, p] = res
  const done = f!.length === 1 && d!.length === 1 && p!.length === 1
  if (done) await afterRecovery(db, r, env, c)
  return { done }
}

const today = () => new Date().toISOString().slice(0, 10)

async function afterRecovery(db: DB, r: OpenRecovery, env: Env | undefined, c: Context | null) {
  const names = await db.select({ userId: users.userId, username: users.username, email: users.email }).from(users)
    .where(inArray(users.userId, [r.formerOwnerId, r.successorId]))
  const former = names.find((n) => n.userId === r.formerOwnerId)
  const successor = names.find((n) => n.userId === r.successorId)
  const note = ownershipChangedNotice(former?.username ?? '', successor?.username ?? '', today())
  await postNotice(db, r.tenantId, null, 'ownership_changed', note)
  await postNotice(db, r.tenantId, r.successorId, 'owner_checklist', ownerChecklist(completionEffects(r.reason).checklistHasAgentKeys))
  await audit(db, c, {
    userId: r.successorId, tenantId: r.tenantId, actionType: 'ownership.recovered', targetEntity: r.formerOwnerId,
    previousState: { owner: r.formerOwnerId },
    newState: { owner: r.successorId, recovery_id: r.recoveryId, reason: r.reason },
  })
  if (env) {
    for (const to of [former?.email, successor?.email]) {
      if (to) await sendMail(env, { to, subject: 'Tenant ownership changed', text: note })
    }
  }
}

/** A recovery that can no longer complete (owner or successor changed) is closed as 'cancelled' so a new one can start. */
export async function closeStaleRecovery(db: DB, r: OpenRecovery) {
  await db.update(ownershipRecoveries).set({ status: 'cancelled' })
    .where(and(
      eq(ownershipRecoveries.recoveryId, r.recoveryId), inArray(ownershipRecoveries.status, ['awaiting_approval', 'on_hold']),
      sql`not (${recoveryStateOk(r)})`,
    ))
}

async function settleRecovery(db: DB, tenantId: string, env?: Env) {
  const r = await openRecovery(db, tenantId)
  if (!r) return
  const next = recoveryNext(r, 'settle', new Date())
  if (next?.status === 'expired') {
    await db.update(ownershipRecoveries).set({ status: 'expired' }).where(and(
      eq(ownershipRecoveries.recoveryId, r.recoveryId), eq(ownershipRecoveries.status, 'awaiting_approval'),
      lte(ownershipRecoveries.expiresAt, sql`now()`),
    ))
    return
  }
  // complete_now: the hold ended. Or both approvals are in for an immediate reason but completion did not finish.
  const approvedNotCompleted = r.status === 'awaiting_approval' && !!r.approver1At && !!r.approver2At
  if (next?.status === 'complete_now' || approvedNotCompleted) {
    const { done } = await completeRecovery(db, r, env)
    if (!done) await closeStaleRecovery(db, r)
  }
}
