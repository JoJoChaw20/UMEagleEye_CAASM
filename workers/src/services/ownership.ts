// Tenant ownership handover, DB side (rules are in lib/ownership.ts, response shape in lib/ownershipView.ts).
import { and, eq, gt, gte, inArray, isNotNull, isNull, lte, or, sql, type SQL } from 'drizzle-orm'
import type { Context } from 'hono'
import type { DB } from '../db/client'
import type { Env } from '../types'
import {
  enrolmentTokens, ownershipRecoveries, ownershipTransfers, tenantNotices, tenantRecoveryPlans, users,
} from '../db/schema'
import {
  completionEffects, ownerChecklist, ownershipChangedNotice, ownershipNoticeExpiry, recoveryNext, restoredNotice, swapStatements, type AfterChoice,
} from '../lib/ownership'
import { auditOwnerInvite, candidateEligible, ownerInviteStatement, type OwnerInvitePlan } from './ownerInvite'
import { audit } from './audit'
import { sendMail } from './mailer'

/**
 * Settles what time alone decides: pending transfers past expires_at become 'expired'; an open recovery
 * past its approval window expires, and one whose 72-hour hold ended (or whose approvals are in but
 * completion did not finish) is completed. `env`, when given, lets a completion send its emails.
 */
export async function settleOwnership(db: DB, tenantId: string, env?: Env): Promise<void> {
  try {
    await settleRecovery(db, tenantId, env)
  } catch (err) {
    console.error('settling recovery failed:', err)   // never blocks transfer settling or the calling route
  }
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
export function clearPlanStatement(db: DB, tenantId: string, a: string, b: string, guard: SQL) {
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
  if (done) {
    try {
      await afterRecovery(db, r, env, c)   // the swap is committed; a notice failure must not undo or hide it
    } catch (err) {
      console.error('after-recovery notices failed:', err)
    }
  }
  return { done }
}

const today = () => new Date().toISOString().slice(0, 10)

async function afterRecovery(db: DB, r: OpenRecovery, env: Env | undefined, c: Context | null) {
  const names = await db.select({ userId: users.userId, username: users.username, email: users.email }).from(users)
    .where(inArray(users.userId, [r.formerOwnerId, r.successorId]))
  const former = names.find((n) => n.userId === r.formerOwnerId)
  const successor = names.find((n) => n.userId === r.successorId)
  const note = ownershipChangedNotice(former?.username ?? '', successor?.username ?? '', today())
  await postNotice(db, r.tenantId, null, 'ownership_changed', note, ownershipNoticeExpiry())
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


type Person = { userId: string; username: string; email: string | null }

/**
 * Path C, platform restore, as ONE batch (one transaction), so the tenant never ends without an owner:
 *  1. lock the current owner and the invited account (FOR UPDATE), when they exist;
 *  2. demote + suspend the current owner (role tenant_user, is_active = false, actions cleared, sessions_valid_after = now()),
 *     only if they are still the owner AND (for an existing invited account) that account is still promotable, so
 *     the demote cannot commit without the promote;
 *  3. guarded by "this transaction demoted the owner" (sessions_valid_after = now() and is_active = false): delete unused
 *     enrolment tokens (uses = 0), clear the owner and the invited account from the recovery plan, cancel an open
 *     transfer and recovery, end their request notices;
 *  4. the owner write from services/ownerInvite.ts: promote the existing account (guarded: no owner left, still
 *     eligible, demote happened) or insert a new Tenant Superadmin (the unique index uq_users_one_tenant_superadmin
 *     makes it raise if an owner is still present, and the raise rolls the whole batch back).
 * done = demote (when there was an owner) and the owner write each returned 1 row; otherwise nothing changed.
 * Notices, audit and emails follow outside the batch.
 */
export async function restoreOwnership(
  db: DB, c: Context | null,
  i: { tenantId: string; platformUserId: string; email: string; plan: Extract<OwnerInvitePlan, { ok: true }>; formerOwner: Person | null },
  env?: Env,
): Promise<{ done: boolean; newOwner?: Person }> {
  const { tenantId, plan, email, formerOwner } = i
  const oldId = formerOwner?.userId
  const candidateId = plan.existing?.userId
  const lockIds = [oldId, candidateId].filter((x): x is string => !!x)
  const stmts: unknown[] = []
  if (lockIds.length) {
    stmts.push(db.select({ userId: users.userId }).from(users)
      .where(and(eq(users.tenantId, tenantId), inArray(users.userId, lockIds))).for('update'))
  }
  // An invited account with no tenant yet is not matched by the tenant filter above: lock it by id.
  if (candidateId && plan.existing?.tenantId === null) {
    stmts.push(db.select({ userId: users.userId }).from(users).where(eq(users.userId, candidateId)).for('update'))
  }
  let demoteAt = -1
  let demoted: SQL | undefined
  if (oldId) {
    demoted = sql`exists (select 1 from users where user_id = ${oldId}::uuid and tenant_id = ${tenantId}::uuid
      and role = 'tenant_user' and is_active = false and sessions_valid_after = now())`
    demoteAt = stmts.length
    stmts.push(db.update(users).set({
      role: 'tenant_user', isActive: false, actions: [], scheduledDeactivationAt: null, sessionsValidAfter: sql`now()`,
    }).where(and(
      eq(users.userId, oldId), eq(users.tenantId, tenantId), eq(users.role, 'tenant_superadmin'),
      candidateId ? candidateEligible(candidateId, tenantId) : undefined,
    )).returning({ userId: users.userId }))
    stmts.push(db.delete(enrolmentTokens).where(and(eq(enrolmentTokens.tenantId, tenantId), eq(enrolmentTokens.uses, 0), demoted)))
    stmts.push(clearPlanStatement(db, tenantId, oldId, candidateId ?? oldId, demoted))
    stmts.push(db.update(ownershipTransfers).set({ status: 'cancelled', decidedAt: sql`now()` })
      .where(and(eq(ownershipTransfers.tenantId, tenantId), eq(ownershipTransfers.status, 'pending'), demoted)))
    stmts.push(db.update(ownershipRecoveries).set({ status: 'cancelled' })
      .where(and(eq(ownershipRecoveries.tenantId, tenantId), inArray(ownershipRecoveries.status, ['awaiting_approval', 'on_hold']), demoted)))
    stmts.push(db.update(tenantNotices).set({ expiresAt: sql`now()` }).where(and(
      eq(tenantNotices.tenantId, tenantId), inArray(tenantNotices.kind, ['transfer_request', 'recovery_request', 'recovery_hold']),
      or(isNull(tenantNotices.expiresAt), gt(tenantNotices.expiresAt, sql`now()`)), demoted,
    )))
  }
  const ownerAt = stmts.length
  stmts.push(ownerInviteStatement(db, plan, tenantId, email, demoted))
  const res = await db.batch(stmts as any) as unknown as unknown[][]
  const added = res[ownerAt]![0] as Person | undefined
  const done = (!oldId || res[demoteAt]!.length === 1) && !!added
  if (!done || !added) return { done: false }
  try {
    await afterRestore(db, c, tenantId, i.platformUserId, formerOwner, added, plan, email, env)
  } catch (err) {
    console.error('after-restore notices failed:', err)   // the restore is committed; a notice failure must not hide it
  }
  return { done: true, newOwner: added }
}

async function afterRestore(
  db: DB, c: Context | null, tenantId: string, platformUserId: string, former: Person | null, added: Person,
  plan: Extract<OwnerInvitePlan, { ok: true }>, email: string, env: Env | undefined,
) {
  const date = today()
  await postNotice(db, tenantId, null, 'ownership_restored', restoredNotice(date), ownershipNoticeExpiry())
  if (former) await postNotice(db, tenantId, null, 'ownership_changed', ownershipChangedNotice(former.username, added.username, date), ownershipNoticeExpiry())
  await postNotice(db, tenantId, added.userId, 'owner_checklist', ownerChecklist(true))
  await auditOwnerInvite(db, c, { userId: platformUserId, role: 'superadmin' }, tenantId, plan, added, email)
  await audit(db, c, {
    userId: platformUserId, tenantId, actionType: 'ownership.restored', targetEntity: added.userId,
    previousState: { owner: former?.userId ?? null }, newState: { owner: added.userId },
  })
  if (env) {
    const text = former
      ? ownershipChangedNotice(former.username, added.username, date) + ' ' + restoredNotice(date)
      : restoredNotice(date)
    for (const to of [former?.email, added.email]) {
      if (to) await sendMail(env, { to, subject: 'Tenant ownership restored', text })
    }
  }
}
