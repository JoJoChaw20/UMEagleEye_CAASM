// Tenant ownership handover, DB side (rules are in lib/ownership.ts, response shape in lib/ownershipView.ts).
import { and, eq, gt, gte, isNull, lte, or, sql } from 'drizzle-orm'
import type { DB } from '../db/client'
import { ownershipTransfers, tenantNotices, tenantRecoveryPlans } from '../db/schema'
import { swapStatements, type AfterChoice } from '../lib/ownership'

/** Settles what time alone decides. For now: pending transfers past expires_at become 'expired'. */
export async function settleOwnership(db: DB, tenantId: string): Promise<void> {
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
  const clear = (col: string) => sql.raw(col)
  const nullIfMember = (col: string) => sql`case when ${clear(col)} in (${fromUserId}::uuid, ${toUserId}::uuid) then null else ${clear(col)} end`
  const clearPlan = db.update(tenantRecoveryPlans).set({
    successorId: nullIfMember('successor_id'), approver1Id: nullIfMember('approver1_id'),
    approver2Id: nullIfMember('approver2_id'), updatedAt: sql`now()`,
  }).where(and(eq(tenantRecoveryPlans.tenantId, tenantId), flipped))
  const closeNotice = db.update(tenantNotices).set({ expiresAt: sql`now()` })
    .where(and(requestNoticeWhere(tenantId, toUserId, t.createdAt), flipped))
  const res = await db.batch([
    lock.build(db), flip, demote.build(db), promote.build(db), clearPlan, closeNotice,
  ] as any) as unknown as unknown[][]
  const [, f, d, p] = res
  return { done: f!.length === 1 && d!.length === 1 && p!.length === 1 }
}
