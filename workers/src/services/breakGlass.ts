// Applying a confirmed platform break-glass reset once its 24-hour hold is over.
import { and, eq, lte, sql } from 'drizzle-orm'
import type { DB } from '../db/client'
import { platformMfaResets } from '../db/schema'
import { audit } from './audit'
import { mfaClearStatements } from './mfaStepUp'

/**
 * The batch (one transaction) that applies reset `resetId`. The status flip to 'done' comes first
 * and only matches a row that is still confirmed and due, so a cancel that landed after the read
 * makes it match nothing. The two clearing statements run only if this transaction made that flip
 * (completed_at = now() is the transaction's own timestamp), so a lost race changes nothing.
 */
export function applyStatements(db: DB, userId: string, resetId: string) {
  const flipped = sql`exists (select 1 from platform_mfa_resets where reset_id = ${resetId}
    and status = 'done' and completed_at = now())`
  return [
    db.update(platformMfaResets).set({ status: 'done', completedAt: sql`now()` })
      .where(and(
        eq(platformMfaResets.resetId, resetId), eq(platformMfaResets.status, 'confirmed'),
        lte(platformMfaResets.effectiveAt, sql`now()`),
      ))
      .returning({ resetId: platformMfaResets.resetId }),
    ...mfaClearStatements(db, userId, flipped),
  ] as const
}

/**
 * If this account has a confirmed reset whose hold is over: clear its MFA (as the Tenant
 * Superadmin's reset does) and mark the row done, in one transaction. Returns true only when this
 * call applied it. Called at sign-in before the MFA stage is decided.
 */
export async function applyDueBreakGlass(db: DB, userId: string): Promise<boolean> {
  const [due] = await db.select({ resetId: platformMfaResets.resetId }).from(platformMfaResets)
    .where(and(
      eq(platformMfaResets.userId, userId), eq(platformMfaResets.status, 'confirmed'),
      lte(platformMfaResets.effectiveAt, sql`now()`),
    )).limit(1)
  if (!due) return false

  const [flip] = await db.batch([...applyStatements(db, userId, due.resetId)])
  if (flip.length === 0) return false   // cancelled or applied by another sign-in first: nothing was cleared here
  await audit(db, null, {
    userId, tenantId: null, actionType: 'auth.break_glass_applied', targetEntity: userId,
    newState: { reset_id: due.resetId },
  })
  return true
}
