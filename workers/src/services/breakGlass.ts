// Applying a confirmed platform break-glass reset once its 24-hour hold is over.
import { and, eq, lte, sql } from 'drizzle-orm'
import type { DB } from '../db/client'
import { platformMfaResets } from '../db/schema'
import { audit } from './audit'
import { mfaClearStatements } from './mfaStepUp'

/**
 * If this account has a confirmed reset whose hold is over: clear its MFA (as the Tenant
 * Superadmin's reset does) and mark the row done, in one transaction. Returns true when applied.
 * Called at sign-in before the MFA stage is decided, so the account then sets MFA up again.
 */
export async function applyDueBreakGlass(db: DB, userId: string): Promise<boolean> {
  const [due] = await db.select({ resetId: platformMfaResets.resetId }).from(platformMfaResets)
    .where(and(
      eq(platformMfaResets.userId, userId), eq(platformMfaResets.status, 'confirmed'),
      lte(platformMfaResets.effectiveAt, sql`now()`),
    )).limit(1)
  if (!due) return false

  const [, , marked] = await db.batch([
    ...mfaClearStatements(db, userId),
    db.update(platformMfaResets).set({ status: 'done', completedAt: sql`now()` })
      .where(and(eq(platformMfaResets.resetId, due.resetId), eq(platformMfaResets.status, 'confirmed')))
      .returning({ resetId: platformMfaResets.resetId }),
  ])
  if (marked.length === 0) return false   // another sign-in applied it first (the clear is the same)
  await audit(db, null, {
    userId, tenantId: null, actionType: 'auth.break_glass_applied', targetEntity: userId,
    newState: { reset_id: due.resetId },
  })
  return true
}
