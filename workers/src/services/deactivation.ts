// Scheduled deactivation (users.scheduled_deactivation_at) has no cron: the session gate and sign-in refuse a due
// account, and this makes the stored flag agree, so lists and SQL checks see it as inactive too.
import { and, eq, isNotNull, sql } from 'drizzle-orm'
import type { DB } from '../db/client'
import { users } from '../db/schema'

/** Sets is_active = false for a user whose scheduled deactivation is due. One UPDATE; a failure is logged, never thrown. */
export async function flipIfDue(db: DB, userId: string): Promise<void> {
  try {
    await db.update(users).set({ isActive: false })
      .where(and(
        eq(users.userId, userId), eq(users.isActive, true),
        isNotNull(users.scheduledDeactivationAt), sql`${users.scheduledDeactivationAt} <= now()`,
      ))
  } catch (err) {
    console.error('flipping scheduled deactivation failed:', err)
  }
}
