// Deleting a tenant user (DELETE /tenants/:tenantId/users/:userId). Run with db.batch (one Neon HTTP
// transaction): the user's audit rows keep their username in actor_username before the delete sets
// user_id to NULL, so history shows "<username> (deleted)". A refused delete (23503) undoes both.
import { and, eq } from 'drizzle-orm'
import type { DB } from '../db/client'
import { auditLogs, users } from '../db/schema'

export function deleteUserStatements(db: DB, tenantId: string, userId: string, username: string) {
  return [
    db.update(auditLogs).set({ actorUsername: username }).where(eq(auditLogs.userId, userId)),
    db.delete(users).where(and(eq(users.userId, userId), eq(users.tenantId, tenantId))),
  ] as const
}
