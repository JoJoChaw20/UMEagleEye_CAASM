// Deleting a tenant user (DELETE /tenants/:tenantId/users/:userId). Run with db.batch (one Neon HTTP
// transaction): the user's audit rows keep their username in actor_username before the delete sets
// user_id to NULL, so history shows "<username> (deleted)". A refused delete (23503) undoes both.
// The delete only matches a tenant_user of this tenant while the caller is still its Tenant Superadmin, so a
// role change or a transfer between the read and the write cannot delete the new owner. No row back = 409.
import { and, eq } from 'drizzle-orm'
import type { DB } from '../db/client'
import { auditLogs, users } from '../db/schema'
import { stillOwner } from '../lib/ownership'

export const ACCOUNT_CHANGED = 'This account changed. Reload and try again.'

export function deleteUserStatements(db: DB, tenantId: string, userId: string, username: string, callerId: string) {
  return [
    db.update(auditLogs).set({ actorUsername: username }).where(eq(auditLogs.userId, userId)),
    db.delete(users).where(and(
      eq(users.userId, userId), eq(users.tenantId, tenantId), eq(users.role, 'tenant_user'), stillOwner(callerId, tenantId),
    )).returning({ userId: users.userId }),
  ] as const
}
