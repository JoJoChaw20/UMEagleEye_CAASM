// One audit-log row for something a signed-in user did (users, roles, agents, sign-in security).
// The caller's address is kept with the new state (audit_logs has no column for it). A failed
// write is logged and never fails the action itself.
import type { Context } from 'hono'
import type { DB } from '../db/client'
import { auditLogs } from '../db/schema'

export interface AuditEntry {
  userId: string | null
  tenantId: string | null
  actionType: string
  targetEntity?: string | null
  previousState?: unknown
  newState?: unknown
}

export function callerIp(c: Context): string | null {
  return c.req.header('cf-connecting-ip') ?? null
}

export async function audit(db: DB, c: Context | null, entry: AuditEntry): Promise<void> {
  const ip = c ? callerIp(c) : null
  const newState = entry.newState === undefined && !ip ? null
    : { ...(entry.newState && typeof entry.newState === 'object' ? entry.newState as Record<string, unknown> : { value: entry.newState ?? null }), ...(ip ? { ip } : {}) }
  try {
    await db.insert(auditLogs).values({
      userId: entry.userId, tenantId: entry.tenantId, actionType: entry.actionType,
      targetEntity: entry.targetEntity ?? null, previousState: entry.previousState ?? null, newState,
    })
  } catch (err) {
    console.error(`audit ${entry.actionType} failed:`, err)
  }
}
