// Tenant ownership handover rules. Pure logic: no DB calls, no clock reads (callers pass `now`).
import { and, eq, exists, inArray, notExists, sql, type SQL } from 'drizzle-orm'
import { alias } from 'drizzle-orm/pg-core'
import { users } from '../db/schema'
import { isDeactivated } from './sessionGate'
import { parseActionList } from './userAdmin'

export const HOURS_72 = 72 * 60 * 60 * 1000

export const AFTER_MODES = ['stay', 'deactivate_on', 'deactivate_now'] as const
export type AfterMode = (typeof AFTER_MODES)[number]
export const RECOVERY_REASONS = ['terminated', 'compromised', 'resigned', 'unreachable'] as const
export type RecoveryReason = (typeof RECOVERY_REASONS)[number]
export const RECOVERY_REASON_LABELS: Record<RecoveryReason, string> = {
  terminated: 'Terminated',
  compromised: 'Account compromised',
  resigned: 'Resigned without handover',
  unreachable: 'Unreachable',
}
export const NO_RECOVERY_PLAN_BANNER =
  'No recovery plan. If you lose access, your tenant cannot recover without platform verification.'

export type AfterChoice = { mode: string; actions?: unknown; deactivateOn?: Date | null }
export type TenantMember = {
  userId: string; tenantId: string | null; isActive: boolean; role: string; scheduledDeactivationAt?: Date | null
}

export function validateTransfer(i: {
  ownerId: string; toUser: TenantMember; tenantId: string; after: AfterChoice; now: Date
}): string | null {
  const { toUser, after } = i
  if (toUser.userId === i.ownerId) return 'The recipient cannot be the current owner'
  if (toUser.tenantId !== i.tenantId) return 'The recipient must belong to this tenant'
  if (toUser.role !== 'tenant_user') return 'The recipient must be a Tenant user'
  if (isDeactivated(toUser, i.now)) return 'The recipient must be an active user'
  if (!(AFTER_MODES as readonly string[]).includes(after.mode)) return 'Unknown choice for your own account'
  if (after.mode === 'deactivate_on') {
    if (!after.deactivateOn || after.deactivateOn.getTime() <= i.now.getTime()) return 'deactivate_on must be in the future'
  }
  if (after.actions !== undefined) {
    const p = parseActionList(after.actions)
    if (!p.ok) return `Unknown actions: ${p.unknown.join(', ')}`
  }
  return null
}

export function validateRecoveryPlan(i: {
  ownerId: string; successor: TenantMember; approvers: [TenantMember, TenantMember]; tenantId: string; now?: Date
}): string | null {
  const three = [i.successor, i.approvers[0], i.approvers[1]]
  if (new Set(three.map((u) => u.userId)).size !== 3) return 'The successor and the two approvers must be three different users'
  for (const u of three) {
    if (u.userId === i.ownerId) return 'The owner cannot be the successor or an approver'
    if (u.tenantId !== i.tenantId) return 'Everyone in the plan must belong to this tenant'
    if (isDeactivated(u, i.now)) return 'Everyone in the plan must be an active user'
    if (u.role !== 'tenant_user') return 'Everyone in the plan must be a Tenant user'
  }
  return null
}

export type TransferStatus = 'pending' | 'accepted' | 'declined' | 'cancelled' | 'expired'

export function transferNext(
  status: string, action: 'accept' | 'decline' | 'cancel' | 'expire', now: Date, expiresAt: Date,
): TransferStatus | null {
  if (status !== 'pending') return null
  if ((action === 'accept' || action === 'decline') && now.getTime() > expiresAt.getTime()) return null
  return ({ accept: 'accepted', decline: 'declined', cancel: 'cancelled', expire: 'expired' } as const)[action]
}

/** `complete_now` means "ready to swap": the service runs the swap, then stamps `completed`. */
export type RecoveryStatus =
  | 'awaiting_approval' | 'on_hold' | 'complete_now' | 'completed' | 'expired' | 'cancelled' | 'disputed'
export type RecoveryState = {
  status: string; reason: string; approver1At: Date | null; approver2At: Date | null
  expiresAt: Date; holdUntil: Date | null
}
export type RecoveryFields = {
  status: RecoveryStatus; approver1At: Date | null; approver2At: Date | null; holdUntil: Date | null
}

export function recoveryNext(
  r: RecoveryState, action: 'approve1' | 'approve2' | 'cancel_by_owner' | 'settle', now: Date,
): RecoveryFields | null {
  const keep = { approver1At: r.approver1At, approver2At: r.approver2At, holdUntil: r.holdUntil }
  const t = now.getTime()
  if (action === 'approve1' || action === 'approve2') {
    if (r.status !== 'awaiting_approval' || t > r.expiresAt.getTime()) return null
    if (action === 'approve1' && r.approver1At) return null
    if (action === 'approve2' && r.approver2At) return null
    const a1 = action === 'approve1' ? now : r.approver1At
    const a2 = action === 'approve2' ? now : r.approver2At
    const next = { ...keep, approver1At: a1, approver2At: a2 }
    if (!a1 || !a2) return { ...next, status: 'awaiting_approval' }
    if (r.reason === 'terminated' || r.reason === 'compromised') return { ...next, status: 'complete_now' }
    return { ...next, status: 'on_hold', holdUntil: new Date(t + HOURS_72) }
  }
  if (action === 'cancel_by_owner') {
    if (r.status === 'on_hold') return { ...keep, status: 'disputed' }
    return null
  }
  if (r.status === 'on_hold' && r.holdUntil && t >= r.holdUntil.getTime()) return { ...keep, status: 'complete_now' }
  if (r.status === 'awaiting_approval' && t > r.expiresAt.getTime()) return { ...keep, status: 'expired' }
  return null
}

export function approverSlot(
  plan: { successorId: string | null; approver1Id: string | null; approver2Id: string | null },
  userId: string, successorId: string,
): 'approver1' | 'approver2' | null {
  if (userId === successorId || userId === plan.successorId) return null
  if (userId === plan.approver1Id) return 'approver1'
  if (userId === plan.approver2Id) return 'approver2'
  return null
}

/** SQL: no scheduled deactivation that has come due. */
const notDue = (col: any): SQL => sql`(${col} is null or ${col} > now())`

export type SwapUpdate = {
  label: 'lock' | 'demote' | 'promote'
  userId: string
  tenantId: string
  set: Record<string, unknown>
  /** Drizzle builder for one `db.batch([...])` entry. */
  build: (db: any) => any
}

/**
 * Ordered statements for one db.batch: lock -> demote -> promote.
 * `lock` is a SELECT ... FOR UPDATE on both users: it holds both rows until commit, so a
 * concurrent deactivate or role change of either user waits, and the guards below see a stable
 * recipient. Its result is not an update result; check only demote and promote.
 * All-or-nothing at the SQL level (a 0-row statement does not abort a batch):
 *  - demote runs only if the sender is still the owner AND the recipient is still an active tenant_user;
 *  - promote runs only if the recipient is still an active tenant_user AND the tenant has no owner
 *    (so it is a no-op when the demote was a no-op).
 * An optional `guard` (SQL) is ANDed into the demote's WHERE, so the caller can make the swap depend on another
 * statement of the same batch (e.g. a transfer flipped by this transaction); promote then no-ops with it.
 * Success = demote and promote each returned 1 row. With the lock held, otherwise nothing changed: the caller answers 409
 * "Ownership changed. Reload and try again." The unique index `uq_users_one_tenant_superadmin`
 * is the final backstop against two owners.
 */
export function swapStatements(
  tenantId: string, fromId: string, toId: string, after: AfterChoice, guard?: SQL,
): [SwapUpdate, SwapUpdate, SwapUpdate] {
  const mode = after.mode
  if (!(AFTER_MODES as readonly string[]).includes(mode)) throw new Error(`Unknown after mode: ${mode}`)
  const actions = mode === 'deactivate_now' ? [] : ((after.actions as string[] | undefined) ?? [])
  const demoteSet = {
    role: 'tenant_user',
    actions,
    isActive: mode !== 'deactivate_now',
    scheduledDeactivationAt: mode === 'deactivate_on' ? (after.deactivateOn ?? null) : null,
  }
  const promoteSet = { role: 'tenant_superadmin', actions: [] as string[] }
  const r = alias(users, 'r')
  const o = alias(users, 'o')
  const demote: SwapUpdate = {
    label: 'demote', userId: fromId, tenantId, set: demoteSet,
    build: (db) => db.update(users).set(demoteSet).where(and(
      eq(users.userId, fromId), eq(users.tenantId, tenantId), eq(users.role, 'tenant_superadmin'),
      exists(db.select({ one: sql`1` }).from(r).where(and(
        eq(r.userId, toId), eq(r.tenantId, tenantId), eq(r.role, 'tenant_user'), eq(r.isActive, true), notDue(r.scheduledDeactivationAt),
      ))),
      guard,
    )).returning({ userId: users.userId }),
  }
  const promote: SwapUpdate = {
    label: 'promote', userId: toId, tenantId, set: promoteSet,
    build: (db) => db.update(users).set(promoteSet).where(and(
      eq(users.userId, toId), eq(users.tenantId, tenantId), eq(users.role, 'tenant_user'), eq(users.isActive, true), notDue(users.scheduledDeactivationAt),
      notExists(db.select({ one: sql`1` }).from(o).where(and(
        eq(o.tenantId, tenantId), eq(o.role, 'tenant_superadmin'),
      ))),
    )).returning({ userId: users.userId }),
  }
  const lock: SwapUpdate = {
    label: 'lock', userId: fromId, tenantId, set: {},
    build: (db) => db.select({ userId: users.userId }).from(users)
      .where(and(eq(users.tenantId, tenantId), inArray(users.userId, [fromId, toId])))
      .for('update'),
  }
  return [lock, demote, promote]
}

export function ownershipChangedNotice(a: string, b: string, date: string): string {
  return `Tenant ownership changed from ${a} to ${b} on ${date}.`
}
/** Tenant-wide ownership notices stay for 30 days. */
export const OWNERSHIP_NOTICE_DAYS = 30
export function ownershipNoticeExpiry(now: Date = new Date()): Date {
  return new Date(now.getTime() + OWNERSHIP_NOTICE_DAYS * 24 * 60 * 60 * 1000)
}
export function restoredNotice(date: string): string {
  return `Ownership of this tenant was restored by platform verification on ${date}.`
}

/** Facts about an emergency completion (Path B) the service needs; the swap itself is one guarded batch in the service. */
export function completionEffects(_reason: string) {
  return { checklistHasAgentKeys: true } as const
}

export const RECOVERY_DISPUTED_NOTICE = 'Recovery was disputed. Contact platform support for verification.'

const CHECKLIST_ITEMS = [
  "review every user's actions",
  'choose a new successor and recovery approvers',
  'reassign alerts and advisories assigned to the former owner',
]
/** The new owner's security checklist notice. `emergency` adds "Consider replacing agent keys". */
export function ownerChecklist(emergency: boolean): string {
  const items = emergency ? [...CHECKLIST_ITEMS, 'Consider replacing agent keys'] : CHECKLIST_ITEMS
  return `Security checklist for the new Tenant Superadmin: ${items.join('; ')}.`
}
