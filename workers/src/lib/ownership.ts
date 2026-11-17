// Tenant ownership handover rules. Pure logic: no DB calls, no clock reads (callers pass `now`).
import { and, eq } from 'drizzle-orm'
import { users } from '../db/schema'
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
export type TenantMember = { userId: string; tenantId: string | null; isActive: boolean; role: string }

export function validateTransfer(i: {
  ownerId: string; toUser: TenantMember; tenantId: string; after: AfterChoice; now: Date
}): string | null {
  const { toUser, after } = i
  if (toUser.userId === i.ownerId) return 'The recipient cannot be the current owner'
  if (toUser.tenantId !== i.tenantId) return 'The recipient must belong to this tenant'
  if (toUser.role !== 'tenant_user') return 'The recipient must be a Tenant user'
  if (!toUser.isActive) return 'The recipient must be an active user'
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
  ownerId: string; successor: TenantMember; approvers: [TenantMember, TenantMember]; tenantId: string
}): string | null {
  const three = [i.successor, i.approvers[0], i.approvers[1]]
  if (new Set(three.map((u) => u.userId)).size !== 3) return 'The successor and the two approvers must be three different users'
  for (const u of three) {
    if (u.userId === i.ownerId) return 'The owner cannot be the successor or an approver'
    if (u.tenantId !== i.tenantId) return 'Everyone in the plan must belong to this tenant'
    if (!u.isActive) return 'Everyone in the plan must be an active user'
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
    if (r.status === 'awaiting_approval') return { ...keep, status: 'cancelled' }
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

export type SwapUpdate = {
  label: 'demote' | 'promote'
  userId: string
  tenantId: string
  set: Record<string, unknown>
  /** Drizzle builder for one `db.batch([...])` entry. */
  build: (db: any) => any
}

/**
 * Ordered updates for one db.batch: demote the old owner first, then promote the new one.
 * Each update pins the row's current role and has `.returning({ userId })`. The caller MUST
 * check both results: a demote returning 0 rows means the sender is no longer the owner, a
 * promote returning 0 rows means the recipient is no longer a plain tenant_user; either way
 * treat the swap as failed. The unique index `uq_users_one_tenant_superadmin` is the backstop
 * against two owners.
 */
export function swapStatements(
  tenantId: string, fromId: string, toId: string, after: AfterChoice,
): [SwapUpdate, SwapUpdate] {
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
  const mk = (label: 'demote' | 'promote', userId: string, currentRole: 'tenant_superadmin' | 'tenant_user', set: Record<string, unknown>): SwapUpdate => ({
    label, userId, tenantId, set,
    build: (db) => db.update(users).set(set)
      .where(and(eq(users.userId, userId), eq(users.tenantId, tenantId), eq(users.role, currentRole)))
      .returning({ userId: users.userId }),
  })
  return [mk('demote', fromId, 'tenant_superadmin', demoteSet), mk('promote', toId, 'tenant_user', promoteSet)]
}

export function ownershipChangedNotice(a: string, b: string, date: string): string {
  return `Tenant ownership changed from ${a} to ${b} on ${date}.`
}
export function restoredNotice(date: string): string {
  return `Ownership of this tenant was restored by platform verification on ${date}.`
}
