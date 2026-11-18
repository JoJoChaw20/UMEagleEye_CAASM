// Response shape of GET /tenants/:tenantId/ownership. Pure: who sees what.
export type TransferRow = {
  transferId: string; fromUserId: string; toUserId: string; afterMode: string; afterActions: string[]
  deactivateOn: Date | null; status: string; createdAt: Date; expiresAt: Date
}
export type PlanRow = { successorId: string | null; approver1Id: string | null; approver2Id: string | null }
export type RecoveryRow = {
  recoveryId: string; successorId: string; reason: string; status: string
  approver1At: Date | null; approver2At: Date | null; createdAt: Date; expiresAt: Date; holdUntil: Date | null
}
type Person = { user_id: string; username: string }

export function transferMessage(name: string, tenant: string, mode: string, deactivateOn: Date | null): string {
  const after = mode === 'deactivate_on' && deactivateOn
    ? `${name} will be deactivated on ${deactivateOn.toISOString().slice(0, 10)}.`
    : mode === 'deactivate_now' ? `${name} will be deactivated.` : `${name} will become a Tenant user.`
  return `${name} wants to make you the Tenant Superadmin of ${tenant}. You will be able to grant and remove access for every user, reset MFA, and transfer ownership. ${after}`
}

export function ownershipView(
  i: { owner: { userId: string; username: string }; transfer: TransferRow | null; plan: PlanRow | null; recovery?: RecoveryRow | null; names: Record<string, string>; tenantName?: string },
  viewerId: string,
) {
  const person = (id: string | null): Person | null => (id ? { user_id: id, username: i.names[id] ?? '' } : null)
  const isOwner = viewerId === i.owner.userId
  const t = i.transfer
  const concerned = t && (viewerId === t.fromUserId || viewerId === t.toUserId)
  const p = i.plan
  const r = i.recovery ?? null
  const role = !r ? null : viewerId === i.owner.userId ? 'owner' : viewerId === r.successorId ? 'successor'
    : viewerId === p?.approver1Id || viewerId === p?.approver2Id ? 'approver' : null
  const slot: 1 | 2 | null = p?.approver1Id === viewerId ? 1 : p?.approver2Id === viewerId ? 2 : null
  const me = {
    is_successor: !!p?.successorId && p.successorId === viewerId,
    approver_slot: slot,
    has_approved: !!r && (slot === 1 ? !!r.approver1At : slot === 2 ? !!r.approver2At : false),
  }
  return {
    me,
    recovery_open: !!r,
    owner: { user_id: i.owner.userId, username: i.owner.username },
    ...(t && concerned ? {
      pending_transfer: {
        transfer_id: t.transferId, from_user: person(t.fromUserId)!, to_user: person(t.toUserId)!,
        after: { mode: t.afterMode, actions: t.afterActions, deactivate_on: t.deactivateOn?.toISOString() ?? null },
        created_at: t.createdAt.toISOString(), expires_at: t.expiresAt.toISOString(),
        ...(viewerId === t.toUserId ? { message: transferMessage(i.names[t.fromUserId] ?? '', i.tenantName ?? 'this tenant', t.afterMode, t.deactivateOn) } : {}),
      },
    } : {}),
    recovery_plan: isOwner && p
      ? { successor: person(p.successorId), approver1: person(p.approver1Id), approver2: person(p.approver2Id) }
      : null,
    recovery: r && role ? {
      recovery_id: r.recoveryId, status: r.status, reason: r.reason, your_role: role, successor: person(r.successorId)!,
      approver1_approved: !!r.approver1At, approver2_approved: !!r.approver2At,
      created_at: r.createdAt.toISOString(), expires_at: r.expiresAt.toISOString(), hold_until: r.holdUntil?.toISOString() ?? null,
    } : null,
    plan_complete: !!(p && p.successorId && p.approver1Id && p.approver2Id),
  }
}
