// Response shape of GET /tenants/:tenantId/ownership. Pure: who sees what.
export type TransferRow = {
  transferId: string; fromUserId: string; toUserId: string; afterMode: string; afterActions: string[]
  deactivateOn: Date | null; status: string; createdAt: Date; expiresAt: Date
}
export type PlanRow = { successorId: string | null; approver1Id: string | null; approver2Id: string | null }
type Person = { user_id: string; username: string }

export function transferMessage(name: string, tenant: string, mode: string, deactivateOn: Date | null): string {
  const after = mode === 'deactivate_on' && deactivateOn
    ? `${name} will be deactivated on ${deactivateOn.toISOString().slice(0, 10)}.`
    : mode === 'deactivate_now' ? `${name} will be deactivated.` : `${name} will become a Tenant user.`
  return `${name} wants to make you the Tenant Superadmin of ${tenant}. You will be able to grant and remove access for every user, reset MFA, and transfer ownership. ${after}`
}

export function ownershipView(
  i: { owner: { userId: string; username: string }; transfer: TransferRow | null; plan: PlanRow | null; names: Record<string, string> },
  viewerId: string,
) {
  const person = (id: string | null): Person | null => (id ? { user_id: id, username: i.names[id] ?? '' } : null)
  const isOwner = viewerId === i.owner.userId
  const t = i.transfer
  const concerned = t && (viewerId === t.fromUserId || viewerId === t.toUserId)
  const p = i.plan
  return {
    owner: { user_id: i.owner.userId, username: i.owner.username },
    ...(t && concerned ? {
      pending_transfer: {
        transfer_id: t.transferId, from_user: person(t.fromUserId)!, to_user: person(t.toUserId)!,
        after: { mode: t.afterMode, actions: t.afterActions, deactivate_on: t.deactivateOn?.toISOString() ?? null },
        created_at: t.createdAt.toISOString(), expires_at: t.expiresAt.toISOString(),
      },
    } : {}),
    recovery_plan: isOwner && p
      ? { successor: person(p.successorId), approver1: person(p.approver1Id), approver2: person(p.approver2Id) }
      : null,
    recovery: null as null,
    plan_complete: !!(p && p.successorId && p.approver1Id && p.approver2Id),
  }
}
