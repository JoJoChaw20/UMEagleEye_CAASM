// Pure helpers for the Tenant ownership section (GET /tenants/:id/ownership).

export const PLAN_BANNER = 'No recovery plan. If you lose access, your tenant cannot recover without platform verification.'

export const REASONS = [
  { key: 'terminated', label: 'Terminated' },
  { key: 'compromised', label: 'Account compromised' },
  { key: 'resigned', label: 'Resigned without handover' },
  { key: 'unreachable', label: 'Unreachable' },
]
export const reasonLabel = (key) => REASONS.find((r) => r.key === key)?.label ?? key

const AFTER = {
  stay: 'Stay as a Tenant user',
  deactivate_on: 'Stay until a date, then be deactivated',
  deactivate_now: 'Be deactivated now',
}
export const afterModeLabel = (mode) => AFTER[mode] ?? mode
export const AFTER_MODES = Object.keys(AFTER)

export function plan3Ready(a, b, c) {
  return !!(a && b && c) && new Set([a, b, c]).size === 3
}

export function transferBodyReady({ to, mode, date }) {
  if (!to || !AFTER[mode]) return false
  return mode !== 'deactivate_on' || !!date
}

// Which parts to show. The backend does not say who the successor is before a recovery opens
// (plan is owner-only), so any non-owner may try to start one; the server refuses others.
export function viewFor(res, me) {
  if (!res) return { owner: null, isOwner: false }
  const isOwner = !!me && res.owner?.user_id === me.userId
  const t = res.pending_transfer || null
  const r = res.recovery || null
  return {
    owner: res.owner,
    isOwner,
    canTransfer: isOwner && !t,
    pendingAsOwner: isOwner && !!t,
    pendingAsRecipient: !!t && !!me && t.to_user?.user_id === me.userId && !isOwner,
    pendingTransfer: t,
    showPlanBanner: isOwner && res.plan_complete === false,
    plan: res.recovery_plan || null,
    recovery: r,
    canStartRecovery: !isOwner && !r,
    canApprove: !!r && r.your_role === 'approver' && r.status === 'awaiting_approval',
    canCancelRecovery: !!r && r.your_role === 'owner' && r.status === 'on_hold',
  }
}

export function transferMessage(name, tenant, after) {
  const tail = after?.mode === 'deactivate_on' && after.deactivate_on
    ? `${name} will be deactivated on ${String(after.deactivate_on).slice(0, 10)}.`
    : after?.mode === 'deactivate_now' ? `${name} will be deactivated.` : `${name} will become a Tenant user.`
  return `${name} wants to make you the Tenant Superadmin of ${tenant}. You will be able to grant and remove access for every user, reset MFA, and transfer ownership. ${tail}`
}
