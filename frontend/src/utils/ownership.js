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

// Local calendar date (YYYY-MM-DD). One convention for the min attribute, the check and the deadline sent.
export function localDate(offsetDays = 0, now = new Date()) {
  const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() + offsetDays)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}

export const dateAfterToday = (date, now = new Date()) => !!date && date > localDate(0, now)

// The deadline sent: end of that local day.
export const deadlineISO = (date) => new Date(`${date}T23:59:59`).toISOString()

export function transferBodyReady({ to, mode, date, now }) {
  if (!to || !AFTER[mode]) return false
  return mode !== 'deactivate_on' || dateAfterToday(date, now)
}

// Which parts to show, from the server's per-viewer `me` block and `recovery_open` flag.
export function viewFor(res, me) {
  if (!res) return { owner: null, isOwner: false }
  const isOwner = !!me && res.owner?.user_id === me.userId
  const t = res.pending_transfer || null
  const me_ = res.me || {}
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
    canStartRecovery: !isOwner && !!me_.is_successor && !res.recovery_open,
    canApprove: !!r && r.status === 'awaiting_approval' && !!me_.approver_slot && !me_.has_approved,
    recoveryInProgress: !!res.recovery_open && !isOwner && !r,
    canCancelRecovery: !!r && r.your_role === 'owner' && r.status === 'on_hold',
  }
}

export function transferMessage(name, tenant, after) {
  const tail = after?.mode === 'deactivate_on' && after.deactivate_on
    ? `${name} will be deactivated on ${String(after.deactivate_on).slice(0, 10)}.`
    : after?.mode === 'deactivate_now' ? `${name} will be deactivated.` : `${name} will become a Tenant user.`
  return `${name} wants to make you the Tenant Superadmin of ${tenant}. You will be able to grant and remove access for every user, reset MFA, and transfer ownership. ${tail}`
}
