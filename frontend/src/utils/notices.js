// Pure helpers for the in-app notice bar, the new-owner checklist and the platform restore dialog.

export const RESTORE_VERIFICATION =
  'Verify the request by calling back the organisation contact on record. Do not use contact details given in the request itself.'

/** Only a notice addressed to the caller can be dismissed; tenant-wide ones expire instead. */
export function canDismiss(notice) {
  return !!notice && notice.personal === true
}

/** Where a member of the tenant handles ownership: every tenant member can open it, not only the owner. */
export const OWNERSHIP_ROUTE = '/ownership'
const OWNERSHIP_ACTION_KINDS = ['transfer_request', 'recovery_request', 'recovery_hold', 'recovery_started', 'recovery_disputed']

/** The page a notice asks the reader to open (the ownership page for transfer and recovery notices), or null. */
export function noticeLink(notice) {
  return notice && OWNERSHIP_ACTION_KINDS.includes(notice.kind) ? OWNERSHIP_ROUTE : null
}

/** The API's rows, ignoring anything malformed (a bad response must never break the layout). */
export function visibleNotices(data) {
  return Array.isArray(data) ? data.filter((n) => n && typeof n === 'object' && n.notice_id && typeof n.body === 'string') : []
}

// The new owner's checklist: fixed items (the plan's verbatim texts), each with the page that helps.
const BASE_ITEMS = [
  { label: "Review every user's actions", to: '/users' },
  { label: 'Choose a new successor and recovery approvers', to: OWNERSHIP_ROUTE },
  { label: 'Reassign alerts and advisories assigned to the former owner', to: '/alerts' },
]
const AGENT_KEYS_ITEM = { label: 'Consider replacing agent keys', to: '/agents' }

/** Items for an owner_checklist notice; [] when anything is off (the caller then shows a plain, dismissable card). */
export function checklistItems(notice) {
  if (!notice || notice.kind !== 'owner_checklist' || typeof notice.body !== 'string' || !/checklist/i.test(notice.body)) return []
  return /agent keys/i.test(notice.body) ? [...BASE_ITEMS, AGENT_KEYS_ITEM] : [...BASE_ITEMS]
}

export function restoreReady(email, username = '') {
  const u = String(username ?? '').trim()
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email ?? '').trim()) && (u === '' || u.length >= 3)
}

/** Request body for POST /tenants/:id/ownership/restore: the new owner plus the step-up fields. */
export function restoreBody({ email, username, stepUp }) {
  const u = String(username ?? '').trim()
  return { email: String(email).trim(), ...(u ? { username: u } : {}), ...stepUp }
}
