// Pure helpers for the in-app notice bar, the new-owner checklist and the platform restore dialog.

export const RESTORE_VERIFICATION =
  'Verify the request by calling back the organisation contact on record. Do not use contact details given in the request itself.'

/** Only a notice addressed to the caller can be dismissed; tenant-wide ones expire instead. */
export function canDismiss(notice) {
  return !!notice && notice.personal === true
}

/** The API's rows, ignoring anything malformed (a bad response must never break the layout). */
export function visibleNotices(data) {
  return Array.isArray(data) ? data.filter((n) => n && typeof n === 'object' && n.notice_id && typeof n.body === 'string') : []
}

// The checklist arrives as one sentence: "<intro>: item; item; item." Each item gets the page that helps with it.
const LINKS = [
  [/review every user/i, '/users'],
  [/successor|recovery approvers/i, '/users#ownership'],
  [/reassign alerts/i, '/alerts'],
  [/agent keys/i, '/agents'],
]

export function checklistItems(notice) {
  if (!notice || notice.kind !== 'owner_checklist' || typeof notice.body !== 'string') return []
  const i = notice.body.indexOf(':')
  if (i < 0) return []
  return notice.body.slice(i + 1).replace(/\.\s*$/, '').split(';')
    .map((s) => s.trim()).filter(Boolean)
    .map((s) => {
      const label = s.charAt(0).toUpperCase() + s.slice(1)
      const hit = LINKS.find(([re]) => re.test(s))
      return { label, to: hit ? hit[1] : null }
    })
}

export function restoreReady(email) {
  return String(email ?? '').trim().length > 0
}

/** Request body for POST /tenants/:id/ownership/restore: the new owner plus the step-up fields. */
export function restoreBody({ email, username, stepUp }) {
  const u = String(username ?? '').trim()
  return { email: String(email).trim(), ...(u ? { username: u } : {}), ...stepUp }
}
