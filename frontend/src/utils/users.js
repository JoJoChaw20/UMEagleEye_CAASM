// Pure helpers for the Users page. Tested with node --test (users.test.js).
import { stepUpReady } from './mfa.js'

/** Delete stays disabled until the typed username matches exactly and the step-up fields are filled. */
export function canConfirmDelete({ typed, username, code, needsPassword, password }) {
  if (!username || typed !== username) return false
  return stepUpReady({ hasPassword: needsPassword, password, code })
}
