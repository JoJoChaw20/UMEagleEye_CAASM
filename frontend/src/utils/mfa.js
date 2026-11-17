// Pure helpers for the MFA sign-in screens (LoginPage, MfaEnrol, RecoveryCodes, MfaRecoveryPage)
// and the API client. Tested with node --test (mfa.test.js), so no React or browser APIs here.

/** The server's answer for a bad, expired or wrong-stage mfa_token (workers/src/routes/auth.ts). */
const SIGN_IN_EXPIRED = 'Your sign-in has expired. Sign in again.'

export const SIGN_IN_TOOK_TOO_LONG = 'The sign-in took too long. Sign in again.'
export const SET_UP_MFA_TO_CONTINUE = 'Set up MFA to continue.'
const DEACTIVATED = 'Your account is deactivated. Contact your Tenant Superadmin.'

/** Text for "Copy" and "Download .txt" on the recovery-codes screen: a short header, then one code per line. */
export function formatRecoveryCodes(codes) {
  const list = Array.isArray(codes) ? codes : []
  return [
    'UMEagleEye recovery codes',
    'Each code works once. Use one when you cannot use your authenticator app.',
    'Keep them somewhere safe.',
    '',
    ...list,
  ].join('\n') + '\n'
}

/** True for the 403 that an account without MFA gets outside /auth (lib/sessionGate.ts). */
export function isMfaSetupRequired(response) {
  return response?.status === 403 && response?.data?.mfa_setup_required === true
}

/** True when an mfa_token route refused the token: the sign-in must start again. */
export function isMfaTokenExpired(response) {
  return response?.status === 401 && response?.data?.detail === SIGN_IN_EXPIRED
}

/** Digits only, at most 6: what the authenticator-code field keeps of any input or paste. */
export function cleanTotpInput(value) {
  return String(value ?? '').replace(/\D/g, '').slice(0, 6)
}

/** Upper case, letters and digits only: a recovery code typed in any case, with spaces or dashes. */
export function normalizeRecoveryCode(value) {
  return String(value ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '')
}

export function isRecoveryCodeComplete(value) {
  return normalizeRecoveryCode(value).length === 10
}

/** The break-glass email link: exactly one of ?confirm= or ?cancel=, with a token. Otherwise null. */
export function readRecoveryLink(search) {
  const params = new URLSearchParams(String(search ?? ''))
  const confirm = params.get('confirm')
  const cancel = params.get('cancel')
  if (confirm && !cancel) return { action: 'confirm', token: confirm }
  if (cancel && !confirm) return { action: 'cancel', token: cancel }
  return null
}

/** The message LoginPage shows for /login?reason=… (set by api/client.js). */
export function loginReasonMessage(reason) {
  if (reason === 'mfa_setup') return SET_UP_MFA_TO_CONTINUE
  if (reason === 'deactivated') return DEACTIVATED
  return ''
}

/** The 401 texts that mean the session itself is over (middleware/auth.ts, lib/sessionGate.ts). */
const SESSION_ENDED = new Set([
  'Missing or invalid Authorization header',
  'Token expired or invalid',
  'Your session has ended. Sign in again.',
  DEACTIVATED,
])

/**
 * True when a 401 ends the session, so api/client.js signs the user out. Any other 401 (a wrong
 * step-up password or MFA code) is the screen's to show, and the user stays signed in.
 */
export function isSessionEnded(status, detail) {
  return status === 401 && SESSION_ENDED.has(detail)
}

// Who can help an account that cannot use its authenticator (spec section 7). Only a Tenant user
// has someone in the tenant who can reset their MFA. Until the ownership handover (Path B) ships,
// a Tenant Superadmin with no recovery codes left goes to platform support.
const RUNNING_OUT = {
  tenant_user: 'You are running out of recovery codes. Ask your Tenant Superadmin to reset your MFA so you can set up your authenticator again.',
  tenant_superadmin: 'You are running out of recovery codes. If you have none left and cannot use your authenticator, contact platform support.',
  superadmin: 'You are running out of recovery codes. Use your backup device, then get new recovery codes in Settings.',
}
const LOST_MFA = {
  tenant_user: 'Ask your Tenant Superadmin to reset your MFA.',
  tenant_superadmin: 'Use a recovery code. If you have none, contact platform support.',
  superadmin: 'Use your backup device or a recovery code.',
}

/** What to do without the authenticator, by role; an unknown role gets the Tenant user text. */
export function lostMfaAdvice(role) {
  return LOST_MFA[role] ?? LOST_MFA.tenant_user
}

/** The note after a recovery-code sign-in; warning is '' unless 2 or fewer codes are left. */
export function recoveryCodesLeftText(left, role) {
  const n = Number(left)
  return {
    message: `Signed in with a recovery code. You have ${n} recovery ${n === 1 ? 'code' : 'codes'} left.`,
    warning: n <= 2 ? (RUNNING_OUT[role] ?? RUNNING_OUT.tenant_user) : '',
  }
}

// ── Step-up confirmation (new recovery codes, MFA reset) ──────────────────────

export const MFA_RESET_GUIDANCE = 'Confirm this request in person or by phone. Do not reset MFA based only on an email or chat message, because these are common ways attackers take over accounts.'

/** A Google-only account (/auth/me hasPassword === false) confirms with the code alone. */
export function needsPasswordForStepUp(user) {
  return user?.hasPassword !== false
}

export function stepUpReady({ hasPassword, password, code }) {
  return cleanTotpInput(code).length === 6 && (!hasPassword || String(password ?? '').length > 0)
}

/** The request body for a step-up route: { password?, code }. */
export function stepUpBody({ hasPassword, password, code }) {
  return hasPassword ? { password, code } : { code }
}

export function recoveryCodesLeftLabel(left) {
  const n = Number(left)
  return `${n} recovery ${n === 1 ? 'code' : 'codes'} left`
}

export function mfaResetToast(name) {
  return `MFA reset. ${name} must set it up at their next sign-in.`
}
