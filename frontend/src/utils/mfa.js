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

const RUNNING_OUT = 'You are running out of recovery codes. Ask your Tenant Superadmin to reset your MFA so you can set up your authenticator again.'

/** The note after a recovery-code sign-in; warning is '' unless 2 or fewer codes are left. */
export function recoveryCodesLeftText(left) {
  const n = Number(left)
  return {
    message: `Signed in with a recovery code. You have ${n} recovery ${n === 1 ? 'code' : 'codes'} left.`,
    warning: n <= 2 ? RUNNING_OUT : '',
  }
}
