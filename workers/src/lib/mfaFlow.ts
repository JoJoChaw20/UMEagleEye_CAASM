// Decisions of the MFA sign-in routes (routes/auth.ts: login, google, mfa/verify, mfa/enrol/*,
// mfa/recovery-codes). Pure, so they are tested without a database (mfaFlow.test.ts).
import { roleOf } from './accountRows'
import { clockSkewMinutes, hashRecoveryCode, normalizeRecoveryCode, type MfaStage } from './mfa'

export const CODE_REPLAYED = 'This code was already used. Wait for the next one.'
export const RECOVERY_CODE_INVALID = 'That recovery code is not valid.'
export const WRONG_CODE = 'That code is not correct. Enter the code your authenticator app shows now.'

const minutes = (n: number) => `${n} minute${n === 1 ? '' : 's'}`

/** After the password or Google step: verify a code, or set up MFA first. */
export function signInOutcome(mfaEnabled: boolean): MfaStage {
  return mfaEnabled ? 'verify' : 'enrol'
}

/**
 * Staging-only exception to mandatory MFA: usernames in MFA_EXEMPT_USERNAMES (comma list, exact
 * match) sign in with the password alone. Active only when APP_ENV is exactly 'staging' (fail closed: production,
 * unset or anything else is never exempt).
 */
export function isMfaExempt(env: { MFA_EXEMPT_USERNAMES?: string; APP_ENV?: string }, username: string): boolean {
  if (env.APP_ENV !== 'staging') return false
  if (!username) return false
  // The username is compared exactly; only the list entries are trimmed.
  return (env.MFA_EXEMPT_USERNAMES ?? '').split(',').map((s) => s.trim()).filter(Boolean).some((n) => n === username)
}

export type VerifyInput = { kind: 'code'; code: string } | { kind: 'recovery'; recoveryCode: string }

/** POST /auth/mfa/verify body: exactly one of `code` (6 digits) and `recovery_code`. Blank counts as absent. */
export function parseVerifyBody(
  body: { code?: string | null; recovery_code?: string | null },
): { ok: true; input: VerifyInput } | { ok: false; detail: string } {
  const code = (body.code ?? '').replace(/\s/g, '')
  const recoveryCode = (body.recovery_code ?? '').trim()
  if (code && recoveryCode) return { ok: false, detail: 'Enter a code or a recovery code, not both.' }
  if (recoveryCode) return { ok: true, input: { kind: 'recovery', recoveryCode } }
  if (!code) return { ok: false, detail: 'Enter the 6-digit code from your authenticator app, or a recovery code.' }
  if (!/^\d{6}$/.test(code)) return { ok: false, detail: 'Enter the 6-digit code from your authenticator app.' }
  return { ok: true, input: { kind: 'code', code } }
}

/**
 * Step-up confirmation (regenerating recovery codes, MFA reset): the password and the current MFA
 * code. An account with no password (Google-only, NO_PASSWORD_HASH) gives the code alone.
 */
export function stepUpOk(
  s: { hasPassword: boolean; passwordOk: boolean; codeOk: boolean; passwordOnly?: boolean },
): boolean {
  // An MFA-exempt account with MFA off: the password alone (an account with no password cannot confirm).
  if (s.passwordOnly) return s.hasPassword && s.passwordOk
  return s.codeOk && (!s.hasPassword || s.passwordOk)
}

/** Marks an unused code as used, atomically: true only for the one call that changed it. */
export interface RecoveryCodeStore {
  markUsed(userId: string, codeHash: string): Promise<boolean>
}

/** A recovery code works once: anything not in the code format is refused without a lookup. */
export async function useRecoveryCode(store: RecoveryCodeStore, userId: string, input: string): Promise<boolean> {
  const normalized = normalizeRecoveryCode(input)
  if (!/^[2-9A-HJ-NP-Z]{10}$/.test(normalized)) return false
  return store.markUsed(userId, await hashRecoveryCode(normalized))
}

/**
 * POST /auth/mfa/enrol/start: the secret the phone may already have scanned is kept, so a retry or
 * a new sign-in shows the same QR. A new one only when none exists or the user asks for it.
 */
export function pendingSecretPlan(pending: string | null, newSecret: boolean | undefined): 'reuse' | 'create' {
  return pending && !newSecret ? 'reuse' : 'create'
}

/** 401 detail for a code that was not accepted: the clock message when the phone clock is off. */
export function wrongCodeDetail(secret: string, code: string, nowMs: number = Date.now()): string {
  const skew = clockSkewMinutes(secret, code, nowMs)
  if (skew === null) return WRONG_CODE
  return `Your phone's clock is about ${minutes(Math.abs(skew))} off. Turn on automatic date and time on your phone, then try again.`
}

/** 429 detail while the MFA failure limit blocks the account. */
export function tooManyCodesDetail(minutesLeft: number): string {
  return `Too many wrong codes. Try again in ${minutes(minutesLeft)}.`
}

/** MFA reset by a Tenant Superadmin: only a tenant_user of the caller's own tenant, never the caller. */
export function resetTarget(
  target: { userId: string; tenantId: string | null; role: string }, callerId: string, tenantId: string,
): 'ok' | 'refused' {
  if (target.userId === callerId || target.tenantId !== tenantId) return 'refused'
  return roleOf(target) === 'tenant_user' ? 'ok' : 'refused'
}

/** Deleting a user: the same rule as the MFA reset (a tenant_user of the caller's tenant, never the caller). */
export function deleteTarget(
  caller: { userId: string }, target: { userId: string; tenantId: string | null; role: string }, tenantId: string,
): 'ok' | 'refused' {
  return resetTarget(target, caller.userId, tenantId)
}

/** The typed username must equal the target's username exactly: case-sensitive, no trimming. */
export function confirmMatches(typed: unknown, username: string): boolean {
  return typeof typed === 'string' && typed === username
}
