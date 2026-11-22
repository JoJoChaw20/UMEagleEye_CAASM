// Decisions of the MFA sign-in routes (routes/auth.ts). The routes have no database harness, so the
// logic they share with these tests lives in mfaFlow.ts.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { authenticator } from 'otplib'
import {
  CODE_REPLAYED, RECOVERY_CODE_INVALID, WRONG_CODE, parseVerifyBody, pendingSecretPlan, signInOutcome,
  resetTarget, deleteTarget, confirmMatches, stepUpOk, isMfaExempt, tooManyCodesDetail, useRecoveryCode, wrongCodeDetail, type RecoveryCodeStore,
} from './mfaFlow'
import { generateRecoveryCodes, hashRecoveryCode } from './mfa'

const SECRET = 'JBSWY3DPEHPK3PXP'
const T0 = 1_700_000_027_000
const STEP = 30_000
const codeAt = (ms: number) => authenticator.clone({ epoch: ms }).generate(SECRET)

test('sign-in ends in verify for an account with MFA, in enrol for one without', () => {
  assert.equal(signInOutcome(true), 'verify')
  assert.equal(signInOutcome(false), 'enrol')
})

test('verify body: exactly one of code or recovery_code', () => {
  assert.deepEqual(parseVerifyBody({ code: '123456' }), { ok: true, input: { kind: 'code', code: '123456' } })
  assert.deepEqual(parseVerifyBody({ code: ' 123 456 ' }), { ok: true, input: { kind: 'code', code: '123456' } })
  assert.deepEqual(parseVerifyBody({ recovery_code: 'abcde-fghjk' }),
    { ok: true, input: { kind: 'recovery', recoveryCode: 'abcde-fghjk' } })
  // An empty string counts as absent (a form that sends both fields).
  assert.deepEqual(parseVerifyBody({ code: '', recovery_code: 'ABCDE-FGHJK' }),
    { ok: true, input: { kind: 'recovery', recoveryCode: 'ABCDE-FGHJK' } })

  const both = parseVerifyBody({ code: '123456', recovery_code: 'ABCDE-FGHJK' })
  assert.equal(both.ok, false)
  const neither = parseVerifyBody({})
  assert.equal(neither.ok, false)
  const blank = parseVerifyBody({ code: '  ', recovery_code: '' })
  assert.equal(blank.ok, false)
  const short = parseVerifyBody({ code: '12345' })
  assert.equal(short.ok, false)
  const letters = parseVerifyBody({ code: '12a456' })
  assert.equal(letters.ok, false)
})

test('step-up: password and code; code alone only for an account with no password', () => {
  assert.equal(stepUpOk({ hasPassword: true, passwordOk: true, codeOk: true }), true)
  assert.equal(stepUpOk({ hasPassword: true, passwordOk: false, codeOk: true }), false)
  assert.equal(stepUpOk({ hasPassword: true, passwordOk: true, codeOk: false }), false)
  assert.equal(stepUpOk({ hasPassword: true, passwordOk: false, codeOk: false }), false)
  // Google-only account (NO_PASSWORD_HASH): the code alone.
  assert.equal(stepUpOk({ hasPassword: false, passwordOk: false, codeOk: true }), true)
  assert.equal(stepUpOk({ hasPassword: false, passwordOk: false, codeOk: false }), false)
})

// The same rule as the route's SQL: UPDATE ... SET used_at = now() WHERE user_id = $1 AND
// code_hash = $2 AND used_at IS NULL RETURNING code_id.
function memoryStore(rows: { userId: string; codeHash: string; usedAt: Date | null }[]): RecoveryCodeStore {
  return {
    async markUsed(userId, codeHash) {
      const row = rows.find((r) => r.userId === userId && r.codeHash === codeHash && r.usedAt === null)
      if (!row) return false
      row.usedAt = new Date()
      return true
    },
  }
}

test('recovery code consumed once', async () => {
  const codes = generateRecoveryCodes()
  const rows = await Promise.all(codes.map(async (c) => ({ userId: 'u1', codeHash: await hashRecoveryCode(c), usedAt: null })))
  const store = memoryStore(rows)
  const code = codes[0]!

  assert.equal(await useRecoveryCode(store, 'u2', code), false)                // another account's code
  assert.equal(await useRecoveryCode(store, 'u1', code.toLowerCase().replace('-', ' ')), true)
  assert.equal(await useRecoveryCode(store, 'u1', code), false)                // second use
  assert.equal(rows.filter((r) => r.usedAt === null).length, 9)
  assert.equal(await useRecoveryCode(store, 'u1', codes[1]!), true)
  assert.equal(await useRecoveryCode(store, 'u1', 'not-a-code'), false)
  assert.equal(await useRecoveryCode(store, 'u1', ''), false)
})

test('enrol/start reuses the pending secret unless a new one is asked for', () => {
  assert.equal(pendingSecretPlan('PENDING', false), 'reuse')
  assert.equal(pendingSecretPlan('PENDING', undefined), 'reuse')
  assert.equal(pendingSecretPlan('PENDING', true), 'create')
  assert.equal(pendingSecretPlan(null, false), 'create')
  assert.equal(pendingSecretPlan(null, true), 'create')
})

test('wrong code: the clock message when the phone clock is off, else the plain one', () => {
  assert.equal(wrongCodeDetail(SECRET, codeAt(T0 - 3 * STEP - 1_000_000), T0), WRONG_CODE)
  // Past the ±10-step clock window: the plain message, not a clock hint.
  assert.equal(wrongCodeDetail(SECRET, codeAt(T0 + 11 * STEP), T0), WRONG_CODE)
  assert.equal(wrongCodeDetail(SECRET, codeAt(T0 - 11 * STEP), T0), WRONG_CODE)
  assert.equal(wrongCodeDetail(SECRET, codeAt(T0 + 4 * STEP), T0),
    "Your phone's clock is about 2 minutes off. Turn on automatic date and time on your phone, then try again.")
  assert.equal(wrongCodeDetail(SECRET, codeAt(T0 - 10 * STEP), T0),
    "Your phone's clock is about 5 minutes off. Turn on automatic date and time on your phone, then try again.")
  assert.equal(wrongCodeDetail(SECRET, codeAt(T0 + 2 * STEP), T0),
    "Your phone's clock is about 1 minute off. Turn on automatic date and time on your phone, then try again.")
})

test('lockout message names the remaining minutes', () => {
  assert.equal(tooManyCodesDetail(12), 'Too many wrong codes. Try again in 12 minutes.')
  assert.equal(tooManyCodesDetail(1), 'Too many wrong codes. Try again in 1 minute.')
})

test('fixed messages', () => {
  assert.equal(CODE_REPLAYED, 'This code was already used. Wait for the next one.')
  assert.equal(RECOVERY_CODE_INVALID, 'That recovery code is not valid.')
})

test('resetTarget: a tenant_user of this tenant is ok; self, owner, platform superadmin, other tenant are refused', () => {
  const t = (over: object) => ({ userId: 'u2', tenantId: 't1', role: 'tenant_user', ...over })
  assert.equal(resetTarget(t({}), 'u1', 't1'), 'ok')
  assert.equal(resetTarget(t({ userId: 'u1' }), 'u1', 't1'), 'refused')
  assert.equal(resetTarget(t({ role: 'tenant_superadmin' }), 'u1', 't1'), 'refused')
  assert.equal(resetTarget(t({ role: 'superadmin' }), 'u1', 't1'), 'refused')
  assert.equal(resetTarget(t({ tenantId: 't2' }), 'u1', 't1'), 'refused')
  assert.equal(resetTarget(t({ tenantId: null }), 'u1', 't1'), 'refused')
})

test('deleteTarget refuses self, owner, superadmin, other tenant', () => {
  const t = (over: object) => ({ userId: 'u2', tenantId: 't1', role: 'tenant_user', ...over })
  const caller = { userId: 'u1' }
  assert.equal(deleteTarget(caller, t({}), 't1'), 'ok')
  assert.equal(deleteTarget(caller, t({ userId: 'u1' }), 't1'), 'refused')
  assert.equal(deleteTarget(caller, t({ role: 'tenant_superadmin' }), 't1'), 'refused')
  assert.equal(deleteTarget(caller, t({ role: 'superadmin' }), 't1'), 'refused')
  assert.equal(deleteTarget(caller, t({ tenantId: 't2' }), 't1'), 'refused')
})

test('confirm_username must match exactly', () => {
  assert.equal(confirmMatches('alice', 'alice'), true)
  assert.equal(confirmMatches('Alice', 'alice'), false)
  assert.equal(confirmMatches(' alice', 'alice'), false)
  assert.equal(confirmMatches('alice ', 'alice'), false)
  assert.equal(confirmMatches('', 'alice'), false)
  assert.equal(confirmMatches(undefined, 'alice'), false)
  assert.equal(confirmMatches(null, 'alice'), false)
  assert.equal(confirmMatches(5, 'alice'), false)
})

test('isMfaExempt: listed name on staging', () => {
  const env = { MFA_EXEMPT_USERNAMES: 'admin', APP_ENV: 'staging' }
  assert.equal(isMfaExempt(env, 'admin'), true)
  assert.equal(isMfaExempt(env, 'other'), false)
  assert.equal(isMfaExempt(env, 'Admin'), false)
})

test('isMfaExempt: empty or missing var is false', () => {
  assert.equal(isMfaExempt({ APP_ENV: 'staging' }, 'admin'), false)
  assert.equal(isMfaExempt({ MFA_EXEMPT_USERNAMES: '', APP_ENV: 'staging' }, 'admin'), false)
  assert.equal(isMfaExempt({ MFA_EXEMPT_USERNAMES: 'admin', APP_ENV: 'staging' }, ''), false)
})

test('isMfaExempt: only APP_ENV staging', () => {
  assert.equal(isMfaExempt({ MFA_EXEMPT_USERNAMES: 'admin', APP_ENV: 'production' }, 'admin'), false)
  assert.equal(isMfaExempt({ MFA_EXEMPT_USERNAMES: 'admin' }, 'admin'), false)
  assert.equal(isMfaExempt({ MFA_EXEMPT_USERNAMES: 'admin', APP_ENV: 'staging' }, 'admin'), true)
})

test('isMfaExempt: MFA_EXEMPT_SUPERADMINS covers Platform Superadmins in any environment, no one else', () => {
  const env = { MFA_EXEMPT_SUPERADMINS: 'true', APP_ENV: 'production' }
  assert.equal(isMfaExempt(env, 'Prof Badrul', 'superadmin'), true)
  assert.equal(isMfaExempt({ MFA_EXEMPT_SUPERADMINS: 'true' }, 'admin', 'superadmin'), true)
  assert.equal(isMfaExempt(env, 'owner', 'tenant_superadmin'), false)
  assert.equal(isMfaExempt(env, 'user', 'tenant_user'), false)
  assert.equal(isMfaExempt(env, 'admin'), false)
  assert.equal(isMfaExempt({ APP_ENV: 'production' }, 'admin', 'superadmin'), false)
  assert.equal(isMfaExempt({ MFA_EXEMPT_SUPERADMINS: 'yes', APP_ENV: 'production' }, 'admin', 'superadmin'), false)
})

test('isMfaExempt: whitespace around names tolerated', () => {
  const env = { MFA_EXEMPT_USERNAMES: ' alice , admin ', APP_ENV: 'staging' }
  assert.equal(isMfaExempt(env, 'admin'), true)
  assert.equal(isMfaExempt(env, ' alice '), false)
  assert.equal(isMfaExempt(env, 'admin '), false)
  assert.equal(isMfaExempt(env, ' admin'), false)
  assert.equal(isMfaExempt({ MFA_EXEMPT_USERNAMES: 'admin,', APP_ENV: 'staging' }, 'admin'), true)
  assert.equal(isMfaExempt({ MFA_EXEMPT_USERNAMES: ',admin', APP_ENV: 'staging' }, 'admin'), true)
})

test('stepUpOk: password-only for an exempt account with MFA off', () => {
  assert.equal(stepUpOk({ hasPassword: true, passwordOk: true, codeOk: false, passwordOnly: true }), true)
  assert.equal(stepUpOk({ hasPassword: true, passwordOk: false, codeOk: true, passwordOnly: true }), false)
  assert.equal(stepUpOk({ hasPassword: false, passwordOk: false, codeOk: true, passwordOnly: true }), false)
  assert.equal(stepUpOk({ hasPassword: true, passwordOk: true, codeOk: false }), false)
})
