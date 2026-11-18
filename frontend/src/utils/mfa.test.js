import test from 'node:test'
import assert from 'node:assert/strict'
import {
  formatRecoveryCodes, isMfaSetupRequired, isMfaTokenExpired, cleanTotpInput,
  normalizeRecoveryCode, isRecoveryCodeComplete, readRecoveryLink, loginReasonMessage,
  SIGN_IN_TOOK_TOO_LONG, SET_UP_MFA_TO_CONTINUE, isSessionEnded, recoveryCodesLeftText, lostMfaAdvice,
} from './mfa.js'

const CODES = ['ABCDE-23456', 'FGHJK-78923', 'LMNPQ-RSTUV']

test('formatRecoveryCodes lists every code on its own line under a short header', () => {
  const text = formatRecoveryCodes(CODES)
  const lines = text.split('\n')
  assert.ok(lines[0].includes('UMEagleEye'))
  for (const code of CODES) assert.ok(lines.includes(code), `missing ${code}`)
  assert.ok(/once/i.test(text), 'says each code works once')
  assert.ok(text.endsWith('\n'))
  // the codes keep their order and come last
  assert.deepEqual(lines.slice(-CODES.length - 1, -1), CODES)
})

test('formatRecoveryCodes copes with no codes', () => {
  assert.equal(typeof formatRecoveryCodes([]), 'string')
  assert.equal(typeof formatRecoveryCodes(undefined), 'string')
})

test('isMfaSetupRequired is true only for 403 with mfa_setup_required', () => {
  assert.equal(isMfaSetupRequired({ status: 403, data: { detail: 'Set up MFA to continue.', mfa_setup_required: true } }), true)
  assert.equal(isMfaSetupRequired({ status: 403, data: { missing_action: 'asset.view' } }), false)
  assert.equal(isMfaSetupRequired({ status: 401, data: { mfa_setup_required: true } }), false)
  assert.equal(isMfaSetupRequired({ status: 403, data: { mfa_setup_required: 'yes' } }), false)
  assert.equal(isMfaSetupRequired({ status: 403 }), false)
  assert.equal(isMfaSetupRequired(undefined), false)
  assert.equal(isMfaSetupRequired(null), false)
})

test('isMfaTokenExpired matches the 401 sign-in-expired answer only', () => {
  assert.equal(isMfaTokenExpired({ status: 401, data: { detail: 'Your sign-in has expired. Sign in again.' } }), true)
  assert.equal(isMfaTokenExpired({ status: 401, data: { detail: 'That code is not correct. Enter the code your authenticator app shows now.' } }), false)
  assert.equal(isMfaTokenExpired({ status: 400, data: { detail: 'Your sign-in has expired. Sign in again.' } }), false)
  assert.equal(isMfaTokenExpired(undefined), false)
  assert.equal(SIGN_IN_TOOK_TOO_LONG, 'The sign-in took too long. Sign in again.')
})

test('cleanTotpInput keeps at most 6 digits', () => {
  assert.equal(cleanTotpInput('123 456'), '123456')
  assert.equal(cleanTotpInput('12-34-56-78'), '123456')
  assert.equal(cleanTotpInput('abc'), '')
  assert.equal(cleanTotpInput(''), '')
  assert.equal(cleanTotpInput(undefined), '')
})

test('normalizeRecoveryCode accepts any case, spaces and dashes', () => {
  assert.equal(normalizeRecoveryCode('abcde-23456'), 'ABCDE23456')
  assert.equal(normalizeRecoveryCode('  AbCdE 23456 '), 'ABCDE23456')
  assert.equal(normalizeRecoveryCode('ab-cd-e2-34-56'), 'ABCDE23456')
  assert.equal(normalizeRecoveryCode(undefined), '')
})

test('isRecoveryCodeComplete needs 10 characters after normalising', () => {
  assert.equal(isRecoveryCodeComplete('abcde-23456'), true)
  assert.equal(isRecoveryCodeComplete('ABCDE 2345'), false)
  assert.equal(isRecoveryCodeComplete('ABCDE-234567'), false)
  assert.equal(isRecoveryCodeComplete(''), false)
})

test('readRecoveryLink reads one confirm or cancel token', () => {
  assert.deepEqual(readRecoveryLink('?confirm=abc_-1'), { action: 'confirm', token: 'abc_-1' })
  assert.deepEqual(readRecoveryLink('?cancel=xyz'), { action: 'cancel', token: 'xyz' })
  assert.deepEqual(readRecoveryLink('cancel=xyz'), { action: 'cancel', token: 'xyz' })
  assert.equal(readRecoveryLink(''), null)
  assert.equal(readRecoveryLink('?confirm='), null)
  assert.equal(readRecoveryLink('?confirm=a&cancel=b'), null)
  assert.equal(readRecoveryLink(undefined), null)
})

test('loginReasonMessage maps the redirect reasons', () => {
  assert.equal(loginReasonMessage('mfa_setup'), SET_UP_MFA_TO_CONTINUE)
  assert.equal(SET_UP_MFA_TO_CONTINUE, 'Set up MFA to continue.')
  assert.equal(loginReasonMessage('deactivated'), 'Your account is deactivated. Contact your Tenant Superadmin.')
  assert.equal(loginReasonMessage('other'), '')
  assert.equal(loginReasonMessage(null), '')
})

test('isSessionEnded is true only for the session-level 401 texts', () => {
  for (const detail of [
    'Missing or invalid Authorization header',
    'Token expired or invalid',
    'Your session has ended. Sign in again.',
    'Your account is deactivated. Contact your Tenant Superadmin.',
  ]) assert.equal(isSessionEnded(401, detail), true, detail)
  // step-up and code refusals are shown by the screen that asked
  assert.equal(isSessionEnded(401, 'Your password is not correct.'), false)
  assert.equal(isSessionEnded(401, 'That code is not correct. Enter the code your authenticator app shows now.'), false)
  assert.equal(isSessionEnded(401, 'Your sign-in has expired. Sign in again.'), false)
  assert.equal(isSessionEnded(401, 'Invalid credentials'), false)
  assert.equal(isSessionEnded(401, undefined), false)
  assert.equal(isSessionEnded(401, ''), false)
  assert.equal(isSessionEnded(403, 'Token expired or invalid'), false)
  assert.equal(isSessionEnded(500, 'Your session has ended. Sign in again.'), false)
})

test('recoveryCodesLeftText counts the codes left and warns at 2 or fewer', () => {
  const warn = 'You are running out of recovery codes. Ask your Tenant Superadmin to reset your MFA so you can set up your authenticator again.'
  assert.deepEqual(recoveryCodesLeftText(5, 'tenant_user'), {
    message: 'Signed in with a recovery code. You have 5 recovery codes left.', warning: '',
  })
  assert.deepEqual(recoveryCodesLeftText(3, 'tenant_user').warning, '')
  assert.deepEqual(recoveryCodesLeftText(2, 'tenant_user'), {
    message: 'Signed in with a recovery code. You have 2 recovery codes left.', warning: warn,
  })
  assert.deepEqual(recoveryCodesLeftText(1, 'tenant_user'), {
    message: 'Signed in with a recovery code. You have 1 recovery code left.', warning: warn,
  })
  assert.deepEqual(recoveryCodesLeftText(0, 'tenant_user'), {
    message: 'Signed in with a recovery code. You have 0 recovery codes left.', warning: warn,
  })
})

test('recoveryCodesLeftText warns by role: only a tenant user is sent to the Tenant Superadmin', () => {
  assert.equal(recoveryCodesLeftText(1, 'tenant_superadmin').warning,
    'You are running out of recovery codes. If you have none left and cannot use your authenticator, contact platform support.')
  assert.equal(recoveryCodesLeftText(1, 'superadmin').warning,
    'You are running out of recovery codes. Use your backup device, then get new recovery codes in Settings.')
  assert.equal(recoveryCodesLeftText(5, 'superadmin').warning, '')
  // Unknown role: the tenant-user text.
  assert.match(recoveryCodesLeftText(1).warning, /Ask your Tenant Superadmin/)
})

test('lostMfaAdvice names who can help, by role', () => {
  assert.equal(lostMfaAdvice('tenant_user'), 'Ask your Tenant Superadmin to reset your MFA.')
  assert.equal(lostMfaAdvice('tenant_superadmin'), 'Use a recovery code. If you have none, contact platform support.')
  assert.equal(lostMfaAdvice('superadmin'), 'Use your backup device or a recovery code.')
  assert.equal(lostMfaAdvice(undefined), 'Ask your Tenant Superadmin to reset your MFA.')
  for (const role of ['tenant_user', 'tenant_superadmin', 'superadmin']) {
    assert.doesNotMatch(lostMfaAdvice(role), /emergency recovery/i)
  }
})

import {
  needsPasswordForStepUp, stepUpReady, stepUpBody, recoveryCodesLeftLabel, mfaResetToast, MFA_RESET_GUIDANCE,
} from './mfa.js'

test('needsPasswordForStepUp is false only for an account known to have no password', () => {
  assert.equal(needsPasswordForStepUp({ hasPassword: true }), true)
  assert.equal(needsPasswordForStepUp({ hasPassword: false }), false)
  assert.equal(needsPasswordForStepUp({}), true)
  assert.equal(needsPasswordForStepUp(null), true)
})

test('stepUpReady needs a 6-digit code, and a password when the account has one', () => {
  assert.equal(stepUpReady({ hasPassword: true, password: 'x', code: '123456' }), true)
  assert.equal(stepUpReady({ hasPassword: true, password: '', code: '123456' }), false)
  assert.equal(stepUpReady({ hasPassword: true, password: 'x', code: '12345' }), false)
  assert.equal(stepUpReady({ hasPassword: false, password: '', code: '123456' }), true)
  assert.equal(stepUpReady({ hasPassword: false, password: '', code: '' }), false)
})

test('stepUpBody leaves the password out for an account without one', () => {
  assert.deepEqual(stepUpBody({ hasPassword: true, password: 'pw', code: '123456' }), { password: 'pw', code: '123456' })
  assert.deepEqual(stepUpBody({ hasPassword: false, password: 'pw', code: '123456' }), { code: '123456' })
})

test('recoveryCodesLeftLabel pluralises', () => {
  assert.equal(recoveryCodesLeftLabel(10), '10 recovery codes left')
  assert.equal(recoveryCodesLeftLabel(1), '1 recovery code left')
  assert.equal(recoveryCodesLeftLabel(0), '0 recovery codes left')
})

test('mfaResetToast and guidance are verbatim', () => {
  assert.equal(mfaResetToast('Sam'), 'MFA reset. Sam must set it up at their next sign-in.')
  assert.equal(MFA_RESET_GUIDANCE, 'Confirm this request in person or by phone. Do not reset MFA based only on an email or chat message, because these are common ways attackers take over accounts.')
})

test('exempt account: password only, no code sent', async () => {
  const { isMfaExemptUser } = await import('./mfa.js')
  assert.equal(isMfaExemptUser({ mfa_exempt: true, mfaEnabled: false }), true)
  assert.equal(isMfaExemptUser({ mfa_exempt: true, mfaEnabled: true }), false)
  assert.equal(isMfaExemptUser({ mfa_exempt: false, mfaEnabled: false }), false)
  assert.equal(isMfaExemptUser({}), false)
  assert.equal(stepUpReady({ hasPassword: true, password: 'x', code: '', mfaExempt: true }), true)
  assert.equal(stepUpReady({ hasPassword: true, password: '', code: '123456', mfaExempt: true }), false)
  assert.equal(stepUpReady({ hasPassword: false, password: '', code: '', mfaExempt: true }), false)
  assert.deepEqual(stepUpBody({ hasPassword: true, password: 'pw', code: '123456', mfaExempt: true }), { password: 'pw' })
})
