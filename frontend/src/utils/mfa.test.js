import test from 'node:test'
import assert from 'node:assert/strict'
import {
  formatRecoveryCodes, isMfaSetupRequired, isMfaTokenExpired, cleanTotpInput,
  normalizeRecoveryCode, isRecoveryCodeComplete, readRecoveryLink, loginReasonMessage,
  SIGN_IN_TOOK_TOO_LONG, SET_UP_MFA_TO_CONTINUE,
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
