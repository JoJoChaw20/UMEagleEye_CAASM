import { test } from 'node:test'
import assert from 'node:assert/strict'
import { isDeactivated, sessionGate } from './sessionGate'

const ROW = { isActive: true, mfaEnabled: true, sessionsValidAfter: null as Date | null, scheduledDeactivationAt: null as Date | null }
const DATA = '/api/v1/assets'

test('mfa purpose token is not an access token', () => {
  const r = sessionGate({ iat: 100, purpose: 'mfa' }, ROW, DATA)
  assert.equal(r?.status, 401)
  assert.equal(r?.body.detail, 'Token expired or invalid')
})

test('token issued before sessions_valid_after is refused', () => {
  const cut = new Date(1_000_000)  // 1000 s
  const old = sessionGate({ iat: 999 }, { ...ROW, sessionsValidAfter: cut }, DATA)
  assert.equal(old?.status, 401)
  assert.equal(old?.body.detail, 'Your session has ended. Sign in again.')
  assert.equal(sessionGate({ iat: 1000 }, { ...ROW, sessionsValidAfter: cut }, DATA), null)
  assert.equal(sessionGate({ iat: 1001 }, { ...ROW, sessionsValidAfter: cut }, DATA), null)
})

test('account without MFA is refused outside /auth', () => {
  const row = { ...ROW, mfaEnabled: false }
  const r = sessionGate({ iat: 1 }, row, DATA)
  assert.equal(r?.status, 403)
  assert.deepEqual(r?.body, { detail: 'Set up MFA to continue.', mfa_setup_required: true })
  assert.equal(sessionGate({ iat: 1 }, row, '/api/v1/auth/me'), null)
})

test('deactivated account still gets the deactivation message', () => {
  const r = sessionGate({ iat: 1 }, { ...ROW, isActive: false }, DATA)
  assert.equal(r?.status, 401)
  assert.equal(r?.body.detail, 'Your account is deactivated. Contact your Tenant Superadmin.')
})

test('healthy account passes', () => {
  assert.equal(sessionGate({ iat: 1 }, ROW, DATA), null)
})

test('scheduled deactivation: refused from the moment it is due, with the deactivation message', () => {
  const at = new Date(5_000_000)
  const row = { ...ROW, scheduledDeactivationAt: at }
  const before = sessionGate({ iat: 1 }, row, DATA, new Date(4_999_999))
  assert.equal(before, null)
  for (const now of [new Date(5_000_000), new Date(6_000_000)]) {
    const r = sessionGate({ iat: 1 }, row, DATA, now)
    assert.equal(r?.status, 401)
    assert.equal(r?.body.detail, 'Your account is deactivated. Contact your Tenant Superadmin.')
  }
})

test('isDeactivated: inactive, or scheduled time reached', () => {
  const now = new Date(1000)
  assert.equal(isDeactivated({ isActive: true, scheduledDeactivationAt: null }, now), false)
  assert.equal(isDeactivated({ isActive: false, scheduledDeactivationAt: null }, now), true)
  assert.equal(isDeactivated({ isActive: true, scheduledDeactivationAt: new Date(1001) }, now), false)
  assert.equal(isDeactivated({ isActive: true, scheduledDeactivationAt: new Date(1000) }, now), true)
  assert.equal(isDeactivated({ isActive: null, scheduledDeactivationAt: undefined }, now), true)
})

test('exempt account without MFA passes outside /auth; non-exempt is still refused', () => {
  const row = { ...ROW, mfaEnabled: false }
  assert.equal(sessionGate({ iat: 1 }, row, DATA, new Date(), true), null)
  assert.equal(sessionGate({ iat: 1 }, row, DATA, new Date(), false)?.status, 403)
})

test('starting password: refused outside /auth until changed, MFA-exempt or not', () => {
  const row = { ...ROW, passwordChangeRequired: true }
  const r = sessionGate({ iat: 1 }, row, DATA)
  assert.equal(r?.status, 403)
  assert.deepEqual(r?.body, { detail: 'Choose your own password to continue.', password_change_required: true })
  assert.equal(sessionGate({ iat: 1 }, row, DATA, new Date(), true)?.status, 403)
  assert.equal(sessionGate({ iat: 1 }, row, '/api/v1/auth/me'), null)
  assert.equal(sessionGate({ iat: 1 }, row, '/api/v1/auth/change-password'), null)
  assert.equal(sessionGate({ iat: 1 }, { ...ROW, passwordChangeRequired: false }, DATA), null)
})

test('MFA setup is asked before the password change', () => {
  const r = sessionGate({ iat: 1 }, { ...ROW, mfaEnabled: false, passwordChangeRequired: true }, DATA)
  assert.equal(r?.body.mfa_setup_required, true)
})

test('exempt account is still refused when deactivated or session ended', () => {
  const row = { ...ROW, mfaEnabled: false }
  assert.equal(sessionGate({ iat: 1 }, { ...row, isActive: false }, DATA, new Date(), true)?.status, 401)
  assert.equal(sessionGate({ iat: 1 }, { ...row, sessionsValidAfter: new Date(5000) }, DATA, new Date(), true)?.status, 401)
  assert.equal(sessionGate({ iat: 1, purpose: 'mfa' }, row, DATA, new Date(), true)?.status, 401)
})
