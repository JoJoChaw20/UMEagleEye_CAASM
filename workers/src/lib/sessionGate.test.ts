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
