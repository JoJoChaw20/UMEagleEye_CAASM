import { test } from 'node:test'
import assert from 'node:assert/strict'
import { connectRefusal } from './googleConnect'

const me = { userId: 'me', googleId: null }
const verified = { email_verified: true }

test('an account without Google and a verified, unused Google account: allowed', () => {
  assert.equal(connectRefusal(me, verified, null, null), null)
  assert.equal(connectRefusal(me, verified, undefined, undefined), null)
})

test('the placeholder email of the same account is replaced, not a conflict', () => {
  assert.equal(connectRefusal(me, verified, null, { userId: 'me' }), null)
})

test('already connected: refused', () => {
  const r = connectRefusal({ userId: 'me', googleId: 'g1' }, verified, null, null)
  assert.equal(r?.status, 409)
  assert.match(r!.detail, /already connected to this account/)
})

test('unverified Google address: refused', () => {
  assert.equal(connectRefusal(me, {}, null, null)?.status, 403)
  assert.equal(connectRefusal(me, { email_verified: false }, null, null)?.status, 403)
})

test('Google account or address held by another account: refused', () => {
  assert.match(connectRefusal(me, verified, { userId: 'other' }, null)!.detail, /another EagleEye account/)
  assert.match(connectRefusal(me, verified, null, { userId: 'other' })!.detail, /belongs to another EagleEye account/)
})
