import { test } from 'node:test'
import assert from 'node:assert/strict'
import { inviteCredentials } from './passwordRules'

const STRONG = 'Start-Pass-2026!'

test('by email: as before, username optional', () => {
  assert.deepEqual(inviteCredentials({ email: 'a@b.com' }), { ok: true, email: 'a@b.com', username: undefined, password: null })
  assert.deepEqual(inviteCredentials({ email: ' a@b.com ', username: ' ann ' }), { ok: true, email: 'a@b.com', username: 'ann', password: null })
  assert.equal(inviteCredentials({ email: 'not-an-email' }).ok, false)
})

test('without email: username and a strong starting password', () => {
  assert.deepEqual(inviteCredentials({ username: 'ann', password: STRONG }), { ok: true, email: null, username: 'ann', password: STRONG })
  assert.deepEqual(inviteCredentials({ email: '', username: 'ann', password: STRONG }), { ok: true, email: null, username: 'ann', password: STRONG })
})

test('without email: missing or weak parts are refused with a reason', () => {
  assert.match((inviteCredentials({}) as { detail: string }).detail, /email, or a username and a starting password/)
  assert.match((inviteCredentials({ password: STRONG }) as { detail: string }).detail, /username is needed/)
  assert.match((inviteCredentials({ username: 'an', password: STRONG }) as { detail: string }).detail, /3 to 100/)
  assert.match((inviteCredentials({ username: 'ann', password: 'short' }) as { detail: string }).detail, /at least 12/)
  assert.match((inviteCredentials({ username: 'ann', password: 'nouppercase-2026!' }) as { detail: string }).detail, /uppercase/)
})

test('email and password together are refused', () => {
  assert.equal(inviteCredentials({ email: 'a@b.com', username: 'ann', password: STRONG }).ok, false)
})
