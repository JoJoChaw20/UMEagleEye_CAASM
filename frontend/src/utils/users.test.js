import test from 'node:test'
import assert from 'node:assert/strict'
import { canConfirmDelete } from './users.js'

const base = { typed: 'alice', username: 'alice', code: '123456', needsPassword: true, password: 'pw' }

test('canConfirmDelete passes when everything is filled in', () => {
  assert.equal(canConfirmDelete(base), true)
})
test('canConfirmDelete needs the username to match exactly (case, spaces)', () => {
  assert.equal(canConfirmDelete({ ...base, typed: 'Alice' }), false)
  assert.equal(canConfirmDelete({ ...base, typed: 'alice ' }), false)
  assert.equal(canConfirmDelete({ ...base, typed: '' }), false)
})
test('canConfirmDelete needs a 6-digit code', () => {
  assert.equal(canConfirmDelete({ ...base, code: '12345' }), false)
  assert.equal(canConfirmDelete({ ...base, code: '' }), false)
})
test('canConfirmDelete needs a password only when the account has one', () => {
  assert.equal(canConfirmDelete({ ...base, password: '' }), false)
  assert.equal(canConfirmDelete({ ...base, needsPassword: false, password: '' }), true)
})
test('canConfirmDelete refuses an empty username', () => {
  assert.equal(canConfirmDelete({ ...base, typed: '', username: '' }), false)
})
