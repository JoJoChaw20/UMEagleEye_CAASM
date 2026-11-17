import { test } from 'node:test'
import assert from 'node:assert/strict'
import { isFkViolation } from './fkViolation'

test('detects code on the error', () => assert.equal(isFkViolation({ code: '23503' }), true))
test('detects code on the cause', () => assert.equal(isFkViolation({ cause: { code: '23503' } }), true))
test('detects by message', () => {
  assert.equal(isFkViolation(new Error('update or delete on table "users" violates foreign key constraint "x"')), true)
})
test('ignores other errors', () => {
  assert.equal(isFkViolation({ code: '23505' }), false)
  assert.equal(isFkViolation(new Error('boom')), false)
  assert.equal(isFkViolation(null), false)
  assert.equal(isFkViolation('x'), false)
})
