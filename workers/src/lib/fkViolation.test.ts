import { test } from 'node:test'
import assert from 'node:assert/strict'
import { isFkViolation, isUniqueViolation } from './fkViolation'

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

test('isUniqueViolation reads code, cause code and message; ignores other errors', () => {
  assert.equal(isUniqueViolation({ code: '23505' }), true)
  assert.equal(isUniqueViolation({ cause: { code: '23505' } }), true)
  assert.equal(isUniqueViolation(new Error('duplicate key value violates unique constraint "uq_x"')), true)
  assert.equal(isUniqueViolation({ code: '23503' }), false)
  assert.equal(isUniqueViolation(new Error('connection reset')), false)
  assert.equal(isUniqueViolation(null), false)
})

test('isNotNullViolation and isOwnerIndexViolation', async () => {
  const { isNotNullViolation, isOwnerIndexViolation } = await import('./fkViolation')
  assert.equal(isNotNullViolation({ code: '23502' }), true)
  assert.equal(isNotNullViolation({ message: 'null value in column "username" violates not-null constraint' }), true)
  assert.equal(isNotNullViolation({ code: '23505' }), false)
  assert.equal(isOwnerIndexViolation({ code: '23505', message: 'duplicate key value violates unique constraint "uq_users_one_tenant_superadmin"' }), true)
  assert.equal(isOwnerIndexViolation({ code: '23505', message: 'duplicate key value violates unique constraint "users_email_key"' }), false)
})
