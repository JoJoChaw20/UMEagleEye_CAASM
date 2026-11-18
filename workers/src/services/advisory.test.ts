import { test } from 'node:test'
import assert from 'node:assert/strict'
import { shouldRetryForLength } from './advisory'

test('shouldRetryForLength retries only on a token-limit cut-off', () => {
  assert.equal(shouldRetryForLength('length'), true)
  assert.equal(shouldRetryForLength('stop'), false)
  assert.equal(shouldRetryForLength(null), false)
  assert.equal(shouldRetryForLength(undefined), false)
})
