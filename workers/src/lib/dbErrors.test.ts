import { test } from 'node:test'
import assert from 'node:assert/strict'
import { isDatabaseUnavailable } from './dbErrors'

class NeonDbError extends Error {
  override name = 'NeonDbError'
}

test('Neon refusing or unreachable is "unavailable"', () => {
  // The message Neon gave on 23 Nov 2026 when the free compute allowance ran out
  assert.equal(isDatabaseUnavailable(new NeonDbError('Server error (HTTP status 402): {"message":"Your account or project has exceeded the quota. Upgrade your plan to increase limits."}')), true)
  assert.equal(isDatabaseUnavailable(new NeonDbError('Error connecting to database: fetch failed')), true)
  assert.equal(isDatabaseUnavailable(new NeonDbError("Couldn't connect to compute node")), true)
  assert.equal(isDatabaseUnavailable(new Error('Server error (HTTP status 503): upstream')), true)
  assert.equal(isDatabaseUnavailable(new Error('query failed', { cause: new NeonDbError('Server error (HTTP status 402): quota') })), true)
})

test('other failures are not', () => {
  assert.equal(isDatabaseUnavailable(new NeonDbError('duplicate key value violates unique constraint')), false)
  assert.equal(isDatabaseUnavailable(new NeonDbError('column "x" does not exist')), false)
  assert.equal(isDatabaseUnavailable(new Error('fetch failed')), false)           // not the database
  assert.equal(isDatabaseUnavailable(new TypeError('x is undefined')), false)
  assert.equal(isDatabaseUnavailable(null), false)
  assert.equal(isDatabaseUnavailable('HTTP status 402'), false)
})
