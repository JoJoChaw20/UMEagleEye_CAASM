import { test } from 'node:test'
import assert from 'node:assert/strict'
import { confidenceLevel } from './confidence'

test('confidence levels: 75% and up sure, 50% likely, below weak; none recorded counts as sure', () => {
  assert.equal(confidenceLevel(1), 3)
  assert.equal(confidenceLevel('0.75'), 3)
  assert.equal(confidenceLevel(0.74), 2)
  assert.equal(confidenceLevel(0.5), 2)
  assert.equal(confidenceLevel(0.49), 1)
  assert.equal(confidenceLevel(0), 1)
  assert.equal(confidenceLevel(null), 3)
  assert.equal(confidenceLevel(undefined), 3)
})
