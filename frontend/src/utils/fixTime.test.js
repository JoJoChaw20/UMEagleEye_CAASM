import { test } from 'node:test'
import assert from 'node:assert/strict'
import { hoursText, onTimeBand, workText } from './fixTime.js'

test('hours read as minutes, hours or days', () => {
  assert.equal(hoursText(0.25), '15 min')
  assert.equal(hoursText(0.5), '30 min')
  assert.equal(hoursText(4), '4 h')
  assert.equal(hoursText(36.44), '36.4 h')
  assert.equal(hoursText(84), '3.5 days')
  assert.equal(hoursText(null), '-')
})

test('work stays in hours (it is effort, not calendar time), with working days when large', () => {
  assert.equal(workText(0.25), '15 min')
  assert.equal(workText(4.3), '4.3 h')
  assert.equal(workText(155.8), '155.8 h (19.5 working days)')
  assert.equal(workText(137), '137 h (17.1 working days)')
})

test('on-time bands', () => {
  assert.equal(onTimeBand(92), 'good')
  assert.equal(onTimeBand(60), 'fair')
  assert.equal(onTimeBand(10), 'poor')
  assert.equal(onTimeBand(null), null)
})
