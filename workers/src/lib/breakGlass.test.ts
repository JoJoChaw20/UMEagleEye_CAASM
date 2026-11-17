import { test } from 'node:test'
import assert from 'node:assert/strict'
import { breakGlassEligible, nextState } from './breakGlass'

const ok = { role: 'superadmin', active: true, passwordOk: true, secretSet: true, secretMatches: true, secretUsedBefore: false }

test('eligible only when every condition holds', () => {
  assert.equal(breakGlassEligible(ok), true)
  assert.equal(breakGlassEligible({ ...ok, role: 'tenant_superadmin' }), false)
  assert.equal(breakGlassEligible({ ...ok, role: 'user' }), false)
  assert.equal(breakGlassEligible({ ...ok, active: false }), false)
  assert.equal(breakGlassEligible({ ...ok, passwordOk: false }), false)
  assert.equal(breakGlassEligible({ ...ok, secretSet: false }), false)
  assert.equal(breakGlassEligible({ ...ok, secretMatches: false }), false)
  assert.equal(breakGlassEligible({ ...ok, secretUsedBefore: true }), false)
})

const now = new Date('2026-11-18T12:00:00Z')
const past = new Date('2026-11-18T11:00:00Z')
const future = new Date('2026-11-19T11:00:00Z')

test('confirm only from requested', () => {
  assert.equal(nextState('requested', 'confirm', now, null), 'confirmed')
  for (const s of ['confirmed', 'cancelled', 'done']) assert.equal(nextState(s, 'confirm', now, future), null, s)
})

test('cancel from requested or confirmed', () => {
  assert.equal(nextState('requested', 'cancel', now, null), 'cancelled')
  assert.equal(nextState('confirmed', 'cancel', now, future), 'cancelled')
  assert.equal(nextState('done', 'cancel', now, past), null)
  assert.equal(nextState('cancelled', 'cancel', now, past), null)
})

test('apply only when confirmed and due', () => {
  assert.equal(nextState('confirmed', 'apply', now, past), 'done')
  assert.equal(nextState('confirmed', 'apply', now, now), 'done')
  assert.equal(nextState('confirmed', 'apply', now, future), null)
  assert.equal(nextState('confirmed', 'apply', now, null), null)
  assert.equal(nextState('requested', 'apply', now, past), null)
})

test('a done or cancelled row cannot move', () => {
  for (const s of ['done', 'cancelled']) {
    for (const a of ['confirm', 'cancel', 'apply'] as const) assert.equal(nextState(s, a, now, past), null, `${s} ${a}`)
  }
})

test('an unknown status cannot move', () => {
  assert.equal(nextState('weird', 'confirm', now, past), null)
})
