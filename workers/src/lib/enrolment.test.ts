import { test } from 'node:test'
import assert from 'node:assert/strict'
import { agentName, tokenState } from './enrolment'

const now = new Date('2026-11-09T00:00:00Z')
const later = new Date('2026-11-20T00:00:00Z')

test('an install code is active until it expires, is withdrawn or is used up', () => {
  assert.equal(tokenState({ expiresAt: later, revokedAt: null, maxUses: null, uses: 900 }, now), 'active')
  assert.equal(tokenState({ expiresAt: later, revokedAt: null, maxUses: 10, uses: 9 }, now), 'active')
  assert.equal(tokenState({ expiresAt: later, revokedAt: null, maxUses: 10, uses: 10 }, now), 'used_up')
  assert.equal(tokenState({ expiresAt: now, revokedAt: null, maxUses: null, uses: 0 }, now), 'expired')
  assert.equal(tokenState({ expiresAt: later, revokedAt: now, maxUses: 10, uses: 10 }, now), 'revoked')
})

test('the new agent is named after the computer, printable and short', () => {
  assert.equal(agentName('LAB-WIN11'), 'LAB-WIN11')
  assert.equal(agentName('  PC\u0007-01\n '), 'PC-01')
  assert.equal(agentName(''), 'New agent')
  assert.equal(agentName(undefined), 'New agent')
  assert.equal(agentName('x'.repeat(300)).length, 100)
})
