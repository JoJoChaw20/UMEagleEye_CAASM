import { test } from 'node:test'
import assert from 'node:assert/strict'
import { agentLiveness } from './agentLiveness'

test('a phone that checks in every 15 minutes is online between check-ins; a computer agent is not', () => {
  const now = Date.parse('2026-11-09T15:30:00Z')
  const ago = (min: number) => new Date(now - min * 60_000)
  assert.equal(agentLiveness(ago(14), 'mobile', now), 'online')
  assert.equal(agentLiveness(ago(25), 'mobile', now), 'online')              // a dozing phone's usual gap
  assert.equal(agentLiveness(ago(40), 'mobile', now), 'degraded')
  assert.equal(agentLiveness(ago(61), 'mobile', now), 'degraded')            // dozing
  assert.equal(agentLiveness(ago(361), 'mobile', now), 'offline')
  assert.equal(agentLiveness(ago(1), 'host', now), 'online')
  assert.equal(agentLiveness(ago(5), 'host', now), 'degraded')
  assert.equal(agentLiveness(ago(14), 'network', now), 'offline')
  assert.equal(agentLiveness(null, 'mobile', now), 'offline')
})
