import { test } from 'node:test'
import assert from 'node:assert/strict'
import { HubState, REVALIDATE_MS, SPREAD_MS, reportKey, spreadOf, type HubRemember } from './agentHub'

const A = '11111111-1111-1111-1111-111111111111'
const B = '22222222-2222-2222-2222-222222222222'
const answer = { ok: true as const, policy: { local_scans: false, managed: { sbom: true }, version: 'v1' } }
const base = (over: Partial<HubRemember> = {}): HubRemember => ({
  tenantId: 't1', keyHash: 'k', report: reportKey({ version: '0.1.0', build: 'b1' }), publicIp: '203.106.93.7',
  answer, jobsWaiting: false, ...over,
})

test('an unknown agent takes the slow path; once remembered, the same check-in hits', () => {
  const h = new HubState()
  assert.deepEqual(h.check(A, 'k', base().report, '203.106.93.7', 1000), { hit: false })
  h.remember(A, base(), 1000)
  assert.deepEqual(h.check(A, 'k', base().report, '203.106.93.7', 31_000), { hit: true, answer })
  assert.deepEqual(h.takeDirty(), [{ agentId: A, lastSeen: 31_000 }])
  assert.deepEqual(h.takeDirty(), [])
})

test('a different key, report or public address, or jobs waiting, take the slow path', () => {
  const h = new HubState()
  h.remember(A, base(), 0)
  assert.equal(h.check(A, 'other', base().report, '203.106.93.7', 1).hit, false)
  assert.equal(h.check(A, 'k', reportKey({ version: '0.1.0', build: 'b2' }), '203.106.93.7', 1).hit, false)
  assert.equal(h.check(A, 'k', base().report, '203.106.93.8', 1).hit, false)
  h.remember(B, base({ jobsWaiting: true }), 0)
  assert.equal(h.check(B, 'k', base().report, '203.106.93.7', 1).hit, false)
  assert.equal(h.hasDirty(), false)
})

test('the cached answer is rebuilt after REVALIDATE_MS plus the agent spread', () => {
  const h = new HubState()
  h.remember(A, base(), 0)
  const edge = REVALIDATE_MS + spreadOf(A)
  assert.equal(h.check(A, 'k', base().report, '203.106.93.7', edge - 1).hit, true)
  assert.equal(h.check(A, 'k', base().report, '203.106.93.7', edge).hit, false)
  assert.ok(spreadOf(A) >= 0 && spreadOf(A) < SPREAD_MS)
})

test('invalidate by agent, tenant or all; an unsaved last-seen survives it for the flush', () => {
  const h = new HubState()
  h.remember(A, base(), 0)
  h.remember(B, base({ tenantId: 't2' }), 0)
  h.check(A, 'k', base().report, '203.106.93.7', 5)            // A now has an unsaved last-seen
  assert.equal(h.invalidate({ tenantId: 't1' }), 1)
  assert.equal(h.check(A, 'k', base().report, '203.106.93.7', 6).hit, false)
  assert.deepEqual(h.takeDirty(), [{ agentId: A, lastSeen: 5 }])
  assert.equal(h.check(B, 'k', base().report, '203.106.93.7', 6).hit, true)
  assert.equal(h.invalidate({ agentIds: [B] }), 1)
  assert.equal(h.check(B, 'k', base().report, '203.106.93.7', 7).hit, false)
  h.remember(A, base(), 8)
  assert.equal(h.invalidate({ all: true }), 2)                    // A, and B kept for its unsaved time
  assert.deepEqual(h.takeDirty(), [{ agentId: B, lastSeen: 6 }])
})

test('a failed flush puts the times back, unless a newer check-in came', () => {
  const h = new HubState()
  h.remember(A, base(), 0)
  h.remember(B, base(), 0)
  h.check(A, 'k', base().report, '203.106.93.7', 10)
  h.check(B, 'k', base().report, '203.106.93.7', 10)
  const taken = h.takeDirty()
  h.check(B, 'k', base().report, '203.106.93.7', 20)
  h.restore(taken)
  assert.deepEqual(h.takeDirty().sort((x, y) => x.agentId.localeCompare(y.agentId)),
    [{ agentId: A, lastSeen: 10 }, { agentId: B, lastSeen: 20 }])
})

test('reportKey ignores key order and undefined fields', () => {
  assert.equal(reportKey({ a: 1, b: { y: 2, x: [1, 'z'] } }), reportKey({ b: { x: [1, 'z'], y: 2 }, a: 1, c: undefined }))
  assert.notEqual(reportKey({ a: 1 }), reportKey({ a: 2 }))
})
