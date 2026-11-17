import { test } from 'node:test'
import assert from 'node:assert/strict'
import { getDb } from '../db/client'
import {
  validateTransfer, validateRecoveryPlan, transferNext, recoveryNext, approverSlot,
  swapStatements, ownershipChangedNotice, restoredNotice, HOURS_72,
} from './ownership'

const db = getDb('postgres://u:p@localhost/none')   // builds queries only; nothing connects
const now = new Date('2026-11-18T00:00:00Z')
const T = 'tenant-a'
const to = { userId: 'u2', tenantId: T, isActive: true, role: 'tenant_user' }
const base = { ownerId: 'o', toUser: to, tenantId: T, after: { mode: 'stay', actions: [] as string[] }, now }
const plus = (ms: number) => new Date(now.getTime() + ms)

test('transfer recipient rules', () => {
  assert.equal(validateTransfer(base), null)
  assert.ok(validateTransfer({ ...base, toUser: { ...to, userId: 'o' } }))
  assert.ok(validateTransfer({ ...base, toUser: { ...to, isActive: false } }))
  assert.ok(validateTransfer({ ...base, toUser: { ...to, tenantId: 'other' } }))
  assert.ok(validateTransfer({ ...base, toUser: { ...to, role: 'superadmin' } }))
  assert.ok(validateTransfer({ ...base, toUser: { ...to, role: 'tenant_superadmin' } }))
})

test('transfer mode and actions are checked', () => {
  assert.ok(validateTransfer({ ...base, after: { mode: 'bogus' } }))
  assert.ok(validateTransfer({ ...base, after: { mode: 'stay', actions: ['not_an_action'] } }))
  assert.equal(validateTransfer({ ...base, after: { mode: 'deactivate_now' } }), null)
})

test('deactivate_on must be in the future', () => {
  const mk = (d?: Date) => ({ ...base, after: { mode: 'deactivate_on', actions: [], deactivateOn: d } })
  assert.equal(validateTransfer(mk(plus(1000))), null)
  assert.equal(validateTransfer(mk(now)), 'deactivate_on must be in the future')
  assert.equal(validateTransfer(mk(plus(-1000))), 'deactivate_on must be in the future')
  assert.equal(validateTransfer(mk(undefined)), 'deactivate_on must be in the future')
})

test('recovery plan needs three distinct active tenant users, none the owner', () => {
  const u = (id: string, extra = {}) => ({ userId: id, tenantId: T, isActive: true, role: 'tenant_user', ...extra })
  const ok = { ownerId: 'o', successor: u('s'), approvers: [u('a'), u('b')] as [any, any], tenantId: T }
  assert.equal(validateRecoveryPlan(ok), null)
  assert.ok(validateRecoveryPlan({ ...ok, approvers: [u('a'), u('a')] }))
  assert.ok(validateRecoveryPlan({ ...ok, approvers: [u('a'), u('s')] }))
  assert.ok(validateRecoveryPlan({ ...ok, successor: u('o') }))
  assert.ok(validateRecoveryPlan({ ...ok, approvers: [u('a', { isActive: false }), u('b')] }))
  assert.ok(validateRecoveryPlan({ ...ok, successor: u('s', { isActive: false }) }))
  assert.ok(validateRecoveryPlan({ ...ok, approvers: [u('a', { tenantId: 'x' }), u('b')] }))
})

test('transferNext moves only pending; expired accept/decline refused', () => {
  const exp = plus(HOURS_72)
  assert.equal(transferNext('pending', 'accept', now, exp), 'accepted')
  assert.equal(transferNext('pending', 'decline', now, exp), 'declined')
  assert.equal(transferNext('pending', 'cancel', now, exp), 'cancelled')
  assert.equal(transferNext('pending', 'expire', now, exp), 'expired')
  assert.equal(transferNext('accepted', 'cancel', now, exp), null)
  assert.equal(transferNext('pending', 'accept', plus(HOURS_72 + 1), exp), null)
  assert.equal(transferNext('pending', 'decline', plus(HOURS_72 + 1), exp), null)
  assert.equal(transferNext('pending', 'cancel', plus(HOURS_72 + 1), exp), 'cancelled')
})

const rec = (reason: string, extra = {}) => ({
  status: 'awaiting_approval', reason, approver1At: null as Date | null, approver2At: null as Date | null,
  expiresAt: plus(HOURS_72), holdUntil: null as Date | null, ...extra,
})

test('recovery: two approvals, all four reasons', () => {
  for (const reason of ['terminated', 'compromised']) {
    const one = recoveryNext(rec(reason), 'approve1', now)!
    assert.equal(one.status, 'awaiting_approval')
    const two = recoveryNext({ ...rec(reason), ...one }, 'approve2', now)!
    assert.equal(two.status, 'complete_now')
    assert.equal(two.holdUntil, null)
  }
  for (const reason of ['resigned', 'unreachable']) {
    const one = recoveryNext(rec(reason), 'approve2', now)!
    const two = recoveryNext({ ...rec(reason), ...one }, 'approve1', now)!
    assert.equal(two.status, 'on_hold')
    assert.equal(two.holdUntil!.getTime(), now.getTime() + HOURS_72)
  }
})

test('approvals need two distinct approvers, not the successor (no double approve)', () => {
  const one = recoveryNext(rec('resigned'), 'approve1', now)!
  assert.equal(recoveryNext({ ...rec('resigned'), ...one }, 'approve1', now), null)
})

test('expired transitions are refused', () => {
  const late = plus(HOURS_72 + 1)
  assert.equal(recoveryNext(rec('terminated'), 'approve1', late), null)
  assert.equal(recoveryNext(rec('terminated'), 'approve2', late), null)
  assert.equal(transferNext('pending', 'accept', late, plus(HOURS_72)), null)
})

test('owner cancel: disputes a hold, cancels an open request', () => {
  const hold = rec('resigned', { status: 'on_hold', approver1At: now, approver2At: now, holdUntil: plus(HOURS_72) })
  assert.equal(recoveryNext(hold, 'cancel_by_owner', plus(1000))!.status, 'disputed')
  assert.equal(recoveryNext(rec('resigned'), 'cancel_by_owner', now)!.status, 'cancelled')
  assert.equal(recoveryNext({ ...hold, status: 'complete_now' }, 'cancel_by_owner', now), null)
})

test('settle completes on_hold after 72h only', () => {
  const hold = rec('resigned', { status: 'on_hold', approver1At: now, approver2At: now, holdUntil: plus(HOURS_72) })
  assert.equal(recoveryNext(hold, 'settle', plus(HOURS_72 - 1)), null)
  assert.equal(recoveryNext(hold, 'settle', plus(HOURS_72))!.status, 'complete_now')
  const open = rec('resigned')
  assert.equal(recoveryNext(open, 'settle', plus(HOURS_72 - 1)), null)
  assert.equal(recoveryNext(open, 'settle', plus(HOURS_72 + 1))!.status, 'expired')
})

test('approverSlot: successor and strangers get null', () => {
  const plan = { successorId: 's', approver1Id: 'a', approver2Id: 'b' }
  assert.equal(approverSlot(plan, 'a', 's'), 'approver1')
  assert.equal(approverSlot(plan, 'b', 's'), 'approver2')
  assert.equal(approverSlot(plan, 's', 's'), null)
  assert.equal(approverSlot(plan, 'x', 's'), null)
  assert.equal(approverSlot({ ...plan, approver1Id: 's' }, 's', 's'), null)
})

test('swap runs demote before promote in one transaction (statement order)', () => {
  const d = new Date('2026-12-01T00:00:00Z')
  const s = swapStatements(T, 'o', 'n', { mode: 'deactivate_on', actions: ['a'], deactivateOn: d })
  assert.deepEqual(s.map((x) => x.label), ['demote', 'promote'])
  assert.deepEqual(s[0].set, { role: 'tenant_user', actions: ['a'], isActive: true, scheduledDeactivationAt: d })
  assert.equal(s[0].userId, 'o')
  assert.deepEqual(s[1].set, { role: 'tenant_superadmin', actions: [] })
  assert.equal(s[1].userId, 'n')
  const gone = swapStatements(T, 'o', 'n', { mode: 'deactivate_now' })
  assert.equal(gone[0].set.isActive, false)
  assert.equal(gone[0].set.scheduledDeactivationAt, null)
  const stay = swapStatements(T, 'o', 'n', { mode: 'stay' })
  assert.deepEqual(stay[0].set.actions, [])
  const q = s.map((x) => (x.build(db) as unknown as { toSQL(): { sql: string; params: unknown[] } }).toSQL())
  for (const { sql } of q) {
    assert.match(sql, /^update "users"/)
    assert.match(sql, /"user_id" = \$\d+/)
    assert.match(sql, /"tenant_id" = \$\d+/)
    assert.match(sql, /"role" = \$\d+/)
    assert.match(sql, /returning "user_id"/)
  }
  assert.ok(q[0].params.includes('o') && q[0].params.includes('tenant_superadmin') && q[0].params.includes(T))
  assert.ok(q[1].params.includes('n') && q[1].params.includes('tenant_user') && q[1].params.includes(T))
  assert.throws(() => swapStatements(T, 'o', 'n', { mode: 'bogus' }), /Unknown after mode/)
})

test('notice texts verbatim', () => {
  assert.equal(ownershipChangedNotice('Ann', 'Bob', '18 Nov 2026'), 'Tenant ownership changed from Ann to Bob on 18 Nov 2026.')
  assert.equal(restoredNotice('18 Nov 2026'), 'Ownership of this tenant was restored by platform verification on 18 Nov 2026.')
})
