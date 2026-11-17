import { test } from 'node:test'
import assert from 'node:assert/strict'
import { sql } from 'drizzle-orm'
import { getDb } from '../db/client'
import {
  validateTransfer, validateRecoveryPlan, transferNext, recoveryNext, approverSlot,
  swapStatements, ownershipChangedNotice, restoredNotice, HOURS_72,
  completionEffects, ownerChecklist, RECOVERY_DISPUTED_NOTICE, ownershipNoticeExpiry,
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
  assert.equal(recoveryNext(rec('resigned'), 'cancel_by_owner', now), null)   // not while awaiting approval
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
  assert.deepEqual(s.map((x) => x.label), ['lock', 'demote', 'promote'])
  assert.deepEqual(s[1].set, { role: 'tenant_user', actions: ['a'], isActive: true, scheduledDeactivationAt: d })
  assert.equal(s[1].userId, 'o')
  assert.deepEqual(s[2].set, { role: 'tenant_superadmin', actions: [] })
  assert.equal(s[2].userId, 'n')
  const gone = swapStatements(T, 'o', 'n', { mode: 'deactivate_now' })
  assert.equal(gone[1].set.isActive, false)
  assert.equal(gone[1].set.scheduledDeactivationAt, null)
  const stay = swapStatements(T, 'o', 'n', { mode: 'stay' })
  assert.deepEqual(stay[1].set.actions, [])
  const [lockQ, ...q] = s.map((x) => (x.build(db) as unknown as { toSQL(): { sql: string; params: unknown[] } }).toSQL())
  assert.match(lockQ.sql, /^select "user_id" from "users"/)
  assert.match(lockQ.sql, / for update$/)
  assert.ok(lockQ.params.includes('o') && lockQ.params.includes('n') && lockQ.params.includes(T))
  for (const { sql } of q) {
    assert.match(sql, /^update "users"/)
    assert.match(sql, /"user_id" = \$\d+/)
    assert.match(sql, /"tenant_id" = \$\d+/)
    assert.match(sql, /"role" = \$\d+/)
    assert.match(sql, /returning "user_id"/)
  }
  assert.ok(q[0].params.includes('o') && q[0].params.includes('tenant_superadmin') && q[0].params.includes(T))
  assert.ok(q[1].params.includes('n') && q[1].params.includes('tenant_user') && q[1].params.includes(T))
  assert.match(q[0].sql, /exists \(select 1 from "users" "r" where/)
  assert.match(q[0].sql, /"r"\."is_active" = \$\d+/)
  assert.ok(q[0].params.includes('n') && q[0].params.includes('tenant_user') && q[0].params.includes(true))
  assert.match(q[1].sql, /"is_active" = \$\d+/)
  assert.match(q[1].sql, /not exists \(select 1 from "users" "o" where/)
  assert.ok(q[1].params.includes('tenant_superadmin'))
  assert.throws(() => swapStatements(T, 'o', 'n', { mode: 'bogus' }), /Unknown after mode/)
})

test('notice texts verbatim', () => {
  assert.equal(ownershipChangedNotice('Ann', 'Bob', '18 Nov 2026'), 'Tenant ownership changed from Ann to Bob on 18 Nov 2026.')
  assert.equal(restoredNotice('18 Nov 2026'), 'Ownership of this tenant was restored by platform verification on 18 Nov 2026.')
})

test('swap guard is ANDed into the demote only', () => {
  const g = sql`exists (select 1 from ownership_transfers where transfer_id = ${'tx'})`
  const s = swapStatements(T, 'o', 'n', { mode: 'stay' }, g)
  const q = s.map((x) => (x.build(db) as unknown as { toSQL(): { sql: string; params: unknown[] } }).toSQL())
  assert.match(q[1].sql, /exists \(select 1 from ownership_transfers where transfer_id = \$\d+\)/)
  assert.ok(q[1].params.includes('tx'))
  assert.ok(!q[2].params.includes('tx'))
  const plain = swapStatements(T, 'o', 'n', { mode: 'stay' })[1].build(db).toSQL()
  assert.ok(!/ownership_transfers/.test(plain.sql))
})

test('completionEffects: the checklist has agent keys for every Path B reason', () => {
  for (const r of ['terminated', 'compromised', 'resigned', 'unreachable']) {
    assert.equal(completionEffects(r).checklistHasAgentKeys, true)
  }
})

test('owner checklist: agent keys only after an emergency; Path A text unchanged', () => {
  assert.equal(ownerChecklist(false), "Security checklist for the new Tenant Superadmin: review every user's actions; choose a new successor and recovery approvers; reassign alerts and advisories assigned to the former owner.")
  assert.ok(ownerChecklist(true).includes('Consider replacing agent keys'))
  assert.ok(!ownerChecklist(false).includes('agent keys'))
})

test('dispute notice is verbatim', () => {
  assert.equal(RECOVERY_DISPUTED_NOTICE, 'Recovery was disputed. Contact platform support for verification.')
})

test('a due scheduled deactivation makes a recipient or plan member ineligible', () => {
  const due = { ...to, scheduledDeactivationAt: plus(-1000) }
  const later = { ...to, scheduledDeactivationAt: plus(1000) }
  assert.equal(validateTransfer({ ...base, toUser: due }), 'The recipient must be an active user')
  assert.equal(validateTransfer({ ...base, toUser: later }), null)
  const m = (id: string, x = {}) => ({ ...to, userId: id, ...x })
  const plan = { ownerId: 'o', tenantId: T, now }
  assert.equal(validateRecoveryPlan({ ...plan, successor: m('a'), approvers: [m('b'), m('c')] }), null)
  for (const slot of [0, 1, 2]) {
    const ms = [m('a'), m('b'), m('c')]
    ms[slot] = m(['a', 'b', 'c'][slot]!, { scheduledDeactivationAt: plus(-1) })
    assert.equal(validateRecoveryPlan({ ...plan, successor: ms[0]!, approvers: [ms[1]!, ms[2]!] }), 'Everyone in the plan must be an active user')
  }
})

test('tenant-wide ownership notices expire after 30 days', () => {
  assert.equal(ownershipNoticeExpiry(now).getTime(), now.getTime() + 30 * 24 * 60 * 60 * 1000)
})
