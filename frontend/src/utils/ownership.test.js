import test from 'node:test'
import assert from 'node:assert/strict'
import { viewFor, afterModeLabel, REASONS, reasonLabel, PLAN_BANNER, plan3Ready, transferBodyReady, transferMessage, localDate, dateAfterToday } from './ownership.js'

const owner = { user_id: 'o', username: 'Olga' }
const me = (id) => ({ userId: id })
const base = { owner, plan_complete: true, recovery_plan: { successor: null }, recovery: null }

test('owner view: transfer form, no banner when plan complete', () => {
  const v = viewFor(base, me('o'))
  assert.equal(v.isOwner, true)
  assert.equal(v.canTransfer, true)
  assert.equal(v.showPlanBanner, false)
  assert.equal(v.canStartRecovery, false)
})
test('owner banner when plan incomplete; no transfer form while one is pending', () => {
  const v = viewFor({ ...base, plan_complete: false, pending_transfer: { to_user: { user_id: 'r' } } }, me('o'))
  assert.equal(v.showPlanBanner, true)
  assert.equal(v.canTransfer, false)
  assert.equal(v.pendingAsOwner, true)
})
test('recipient sees accept/decline', () => {
  const v = viewFor({ ...base, pending_transfer: { from_user: owner, to_user: { user_id: 'r' } } }, me('r'))
  assert.equal(v.pendingAsRecipient, true)
  assert.equal(v.isOwner, false)
  assert.equal(v.canStartRecovery, false)
})
test('approver sees approve while awaiting approval, not once approved', () => {
  const rec = (status, me_ = { approver_slot: 1, has_approved: false }) => ({ ...base, recovery_open: true, me: me_, recovery: { status, your_role: 'approver' } })
  assert.equal(viewFor(rec('awaiting_approval'), me('a')).canApprove, true)
  assert.equal(viewFor(rec('on_hold'), me('a')).canApprove, false)
  assert.equal(viewFor(rec('awaiting_approval', { approver_slot: 1, has_approved: true }), me('a')).canApprove, false)
  assert.equal(viewFor(rec('awaiting_approval', { approver_slot: null, has_approved: false }), me('a')).canApprove, false)
})
test('former owner may cancel only during hold', () => {
  const rec = (status) => ({ ...base, recovery: { status, your_role: 'owner' } })
  assert.equal(viewFor(rec('on_hold'), me('o')).canCancelRecovery, true)
  assert.equal(viewFor(rec('awaiting_approval'), me('o')).canCancelRecovery, false)
})
test('successor may start only when none is open; bystander sees neither button', () => {
  const succ = { ...base, me: { is_successor: true, approver_slot: null, has_approved: false }, recovery_open: false }
  assert.equal(viewFor(succ, me('s')).canStartRecovery, true)
  assert.equal(viewFor({ ...succ, recovery_open: true }, me('s')).canStartRecovery, false)
  const by = { ...base, me: { is_successor: false, approver_slot: null, has_approved: false }, recovery_open: false }
  const v = viewFor(by, me('x'))
  assert.equal(v.canStartRecovery, false)
  assert.equal(v.canApprove, false)
  assert.equal(v.recoveryInProgress, false)
  assert.equal(viewFor({ ...by, recovery_open: true }, me('x')).recoveryInProgress, true)
})
test('missing response gives empty view', () => {
  assert.equal(viewFor(null, me('x')).owner, null)
})
test('afterModeLabel', () => {
  assert.equal(afterModeLabel('stay'), 'Stay as a Tenant user')
  assert.equal(afterModeLabel('deactivate_on'), 'Stay until a date, then be deactivated')
  assert.equal(afterModeLabel('deactivate_now'), 'Be deactivated now')
  assert.equal(afterModeLabel('x'), 'x')
})
test('reasons and banner verbatim', () => {
  assert.deepEqual(REASONS.map((r) => r.label), ['Terminated', 'Account compromised', 'Resigned without handover', 'Unreachable'])
  assert.equal(reasonLabel('resigned'), 'Resigned without handover')
  assert.equal(PLAN_BANNER, 'No recovery plan. If you lose access, your tenant cannot recover without platform verification.')
})
test('plan3Ready needs three distinct picks', () => {
  assert.equal(plan3Ready('a', 'b', 'c'), true)
  assert.equal(plan3Ready('a', 'a', 'c'), false)
  assert.equal(plan3Ready('a', '', 'c'), false)
})
test('transferBodyReady', () => {
  assert.equal(transferBodyReady({ to: 'r', mode: 'stay', date: '' }), true)
  assert.equal(transferBodyReady({ to: '', mode: 'stay', date: '' }), false)
  assert.equal(transferBodyReady({ to: 'r', mode: 'deactivate_on', date: '' }), false)
  assert.equal(transferBodyReady({ to: 'r', mode: 'deactivate_now', date: '' }), true)
})
test('transferMessage verbatim', () => {
  const head = 'Ann wants to make you the Tenant Superadmin of Acme. You will be able to grant and remove access for every user, reset MFA, and transfer ownership. '
  assert.equal(transferMessage('Ann', 'Acme', { mode: 'stay' }), head + 'Ann will become a Tenant user.')
  assert.equal(transferMessage('Ann', 'Acme', { mode: 'deactivate_on', deactivate_on: '2026-12-01T00:00:00.000Z' }), head + 'Ann will be deactivated on 2026-12-01.')
})

test('deactivate_on date must be after today (local)', () => {
  const now = new Date(2026, 10, 18, 23, 30)
  assert.equal(localDate(0, now), '2026-11-18')
  assert.equal(localDate(1, now), '2026-11-19')
  assert.equal(dateAfterToday('2026-11-17', now), false)
  assert.equal(dateAfterToday('2026-11-18', now), false)
  assert.equal(dateAfterToday('2026-11-19', now), true)
  assert.equal(transferBodyReady({ to: 'r', mode: 'deactivate_on', date: '2026-11-18', now }), false)
  assert.equal(transferBodyReady({ to: 'r', mode: 'deactivate_on', date: '2026-11-19', now }), true)
})
