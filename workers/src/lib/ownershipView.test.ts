import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ownershipView, transferMessage } from './ownershipView'

const owner = { userId: 'o', username: 'Olive' }
const names = { o: 'Olive', r: 'Rae', s: 'Sam', a1: 'Ann', a2: 'Abe' }
const t = {
  transferId: 't1', fromUserId: 'o', toUserId: 'r', afterMode: 'stay', afterActions: ['assets.view'],
  deactivateOn: null, status: 'pending', createdAt: new Date('2026-11-18T00:00:00Z'), expiresAt: new Date('2026-11-21T00:00:00Z'),
}
const plan = { successorId: 's', approver1Id: 'a1', approver2Id: 'a2' }

test('transfer is shown to the owner and the recipient only', () => {
  assert.equal(ownershipView({ owner, transfer: t, plan: null, names }, 'o').pending_transfer?.to_user.username, 'Rae')
  assert.equal(ownershipView({ owner, transfer: t, plan: null, names }, 'r').pending_transfer?.from_user.username, 'Olive')
  assert.equal(ownershipView({ owner, transfer: t, plan: null, names }, 'x').pending_transfer, undefined)
})

test('plan members are shown to the owner only; plan_complete is for everyone', () => {
  const ov = ownershipView({ owner, transfer: null, plan, names }, 'o')
  assert.equal(ov.recovery_plan?.successor?.username, 'Sam')
  assert.equal(ov.plan_complete, true)
  const other = ownershipView({ owner, transfer: null, plan, names }, 's')
  assert.equal(other.recovery_plan, null)
  assert.equal(ownershipView({ owner, transfer: null, plan: { ...plan, approver2Id: null }, names }, 'o').plan_complete, false)
  assert.equal(ownershipView({ owner, transfer: null, plan: null, names }, 'o').plan_complete, false)
})

test('recipient message is verbatim for each choice', () => {
  const base = 'Olive wants to make you the Tenant Superadmin of Acme. You will be able to grant and remove access for every user, reset MFA, and transfer ownership. '
  assert.equal(transferMessage('Olive', 'Acme', 'stay', null), base + 'Olive will become a Tenant user.')
  assert.equal(transferMessage('Olive', 'Acme', 'deactivate_on', new Date('2027-01-05T00:00:00Z')),
    base + 'Olive will be deactivated on 2027-01-05.')
  assert.equal(transferMessage('Olive', 'Acme', 'deactivate_now', null), base + 'Olive will be deactivated.')
})

test('open recovery is shown to the owner, successor and approvers only', () => {
  const recovery = {
    recoveryId: 'r1', successorId: 's', reason: 'terminated', status: 'awaiting_approval', approver1At: new Date('2026-11-18T01:00:00Z'),
    approver2At: null, createdAt: new Date('2026-11-18T00:00:00Z'), expiresAt: new Date('2026-11-21T00:00:00Z'), holdUntil: null,
  }
  const v = (id: string) => ownershipView({ owner, transfer: null, plan, recovery, names }, id).recovery
  assert.equal(v('o')?.your_role, 'owner')
  assert.equal(v('s')?.your_role, 'successor')
  assert.equal(v('a2')?.your_role, 'approver')
  assert.equal(v('a1')?.approver1_approved, true)
  assert.equal(v('a1')?.approver2_approved, false)
  assert.equal(v('x'), null)
  assert.equal(ownershipView({ owner, transfer: null, plan, names }, 'o').recovery, null)
})

test('me block and recovery_open reveal only the viewer own position', () => {
  const view = (id: string, recovery: any = null) => ownershipView({ owner, transfer: null, plan, recovery, names }, id)
  assert.deepEqual(view('o').me, { is_successor: false, approver_slot: null, has_approved: false })
  assert.deepEqual(view('x').me, { is_successor: false, approver_slot: null, has_approved: false })
  assert.deepEqual(view('s').me, { is_successor: true, approver_slot: null, has_approved: false })
  assert.equal(view('x').recovery_open, false)
  const rec = {
    recoveryId: 'r1', successorId: 's', reason: 'terminated', status: 'awaiting_approval', approver1At: null as Date | null,
    approver2At: null as Date | null, createdAt: new Date(), expiresAt: new Date(), holdUntil: null,
  }
  assert.deepEqual(view('a1', rec).me, { is_successor: false, approver_slot: 1, has_approved: false })
  assert.equal(view('x', rec).recovery_open, true)
  assert.equal(view('x', rec).recovery, null)
  const rec1 = { ...rec, approver1At: new Date() }
  assert.equal(view('a1', rec1).me.has_approved, true)
  assert.equal(view('a2', rec1).me.has_approved, false)
  assert.equal(view('a2', rec1).me.approver_slot, 2)
})

test('recipient gets the server-built message; others do not', () => {
  const v = (id: string) => ownershipView({ owner, transfer: t, plan: null, names, tenantName: 'Acme' }, id).pending_transfer as any
  assert.equal(v('r').message, 'Olive wants to make you the Tenant Superadmin of Acme. You will be able to grant and remove access for every user, reset MFA, and transfer ownership. Olive will become a Tenant user.')
  assert.equal(v('o').message, undefined)
})
