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
