import test from 'node:test'
import assert from 'node:assert/strict'
import { canDismiss, checklistItems, visibleNotices, RESTORE_VERIFICATION, restoreReady, restoreBody } from './notices.js'

const body = 'Security checklist for the new Tenant Superadmin: review every user\'s actions; choose a new successor and recovery approvers; reassign alerts and advisories assigned to the former owner; Consider replacing agent keys.'

test('canDismiss: only own (personal) notices', () => {
  assert.equal(canDismiss({ personal: true }), true)
  assert.equal(canDismiss({ personal: false }), false)
  assert.equal(canDismiss(null), false)
})

test('checklistItems: four items with links when the body mentions agent keys', () => {
  const items = checklistItems({ kind: 'owner_checklist', body })
  assert.deepEqual(items.map((i) => i.to), ['/users', '/users#ownership', '/alerts', '/agents'])
  assert.equal(items[0].label, "Review every user's actions")
  assert.equal(items[3].label, 'Consider replacing agent keys')
})

test('checklistItems: three items without the agent-keys flag', () => {
  const b = body.replace('; Consider replacing agent keys', '')
  assert.equal(checklistItems({ kind: 'owner_checklist', body: b }).length, 3)
})

test('checklistItems: other kinds and garbled bodies give none (card falls back to plain, dismissable)', () => {
  assert.deepEqual(checklistItems({ kind: 'ownership_changed', body }), [])
  assert.deepEqual(checklistItems({ kind: 'owner_checklist', body: 'nothing here' }), [])
  assert.deepEqual(checklistItems({ kind: 'owner_checklist', body: 42 }), [])
  assert.deepEqual(checklistItems(null), [])
  assert.equal(canDismiss({ kind: 'owner_checklist', body: 'nothing here', personal: true }), true)
})

test('visibleNotices: tolerates non-arrays and junk rows', () => {
  assert.deepEqual(visibleNotices(null), [])
  assert.deepEqual(visibleNotices({}), [])
  assert.equal(visibleNotices([{ notice_id: 'a', body: 'x' }, null, { body: 'no id' }]).length, 1)
})

test('restore: verbatim text, readiness and body', () => {
  assert.equal(RESTORE_VERIFICATION, 'Verify the request by calling back the organisation contact on record. Do not use contact details given in the request itself.')
  assert.equal(restoreReady(' a@b.co '), true)
  assert.equal(restoreReady('not-an-email'), false)
  assert.equal(restoreReady('a@b.co', 'ab'), false)
  assert.equal(restoreReady('a@b.co', ' abc '), true)
  assert.equal(restoreReady('  '), false)
  assert.deepEqual(restoreBody({ email: ' a@b.co ', username: ' ', stepUp: { password: 'p', code: '123456' } }), { email: 'a@b.co', password: 'p', code: '123456' })
  assert.deepEqual(restoreBody({ email: 'a@b.co', username: ' bob ', stepUp: { code: '1' } }), { email: 'a@b.co', username: 'bob', code: '1' })
})
