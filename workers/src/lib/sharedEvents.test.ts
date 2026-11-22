import { test } from 'node:test'
import assert from 'node:assert/strict'
import { alertsHere, type AlertSetting } from './sharedEvents'

const OURS = 't-ours'
const ev = (over: Partial<Parameters<typeof alertsHere>[0]> = {}) =>
  ({ tiEventId: 'e1', tenantId: 't-other', status: 'published', distribution: 'all_tenants', ...over })
const setting = (tenantDefault = false, choices: Array<[string, boolean]> = []): AlertSetting =>
  ({ tenantDefault, choices: new Map(choices) })

test('another tenant\'s shared event: off by default, read only', () => {
  assert.deepEqual(alertsHere(ev(), OURS, setting()), { alerts_here: false, alerts_choice: null, shared_in: true })
})

test('the tenant default turns every shared event on', () => {
  assert.equal(alertsHere(ev(), OURS, setting(true)).alerts_here, true)
})

test('a choice for one event wins over the default, both ways', () => {
  assert.deepEqual(alertsHere(ev(), OURS, setting(false, [['e1', true]])), { alerts_here: true, alerts_choice: true, shared_in: true })
  assert.deepEqual(alertsHere(ev(), OURS, setting(true, [['e1', false]])), { alerts_here: false, alerts_choice: false, shared_in: true })
  // a choice for another event does not apply
  assert.equal(alertsHere(ev(), OURS, setting(false, [['e2', true]])).alerts_here, false)
})

test('own and platform events always alert once published; no choice to make', () => {
  assert.deepEqual(alertsHere(ev({ tenantId: OURS }), OURS, setting()), { alerts_here: true, alerts_choice: null, shared_in: false })
  assert.deepEqual(alertsHere(ev({ tenantId: null, distribution: 'platform' }), OURS, setting()), { alerts_here: true, alerts_choice: null, shared_in: false })
  assert.equal(alertsHere(ev({ tenantId: OURS, status: 'draft' }), OURS, setting(true)).alerts_here, false)
})

test('an opted-in shared event that was unpublished or made private stops alerting', () => {
  assert.equal(alertsHere(ev({ status: 'draft' }), OURS, setting(true, [['e1', true]])).alerts_here, false)
  assert.equal(alertsHere(ev({ distribution: 'organisation' }), OURS, setting(true, [['e1', true]])).alerts_here, false)
})

test('the platform superadmin (no tenant) gets nothing', () => {
  assert.deepEqual(alertsHere(ev(), null, setting(true)), {})
})
