import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ACTIONS, ACTION_BY_KEY, ACTION_KEYS, GROUPS, MIGRATION_ACTIONS, PRESETS,
  decide, dependentsOf, isActionKey, matchPreset, normalizeAccount, refusalMessage, scanActionFor, withRequirements,
  type ActionKey,
} from './actions'

test('58 unique actions, every group used, every requirement exists', () => {
  assert.equal(ACTIONS.length, 58)
  assert.equal(new Set(ACTION_KEYS).size, 58)
  for (const a of ACTIONS) for (const r of a.requires) assert.ok(isActionKey(r), `${a.key} -> ${r}`)
  assert.deepEqual(new Set(ACTIONS.map(a => a.group)).size, GROUPS.length)
  assert.ok(!isActionKey('cti.ingest'))
})
test('requirements are acyclic and closure is transitive', () => {
  assert.deepEqual(withRequirements(['alert.bulk_update']), ['alert.view', 'alert.manage', 'alert.bulk_update'])
  assert.deepEqual(withRequirements(['advisory.close_via_chat']).sort(),
    ['advisory.close_via_chat', 'advisory.update', 'advisory.view', 'chatbot.use'].sort())
  assert.deepEqual(withRequirements(['nope', 'asset.edit']), ['asset.view', 'asset.edit'])
})
test('dependentsOf lists what removing a view action would take away', () => {
  assert.deepEqual(dependentsOf('alert.view').sort(),
    ['advisory.generate', 'alert.bulk_update', 'alert.manage', 'scan.drift.run'].sort())
})
test('presets: sizes, cumulative, closed under requirements, never high impact', () => {
  const [v, a, o] = PRESETS
  assert.deepEqual([v.actions.length, a.actions.length, o.actions.length], [15, 27, 44])
  assert.ok(v.actions.every(k => a.actions.includes(k)) && a.actions.every(k => o.actions.includes(k)))
  for (const p of PRESETS) {
    assert.equal(withRequirements(p.actions).length, p.actions.length, p.key)
    assert.ok(p.actions.every(k => ACTION_BY_KEY[k].impact !== 'high'), p.key)
  }
  assert.equal(matchPreset([...a.actions].reverse()), 'analyst')
  assert.equal(matchPreset([...a.actions, 'asset.delete']), null)
})
test('migration map: tenant_admin 53, business_owner 13, both closed', () => {
  assert.equal(MIGRATION_ACTIONS.tenant_admin.length, 53)
  assert.equal(MIGRATION_ACTIONS.business_owner.length, 13)
  for (const list of Object.values(MIGRATION_ACTIONS)) assert.equal(withRequirements(list).length, list.length)
  for (const k of ['asset.delete', 'asset.merge', 'report.snapshot', 'settings.scan_policy.edit', 'settings.agent_defaults.edit'])
    assert.ok(!MIGRATION_ACTIONS.tenant_admin.includes(k as ActionKey), k)
})
test('decide', () => {
  const t = 'tenant-1'
  assert.deepEqual(decide({ role: 'superadmin', actions: [] }, 'asset.view'), { ok: true })
  assert.deepEqual(decide({ role: 'superadmin', actions: [] }, 'asset.edit'), { ok: false, reason: 'superadmin_read_only' })
  assert.deepEqual(decide({ role: 'tenant_superadmin', tenantId: t, actions: [] }, 'agent.remove'), { ok: true })
  assert.deepEqual(decide({ role: 'tenant_user', tenantId: t, actions: ['asset.view'] }, 'asset.view'), { ok: true })
  assert.deepEqual(decide({ role: 'tenant_user', tenantId: t, actions: ['asset.view'] }, 'asset.edit'), { ok: false, reason: 'missing_action' })
  assert.deepEqual(decide({ role: 'tenant_user', tenantId: null, actions: ['asset.view'] }, 'asset.view'), { ok: false, reason: 'not_tenant_member' })
  assert.equal(refusalMessage('missing_action', 'scan.active.run'), 'You do not have the "Run active scans" action. Ask your Tenant Superadmin to grant it.')
})
test('scanActionFor maps scan type to its run action', () => {
  assert.equal(scanActionFor('active'), 'scan.active.run')
  assert.equal(scanActionFor('passive'), 'scan.passive.run')
})

test('normalizeAccount: new roles keep their role; null actions become []', () => {
  assert.deepEqual(normalizeAccount('superadmin', null), { role: 'superadmin', actions: [] })
  assert.deepEqual(normalizeAccount('tenant_superadmin', null), { role: 'tenant_superadmin', actions: [] })
  assert.deepEqual(normalizeAccount('tenant_user', ['scan.view']), { role: 'tenant_user', actions: ['scan.view'] })
})
test('normalizeAccount: unknown action keys are dropped; unknown role fails closed', () => {
  assert.deepEqual(normalizeAccount('tenant_user', ['scan.view', 'feeds.refresh']), { role: 'tenant_user', actions: ['scan.view'] })
  assert.deepEqual(normalizeAccount('owner', ['scan.view']), { role: 'tenant_user', actions: [] })
  // The old role values are gone from the enum (0036); a stray one is just an unknown role.
  assert.deepEqual(normalizeAccount('tenant' + '_admin', null), { role: 'tenant_user', actions: [] })
  assert.deepEqual(normalizeAccount('business' + '_owner', ['scan.view']), { role: 'tenant_user', actions: [] })
})
