import test from 'node:test'
import assert from 'node:assert/strict'
import {
  withRequirements, dependentsOf, matchPreset, roleLabel,
  addAction, removeAction, presetActions, accessSummary, actionLabels,
} from './actions.js'

const cat = {
  groups: [{ key: 'a', label: 'A' }],
  actions: [
    { key: 'a.view', group: 'a', requires: [], read_only: true },
    { key: 'a.edit', group: 'a', requires: ['a.view'], read_only: false },
    { key: 'a.bulk', group: 'a', requires: ['a.edit'], read_only: false },
  ],
  presets: [{ key: 'p', label: 'P', description: '', actions: ['a.view'] }],
}

test('withRequirements', () => assert.deepEqual(withRequirements(['a.bulk'], cat), ['a.view', 'a.edit', 'a.bulk']))
test('dependentsOf', () => assert.deepEqual(dependentsOf('a.view', cat).sort(), ['a.bulk', 'a.edit']))
test('matchPreset', () => {
  assert.equal(matchPreset(['a.view'], cat), 'p')
  assert.equal(matchPreset(['a.view', 'a.edit'], cat), null)
})
test('roleLabel', () => assert.equal(roleLabel('tenant_user'), 'Tenant user'))

const cat2 = {
  groups: [{ key: 'a', label: 'A' }],
  actions: [
    { key: 'a.view', group: 'a', label: 'View A', requires: [] },
    { key: 'a.edit', group: 'a', label: 'Edit A', requires: ['a.view'] },
    { key: 'a.bulk', group: 'a', label: 'Bulk A', requires: ['a.edit'] },
    { key: 'b.view', group: 'a', label: 'View B', requires: [] },
  ],
  presets: [
    { key: 'viewer', label: 'Viewer', description: '', actions: ['a.view', 'b.view'] },
    { key: 'editor', label: 'Editor', description: '', actions: ['a.edit'] },
  ],
}

test('addAction adds the closure and names what came along', () => {
  assert.deepEqual(addAction([], 'a.bulk', cat2), { next: ['a.view', 'a.edit', 'a.bulk'], added: ['a.view', 'a.edit'] })
  assert.deepEqual(addAction(['a.view'], 'a.edit', cat2), { next: ['a.view', 'a.edit'], added: [] })
})
test('removeAction drops selected dependents', () => {
  assert.deepEqual(removeAction(['b.view', 'a.bulk', 'a.edit', 'a.view'], 'a.view', cat2),
    { next: ['b.view'], removed: ['a.edit', 'a.bulk'] })
  assert.deepEqual(removeAction(['a.view', 'a.edit'], 'a.edit', cat2), { next: ['a.view'], removed: [] })
})
test('presetActions closes over requirements', () => {
  assert.deepEqual(presetActions('editor', cat2), ['a.view', 'a.edit'])
  assert.deepEqual(presetActions('nope', cat2), [])
})
test('accessSummary', () => {
  assert.equal(accessSummary([], cat2), 'No access')
  assert.equal(accessSummary(['b.view', 'a.view'], cat2), 'Matches: Viewer')
  assert.equal(accessSummary(['b.view', 'a.view'], cat2, { withCount: true }), 'Matches: Viewer · 2 actions')
  assert.equal(accessSummary(['a.view'], cat2), 'Custom · 1 action')
  assert.equal(accessSummary(['a.view', 'a.edit', 'a.bulk'], cat2, { withCount: true }), 'Custom · 3 actions')
})
test('actionLabels', () => assert.equal(actionLabels(['a.view', 'zz'], cat2), 'View A, zz'))
