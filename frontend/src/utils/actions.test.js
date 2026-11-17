import test from 'node:test'
import assert from 'node:assert/strict'
import { withRequirements, dependentsOf, matchPreset, roleLabel } from './actions.js'

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
