import test from 'node:test'
import assert from 'node:assert/strict'
import { labelTone, kindBadge, advisoryDisplay, REGENERATE_HINT, NOT_ON_TEXT } from './advisoryView.js'

test('labelTone colours each known label', () => {
  assert.equal(labelTone('Auto-fixable').tone, 'green')
  assert.equal(labelTone('Partly auto-fixable').tone, 'amber')
  assert.equal(labelTone('Guided fix').tone, 'blue')
  assert.equal(labelTone('Needs outside support').tone, 'red')
})

test('labelTone gives an unknown label a neutral tone', () => {
  assert.equal(labelTone('Something new').tone, 'neutral')
  assert.equal(labelTone(null).tone, 'neutral')
  assert.ok(labelTone('Guided fix').className.includes('sky'))
})

test('kindBadge names each step kind', () => {
  assert.equal(kindBadge('auto').text, 'Automatic')
  assert.equal(kindBadge('manual').text, 'Manual')
  assert.equal(kindBadge('external').text, 'Outside support')
  assert.equal(kindBadge('weird').text, 'Manual')
})

const content = { summary: 's', steps: [{ id: 's1', text: 't', kind: 'manual', risk: 'low' }] }

test('advisoryDisplay is structured when content has steps', () => {
  const d = advisoryDisplay({ content, automation: { label: 'Guided fix', available: false, reason: 'Follow the steps by hand.' }, recommendedAction: 'x' })
  assert.equal(d.mode, 'structured')
  assert.equal(d.content, content)
  assert.equal(d.automation.label, 'Guided fix')
})

test('advisoryView falls back to text when content is null', () => {
  const d = advisoryDisplay({ content: null, recommendedAction: 'Do it' })
  assert.equal(d.mode, 'text')
  assert.equal(d.text, 'Do it')
  assert.equal(d.hint, REGENERATE_HINT)
})

test('advisoryDisplay accepts snake_case text', () => {
  assert.equal(advisoryDisplay({ recommended_action: 'a' }).text, 'a')
})

test('REGENERATE_HINT is verbatim', () => {
  assert.equal(REGENERATE_HINT, 'Regenerate to get structured steps and automation labels.')
  assert.equal(NOT_ON_TEXT, 'Automatic fixing is not switched on yet.')
})

test('plannedActionText describes known actions in plain words', async () => {
  const { plannedActionText } = await import('./advisoryView.js')
  assert.equal(plannedActionText({ key: 'pkg.upgrade', params: { package: 'openssl', version: '3.0.13' } }), 'Planned automatic action: Upgrade a package (openssl, 3.0.13)')
  assert.equal(plannedActionText({ key: 'nope', params: {} }), null)
  assert.equal(plannedActionText(undefined), null)
})
