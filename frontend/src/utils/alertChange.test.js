import { test } from 'node:test'
import assert from 'node:assert/strict'
import { alertChangeText } from './alertChange.js'

test('names each kind of change apart', () => {
  assert.equal(alertChangeText({ alerts_updated: 3, alerts_change: { total: 3, opened: 1, reopened: 1, resolved: 0, marked: 1 } }),
    '1 alert raised · 1 alert reopened · 1 open CVE alert gained or lost a threat-intel match.')
  assert.equal(alertChangeText({ alerts_change: { total: 2, opened: 0, reopened: 0, resolved: 2, marked: 0 } }), '2 alerts resolved.')
})

test('nothing changed: no text', () => {
  assert.equal(alertChangeText({ alerts_updated: 0, alerts_change: null }), '')
  assert.equal(alertChangeText({ alerts_change: { total: 0, opened: 0, reopened: 0, resolved: 0, marked: 0 } }), '')
  assert.equal(alertChangeText(undefined), '')
})

test('an older response with only the total still reads', () => {
  assert.equal(alertChangeText({ alerts_updated: 4 }), '4 alerts updated.')
})
