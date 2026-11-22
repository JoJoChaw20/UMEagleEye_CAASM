import { test } from 'node:test'
import assert from 'node:assert/strict'
import { isDirectIntel, isKevAlert } from './alertSignals'

test('exploited: a package alert flag or a service with a KEV CVE', () => {
  assert.equal(isKevAlert({ kev: true }), true)
  assert.equal(isKevAlert({ kev_count: 2 }), true)
  assert.equal(isKevAlert({ kev: false, kev_count: 0 }), false)
  assert.equal(isKevAlert({ has_cti_match: true }), false)
})

test('direct intel: indicator matches and sightings, never watchlist hits', () => {
  assert.equal(isDirectIntel('cti_match', { match_kind: 'ioc' }), true)
  assert.equal(isDirectIntel('cti_match', { match_kind: 'sighting' }), true)
  assert.equal(isDirectIntel('cti_match', {}), true)
  assert.equal(isDirectIntel('cti_match', { match_kind: 'watchlist' }), false)
  assert.equal(isDirectIntel('cve_detected', { has_cti_match: true }), false)
})
