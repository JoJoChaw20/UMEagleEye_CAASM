import { test } from 'node:test'
import assert from 'node:assert/strict'
import { computeRiskScore, mapSeverity } from './riskScore'

test('composite risk: CVSS 40%, EPSS 35%, criticality 15% on a 0-100 scale, plus 10 for a threat-intel match', () => {
  // 9.8×10×0.40 + 0.5×100×0.35 + 5×10×0.15 = 39.2 + 17.5 + 7.5
  assert.equal(computeRiskScore(9.8, 0.5, 5, false), 64.2)
  assert.equal(computeRiskScore(9.8, 0.5, 5, true), 74.2)
  // each part alone at its maximum gives exactly its weight
  assert.equal(computeRiskScore(10, 0, 1, false) - computeRiskScore(0, 0, 1, false), 40)
  assert.equal(computeRiskScore(0, 1, 1, false) - computeRiskScore(0, 0, 1, false), 35)
  assert.equal(computeRiskScore(0, 0, 10, false), 15)
})

test('composite risk is capped at 100 and rounded to two decimals', () => {
  assert.equal(computeRiskScore(10, 1, 10, true), 100)
  assert.equal(computeRiskScore(10, 1, 10, false), 90)
  // 29.2 + 4.32075 + 4.5 = 38.02075
  assert.equal(computeRiskScore(7.3, 0.12345, 3, false), 38.02)
})

test('criticality below 1 (unscored asset) counts as 1, never as zero or negative', () => {
  assert.equal(computeRiskScore(0, 0, 0, false), 1.5)
  assert.equal(computeRiskScore(0, 0, -4, false), 1.5)
})

test('composite risk never falls when any one input rises', () => {
  const cvss = [0, 3.1, 5.5, 7.5, 9.8, 10]
  const epss = [0, 0.001, 0.05, 0.4, 0.97]
  const crit = [1, 3, 5, 8, 10]
  for (const c of cvss) for (const e of epss) for (const k of crit) for (const m of [false, true]) {
    const s = computeRiskScore(c, e, k, m)
    assert.ok(s >= 0 && s <= 100)
    if (c < 10) assert.ok(computeRiskScore(Math.min(10, c + 0.5), e, k, m) >= s)
    if (e < 1) assert.ok(computeRiskScore(c, Math.min(1, e + 0.05), k, m) >= s)
    if (k < 10) assert.ok(computeRiskScore(c, e, k + 1, m) >= s)
    if (!m) assert.ok(computeRiskScore(c, e, k, true) >= s)
  }
})

test('a likely-exploited medium can outrank an unlikely critical (EPSS matters, CVSS alone does not decide)', () => {
  const unlikelyCritical = computeRiskScore(9.8, 0.001, 5, false)
  const likelyMedium = computeRiskScore(6.5, 0.9, 5, false)
  assert.ok(likelyMedium > unlikelyCritical)
})

test('severity follows the CVSS bands; Grype\'s label is used only when there is no CVSS score', () => {
  assert.deepEqual([9.0, 8.99, 7.0, 6.9, 4.0, 3.9, 0.1].map((c) => mapSeverity(c, 'Negligible')),
    ['critical', 'high', 'high', 'medium', 'medium', 'low', 'low'])
  assert.deepEqual(['Critical', 'HIGH', 'medium', 'Low', 'Negligible', 'Unknown', ''].map((s) => mapSeverity(0, s)),
    ['critical', 'high', 'medium', 'low', 'low', 'low', 'low'])
  // a scored CVE keeps its CVSS band even if Grype says otherwise
  assert.equal(mapSeverity(2.0, 'Critical'), 'low')
})
