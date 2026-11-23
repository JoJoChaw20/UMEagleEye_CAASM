import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  EFFORT_HOURS, SLA_DEFAULTS, cleanSlaPolicy, dueOf, effortKeyOf, priorityOf, rankScore, slaKeyOf, slaPolicy, tierOf, tierOfPriority, type RankInput,
} from './alertRank'

const alert = (over: Partial<RankInput>): RankInput => ({
  type: 'cve_detected', severity: 'high', details: {}, compositeRiskScore: null, internetFacing: false, criticality: 5, ...over,
})

test('tiers: why it is urgent', () => {
  assert.equal(tierOf(alert({ type: 'cti_match', severity: 'critical', details: { match_kind: 'sighting' } })), 1)
  assert.equal(tierOf(alert({ type: 'cti_match', severity: 'high', details: { match_kind: 'ioc' } })), 1)
  assert.equal(tierOf(alert({ type: 'cti_match', severity: 'medium', details: { match_kind: 'ioc' } })), 4)      // weak match
  assert.equal(tierOf(alert({ type: 'cti_match', severity: 'high', details: { match_kind: 'watchlist' } })), 4)
  assert.equal(tierOf(alert({ details: { kev: true } })), 2)
  assert.equal(tierOf(alert({ type: 'vulnerable_service', details: { kev_count: 1 } })), 2)
  assert.equal(tierOf(alert({ type: 'os_patch_missing', details: { exploited: 2 } })), 2)
  assert.equal(tierOf(alert({ type: 'os_patch_missing', details: { exploited: 0 } })), 3)
  assert.equal(tierOf(alert({ type: 'exposure' })), 3)
  assert.equal(tierOf(alert({ type: 'port_opened', details: { port: 3389 } })), 3)
  assert.equal(tierOf(alert({ type: 'port_opened', details: { port: 8080 } })), 4)
  assert.equal(tierOf(alert({ type: 'new_device', severity: 'high' })), 4)
  assert.equal(tierOf(alert({ type: 'config_change', severity: 'critical' })), 4)
})

test('scores: comparable across types, the validated CVE score unchanged', () => {
  assert.equal(rankScore(alert({ compositeRiskScore: 51 })), 51)
  // a package with no fix yet waits behind fixable work, unless exploited
  assert.equal(rankScore(alert({ compositeRiskScore: 60, details: { shape: 'package', fixable_count: 0 } })), 30)
  assert.equal(rankScore(alert({ compositeRiskScore: 60, details: { shape: 'package', fixable_count: 0, kev: true } })), 60)
  // other types: 0.85 x base + 0.15 x criticality x 10
  assert.equal(rankScore(alert({ type: 'new_device', severity: 'medium', criticality: 5 })), 50)        // 42.5 + 7.5
  assert.equal(rankScore(alert({ type: 'exposure', severity: 'critical', criticality: 10 })), 87.3)   // 72.25 + 15
  // internet-facing counts once: +15 for a CVE, not for an exposure (its severity already includes it)
  assert.equal(rankScore(alert({ compositeRiskScore: 51, internetFacing: true })), 66)
  assert.equal(rankScore(alert({ type: 'exposure', severity: 'high', internetFacing: true })), 67)   // 59.5 + 7.5
  assert.equal(rankScore(alert({ compositeRiskScore: 95, internetFacing: true })), 100)               // capped
  // a vulnerable service: the composite formula on its worst CVE
  assert.equal(rankScore(alert({ type: 'vulnerable_service', details: { max_cvss: 9.8, kev_count: 1 } })), 56.7) // 39.2+7.5+10
})

test('a MAC change no longer outranks a critical CVE; a test threat event no longer outranks KEV in the same way', () => {
  const macChange = alert({ type: 'config_change', severity: 'high', details: { changed_attribute: 'mac' } })
  const criticalCve = alert({ severity: 'critical', compositeRiskScore: 51 })
  assert.ok(priorityOf(criticalCve) > priorityOf(macChange))
  // a weak (medium) threat-intel match is reviewed, after exploited CVEs
  const weak = alert({ type: 'cti_match', severity: 'medium', details: { match_kind: 'ioc' } })
  const kev = alert({ severity: 'critical', compositeRiskScore: 90, details: { kev: true } })
  assert.ok(priorityOf(kev) > priorityOf(weak))
  assert.equal(tierOfPriority(priorityOf(kev)), 2)
  assert.equal(tierOfPriority(priorityOf(weak)), 4)
})

test('fix-time targets: defaults, tenant overrides, which one applies', () => {
  assert.equal(SLA_DEFAULTS.compromise, 24)
  assert.equal(SLA_DEFAULTS.kev, 14 * 24)
  assert.equal(SLA_DEFAULTS.critical, 15 * 24)
  assert.equal(slaKeyOf(1, 'low', false), 'compromise')
  assert.equal(slaKeyOf(2, 'high', true), 'kev_exposed')
  assert.equal(slaKeyOf(2, 'high', false), 'kev')
  assert.equal(slaKeyOf(3, 'medium', true), 'medium')
  assert.equal(slaKeyOf(4, 'critical', false), 'review')
  assert.deepEqual(cleanSlaPolicy({ critical: 72, high: '168', low: 0, bogus: 5, medium: 2.5, kev: 999999 }), { critical: 72, high: 168 })
  assert.equal(slaPolicy({ critical: 72 }).critical, 72)
  assert.equal(slaPolicy(null).high, 30 * 24)
})

test('estimated work per alert: the planning figures, by what fixing it takes', () => {
  const k = (type: string, severity: RankInput['severity'], details: Record<string, unknown> = {}) => effortKeyOf({ type, severity, details })
  assert.equal(k('cti_match', 'critical', { match_kind: 'sighting' }), 'investigate')
  assert.equal(k('cti_match', 'critical', { match_kind: 'malicious_package' }), 'investigate')
  assert.equal(k('cti_match', 'medium', { match_kind: 'malicious_package', match_scope: 'name' }), 'review')   // a name match is reviewed
  assert.equal(k('cti_match', 'high', { match_kind: 'watchlist' }), 'software')
  assert.equal(k('cve_detected', 'critical', { kev: true }), 'package')
  assert.equal(k('vulnerable_service', 'high'), 'service')
  assert.equal(k('os_patch_missing', 'high'), 'windows_update')
  assert.equal(k('exposure', 'medium'), 'exposure')
  assert.equal(k('security_baseline', 'high'), 'hardening')
  assert.equal(tierOf({ type: 'security_baseline', severity: 'medium', details: {} }), 3)
  assert.equal(k('port_opened', 'high', { port: 3389 }), 'exposure')
  assert.equal(k('port_opened', 'low', { port: 8080 }), 'review')
  assert.equal(k('new_device', 'medium'), 'review')
  assert.deepEqual([EFFORT_HOURS.investigate, EFFORT_HOURS.package, EFFORT_HOURS.service, EFFORT_HOURS.windows_update,
    EFFORT_HOURS.exposure, EFFORT_HOURS.review], [4, 0.5, 1, 1, 0.5, 0.25])
})

test('due status: on track, due soon in the last quarter, overdue', () => {
  const start = new Date('2026-11-01T00:00:00Z')
  assert.equal(dueOf(start, 100, new Date('2026-11-02T00:00:00Z')).status, 'on_track')       // 24 h in, 76 left
  assert.equal(dueOf(start, 100, new Date('2026-11-04T04:00:00Z')).status, 'due_soon')       // 24 h left
  assert.equal(dueOf(start, 100, new Date('2026-11-05T05:00:00Z')).status, 'overdue')
  assert.equal(dueOf(start, 24).dueAt.toISOString(), '2026-11-02T00:00:00.000Z')
})
