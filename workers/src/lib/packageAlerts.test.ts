import { test } from 'node:test'
import assert from 'node:assert/strict'
import { computeRiskScore } from './riskScore'
import {
  chooseKept, findingKey, legacyFindings, packageKey, planPackageAlerts, summarisePackage,
  type ExistingAlert, type Finding,
} from './packageAlerts'

const f = (cveId: string, over: Partial<Finding> = {}): Finding => ({
  cveId, advisoryId: null, packageType: 'npm', packageName: 'lodash', packageVersion: '4.17.15', severity: 'medium',
  cvss: 5, epss: 0.01, fixVersions: ['4.17.21'], cweIds: [], description: '', kev: false, hasCtiMatch: false,
  tiEventTitles: [], dismissed: false, ...over,
})
let n = 0
const ids = () => `new-${++n}`
const alert = (eventId: string, over: Partial<ExistingAlert> = {}): ExistingAlert => ({
  eventId, status: 'open', severity: 'medium', firstSeen: new Date('2026-11-01T00:00:00Z'), assignedTo: null,
  hasLiveAdvisory: false, knownCves: [],
  details: { shape: 'package', package_type: 'npm', package_name: 'lodash', package_version: '4.17.15' }, ...over,
})
const legacy = (eventId: string, cve: string, over: Partial<ExistingAlert> = {}): ExistingAlert => alert(eventId, {
  details: { cve_id: cve, package_type: 'npm', package_name: 'lodash', package_version: '4.17.15', cvss_base_score: 7.5,
    epss_score: 0.2, fix_versions: ['4.17.21'], affected_versions: [{ version: '4.17.15', fix_versions: ['4.17.21'] }] },
  knownCves: [cve], ...over,
})

test('one package: the worst CVE sets severity, KEV lifts it to high, the score is the riskiest CVE', () => {
  const s = summarisePackage([
    f('CVE-1', { severity: 'medium', cvss: 6.5, epss: 0.9 }),
    f('CVE-2', { severity: 'low', cvss: 3.1, epss: 0.001, kev: true }),
    f('CVE-3', { severity: 'medium', cvss: 5.3, epss: 0.02, hasCtiMatch: true }),
  ], 5)
  assert.equal(s.severity, 'high')                               // medium at worst, but a CVE is on KEV
  assert.equal(s.score, computeRiskScore(6.5, 0.9, 5, false))     // the highest per-CVE score
  assert.deepEqual([s.details.cve_count, s.details.kev_count, s.details.cti_count], [3, 1, 1])
  assert.equal(s.details.max_cvss, 6.5)
  assert.equal(s.details.max_epss, 0.9)
  assert.equal(s.details.kev, true)
  assert.equal(s.details.has_cti_match, true)
  assert.deepEqual(s.details.top_cves.map((c) => c.id), ['CVE-2', 'CVE-1', 'CVE-3'])   // KEV first, then score
  assert.equal(summarisePackage([f('CVE-9', { severity: 'critical', cvss: 9.8 })], 5).severity, 'critical')
})

test('several installed copies stay one alert; fix_to covers every copy, no-fix CVEs are counted', () => {
  const s = summarisePackage([
    f('CVE-A', { packageVersion: '4.17.20', fixVersions: ['4.17.21'] }),
    f('CVE-A', { packageVersion: '4.17.15', fixVersions: ['4.17.16', '4.17.21'] }),
    f('CVE-B', { packageVersion: '4.17.15', fixVersions: ['4.17.19'] }),
    f('CVE-C', { packageVersion: '4.17.15', fixVersions: [] }),
  ], 5)
  assert.equal(s.details.package_version, '4.17.15')              // the oldest copy names the alert
  assert.deepEqual(s.details.installed_versions, [{ version: '4.17.15', cves: 3 }, { version: '4.17.20', cves: 1 }])
  assert.equal(s.details.cve_count, 3)                            // CVE-A counted once
  assert.equal(s.details.fix_to, '4.17.21')                       // 4.17.19 fixes the old copy's CVEs, 4.17.21 the newer copy's
  assert.deepEqual([s.details.fixable_count, s.details.no_fix_count], [2, 1])
})

test('threat-intel titles and CWEs are merged and capped', () => {
  const s = summarisePackage([
    f('CVE-1', { tiEventTitles: ['A', 'B'], cweIds: ['CWE-79'] }),
    f('CVE-2', { tiEventTitles: ['B', 'C', 'D'], cweIds: ['CWE-79', 'CWE-89'] }),
  ], 5)
  assert.deepEqual(s.details.ti_event_titles, ['A', 'B', 'C'])
  assert.deepEqual(s.details.cwe_ids, ['CWE-79', 'CWE-89'])
})

test('a package seen for the first time gets one open alert holding all its CVEs', () => {
  const p = planPackageAlerts({ findings: [f('CVE-1'), f('CVE-2'), f('CVE-3', { packageName: 'axios' })], existing: [], criticality: 5, newId: ids })
  assert.equal(p.alerts.length, 2)
  const lodash = p.alerts.find((a) => a.details.package_name === 'lodash')!
  assert.equal(lodash.isNew, true)
  assert.equal(lodash.status, 'open')
  assert.equal(lodash.details.cve_count, 2)
  assert.equal(p.owner.get(findingKey(f('CVE-1'))), lodash.eventId)
  assert.deepEqual([p.resolve, p.merge], [[], []])
})

test('an open alert is refreshed; a resolved one reopens; one with nothing left is resolved', () => {
  const open = planPackageAlerts({ findings: [f('CVE-1')], existing: [alert('e1', { status: 'in_progress' })], criticality: 5, newId: ids })
  assert.deepEqual([open.alerts[0]!.eventId, open.alerts[0]!.isNew, open.alerts[0]!.status], ['e1', false, undefined])

  const reopened = planPackageAlerts({ findings: [f('CVE-1')], existing: [alert('e1', { status: 'resolved' })], criticality: 5, newId: ids })
  assert.equal(reopened.alerts[0]!.status, 'open')
  assert.match(reopened.alerts[0]!.note!, /still vulnerable/)

  const gone = planPackageAlerts({ findings: [], existing: [alert('e1'), alert('e2', { status: 'resolved', details: { shape: 'package', package_name: 'axios' } })], criticality: 5, newId: ids })
  assert.deepEqual(gone.resolve.map((r) => r.eventId), ['e1'])     // the closed one is left alone
  assert.equal(gone.alerts.length, 0)
})

test('false positive / accepted risk stay closed, unless a CVE new to the package is on KEV', () => {
  const quiet = planPackageAlerts({ findings: [f('CVE-1'), f('CVE-2')], existing: [alert('e1', { status: 'accepted_risk', knownCves: ['CVE-1'] })], criticality: 5, newId: ids })
  assert.equal(quiet.alerts[0]!.status, undefined)

  const knownKev = planPackageAlerts({ findings: [f('CVE-1', { kev: true })], existing: [alert('e1', { status: 'false_positive', knownCves: ['CVE-1'] })], criticality: 5, newId: ids })
  assert.equal(knownKev.alerts[0]!.status, undefined)            // the person already judged this CVE

  const newKev = planPackageAlerts({ findings: [f('CVE-1'), f('CVE-2', { kev: true })], existing: [alert('e1', { status: 'accepted_risk', knownCves: ['CVE-1'] })], criticality: 5, newId: ids })
  assert.equal(newKev.alerts[0]!.status, 'open')
  assert.match(newKev.alerts[0]!.note!, /CVE-2.*CISA KEV/)
})

test('only dismissed CVEs left: the alert is resolved, and the alert still owns them', () => {
  const p = planPackageAlerts({ findings: [f('CVE-1', { dismissed: true })], existing: [alert('e1')], criticality: 5, newId: ids })
  assert.deepEqual(p.resolve, [{ eventId: 'e1', note: 'Auto-resolved: only CVEs marked not applicable remain' }])
  assert.equal(p.owner.get(findingKey(f('CVE-1'))), 'e1')
})

test('legacy per-CVE rows of a package fold into one alert: the one with an advisory stays', () => {
  const rows = [
    legacy('old-1', 'CVE-1', { firstSeen: new Date('2026-10-01T00:00:00Z') }),
    legacy('old-2', 'CVE-2', { hasLiveAdvisory: true }),
    legacy('old-3', 'CVE-3', { status: 'in_progress', assignedTo: 'u1' }),
  ]
  const p = planPackageAlerts({ findings: [f('CVE-1'), f('CVE-2'), f('CVE-3')], existing: rows, criticality: 5, newId: ids })
  assert.equal(p.alerts.length, 1)
  assert.equal(p.alerts[0]!.eventId, 'old-2')
  assert.equal(p.alerts[0]!.status, 'in_progress')                // the group's most active status
  assert.deepEqual(p.merge.map((m) => [m.from, m.into, m.moveAdvisory]).sort(), [['old-1', 'old-2', false], ['old-3', 'old-2', false]])
  assert.equal(p.alerts[0]!.details.cve_count, 3)
})

test('a legacy CVE closed as false positive inside a still-open package becomes a dismissed finding', () => {
  const rows = [legacy('old-1', 'CVE-1'), legacy('old-2', 'CVE-2', { status: 'false_positive' })]
  const p = planPackageAlerts({ findings: [f('CVE-1'), f('CVE-2')], existing: rows, criticality: 5, newId: ids })
  assert.deepEqual([...p.dismiss], [findingKey(f('CVE-2'))])
  assert.equal(p.alerts[0]!.details.cve_count, 1)                 // the alert counts only the live CVE
  // every row closed as false positive: the package stays closed, nothing is dismissed one by one
  const closed = planPackageAlerts({ findings: [f('CVE-1')], existing: [legacy('old-1', 'CVE-1', { status: 'false_positive' })], criticality: 5, newId: ids })
  assert.deepEqual([closed.alerts[0]!.status, closed.dismiss.size], [undefined, 0])
})

test('closed history of a package that is gone is not folded', () => {
  const p = planPackageAlerts({ findings: [], existing: [legacy('old-1', 'CVE-1', { status: 'resolved' }), legacy('old-2', 'CVE-2', { status: 'resolved' })], criticality: 5, newId: ids })
  assert.deepEqual([p.merge, p.resolve], [[], []])
})

test('chooseKept prefers a package alert, then an advisory, work in progress, an assignee, then the oldest', () => {
  const old = legacy('a', 'CVE-1', { firstSeen: new Date('2026-01-01T00:00:00Z') })
  const assigned = legacy('b', 'CVE-2', { assignedTo: 'u' })
  assert.equal(chooseKept([old, assigned]).eventId, 'b')
  assert.equal(chooseKept([old, legacy('c', 'CVE-3', { firstSeen: new Date('2026-05-01T00:00:00Z') })]).eventId, 'a')
  assert.equal(chooseKept([assigned, alert('pkg')]).eventId, 'pkg')
})

test('a legacy alert stands for its CVE on every installed version it listed', () => {
  const fs = legacyFindings({ cve_id: 'CVE-1', package_name: 'brace-expansion', package_type: 'npm', cvss_base_score: 7.5,
    epss_score: 0.01, kev: true, affected_versions: [{ version: '1.1.11', fix_versions: ['1.1.12'] }, { version: '2.0.1', fix_versions: ['2.0.2'] }] }, 'high')
  assert.deepEqual(fs.map((x) => [x.packageVersion, x.fixVersions, x.kev, x.severity]), [['1.1.11', ['1.1.12'], true, 'high'], ['2.0.1', ['2.0.2'], true, 'high']])
  assert.deepEqual(legacyFindings({ package_name: 'x' }, 'low'), [])
  assert.equal(packageKey('NPM', 'lodash'), 'npm::lodash')
})
