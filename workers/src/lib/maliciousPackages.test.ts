import { test } from 'node:test'
import assert from 'node:assert/strict'
import { isMalwareId, malDetails, malIdsOf, malSeverity, osvQuery, recordScope } from './maliciousPackages'

test('the OSV query: by purl when it names the version, else name + ecosystem + version', () => {
  assert.deepEqual(osvQuery({ pm: 'npm', name: '@ctrl/tinycolor', version: '4.1.1', purl: 'pkg:npm/%40ctrl/tinycolor@4.1.1' }),
    { package: { purl: 'pkg:npm/%40ctrl/tinycolor@4.1.1' } })
  // qualifiers and subpath are dropped
  assert.deepEqual(osvQuery({ pm: 'maven', name: 'log4j-core', version: '2.14.1', purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar' }),
    { package: { purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1' } })
  assert.deepEqual(osvQuery({ pm: 'pypi', name: 'colourama', version: '0.1.6', purl: null }),
    { package: { name: 'colourama', ecosystem: 'PyPI' }, version: '0.1.6' })
  // a purl without a version, or of another type, is not trusted
  assert.deepEqual(osvQuery({ pm: 'npm', name: 'x', version: '1.0.0', purl: 'pkg:npm/x' }), { package: { name: 'x', ecosystem: 'npm' }, version: '1.0.0' })
})

test('package managers OSV has no malware records for are not asked', () => {
  assert.equal(osvQuery({ pm: 'deb', name: 'openssl', version: '3.0.2', purl: 'pkg:deb/ubuntu/openssl@3.0.2' }), null)
  assert.equal(osvQuery({ pm: null, name: 'x', version: '1', purl: null }), null)
  assert.equal(osvQuery({ pm: 'npm', name: 'x', version: '', purl: null }), null)
})

test('only MAL- ids count from the batch answer (CVE and GHSA advisories are flaws, handled elsewhere)', () => {
  assert.deepEqual(malIdsOf({ vulns: [{ id: 'GHSA-29mw-wpgm-hmr9' }, { id: 'MAL-2025-47141' }, { id: 'MAL-2025-47141' }] }), ['MAL-2025-47141'])
  assert.deepEqual(malIdsOf({}), [])
  assert.deepEqual(malIdsOf(null), [])
  assert.equal(isMalwareId('MAL-2024-1'), true)
  assert.equal(isMalwareId('MALWARE'), false)
})

test('a record listing releases is a release match; one covering every version is a name match', () => {
  // MAL-2025-47141 (@ctrl/tinycolor 4.1.1-4.1.2) and MAL-2022-6972 (vscode-bicep, any version), as OSV serves them
  assert.equal(recordScope({ affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '4.1.1' }, { last_affected: '4.1.2' }] }], versions: ['4.1.2', '4.1.1'] }] }), 'version')
  assert.equal(recordScope({ affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }] }), 'name')
  assert.equal(recordScope({ affected: [{ ranges: [{ events: [{ introduced: '0' }] }], versions: ['1.0.0'] }] }), 'version')
  assert.equal(recordScope({ affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }] }), 'version')
  assert.equal(recordScope(null), 'name')
  assert.equal(malSeverity('version'), 'critical')
  assert.equal(malSeverity('name'), 'medium')
})

test('the alert names the package exactly, as one indicator per version', () => {
  const d = malDetails({ pm: 'npm', name: '@ctrl/tinycolor', version: '4.1.1', purl: 'pkg:npm/%40ctrl/tinycolor@4.1.1' },
    ['MAL-2025-47141'], 'OSV malicious packages (OpenSSF)', 'Malicious code in @ctrl/tinycolor (npm)', 'version')
  assert.equal(d.match_scope, 'version')
  assert.equal(d.indicator_value, 'npm:@ctrl/tinycolor@4.1.1')
  assert.equal(d.match_kind, 'malicious_package')
  assert.equal(d.rule, 'R8')
  assert.equal(d.ecosystem, 'npm')
  assert.deepEqual(d.sources, ['OSV malicious packages (OpenSSF)'])
  // Grype's package types are not OSV's names: shown as they are
  assert.equal(malDetails({ pm: 'python', name: 'x', version: '1', purl: null }, ['CVE-1'], 's', null, 'version').ecosystem, 'python')
})
