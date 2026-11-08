import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  DEFAULTS, adoptLocal, applyChange, cleanPolicy, cleanReport, jobRefusal, kindKeys, policyVersion, resolvePolicy, roleChange,
} from './agentPolicy'

const DEFAULTS_HOST = Object.fromEntries(kindKeys('host').map((k) => [k, DEFAULTS[k]]))

test('a setting nobody set is the built-in default, and every value is delivered', () => {
  const r = resolvePolicy({})
  const passive = r.entries.find((e) => e.key === 'passive')!
  assert.deepEqual([passive.value, passive.source, passive.inherited], [false, 'default', false])
  assert.deepEqual(r.managed, { ...DEFAULTS_HOST })                          // the agent applies all of them
  assert.equal(r.version, policyVersion(r.managed))
})

test('agent override beats tenant default beats the built-in default', () => {
  const r = resolvePolicy({ overrides: { passive: false }, tenantDefaults: { passive: true, sbom: false } })
  const by = Object.fromEntries(r.entries.map((e) => [e.key, e]))
  assert.deepEqual([by.passive!.value, by.passive!.source, by.passive!.tenant_default], [false, 'agent', true])
  assert.deepEqual([by.sbom!.value, by.sbom!.source], [false, 'tenant'])
  assert.deepEqual([by.inventory!.value, by.inventory!.source], [true, 'default'])
  assert.deepEqual([r.managed.passive, r.managed.sbom, r.managed.inventory], [false, false, true])
})

test('engine, capture and agent-started scans are no longer settings', () => {
  for (const gone of ['scan_engine', 'passive_backend', 'local_scans']) {
    assert.ok(!(kindKeys('host') as readonly string[]).includes(gone), gone)
  }
  assert.deepEqual(cleanPolicy({ scan_engine: 'compare', passive_backend: 'npcap', local_scans: true, passive: true }), { passive: true })
})

test('roles are read from the settings', () => {
  const r = resolvePolicy({ overrides: { inventory: false, sbom: true, passive: false, scanner: false } })
  assert.deepEqual(r.roles, { inventory: true, sensor: false, scanner: false })
  assert.deepEqual(resolvePolicy({}).roles, { inventory: true, sensor: false, scanner: true })
  assert.deepEqual(roleChange('inventory', false), { inventory: false, sbom: false })
})

test('stored policy is cleaned: unknown keys and bad values are dropped', () => {
  assert.deepEqual(cleanPolicy({ passive: 'yes', passive_interval: 5, scan_ports: 'wide', evil: 1 }), { scan_ports: 'wide' })
  assert.deepEqual(cleanPolicy(null), {})
  assert.deepEqual(cleanPolicy([1, 2]), {})
})

test('changes are validated and null removes an override', () => {
  const ok = applyChange({ passive: true, sbom: false }, { passive: null, sbom_interval: 86400 }, kindKeys('host'))
  assert.deepEqual([ok.policy, ok.errors], [{ sbom: false, sbom_interval: 86400 }, []])
  const bad = applyChange({}, { sbom_interval: 60, scan_ports: 'all', scan_engine: 'own', nope: true }, kindKeys('host'))
  assert.deepEqual(bad.errors, [
    'sbom_interval: must be a whole number from 3600 to 2592000',
    'scan_ports: must be one of base, consumer, wide',
    'scan_engine: not a setting of this agent',
    'nope: not a setting of this agent',
  ])
})

test('the version changes only when the managed settings change', () => {
  assert.equal(policyVersion({ a: 1, b: true } as never), policyVersion({ b: true, a: 1 } as never))
  assert.notEqual(policyVersion({ passive: true }), policyVersion({ passive: false }))
  assert.match(policyVersion({}), /^[0-9a-f]{8}$/)
})

test('jobs a policy rules out are refused with a reason', () => {
  assert.match(jobRefusal({ scanner: false }, 'active')!, /Scanner role/)
  assert.match(jobRefusal({ inventory: false }, 'inventory')!, /inventory/)
  assert.match(jobRefusal({ sbom: false }, 'sbom')!, /SBOM/)
  assert.equal(jobRefusal({ scanner: true, inventory: true, sbom: true }, 'active'), null)
})

test('what an agent reports is kept within limits', () => {
  const r = cleanReport({
    kind: 'host', settings: { passive: true, junk: 1 }, policy_version: 'abcdef12',
    capabilities: { native_capture: true, os: 'windows', 'Bad Key': 1, long: 'x'.repeat(200), nested: { a: 1 } },
  })
  assert.deepEqual(r, { kind: 'host', settings: { passive: true }, capabilities: { native_capture: true, os: 'windows' },
    policyVersion: 'abcdef12', networks: [] })
  assert.deepEqual(cleanReport({ kind: 'toaster', policy_version: 'x' }).kind, null)
})

test('each setting says what it inherits without this agent override', () => {
  const r = resolvePolicy({ overrides: { passive: false }, tenantDefaults: { passive: true } })
  const by = Object.fromEntries(r.entries.map((e) => [e.key, e]))
  assert.deepEqual([by.passive!.value, by.passive!.inherited], [false, true])     // the tenant default underneath
  assert.deepEqual([by.scanner!.value, by.scanner!.inherited, by.scanner!.source], [true, true, 'default'])
})

test('the networks an agent reports are kept only when they look like IPv4 ranges', () => {
  const r = cleanReport({ networks: ['192.168.36.0/24', 'fe80::/64', 42, '10.0.0.0/8; drop table', '10.1.0.0/16'] })
  assert.deepEqual(r.networks, ['192.168.36.0/24', '10.1.0.0/16'])
  assert.deepEqual(cleanReport({}).networks, [])
})

test('a network agent has its own settings and the Collector role', () => {
  assert.ok(kindKeys('network').includes('network_ranges') && !kindKeys('network').includes('passive'))
  assert.ok(!kindKeys('host').includes('network_seeds'))
  const r = resolvePolicy({ kind: 'network', overrides: { network_seeds: ['10.99.0.1'] } })
  assert.deepEqual(r.roles, { collector: true })
  assert.deepEqual(r.managed, { network_poll: true, network_seeds: ['10.99.0.1'], network_ranges: [], network_depth: 3, network_interval: 900 })
  assert.deepEqual(Object.keys(resolvePolicy({}).roles).sort(), ['inventory', 'scanner', 'sensor'])
  assert.match(jobRefusal({ network_poll: false }, 'snmp')!, /Collector role/)
  assert.equal(jobRefusal({ network_poll: true }, 'snmp'), null)
})

test('address and range lists are checked and written the same way', () => {
  const keys = kindKeys('network')
  const ok = applyChange({}, { network_seeds: ['10.99.0.1', ' 10.99.0.1 '], network_ranges: ['10.10.5.1/16', '10.99.0.0/24', '0.0.0.0/0'] }, keys)
  assert.deepEqual(ok.errors, [])
  assert.deepEqual(ok.policy.network_seeds, ['10.99.0.1'])
  assert.deepEqual(ok.policy.network_ranges, ['10.10.0.0/16', '10.99.0.0/24', '0.0.0.0/0'])
  for (const bad of [['10.99.0'], ['10.99.0.256'], 'x', [1]]) {
    assert.match(applyChange({}, { network_seeds: bad }, keys).errors[0]!, /IPv4 addresses/)
  }
  for (const bad of [['10.0.0.0/33'], ['10.0.0.0'], ['10.0.0.0/8/1'], Array(33).fill('10.0.0.0/8')]) {
    assert.match(applyChange({}, { network_ranges: bad }, keys).errors[0]!, /ranges/)
  }
  assert.deepEqual(cleanPolicy({ network_ranges: ['10.0.0.0/8', 'nope'] }, keys), {})   // a stored bad list is dropped
  assert.deepEqual(cleanReport({ kind: 'network', settings: { network_depth: 3, passive: true } }).settings, { network_depth: 3 })
})

test('an agent own choices become its settings once, without overriding the admin', () => {
  const adopted = adoptLocal('host', { passive: true, inventory: true, sbom_interval: 3600, scan_engine: 'compare' },
    { scanner: false }, { sbom_interval: 7200 })
  // passive differs from the default: adopted; inventory equals the default: left to the default;
  // sbom_interval is the tenant's; scanner was the admin's; scan_engine is no longer a setting
  assert.deepEqual(adopted, { scanner: false, passive: true })
  const net = adoptLocal('network', { network_seeds: ['10.99.0.1'], network_depth: 3 }, {}, {})
  assert.deepEqual(net, { network_seeds: ['10.99.0.1'] })
})
