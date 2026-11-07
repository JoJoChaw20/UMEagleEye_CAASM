import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  applyChange, cleanPolicy, cleanReport, jobRefusal, kindKeys, policyVersion, resolvePolicy, roleChange,
} from './agentPolicy'

test('a setting nobody set stays the agent own setting', () => {
  const r = resolvePolicy({ reported: { passive: true, inventory: false } })
  const passive = r.entries.find((e) => e.key === 'passive')!
  assert.deepEqual([passive.value, passive.source], [true, 'local'])
  assert.deepEqual(r.managed, {})
  assert.equal(r.version, policyVersion({}))
})

test('agent override beats tenant default beats the agent own setting', () => {
  const r = resolvePolicy({
    overrides: { passive: false },
    tenantDefaults: { passive: true, sbom: false },
    reported: { passive: true, sbom: true, inventory: true },
  })
  const by = Object.fromEntries(r.entries.map((e) => [e.key, e]))
  assert.deepEqual([by.passive!.value, by.passive!.source, by.passive!.tenant_default], [false, 'agent', true])
  assert.deepEqual([by.sbom!.value, by.sbom!.source], [false, 'tenant'])
  assert.deepEqual([by.inventory!.value, by.inventory!.source], [true, 'local'])
  assert.deepEqual(r.managed, { passive: false, sbom: false })
})

test('the tenant scan policy column is the default of local_scans', () => {
  const r = resolvePolicy({ allowLocalScans: false, reported: { local_scans: true } })
  assert.equal(r.managed.local_scans, false)
  const overridden = resolvePolicy({ allowLocalScans: false, overrides: { local_scans: true } })
  assert.equal(overridden.managed.local_scans, true)
})

test('an older agent that reports nothing: unknown, except that it runs dashboard scans', () => {
  const r = resolvePolicy({})
  assert.equal(r.entries.find((e) => e.key === 'passive')!.source, 'unknown')
  assert.deepEqual(r.roles, { inventory: null, sensor: null, scanner: true })
  assert.equal(jobRefusal(r.effective, 'inventory'), null)        // unknown never blocks
})

test('roles are read from the settings', () => {
  const r = resolvePolicy({ reported: { inventory: false, sbom: true, passive: false, scanner: false } })
  assert.deepEqual(r.roles, { inventory: true, sensor: false, scanner: false })
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
  const bad = applyChange({}, { sbom_interval: 60, scan_engine: 'nmap', nope: true }, kindKeys('host'))
  assert.deepEqual(bad.errors, [
    'sbom_interval: must be a whole number from 3600 to 2592000',
    'scan_engine: must be one of auto, own, compare',
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
    policyVersion: 'abcdef12' })
  assert.deepEqual(cleanReport({ kind: 'toaster', policy_version: 'x' }).kind, null)
})

test('each setting says what it inherits without this agent override', () => {
  const r = resolvePolicy({ overrides: { passive: false }, tenantDefaults: { passive: true }, reported: { sbom: true } })
  const by = Object.fromEntries(r.entries.map((e) => [e.key, e]))
  assert.deepEqual([by.passive!.value, by.passive!.inherited], [false, true])     // the tenant default underneath
  assert.deepEqual([by.sbom!.value, by.sbom!.inherited], [true, true])
  assert.deepEqual([by.scanner!.value, by.scanner!.inherited, by.scanner!.source], [true, true, 'local'])  // every agent runs them
  assert.equal(by.inventory!.inherited, null)                                     // not reported: unknown
})
