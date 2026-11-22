import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EXPOSURE_TECHNIQUES, exposureAttackOf } from './exposureAttack'
import { RULES, type RuleId } from './exposureRules'
import { techniqueName } from './attack'

test('every exposure rule has a mapping, and every technique is in ATT&CK', () => {
  for (const rule of Object.keys(RULES) as RuleId[]) {
    assert.ok(Array.isArray(EXPOSURE_TECHNIQUES[rule]), rule)
    for (const u of EXPOSURE_TECHNIQUES[rule]) assert.ok(techniqueName(u.id), `${rule}: ${u.id}`)
  }
})

test('an exposure alert gets its rule\'s techniques, named, with why', () => {
  const r = exposureAttackOf('exposure', { rule: 'smb_signing_off', port: 445 }, false)
  assert.deepEqual(r?.techniques.map((t) => t.id), ['T1557.001', 'T1021.002'])
  assert.equal(r?.techniques[0]?.name, 'Name Resolution Poisoning and SMB Relay')
  assert.match(r!.techniques[0]!.why, /relay/)
  assert.match(r!.source, /mapped from the weakness/)
})

test('an expiring certificate and an unknown rule have none', () => {
  assert.equal(exposureAttackOf('exposure', { rule: 'tls_expiring' }, false), null)
  assert.equal(exposureAttackOf('exposure', { rule: 'nope' }, false), null)
  assert.equal(exposureAttackOf('exposure', null, false), null)
})

test('a vulnerable service: exploited remotely, from the internet or inside; KEV ones are left to CTID', () => {
  assert.deepEqual(exposureAttackOf('vulnerable_service', { cve_count: 3 }, true)?.techniques.map((t) => t.id), ['T1190'])
  assert.deepEqual(exposureAttackOf('vulnerable_service', { cve_count: 3 }, false)?.techniques.map((t) => t.id), ['T1210'])
  assert.equal(exposureAttackOf('vulnerable_service', { cve_count: 3, kev: true }, false), null)
  assert.equal(exposureAttackOf('vulnerable_service', { cve_count: 0 }, false), null)
  assert.equal(exposureAttackOf('cve_detected', { rule: 'telnet' }, false), null)
})
