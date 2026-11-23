import { test } from 'node:test'
import assert from 'node:assert/strict'
import { linuxUpdateFacts, planLinuxUpdateAlert } from './linuxUpdates'

const inv = (packages: unknown[] | null, extra: Record<string, unknown> = {}) => ({
  platform: 'linux', os: { name: 'Ubuntu 26.04.1 LTS' }, patches: { pending_reboot: false },
  baseline: { security_updates: packages == null ? null : packages.length, security_update_packages: packages, ...extra },
})
const OPENSSL = { name: 'openssl', installed: '3.5.0-1ubuntu1', available: '3.5.0-1ubuntu1.1' }
const LIBSSL = { name: 'libssl3t64', installed: '3.5.0-1ubuntu1', available: '3.5.0-1ubuntu1.1' }

test('facts: Linux only; no answer from apt/dnf is unknown, not up to date', () => {
  assert.equal(linuxUpdateFacts({ platform: 'windows' }), null)
  assert.equal(linuxUpdateFacts(inv(null))!.status, 'unknown')
  assert.equal(linuxUpdateFacts({ platform: 'linux' })!.status, 'unknown')               // an agent older than the baseline
  assert.deepEqual(linuxUpdateFacts(inv([]))!, { status: 'current', product: 'Ubuntu 26.04.1 LTS', updates: 0, packages: [], restart_pending: false })
  const f = linuxUpdateFacts(inv([OPENSSL, { bogus: 1 }]))!
  assert.equal(f.status, 'behind')
  assert.deepEqual(f.packages, [OPENSSL])                                                 // junk entries dropped
})

test('one alert while updates wait: opened, updated, resolved; quiet after a false positive until a new package', () => {
  const behind = linuxUpdateFacts(inv([OPENSSL]))!
  const open = planLinuxUpdateAlert(behind, null, null)
  assert.equal(open.kind, 'open')
  if (open.kind !== 'open') return
  assert.equal(open.details['platform'], 'linux')
  assert.equal(open.details['updates'], 1)
  assert.equal(planLinuxUpdateAlert(behind, { eventId: 'e1' }, null).kind, 'update')
  assert.deepEqual(planLinuxUpdateAlert(linuxUpdateFacts(inv([]))!, { eventId: 'e1' }, null),
    { kind: 'resolve', eventId: 'e1', note: 'Auto-resolved: no security updates waiting' })
  assert.equal(planLinuxUpdateAlert(linuxUpdateFacts(inv(null))!, { eventId: 'e1' }, null).kind, 'none')
  const closed = { status: 'accepted_risk', details: open.details }
  assert.equal(planLinuxUpdateAlert(behind, null, closed).kind, 'suppressed')
  assert.equal(planLinuxUpdateAlert(linuxUpdateFacts(inv([OPENSSL, LIBSSL]))!, null, closed).kind, 'open')
})
