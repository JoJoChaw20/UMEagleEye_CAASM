import { test } from 'node:test'
import assert from 'node:assert/strict'
import { evaluatePosture } from './endpointPosture'
import { deviceTypeFor, type InventoryPayload } from './endpointInventory'

test("a phone's posture: its own checks, no PC checks, a patch level judged by phone standards", () => {
  const phone = {
    platform: 'android',
    patches: { days_since_last_patch: 75 },
    security: { disk_encryption: [{ volume: '/data', protection: 'on' }], screen_lock: true, rooted: false, usb_debugging: true },
  }
  const r = evaluatePosture(phone)
  assert.deepEqual(r.checks.map((c) => [c.id, c.state]), [
    ['disk_encryption', 'good'], ['updates', 'good'], ['screen_lock', 'good'], ['rooted', 'good'], ['usb_debugging', 'warn']])
  assert.equal(r.score, Math.round(100 * (15 + 20 + 15 + 15 + 2.5) / 70))
  const bad = evaluatePosture({ ...phone, patches: { days_since_last_patch: 200 },
    security: { ...phone.security, screen_lock: false, rooted: true, root_signals: ['su binary'] } })
  assert.deepEqual(bad.checks.filter((c) => c.state === 'bad').map((c) => c.id), ['updates', 'screen_lock', 'rooted'])
  assert.match(bad.checks.find((c) => c.id === 'rooted')!.detail!, /su binary/)
  // A PC with the same patch age is judged as before (75 days: bad)
  assert.equal(evaluatePosture({ platform: 'win32', patches: { days_since_last_patch: 75 } }).checks.find((c) => c.id === 'updates')!.state, 'bad')
})

test('a phone is a mobile device', () => {
  assert.equal(deviceTypeFor({ platform: 'android', os: { role: 'mobile' }, hardware: { form_factor: 'phone' } } as unknown as InventoryPayload), 'mobile')
  assert.equal(deviceTypeFor({ platform: 'linux', os: { role: 'server' } } as unknown as InventoryPayload), 'server')
})
