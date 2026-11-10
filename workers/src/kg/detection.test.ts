import test from 'node:test'
import assert from 'node:assert/strict'
import { sameProblemOpen, stillDetectedMessage } from './detection'

test('the same problem means same device, type, open status and identifying details', () => {
  const sql = sameProblemOpen('o', 'e')
  assert.match(sql, /o\.asset_id = e\.asset_id/)
  assert.match(sql, /o\.event_type = e\.event_type/)
  assert.match(sql, /o\.status::text IN \('open', 'in_progress'\)/)
  for (const k of ['port', 'cve_id', 'rule', 'changed_attribute', 'package_name', 'indicator_value', 'key'])
    assert.ok(sql.includes(`(o.details->>'${k}') IS NOT DISTINCT FROM (e.details->>'${k}')`), k)
})

test('a still-detected port names the port, the device and the last scan in UTC', () => {
  const m = stillDetectedMessage({ hostname: 'JoJochaw', last_scanned: '2026-10-08T08:57:34.532Z', alert_type: 'port_opened', port: '445' })
  assert.match(m, /^Not closed: Port 445 is still detected on JoJochaw\./)
  assert.match(m, /last scan of the device, on 2026-10-08 08:57 UTC\./)
  assert.match(m, /scan the device again/)
})

test('another type says this problem; no hostname falls back to the IP; no scan is said plainly', () => {
  const m = stillDetectedMessage({ hostname: '', ip_address: '192.168.0.1', last_scanned: null, alert_type: 'os_patch_missing', port: null })
  assert.match(m, /^Not closed: This problem is still detected on 192\.168\.0\.1\./)
  assert.match(m, /no recorded scan/)
  assert.match(stillDetectedMessage({}), /on the device\./)
})

test('a CVE names the software scan (SBOM) time, not the network scan', () => {
  const m = stillDetectedMessage({ hostname: 'DESKTOP-8RMHVMR', last_scanned: '2026-07-28T15:04:00Z', last_sbom: '2026-07-20T01:02:00Z', alert_type: 'cve_detected' })
  assert.match(m, /^Not closed: this CVE is still detected on DESKTOP-8RMHVMR\./)
  assert.match(m, /latest software scan \(SBOM\), on 2026-07-20 01:02 UTC/)
  assert.doesNotMatch(m, /2026-07-28/)
  assert.match(stillDetectedMessage({ alert_type: 'cve_detected', hostname: 'x' }), /no software scan \(SBOM\) on record/)
})

test('a new device says how its alert closes, with no scan time', () => {
  const m = stillDetectedMessage({ ip_address: '192.168.100.126', last_scanned: '2026-07-28T15:04:00Z', alert_type: 'new_device' })
  assert.match(m, /^Not closed: the new-device alert for 192\.168\.100\.126 is still open\. It closes when the device is added to My Assets/)
  assert.doesNotMatch(m, /UTC/)
})
