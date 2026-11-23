import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  NOTHING, internetDetails, internetFindings, parseInternetDb, planInternetAlerts, type InternetWant,
} from './internetView'

// The shape of https://internetdb.shodan.io/<ip> (Shodan's documented example)
const SAMPLE = {
  cpes: ['cpe:/a:f5:nginx', 'cpe:/a:openbsd:openssh:8.2p1'], hostnames: ['mail.example.my'], ip: '203.106.93.7',
  ports: [443, 22, 3389, 80, 3389, 7547], tags: ['self-signed'], vulns: ['CVE-2023-38408', 'not-a-cve'],
}

test('InternetDB answers are cleaned', () => {
  const v = parseInternetDb(SAMPLE)!
  assert.equal(v.found, true)
  assert.deepEqual(v.ports, [22, 80, 443, 3389, 7547])
  assert.deepEqual(v.vulns, ['CVE-2023-38408'])
  assert.deepEqual(v.hostnames, ['mail.example.my'])
  assert.equal(parseInternetDb({ detail: 'No information available' }), null)
  assert.equal(parseInternetDb(null), null)
})

test('risky ports are critical, management ports high, web ports nothing', () => {
  const f = internetFindings(parseInternetDb(SAMPLE)!)
  assert.deepEqual(f.map((x) => [x.port, x.severity]), [[22, 'high'], [3389, 'critical'], [7547, 'high']])
  assert.equal(f[1]!.title, 'RDP open to the internet')
  assert.deepEqual(internetFindings(NOTHING), [])
})

test('plan: create, refresh, reopen, resolve; decisions and duplicates', () => {
  const view = parseInternetDb(SAMPLE)!
  const want = (assetId: string, port: number): InternetWant => {
    const finding = internetFindings(view).find((x) => x.port === port)!
    return { assetId, port, finding, details: internetDetails(finding, '203.106.93.7', 'p1', '2026-11-24T00:00:00Z', view) }
  }
  const plan = planInternetAlerts(
    [want('gw', 22), want('gw', 3389), want('gw', 7547)],
    [{ eventId: 'e1', assetId: 'gw', port: 3389, status: 'open', severity: 'critical' },
      { eventId: 'e1b', assetId: 'gw', port: 3389, status: 'open', severity: 'critical' },        // a duplicate
      { eventId: 'e2', assetId: 'gw', port: 7547, status: 'resolved', severity: 'high' },
      { eventId: 'e3', assetId: 'gw', port: 22, status: 'accepted_risk', severity: 'high' },
      { eventId: 'e4', assetId: 'gw', port: 5900, status: 'open', severity: 'critical' }],          // closed since
  )
  assert.deepEqual(plan.create, [])
  assert.deepEqual(plan.refresh.map((r) => [r.eventId, r.reopen]), [['e1', false], ['e2', true]])
  assert.deepEqual(plan.resolve.sort(), ['e1b', 'e4'])
  const d = want('gw', 3389).details
  assert.equal(d.rule, 'internet_view')
  assert.equal((d.evidence as Record<string, unknown>).source, 'Shodan InternetDB')
})
