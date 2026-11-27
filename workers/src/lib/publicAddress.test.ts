import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  isPublicAddressStatus, listKindOf, planR11, publicIpOf, r11Details, r11Severity, REFRESH_MS, shouldRecordPublicIp,
  type Listing, type R11Have,
} from './publicAddress'

const feodo: Listing = { kind: 'c2', source: 'ThreatFox', value: '203.106.93.7', confidence: 0.95, family: 'QakBot', ref: null }
const drop: Listing = { kind: 'event', source: 'MyCERT MA-1508: Infostealer Malware', value: '203.106.93.7', confidence: null, family: null, ref: 'ev-1' }

test('R11 severity: ours is firm, unconfirmed is a review item, not ours never alerts', () => {
  assert.equal(r11Severity('ours', [feodo]), 'critical')
  assert.equal(r11Severity('ours', [drop]), 'high')
  assert.equal(r11Severity('unconfirmed', [feodo, drop]), 'medium')
  assert.equal(r11Severity('unconfirmed', [drop]), 'low')
  assert.equal(r11Severity('not_ours', [feodo]), null)
  assert.equal(r11Severity('ours', []), null)
})

test('which list a matched indicator counts as', () => {
  assert.equal(listKindOf('ThreatFox', 'ip', 0.75, false), 'c2')
  assert.equal(listKindOf('ThreatFox', 'ip', 0.25, false), 'malware')        // weak: not a firm C2 listing
  assert.equal(listKindOf('ThreatFox', 'url', 0.9, false), 'malware')        // a malware URL on the address
  assert.equal(listKindOf('Feodo Tracker', 'ip', 0.95, false), 'malware')    // retired: no longer a C2 list
  assert.equal(listKindOf('ThreatFox', 'ip', 0.95, true), 'event')
})

test('R11 plan: create, keep, update, reopen, resolve; decisions stay closed', () => {
  const want = (assetId: string, ip: string, listings: Listing[], status: 'ours' | 'unconfirmed' = 'ours') =>
    ({ assetId, ip, severity: r11Severity(status, listings)!, details: r11Details(ip, 'p1', status, listings) })
  const have = (eventId: string, assetId: string, ip: string, status: string, listings: Listing[], addr = 'ours'): R11Have =>
    ({ eventId, assetId, ip, status, severity: r11Severity(addr as 'ours', listings)!, details: r11Details(ip, 'p1', addr as 'ours', listings) })

  const plan = planR11(
    [want('a1', '1.1.1.1', [feodo]), want('a2', '2.2.2.2', [drop]), want('a3', '3.3.3.3', [feodo, drop]),
      want('a4', '4.4.4.4', [drop]), want('a6', '6.6.6.6', [drop], 'unconfirmed')],
    [have('e2', 'a2', '2.2.2.2', 'open', [drop]),                    // unchanged: nothing to do
      have('e3', 'a3', '3.3.3.3', 'open', [feodo]),                  // a new listing: update
      have('e4', 'a4', '4.4.4.4', 'resolved', [drop]),               // listed again: reopen
      have('e5', 'a5', '5.5.5.5', 'in_progress', [drop]),            // no longer listed: resolve
      have('e6', 'a6', '6.6.6.6', 'false_positive', [drop]),         // a person's decision stands
      have('e7', 'a7', '7.7.7.7', 'resolved', [drop])],              // already closed
  )
  assert.deepEqual(plan.create.map((w) => w.assetId), ['a1'])
  assert.deepEqual(plan.update.map((u) => [u.eventId, u.reopen]), [['e3', false], ['e4', true]])
  assert.deepEqual(plan.resolve, ['e5'])

  // the database hands the listings back with their keys reordered: not a change
  const reordered = (l: Listing) => ({ ref: l.ref, value: l.value, family: l.family, source: l.source, confidence: l.confidence, kind: l.kind })
  const back = have('e8', 'a8', '8.8.8.8', 'open', [feodo])
  back.details = { ...back.details, listings: [reordered(feodo)] }
  assert.deepEqual(planR11([want('a8', '8.8.8.8', [feodo])], [back]), { create: [], update: [], resolve: [] })
})

test('R11 details look like a threat-intel match', () => {
  const d = r11Details('203.106.93.7', 'p1', 'unconfirmed', [feodo])
  assert.equal(d.match_kind, 'public_address')
  assert.equal(d.rule, 'R11')
  assert.equal(d.indicator_value, '203.106.93.7')
  assert.deepEqual(d.sources, ['ThreatFox'])
})

test('public IPv4 addresses are kept, private and special ones are not', () => {
  assert.equal(publicIpOf('203.106.93.7'), '203.106.93.7')
  assert.equal(publicIpOf(' 8.8.8.8 '), '8.8.8.8')
  for (const ip of ['10.1.2.3', '172.20.0.1', '192.168.36.50', '127.0.0.1', '100.64.1.1', '169.254.1.1',
    '0.0.0.0', '224.0.0.251', '255.255.255.255', '192.0.2.10', '198.51.100.1', '203.0.113.9']) {
    assert.equal(publicIpOf(ip), null, ip)
  }
})

test('malformed values are rejected', () => {
  for (const v of [undefined, null, 42, '', 'not an ip', '256.1.1.1', '1.2.3', '1.2.3.4.5', '01.2.3.4', 'a'.repeat(50)]) {
    assert.equal(publicIpOf(v), null, String(v))
  }
})

test('IPv6: global unicast in canonical form, the rest rejected', () => {
  assert.equal(publicIpOf('2404:8000:1001:0:0:0:0:1'), '2404:8000:1001::1')
  assert.equal(publicIpOf('2606:4700:4700::1111'), '2606:4700:4700::1111')
  assert.equal(publicIpOf('2001:DB8::1'), null)                  // documentation
  for (const ip of ['::1', '::', 'fe80::1', 'fd00::1', 'fc00::1', 'ff02::1', '2404:zz::1', '1:2:3']) {
    assert.equal(publicIpOf(ip), null, ip)
  }
})

test('an IPv4-mapped IPv6 address is the IPv4 address', () => {
  assert.equal(publicIpOf('::ffff:203.106.93.7'), '203.106.93.7')
  assert.equal(publicIpOf('::ffff:192.168.1.1'), null)
})

test('stored when it changes or an hour after the last time', () => {
  const now = new Date('2026-11-24T10:00:00Z')
  const at = new Date(now.getTime() - REFRESH_MS + 1000)
  assert.equal(shouldRecordPublicIp({ ip: null, at: null }, '203.106.93.7', now), true)
  assert.equal(shouldRecordPublicIp({ ip: '203.106.93.7', at }, '203.106.93.7', now), false)
  assert.equal(shouldRecordPublicIp({ ip: '203.106.93.8', at }, '203.106.93.7', now), true)
  assert.equal(shouldRecordPublicIp({ ip: '203.106.93.7', at: new Date(now.getTime() - REFRESH_MS) }, '203.106.93.7', now), true)
})

test('statuses', () => {
  assert.equal(isPublicAddressStatus('ours'), true)
  assert.equal(isPublicAddressStatus('not_ours'), true)
  assert.equal(isPublicAddressStatus('unconfirmed'), true)
  assert.equal(isPublicAddressStatus('mine'), false)
  assert.equal(isPublicAddressStatus(null), false)
})
