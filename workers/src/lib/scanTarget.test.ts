import { test } from 'node:test'
import assert from 'node:assert/strict'
import { networkTargetRefusal, scanTargetRefusal } from './scanTarget'

test('private ranges up to a /16 can be scanned', () => {
  for (const ok of ['192.168.1.0/24', '10.10.1.41', '172.20.0.0/16', '100.64.5.0/24', '10.179.32.0/19']) {
    assert.equal(scanTargetRefusal(ok), null, ok)
  }
})

test('public addresses, larger ranges and nonsense are refused', () => {
  assert.match(scanTargetRefusal('8.8.8.0/24')!, /private/)
  assert.match(scanTargetRefusal('10.0.0.0/8')!, /\/16/)
  assert.match(scanTargetRefusal('0.0.0.0/0')!, /\/16/)
  assert.match(scanTargetRefusal('172.32.0.0/24')!, /private/)        // just outside 172.16.0.0/12
  assert.match(scanTargetRefusal('not-an-ip')!, /IPv4/)
})

test('a public network an agent is directly on can be scanned', () => {
  assert.equal(scanTargetRefusal('203.106.10.0/24', ['203.106.10.0/24']), null)
  assert.equal(scanTargetRefusal('203.106.10.77', ['203.106.10.0/24']), null)
  assert.match(scanTargetRefusal('203.106.11.0/24', ['203.106.10.0/24'])!, /private/)
})

test('a network agent starts from and crawls private addresses only (or its own networks)', () => {
  assert.equal(networkTargetRefusal('10.99.0.1'), null)
  assert.equal(networkTargetRefusal('10.0.0.0/8'), null)
  assert.match(networkTargetRefusal('1.2.3.4')!, /not a private/)
  assert.match(networkTargetRefusal('0.0.0.0/0')!, /not a private/)
  assert.equal(networkTargetRefusal('203.106.10.1', ['203.106.10.0/24']), null)
})
