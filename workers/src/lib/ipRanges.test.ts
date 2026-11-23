import { test } from 'node:test'
import assert from 'node:assert/strict'
import { inCidr, parseDrop, rangesContaining } from './ipRanges'

// The format of https://www.spamhaus.org/drop/drop_v4.json, as fetched on 23 Nov 2026
const SAMPLE = [
  '{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}',
  '{"cidr":"1.19.0.0/16","sblid":"SBL434604","rir":"apnic"}',
  'not json',
  '{"cidr":"999.1.1.0/24","sblid":"SBLbad","rir":"x"}',
  '{"cidr":"2001:678:254::/48","sblid":"SBL697648","rir":"ripencc"}',
  '{"type":"metadata","timestamp":1795435004,"size":106869,"records":1752,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}',
].join('\n')

test('DROP lines: ranges kept, bad lines skipped, metadata read', () => {
  const d = parseDrop(SAMPLE)
  assert.deepEqual(d.ranges.map((r) => r.cidr), ['1.10.16.0/20', '1.19.0.0/16', '2001:678:254::/48'])
  assert.equal(d.ranges[0]!.sblid, 'SBL256894')
  assert.equal(d.timestamp, 1795435004)
  assert.equal(d.copyright, '(c) 2026 The Spamhaus Project SLU')
})

test('IPv4 ranges', () => {
  assert.equal(inCidr('1.10.16.1', '1.10.16.0/20'), true)
  assert.equal(inCidr('1.10.31.255', '1.10.16.0/20'), true)
  assert.equal(inCidr('1.10.32.0', '1.10.16.0/20'), false)
  assert.equal(inCidr('203.106.93.7', '0.0.0.0/0'), true)
  assert.equal(inCidr('203.106.93.7', '203.106.93.7/32'), true)
  assert.equal(inCidr('203.106.93.8', '203.106.93.7/32'), false)
  assert.equal(inCidr('bad', '1.10.16.0/20'), false)
  assert.equal(inCidr('1.10.16.1', '1.10.16.0/33'), false)
})

test('IPv6 ranges, and no mixing of families', () => {
  assert.equal(inCidr('2001:678:254::1', '2001:678:254::/48'), true)
  assert.equal(inCidr('2001:678:254:ffff:1:2:3:4', '2001:678:254::/48'), true)
  assert.equal(inCidr('2001:678:255::1', '2001:678:254::/48'), false)
  assert.equal(inCidr('2404:8000:1001::1', '2404::/16'), true)
  assert.equal(inCidr('1.10.16.1', '2001:678:254::/48'), false)
  assert.equal(inCidr('2001:678:254::1', '1.10.16.0/20'), false)
  assert.equal(inCidr('2001:678::254::1', '2001:678:254::/48'), false)
})

test('the ranges an address is in', () => {
  const { ranges } = parseDrop(SAMPLE)
  assert.deepEqual(rangesContaining('1.19.200.3', ranges).map((r) => r.sblid), ['SBL434604'])
  assert.deepEqual(rangesContaining('8.8.8.8', ranges), [])
})
