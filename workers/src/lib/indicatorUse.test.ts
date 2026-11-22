import { test } from 'node:test'
import assert from 'node:assert/strict'
import { PgDialect } from 'drizzle-orm/pg-core'
import { FEED_FRESH, indicatorUseSql } from '../services/threatIntel'
import { usedFor } from '../routes/cti'
import { listItem } from './sightings'

const render = (q: Parameters<PgDialect['sqlToQuery']>[0]) => new PgDialect().sqlToQuery(q).sql

test('what an indicator is used for: reference reasons first, in the order matching drops them', () => {
  const s = render(indicatorUseSql('c'))
  const order = ['reference:retired', 'reference:safe_list', 'reference:not_for_detection', 'reference:expired', "'agents'", "'assets'", 'reference:no_data']
  const at = order.map((k) => s.indexOf(k))
  assert.ok(at.every((i) => i >= 0), JSON.stringify(at))
  assert.deepEqual([...at].sort((a, b) => a - b), at)
  // the same freshness rule as matching (services/threatIntel.ts FEED_FRESH, alias c)
  assert.ok(s.includes(render(FEED_FRESH)))
})

test('the agents get the types their list takes (lib/sightings.ts listItem): IP, domain, hash, URL on an IPv4 host', () => {
  const s = render(indicatorUseSql('c'))
  assert.match(s, /c\.indicator_type IN \('ip', 'domain', 'hash'\) THEN 'agents'/)
  assert.match(s, /c\.indicator_type = 'url' AND .*\[0-9\]\{1,3\}.*THEN 'agents'/)
  assert.ok(listItem('ip', '203.0.113.9') && listItem('domain', 'evil.com') && listItem('hash', 'a'.repeat(64)) && listItem('url', 'http://198.51.100.7/x'))
  assert.equal(listItem('url', 'https://evil.com/x'), null)      // a named host: checked against assets, not by agents
  assert.equal(listItem('email', 'a@evil.com'), null)
})

test('the API shape: agents / assets, or reference with its reason', () => {
  assert.deepEqual(usedFor('agents'), { used_for: 'agents', reference_reason: null })
  assert.deepEqual(usedFor('assets'), { used_for: 'assets', reference_reason: null })
  assert.deepEqual(usedFor('reference:expired'), { used_for: 'reference', reference_reason: 'expired' })
  assert.deepEqual(usedFor('anything else'), { used_for: 'reference', reference_reason: 'no_data' })
})
