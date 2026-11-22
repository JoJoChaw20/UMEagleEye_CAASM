import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  cleanHits, decodeCursor, domainCandidates, encodeCursor, listItem, listItems, lookupValues, matchHits, planSightings,
  sightingSeverity, type ExistingSighting, type Hit, type IndicatorRow,
} from './sightings'

const NOW = new Date('2026-11-17T10:00:00Z')
const hit = (value: string, over: Partial<Hit> = {}): Hit => ({
  value, type: /^[\d.]+$/.test(value) ? 'ip' : 'domain', via: 'dns', count: 1,
  firstSeen: new Date('2026-11-17T09:00:00Z'), lastSeen: new Date('2026-11-17T09:30:00Z'), process: null, port: null, ...over,
})
let n = 0
const row = (type: IndicatorRow['type'], value: string, over: Partial<IndicatorRow> = {}): IndicatorRow => ({
  indicatorId: `ind-${++n}`, type, value, source: 'ThreatFox', tiEventId: null, title: null, level: null, ...over,
})
let ids = 0
const newId = () => `new-${++ids}`

test('list items: domains and IPs as the agent compares them; a URL only when its host is an IPv4 address', () => {
  assert.deepEqual(listItem('domain', 'Evil.Example.NET.'), { k: 'd', v: 'evil.example.net' })
  assert.deepEqual(listItem('ip', '203.0.113.9'), { k: 'i', v: '203.0.113.9' })
  assert.deepEqual(listItem('ip', '2001:DB8::1'), { k: 'i', v: '2001:db8::1' })
  // a named host may be a shared platform (the lab VM, 17 Nov: t.me, steamcommunity.com, discord.com...)
  assert.equal(listItem('url', 'https://t.me/np33yk'), null)
  assert.equal(listItem('url', 'http://bad.example.org:8080/bins/x86'), null)
  assert.deepEqual(listItem('url', 'http://198.51.100.7:8080/payload.exe'), { k: 'i', v: '198.51.100.7' })
  assert.equal(listItem('url', 'http://[2001:db8::2]/a'), null)
  assert.equal(listItem('domain', 'localhost'), null)          // one label: never seen as a lookup
  assert.equal(listItem('domain', '1.2.3.4'), null)            // an IP filed as a domain
  assert.equal(listItem('url', 'not a url'), null)
  assert.equal(listItem('hash', 'abc'), null)
  assert.deepEqual(listItems([{ type: 'ip', value: '198.51.100.7' }, { type: 'url', value: 'http://198.51.100.7/x' },
    { type: 'url', value: 'https://a.example.com/x' }]), [{ k: 'i', v: '198.51.100.7' }])
})

test('cursor: round trip of the exact Postgres time and id; anything else is no cursor', () => {
  const c = encodeCursor('2026-11-16 21:04:05.123456+00', '6f1c2b1e-3d4a-4b5c-8d9e-0f1a2b3c4d5e')
  assert.match(c, /^[A-Za-z0-9_-]+$/)
  assert.deepEqual(decodeCursor(c), { seen: '2026-11-16 21:04:05.123456+00', id: '6f1c2b1e-3d4a-4b5c-8d9e-0f1a2b3c4d5e' })
  assert.equal(decodeCursor(btoa('2026-11-16|not-a-uuid')), null)
  assert.equal(decodeCursor(btoa("x' OR 1=1|6f1c2b1e-3d4a-4b5c-8d9e-0f1a2b3c4d5e")), null)
  assert.equal(decodeCursor('%%%'), null)
  assert.equal(decodeCursor(undefined), null)
})

test('a looked-up name is listed under itself or any parent with two labels or more', () => {
  assert.deepEqual(domainCandidates('a.b.evil.com'), ['a.b.evil.com', 'b.evil.com', 'evil.com'])
  assert.deepEqual(lookupValues([hit('x.evil.com'), hit('203.0.113.9')]), { ips: ['203.0.113.9'], names: ['x.evil.com', 'evil.com'] })
})

test('clean hits: malformed ones dropped, the agent clock clamped, a process path cut to its name', () => {
  const { hits, rejected } = cleanHits([
    { value: 'C2.Evil.com.', type: 'domain', via: 'dns', count: 14, first_seen: '2026-11-17T09:00:00Z', last_seen: '2026-11-17T09:10:00Z' },
    { value: '203.0.113.9', type: 'ip', via: 'connection', port: 443, process: 'C:\\Program Files\\Edge\\msedge.exe',
      first_seen: '2027-01-01T00:00:00Z', last_seen: '2027-01-01T00:00:00Z' },           // the future: now
    { value: 'evil.com', type: 'ip', via: 'dns' },                                    // not an IP
    { value: 'evil.com', type: 'domain', via: 'http' },                               // unknown way
    'junk',
  ], NOW)
  assert.equal(rejected, 3)
  assert.equal(hits[0]!.value, 'c2.evil.com')
  assert.equal(hits[0]!.count, 14)
  assert.equal(hits[1]!.process, 'msedge.exe')
  assert.equal(hits[1]!.port, 443)
  assert.equal(hits[1]!.lastSeen.getTime(), NOW.getTime())
  assert.equal(cleanHits(Array.from({ length: 205 }, () => ({ value: 'a.evil.com', type: 'domain', via: 'dns' })), NOW).rejected, 5)
})

test('the re-check keeps only listed hits, under the most specific listing; URL-only listings are type url', () => {
  const rows = [row('domain', 'evil.com'), row('domain', 'cdn.evil.com'), row('url', 'http://198.51.100.7/x.sh')]
  const { matched, dropped } = matchHits(
    [hit('a.cdn.evil.com'), hit('www.evil.com'), hit('198.51.100.7', { via: 'connection' }), hit('good.org')], rows)
  assert.deepEqual(dropped.map(h => h.value), ['good.org'])
  assert.deepEqual(matched.map(m => [m.listed, m.itype, m.hits.length]),
    [['cdn.evil.com', 'domain', 1], ['evil.com', 'domain', 1], ['198.51.100.7', 'url', 1]])
})

test('S1 severity: feed and high events critical, medium high, low medium; a URL host one step lower', () => {
  assert.equal(sightingSeverity([row('domain', 'a.com')]), 'critical')
  assert.equal(sightingSeverity([row('domain', 'a.com', { tiEventId: 'e', level: 'medium' })]), 'high')
  assert.equal(sightingSeverity([row('domain', 'a.com', { tiEventId: 'e', level: 'low' })]), 'medium')
  assert.equal(sightingSeverity([row('url', 'http://a.com/x')]), 'high')
  assert.equal(sightingSeverity([row('url', 'http://a.com/x', { tiEventId: 'e', level: 'low' })]), 'low')
  assert.equal(sightingSeverity([row('domain', 'a.com', { tiEventId: 'e', level: 'low' }), row('domain', 'a.com')]), 'critical')
})

test('S1 severity follows a feed entry\'s confidence: 75%+ critical, 50%+ high, below medium', () => {
  assert.equal(sightingSeverity([row('domain', 'a.com', { confidence: 1 })]), 'critical')
  assert.equal(sightingSeverity([row('domain', 'a.com', { confidence: 0.75 })]), 'critical')
  assert.equal(sightingSeverity([row('domain', 'a.com', { confidence: 0.5 })]), 'high')
  assert.equal(sightingSeverity([row('domain', 'a.com', { confidence: 0.25 })]), 'medium')
  assert.equal(sightingSeverity([row('url', 'http://a.com/x', { confidence: 0.25 })]), 'low')
  // the surest source wins
  assert.equal(sightingSeverity([row('domain', 'a.com', { confidence: 0.25 }), row('domain', 'a.com', { confidence: 0.9 })]), 'critical')
  // an event's level does not depend on a confidence
  assert.equal(sightingSeverity([row('domain', 'a.com', { tiEventId: 'e', level: 'high', confidence: null })]), 'critical')
})

test('a first sighting: one alert with what the computer did and who lists it', () => {
  const { matched } = matchHits([
    hit('c2.evil.com', { count: 3 }),
    hit('c2.evil.com', { count: 2, lastSeen: new Date('2026-11-17T09:45:00Z'), process: 'curl', via: 'dns' }),
  ], [row('domain', 'evil.com', { tiEventId: 'ev1', title: 'Campaign X', level: 'medium', source: 'MISP' })])
  const plan = planSightings({ matched, existing: [], newId })
  assert.equal(plan.insert.length, 1)
  const w = plan.insert[0]!
  assert.equal(w.severity, 'high')
  assert.equal(w.details.count, 5)
  assert.equal(w.details.observed, 'c2.evil.com')
  assert.equal(w.details.indicator_value, 'evil.com')
  assert.equal(w.details.rule, 'R7')
  assert.equal(w.details.match_kind, 'sighting')
  assert.equal(w.details.process, 'curl')
  assert.equal(w.details.last_seen_at, '2026-11-17T09:45:00.000Z')
  assert.deepEqual(w.details.ti_event_titles, ['Campaign X'])
  assert.deepEqual(w.details.sources, ['Campaign X'])
  assert.deepEqual(w.details.shared_by, [])
})

test('a sighting of another tenant\'s shared event says who shared it', () => {
  const { matched } = matchHits([hit('c2.evil.com')], [
    row('domain', 'evil.com', { tiEventId: 'ev1', title: 'Campaign X', level: 'high', sharedBy: 'University A' }),
    row('domain', 'evil.com', { tiEventId: 'ev2', title: 'Ours', level: 'low', sharedBy: null }),
  ])
  const w = planSightings({ matched, existing: [], newId }).insert[0]!
  assert.deepEqual(w.details.shared_by, ['University A'])
})

const existing = (status: ExistingSighting['status'], over: Partial<ExistingSighting> = {}): ExistingSighting => ({
  eventId: 'ev-old', status, resolvedAt: null,
  details: { indicator_type: 'domain', indicator_value: 'evil.com', count: 10, seen_via: ['dns'], observed: 'evil.com',
    first_seen_at: '2026-11-10T00:00:00.000Z', last_seen_at: '2026-11-12T00:00:00.000Z', process: 'old.exe', matched_on: 'dns' },
  ...over,
})

test('later contacts add to the count; an open alert stays open; first contact kept', () => {
  const { matched } = matchHits([hit('evil.com', { via: 'connection', count: 2, process: 'new.exe' })], [row('domain', 'evil.com')])
  const plan = planSightings({ matched, existing: [existing('in_progress')], newId })
  assert.equal(plan.insert.length, 0)
  const u = plan.update[0]!
  assert.equal(u.reopen, false)
  assert.equal(u.details.count, 12)
  assert.equal(u.details.first_seen_at, '2026-11-10T00:00:00.000Z')
  assert.deepEqual(u.details.seen_via, ['connection', 'dns'])
  assert.equal(u.details.process, 'new.exe')
  assert.equal(u.details.matched_on, 'connection')
})

test('S4: a contact after resolving reopens it; a late upload from before does not; false positives stay closed', () => {
  const { matched } = matchHits([hit('evil.com')], [row('domain', 'evil.com')])   // last contact 09:30 on the 17th
  const after = planSightings({ matched, existing: [existing('resolved', { resolvedAt: new Date('2026-11-16T00:00:00Z') })], newId })
  assert.equal(after.update[0]!.reopen, true)
  const late = planSightings({ matched, existing: [existing('resolved', { resolvedAt: new Date('2026-11-17T09:40:00Z') })], newId })
  assert.equal(late.update[0]!.reopen, false)
  const fp = planSightings({ matched, existing: [existing('false_positive')], newId })
  assert.equal(fp.update[0]!.reopen, false)
  assert.equal(fp.update[0]!.details.count, 11)
})

test('an older batch never moves the last contact back', () => {
  const { matched } = matchHits([hit('evil.com', { firstSeen: new Date('2026-11-11T00:00:00Z'), lastSeen: new Date('2026-11-11T00:00:00Z'),
    process: 'older.exe' })], [row('domain', 'evil.com')])
  const u = planSightings({ matched, existing: [existing('open')], newId }).update[0]!
  assert.equal(u.details.last_seen_at, '2026-11-12T00:00:00.000Z')
  assert.equal(u.details.process, 'old.exe')
})
