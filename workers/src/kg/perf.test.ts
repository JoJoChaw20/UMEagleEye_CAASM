import test from 'node:test'
import assert from 'node:assert/strict'
import { Hono } from 'hono'
import type { Env } from '../types'
import {
  addDbWait, buildWindows, normalisePath, parsePerfRows, perfMiddleware, perfQuery, recordJob, refreshPerf, resetPerfWarning,
  timedJob, UNMATCHED_ROUTE, type PerfRow,
} from './perf'

type Point = { indexes?: string[]; blobs?: string[]; doubles?: number[] }
const fakePerf = () => { const points: Point[] = []; return { points, writeDataPoint: (p: Point) => { points.push(p) } } }
const envWith = (perf: unknown, extra: object = {}) => ({ PERF: perf, APP_ENV: 'staging', ...extra }) as unknown as Env

// ── normalisePath ───────────────────────────────────────────────────

test('normalisePath: ids and IPs record no value', () => {
  assert.equal(normalisePath('/api/v1/assets/3f2b8c1e-1a2b-4c3d-8e4f-0123456789ab'), '/api/v1/assets/:id')
  assert.equal(normalisePath('/api/v1/assets/42/addresses'), '/api/v1/assets/:id/addresses')
  assert.equal(normalisePath('/api/v1/network/192.168.1.20'), '/api/v1/network/:ip')
  assert.equal(normalisePath('/api/v1/network/fe80::1'), '/api/v1/network/:id')
  assert.equal(normalisePath('/api/v1/assets/web-01.corp.example.com'), '/api/v1/assets/:id')
  assert.equal(normalisePath('/api/v1/agents/deadbeefcafe'), '/api/v1/agents/:id')
})

test('normalisePath: query string and fragment are dropped, plain routes stay', () => {
  assert.equal(normalisePath('/api/v1/events?token=secret&ip=10.0.0.1#x'), '/api/v1/events')
  assert.equal(normalisePath('/api/v1/chatbot/message'), '/api/v1/chatbot/message')
  const long = normalisePath('/' + 'a'.repeat(500))
  assert.ok(long.length <= 96)
})

// ── middleware ──────────────────────────────────────────────────────

function appWith(env: Env) {
  const app = new Hono<{ Bindings: Env }>()
  app.use('*', perfMiddleware)
  app.get('/api/v1/assets/:id', c => c.json({ ok: true }))
  app.get('/api/v1/slowdb', async c => { addDbWait(40); return c.json({ ok: true }) })
  app.get('/api/v1/boom', () => { throw new Error('boom') })
  app.get('/api/v1/bad', c => c.json({ detail: 'nope' }, 404))
  app.onError((_e, c) => c.json({ detail: 'x' }, 500))
  return { request: (path: string) => app.request(path, {}, env) }
}

test('middleware records the route pattern, never the real URL, query or id', async () => {
  const perf = fakePerf()
  const { request } = appWith(envWith(perf))
  const res = await request('/api/v1/assets/3f2b8c1e-1a2b-4c3d-8e4f-0123456789ab?token=SECRET&ip=10.1.2.3')
  assert.equal(res.status, 200)
  assert.equal(perf.points.length, 1)
  const p = perf.points[0]!
  assert.deepEqual(p.blobs, ['req', '/api/v1/assets/:id', 'ok'])
  assert.equal(p.doubles?.[0], 200)
  const dump = JSON.stringify(p)
  for (const leak of ['3f2b8c1e', 'SECRET', '10.1.2.3', 'token']) assert.ok(!dump.includes(leak), leak)
})

test('unmatched routes get a fixed label, not the path', async () => {
  const perf = fakePerf()
  const { request } = appWith(envWith(perf))
  const res = await request('/api/v1/secret-host-10.0.0.9/scan')
  assert.equal(res.status, 404)
  assert.equal(perf.points[0]!.blobs?.[1], UNMATCHED_ROUTE)
  assert.ok(!JSON.stringify(perf.points[0]).includes('10.0.0.9'))
})

test('failures are recorded: a thrown handler and a 5xx are errors, a 404 is not', async () => {
  const perf = fakePerf()
  const { request } = appWith(envWith(perf))
  assert.equal((await request('/api/v1/boom')).status, 500)
  assert.equal((await request('/api/v1/bad')).status, 404)
  assert.deepEqual(perf.points[0]!.blobs, ['req', '/api/v1/boom', 'error'])
  assert.equal(perf.points[0]!.doubles?.[0], 500)
  assert.deepEqual(perf.points[1]!.blobs, ['req', '/api/v1/bad', 'ok'])
})

test('one data point per request', async () => {
  const perf = fakePerf()
  const { request } = appWith(envWith(perf))
  await request('/api/v1/bad')
  assert.equal(perf.points.length, 1)
})

test('database wait is kept per request, even when requests overlap', async () => {
  const perf = fakePerf()
  const app = new Hono<{ Bindings: Env }>()
  app.use('*', perfMiddleware)
  const gate = Promise.withResolvers<void>()
  app.get('/a', async c => { addDbWait(100); await gate.promise; addDbWait(50); return c.text('a') })
  app.get('/b', async c => { addDbWait(7); gate.resolve(); return c.text('b') })
  const env = envWith(perf)
  await Promise.all([app.request('/a', {}, env), app.request('/b', {}, env)])
  const db = Object.fromEntries(perf.points.map(p => [p.blobs![1], p.doubles![2]]))
  assert.equal(db['/a'], 150)
  assert.equal(db['/b'], 7)
})

test('a missing PERF binding or a throwing write never affects the request', async () => {
  const none = appWith(envWith(undefined))
  assert.equal((await none.request('/api/v1/bad')).status, 404)
  const broken = appWith(envWith({ writeDataPoint: () => { throw new Error('AE down') } }))
  const res = await broken.request('/api/v1/assets/1')
  assert.equal(res.status, 200)
  assert.deepEqual(await res.json(), { ok: true })
})

test('addDbWait outside a request does nothing', () => assert.doesNotThrow(() => addDbWait(5)))

// ── jobs ────────────────────────────────────────────────────────────

test('recordJob writes name, duration and outcome; a failing write is swallowed', () => {
  const perf = fakePerf()
  recordJob(envWith(perf), 'cti_ingest', 1234.4, false)
  assert.deepEqual(perf.points[0], { indexes: ['cti_ingest'], blobs: ['job', 'cti_ingest', 'error'], doubles: [0, 1234, 0] })
  assert.doesNotThrow(() => recordJob(envWith({ writeDataPoint: () => { throw new Error('x') } }), 'a', 1, true))
  assert.doesNotThrow(() => recordJob(envWith(undefined), 'a', 1, true))
})

test('timedJob records success and failure and passes the result or error on', async () => {
  const perf = fakePerf()
  const env = envWith(perf)
  assert.equal(await timedJob(env, 'ok-job', async () => 7), 7)
  await assert.rejects(timedJob(env, 'bad-job', async () => { throw new Error('nope') }), /nope/)
  assert.deepEqual(perf.points.map(p => p.blobs![2]), ['ok', 'error'])
})

// ── buildWindows ────────────────────────────────────────────────────

const row = (o: Partial<PerfRow>): PerfRow => ({ bucket: '2026-11-09T15:00:00Z', kind: 'req', name: '/api/v1/assets', n: 10, errors: 0, totalMs: 1000, dbMs: 500, maxMs: 200, ...o })

test('buildWindows: a quiet hour is not flagged', () => {
  const [w] = buildWindows([row({})])
  assert.equal(w!.slow, false)
  assert.equal(w!.requests, 10)
  assert.equal(w!.avgMs, 100)
  assert.equal(w!.dbShare, 0.5)
  assert.equal(w!.errorRate, 0)
})

test('buildWindows: a slow route is flagged and the jobs of that hour are listed', () => {
  const [w] = buildWindows([
    row({ name: '/api/v1/events', n: 20, totalMs: 60_000, errors: 4, maxMs: 9000 }),
    row({ name: '/api/v1/assets', n: 80, totalMs: 8_000 }),
    row({ kind: 'job', name: 'cti_ingest', n: 2, totalMs: 40_000, errors: 1, maxMs: 30_000 }),
    row({ bucket: '2026-11-09T16:00:00Z', name: '/api/v1/events', n: 5, totalMs: 100 }),
  ])
  assert.equal(w!.start, '2026-11-09T15:00:00.000Z')
  assert.equal(w!.end, '2026-11-09T16:00:00.000Z')
  assert.equal(w!.slow, true)
  assert.equal(w!.slowRoutes[0]!.route, '/api/v1/events')
  assert.equal(w!.slowRoutes[0]!.avgMs, 3000)
  assert.equal(w!.slowRoutes[0]!.slow, true)
  assert.equal(w!.requests, 100)
  assert.equal(w!.errorRate, 0.04)
  assert.deepEqual(w!.jobs.map(j => [j.name, j.runs, j.failed]), [['cti_ingest', 2, 1]])
})

test('buildWindows: too few requests do not flag a route; db share is capped; scans are counted; windows are in time order', () => {
  const out = buildWindows([
    row({ bucket: '2026-11-09T17:00:00Z', name: '/api/v1/scans', n: 2, totalMs: 20_000, dbMs: 90_000 }),
    row({ bucket: '2026-11-09T15:00:00Z' }),
  ])
  assert.deepEqual(out.map(w => w.start), ['2026-11-09T15:00:00.000Z', '2026-11-09T17:00:00.000Z'])
  assert.equal(out[1]!.slow, false)
  assert.equal(out[1]!.dbShare, 1)
  assert.equal(out[1]!.scanRequests, 2)
})

test('buildWindows: bad rows and no rows', () => {
  assert.deepEqual(buildWindows([]), [])
  assert.deepEqual(buildWindows([row({ bucket: 'not a date' })]), [])
})

// ── pulling history ─────────────────────────────────────────────────

const fakeQ = () => { const calls: { text: string; params?: unknown[] }[] = []; const q = async (text: string, params?: unknown[]) => { calls.push({ text, params }); return [] as Record<string, unknown>[] }; return { q, calls } }
const apiBody = { meta: [], rows: 1, data: [{ bucket: '2026-11-09 15:00:00', kind: 'req', name: '/api/v1/events', n: '20', errors: '0', total_ms: '60000', db_ms: '1000', max_ms: 4000 }] }

test('parsePerfRows reads the SQL API shape, with numbers as strings or numbers', () => {
  const [r] = parsePerfRows(apiBody)
  assert.deepEqual(r, { bucket: '2026-11-09T15:00:00.000Z', kind: 'req', name: '/api/v1/events', n: 20, errors: 0, totalMs: 60000, dbMs: 1000, maxMs: 4000 })
  assert.throws(() => parsePerfRows({ errors: ['x'] }))
})

test('perfQuery uses the dataset and sampling weights', () => {
  const sql = perfQuery('umeagleeye_perf')
  assert.match(sql, /FROM umeagleeye_perf\b/)
  assert.match(sql, /_sample_interval/)
})

test('refreshPerf without the secrets returns quietly and logs once', async () => {
  resetPerfWarning()
  const warns: unknown[] = []
  const orig = console.warn
  console.warn = (...a: unknown[]) => { warns.push(a) }
  try {
    const { q, calls } = fakeQ()
    let fetched = false
    const f = (async () => { fetched = true; return new Response('{}') }) as typeof fetch
    assert.deepEqual(await refreshPerf(q, envWith(undefined), f), { ok: false, windows: 0, reason: 'not configured' })
    await refreshPerf(q, envWith(undefined, { CF_ACCOUNT_ID: 'a' }), f)
    assert.equal(fetched, false)
    assert.equal(calls.length, 0)
    assert.equal(warns.length, 1)
  } finally { console.warn = orig }
})

test('refreshPerf posts the query with the token and stores platform windows with no tenant', async () => {
  const { q, calls } = fakeQ()
  let seen: { url: string; init: RequestInit } | null = null
  const f = (async (url: string, init: RequestInit) => { seen = { url, init }; return new Response(JSON.stringify(apiBody), { status: 200 }) }) as unknown as typeof fetch
  const r = await refreshPerf(q, envWith(undefined, { CF_ACCOUNT_ID: 'acct1', CF_ANALYTICS_TOKEN: 'tok' }), f)
  assert.deepEqual(r, { ok: true, windows: 1 })
  assert.equal(seen!.url, 'https://api.cloudflare.com/client/v4/accounts/acct1/analytics_engine/sql')
  assert.equal((seen!.init.headers as Record<string, string>).Authorization, 'Bearer tok')
  assert.match(String(seen!.init.body), /umeagleeye_perf_staging/)
  const insert = calls.find(c => c.text.includes('INSERT INTO kg_nodes'))!
  const row = JSON.parse(String(insert.params![0]))[0]
  assert.equal(row.tenant_id, null)
  assert.equal(row.visibility, 'platform')
  assert.equal(row.type, 'performance_window')
  assert.equal(row.key, 'perf:window:2026-11-09T15:00:00.000Z')
})

test('refreshPerf: HTTP failure, bad body and network error all return ok:false and write nothing', async () => {
  const env = envWith(undefined, { CF_ACCOUNT_ID: 'a', CF_ANALYTICS_TOKEN: 't' })
  const errs = console.error
  console.error = () => {}
  try {
    for (const f of [
      (async () => new Response('denied', { status: 403 })) as typeof fetch,
      (async () => new Response('not json', { status: 200 })) as typeof fetch,
      (async () => { throw new Error('network') }) as typeof fetch,
    ]) {
      const { q, calls } = fakeQ()
      assert.equal((await refreshPerf(q, env, f)).ok, false)
      assert.equal(calls.length, 0)
    }
  } finally { console.error = errs }
})

// ── Fix round 1 ─────────────────────────────────────────────────────

import { askedTimeNote, gapRanges, resolveAskedTime } from './perf'

const secretsEnv = () => envWith(undefined, { CF_ACCOUNT_ID: 'a', CF_ANALYTICS_TOKEN: 't' })
const dataRow = (hour: number, name = '/api/v1/events') => ({ bucket: `2026-11-09 ${String(hour).padStart(2, '0')}:00:00`, kind: 'req', name, n: '10', errors: '0', total_ms: '1000', db_ms: '100', max_ms: 200 })
const jsonFetch = (rows: object[]) => (async () => new Response(JSON.stringify({ data: rows }), { status: 200 })) as unknown as typeof fetch

test('I1: the SQL call carries an abort signal and a hung call is aborted', async () => {
  let signal: AbortSignal | undefined
  const hung = ((_url: string, init: RequestInit) => new Promise((_res, rej) => {
    signal = init.signal as AbortSignal
    signal.addEventListener('abort', () => rej(new Error('aborted')))
  })) as unknown as typeof fetch
  const { q, calls } = fakeQ()
  const err = console.error
  console.error = () => {}
  try {
    const t0 = Date.now()
    const r = await refreshPerf(q, secretsEnv(), hung, { timeoutMs: 25 })
    assert.equal(r.ok, false)
    assert.ok(Date.now() - t0 < 2000)
    assert.ok(signal)
    assert.equal(signal!.aborted, true)
    assert.equal(calls.length, 0)
  } finally { console.error = err }
})

test('I3: the query keeps the newest hours and the limit is stated', () => {
  const sql = perfQuery('umeagleeye_perf', 123)
  assert.match(sql, /ORDER BY bucket DESC/)
  assert.match(sql, /LIMIT 123/)
})

test('I3: at the row limit it logs, keeps the newest buckets, drops the possibly partial oldest one, and deletes nothing', async () => {
  const warns: string[] = []
  const orig = console.warn
  console.warn = (...a: unknown[]) => { warns.push(a.join(' ')) }
  try {
    const { q, calls } = fakeQ()
    // newest first, as the DESC query returns them; 3 rows = the limit
    const r = await refreshPerf(q, secretsEnv(), jsonFetch([dataRow(17), dataRow(16), dataRow(15)]), { rowLimit: 3 })
    assert.equal(r.ok, true)
    assert.equal(r.windows, 2)
    const stored = JSON.parse(String(calls.find(c => c.text.includes('INSERT INTO kg_nodes'))!.params![0])).map((n: { key: string }) => n.key)
    assert.deepEqual(stored.sort(), ['perf:window:2026-11-09T16:00:00.000Z', 'perf:window:2026-11-09T17:00:00.000Z'])
    assert.equal(calls.some(c => c.text.includes('DELETE')), false)
    assert.equal(warns.some(w => /row limit/i.test(w)), true)
  } finally { console.warn = orig }
})

test('I4: zero rows from the API delete and write nothing', async () => {
  const { q, calls } = fakeQ()
  const r = await refreshPerf(q, secretsEnv(), jsonFetch([]))
  assert.equal(r.ok, true)
  assert.equal(r.windows, 0)
  assert.equal(calls.length, 0)
})

test('I4: only windows past the history limit are deleted, never ones merely missing from the pull', async () => {
  const calls: { text: string; params?: unknown[] }[] = []
  const q = async (text: string, params?: unknown[]) => {
    calls.push({ text, params })
    return text.startsWith('SELECT key') ? [{ key: 'perf:window:2020-01-01T00:00:00.000Z' }] : []
  }
  await refreshPerf(q, secretsEnv(), jsonFetch([dataRow(15)]))
  const sel = calls.find(c => c.text.startsWith('SELECT key'))!
  assert.match(sel.text, /props ->> 'start' </)
  assert.equal(typeof sel.params?.[0], 'string')
  const cutoff = Date.parse(String(sel.params![0]))
  assert.ok(Math.abs(Date.now() - 14 * 86_400_000 - cutoff) < 60_000)
  assert.deepEqual(calls.find(c => c.text.startsWith('DELETE FROM kg_nodes'))?.params?.[0], ['perf:window:2020-01-01T00:00:00.000Z'])
})

test('I2: a bare clock time is Malaysia time (UTC+8) unless another zone is named', () => {
  const now = new Date('2026-11-09T12:00:00Z') // 20:00 in Kuala Lumpur
  const a = resolveAskedTime('why was it slow at 3pm?', now)!
  assert.equal(a.utc.toISOString(), '2026-11-09T07:00:00.000Z')
  assert.equal(a.label, '15:00 Malaysia time (UTC+8) on 2026-11-09, which is 07:00 UTC')
  assert.equal(resolveAskedTime('slow at 15:30', now)!.utc.toISOString(), '2026-11-09T07:30:00.000Z')
  assert.equal(resolveAskedTime('slow at 3pm UTC', now)!.utc.toISOString(), '2026-11-08T15:00:00.000Z') // 15:00 UTC today is still ahead of 12:00 UTC
  assert.equal(resolveAskedTime('slow yesterday at 3pm', now)!.utc.toISOString(), '2026-11-08T07:00:00.000Z')
  assert.equal(resolveAskedTime('slow at 11pm', now)!.utc.toISOString(), '2026-11-08T15:00:00.000Z') // 23:00 MYT today is still ahead: last night
  assert.equal(resolveAskedTime('slow at 3pm on 2026-11-02', now)!.utc.toISOString(), '2026-11-02T07:00:00.000Z')
  assert.equal(resolveAskedTime('slow at 10am UTC', now)!.utc.toISOString(), '2026-11-09T10:00:00.000Z')
  assert.equal(resolveAskedTime('slow at 3pm PST', now), null)
  assert.equal(resolveAskedTime('why is it slow', now), null)
})

test('a date stated in the question is read, in each common form', () => {
  const now = new Date('2026-11-09T12:00:00Z')
  const want = '2026-03-03T07:00:00.000Z'
  for (const q of [
    'Why was it slow on 3 March 2026 at 3pm?', 'slow on March 3 2026 at 3pm', 'slow on March 3, 2026 at 3pm', 'slow on 2026-03-03 at 3pm',
    'slow on 3rd March 2026 at 3pm', 'slow on the 3rd of March 2026 at 3pm', 'slow on Mar 3 2026 at 3pm', 'slow on 3 mar 2026 at 15:00',
    'slow at 3pm on 3 March', 'slow at 3pm on March 3', 'at 15:00 March 3 2026',
  ]) assert.equal(resolveAskedTime(q, now)?.utc.toISOString(), want, q)
  assert.equal(resolveAskedTime('slow on 3 March 2026 at 3pm', now)!.label, '15:00 Malaysia time (UTC+8) on 2026-03-03, which is 07:00 UTC')
  assert.equal(resolveAskedTime('slow on 3 March 2026 at 15:00 UTC', now)!.utc.toISOString(), '2026-03-03T15:00:00.000Z')
  assert.equal(resolveAskedTime('slow on May 3 at 3pm', now)!.utc.toISOString(), '2026-05-03T07:00:00.000Z')
})

test('a date with no year is the last time that date happened', () => {
  const now = new Date('2026-11-09T12:00:00Z')
  assert.equal(resolveAskedTime('slow on 25 December at 3pm', now)!.utc.toISOString(), '2025-12-25T07:00:00.000Z')
  assert.equal(resolveAskedTime('slow on 9 November at 3pm', now)!.utc.toISOString(), '2026-11-09T07:00:00.000Z')
})

test('with no date named, the day is still worked out as before', () => {
  const now = new Date('2026-11-09T12:00:00Z')
  assert.equal(resolveAskedTime('slow at 3pm', now)!.utc.toISOString(), '2026-11-09T07:00:00.000Z')
  assert.equal(resolveAskedTime('it may be slow at 3pm', now)!.utc.toISOString(), '2026-11-09T07:00:00.000Z')
  assert.equal(resolveAskedTime('slow on 10.0.0.0/24 at 3pm', now)!.utc.toISOString(), '2026-11-09T07:00:00.000Z')
  assert.equal(resolveAskedTime('slow on version 2.4 at 3pm', now)!.utc.toISOString(), '2026-11-09T07:00:00.000Z')
  assert.equal(resolveAskedTime('what happened on 3 March 2026', now), null, 'a date with no clock time names no hour')
})

test('a date that cannot be read gives null, never today', () => {
  const now = new Date('2026-11-09T12:00:00Z')
  for (const q of [
    'slow on 31 February 2026 at 3pm', 'slow on 2026-13-45 at 3pm', 'slow in March at 3pm', 'slow on 03/03/2026 at 3pm', 'slow on 3.3.2026 at 3pm',
    'slow on 03-03-2026 at 3pm', 'slow last Tuesday at 3pm', 'slow the day before yesterday at 3pm', 'slow 3 days ago at 3pm', 'slow last week at 3pm',
    'slow in May at 3pm', 'slow in May 2026 at 3pm', 'slow in Mar at 3pm', 'slow on the 3rd at 3pm',
  ]) assert.equal(resolveAskedTime(q, now), null, q)
})

test('the note for a dated question names that date, not today', () => {
  const now = new Date('2026-11-09T12:00:00Z')
  const note = askedTimeNote('Why was it slow on 3 March 2026 at 3pm?', now, ['2026-11-09T05:00:00.000Z', '2026-11-09T06:00:00.000Z'])!
  assert.match(note, /on 2026-03-03/)
  assert.ok(!note.includes('2026-11-09, which'), note)
  assert.match(note, /no history for that time/)
})

test('I2: coverage verdicts: covered, outside the range, and a gap inside it', () => {
  const now = new Date('2026-11-09T12:00:00Z')
  const hours = (...h: number[]) => h.map(x => `2026-11-09T${String(x).padStart(2, '0')}:00:00.000Z`)
  assert.match(askedTimeNote('slow at 3pm', now, hours(5, 6, 7, 8))!, /is covered by a window/)
  assert.match(askedTimeNote('slow at 3pm', now, hours(9, 10))!, /no history for that time/)
  assert.match(askedTimeNote('slow at 3pm', now, hours(5, 6, 8, 9))!, /no history for that time/)
  assert.match(askedTimeNote('slow at 3pm', now, [])!, /no history for that time/)
  assert.equal(askedTimeNote('why is it slow', now, hours(5)), null)
  assert.deepEqual(gapRanges(hours(5, 6, 8, 9, 12)), ['2026-11-09T07:00:00.000Z to 2026-11-09T08:00:00.000Z', '2026-11-09T10:00:00.000Z to 2026-11-09T12:00:00.000Z'])
  assert.deepEqual(gapRanges(hours(5, 6)), [])
})

// ── Fix round 3: the UTC+8 label must not add the number 8 to the evidence ──

import { verifyAnswer } from './guard'

const nowR3 = new Date('2026-11-09T12:00:00Z')
const startsR3 = ['05', '06', '08', '09', '10'].map(h => `2026-11-09T${h}:00:00.000Z`)
const serverFacts = [
  `Current UTC time: ${nowR3.toISOString()}.`,
  `Recorded performance history currently covers ${startsR3[0]} to 2026-11-09T11:00:00.000Z. A time outside that has no history.`,
  `Hours inside that range with no window (no history for them): ${gapRanges(startsR3).join('; ')}.`,
  askedTimeNote('why was it slow at 3pm?', nowR3, startsR3)!,
]

test('round 3: a bare 8 is still refused when the asked-time line is evidence', () => {
  assert.deepEqual(verifyAnswer('There were 8 hosts [S1].', serverFacts, 'system'), ['8'])
})

test('round 3: UTC+8 passes when the label is in evidence, UTC+9 and GMT+8 do not', () => {
  assert.deepEqual(verifyAnswer('Slow at 15:00 Malaysia time (UTC+8), 07:00 UTC [S1].', serverFacts, 'system'), [])
  assert.ok(verifyAnswer('Slow at 15:00 Malaysia time (UTC+9), 07:00 UTC [S1].', serverFacts, 'system').length > 0)
  assert.ok(verifyAnswer('Slow at 15:00 (GMT+8) [S1].', serverFacts, 'system').length > 0)
  assert.ok(verifyAnswer('Slow at 16:00 Malaysia time (UTC+8), 08:00 UTC [S1].', serverFacts, 'system').length > 0)
})

test('round 3: the server facts add no loose numbers', () => {
  const loose: string[] = []
  for (let n = 0; n <= 40; n++) if (verifyAnswer(`There were ${n} hosts [S1].`, serverFacts, 'system').length === 0) loose.push(String(n))
  for (const n of ['2026', '2025']) if (verifyAnswer(`There were ${n} hosts [S1].`, serverFacts, 'system').length === 0) loose.push(n)
  assert.deepEqual(loose, [])
})
