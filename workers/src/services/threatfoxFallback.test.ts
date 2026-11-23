import { test } from 'node:test'
import assert from 'node:assert/strict'
import { THREATFOX_DAYS, ingestThreatFox, threatFoxExportIocs } from './cti'

// A stand-in ThreatFox: answers each request in turn, and records what was asked (days, or "export").
function fakeThreatFox(answers: Array<() => Response>) {
  const asked: Array<number | string> = []
  const real = globalThis.fetch
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    asked.push(init?.body ? JSON.parse(String(init.body)).days : String(url).includes('/exports/') ? 'export' : 'other')
    return answers[asked.length - 1]!()
  }) as typeof fetch
  return { asked, restore: () => { globalThis.fetch = real } }
}
const db = {} as Parameters<typeof ingestThreatFox>[0]      // not reached: no rows to save
const cut = () => new Response('{"query_status": "ok", "data": [{"ioc": "1.2.3', { status: 200 })

test('a cut-off answer is asked again for fewer days', async () => {
  const tf = fakeThreatFox([cut, () => new Response('', { status: 200 }), () => new Response(JSON.stringify({ query_status: 'no_result' }))])
  try {
    assert.equal(await ingestThreatFox(db, 'key'), 0)
    assert.deepEqual(tf.asked, THREATFOX_DAYS)
  } finally { tf.restore() }
})

test('every API answer cut off: the recent export file is used', async () => {
  const tf = fakeThreatFox([cut, cut, cut, () => new Response('{}', { status: 200 })])
  try {
    assert.equal(await ingestThreatFox(db, 'key'), 0)
    assert.deepEqual(tf.asked, [...THREATFOX_DAYS, 'export'])
  } finally { tf.restore() }
})

test('a refusal is not retried', async () => {
  const tf = fakeThreatFox([() => new Response('{"error": "Unauthorized"}', { status: 401 })])
  try {
    await assert.rejects(ingestThreatFox(db, 'bad'), /HTTP 401/)
    assert.deepEqual(tf.asked, [7])
  } finally { tf.restore() }
})

test('everything cut off and no export: one error naming each try', async () => {
  const tf = fakeThreatFox([cut, cut, cut, () => new Response('gone', { status: 404 })])
  try {
    await assert.rejects(ingestThreatFox(db, 'key'), /7 days: .*3 days: .*1 days: .*export HTTP 404/)
  } finally { tf.restore() }
})

test('export records read as API records (ioc_value, tags as one string, keyed by id)', () => {
  const got = threatFoxExportIocs({ '1': [{ ioc_value: 'evil.example', ioc_type: 'domain', confidence_level: '75', malware_printable: 'Lumma', tags: 'lumma, stealer' }],
    '2': [{ ioc_type: 'domain' }] })
  assert.deepEqual(got.map((r) => [r.ioc, r.confidence_level, r.tags]), [['evil.example', 75, ['lumma', 'stealer']]])
  assert.equal(threatFoxExportIocs([{ ioc: '1.2.3.4:443', ioc_type: 'ip:port', confidence_level: 50 }])[0]!.ioc, '1.2.3.4:443')
})
