import test from 'node:test'
import assert from 'node:assert/strict'
import { drainOutbox, handleKgSyncMessages, kgSyncFlags, runKgSync, MAX_ATTEMPTS } from './sync'
import type { Q } from './store'
import type { Env } from '../types'

const A = '22222222-2222-2222-2222-222222222222'
const B = '33333333-3333-3333-3333-333333333333'
const env = { DATABASE_URL: 'x', ADVISORY_QUEUE: { send: async () => {} } } as unknown as Env

interface Call { text: string; params: unknown[] }

/** A fake query function that answers by the shape of the SQL. */
function fake(opts: {
  claimed?: Array<Record<string, unknown>>
  assets?: Array<Record<string, unknown>>
  left?: Record<string, unknown>
  goneTenants?: string[]
  poison?: string
  unfilled?: number
}) {
  const calls: Call[] = []
  let unfilled = opts.unfilled ?? 0
  const q: Q = async (text, params = []) => {
    calls.push({ text, params })
    if (text.includes('embedding IS NULL')) return unfilled-- > 0 ? [{ key: 'asset:x', title: 't', body: 'b' }] : []
    if (text.includes('UPDATE kg_outbox')) return opts.claimed ?? []
    if (text.includes('FROM assets WHERE asset_id')) return (opts.assets ?? []).filter(r => (params[0] as string[]).includes(r.asset_id as string))
    if (text.includes('SELECT DISTINCT tenant_id FROM kg_nodes')) return (opts.goneTenants ?? []).map(t => ({ tenant_id: t }))
    if (text.includes('INSERT INTO kg_nodes') && opts.poison && String(params[0]).includes(opts.poison)) throw new Error('invalid input syntax')
    if (text.includes('count(*) FILTER')) return [opts.left ?? { n: 0, quarantined: 0 }]
    return []
  }
  return { q, calls }
}
const claim = (id: string, tenant: string | null = null) => ({ table_name: 'assets', row_pk: id, tenant_id: tenant, changed_at: '2026-01-01 00:00:00+00' })
const asset = (id: string, hostname: string, tenant = A) => ({ asset_id: id, tenant_id: tenant, hostname, ip_address: '10.0.0.1' })
const envWith = (sent: unknown[]) => ({ ...env, ADVISORY_QUEUE: { send: async (m: unknown) => { sent.push(m) } } }) as unknown as Env

test('the claim skips quarantined rows and counts attempts', async () => {
  const { q, calls } = fake({})
  await drainOutbox(q, env)
  const sql = calls.find(c => c.text.includes('UPDATE kg_outbox'))!.text
  assert.ok(sql.includes('attempts = o.attempts + 1'))
  assert.ok(sql.includes(`attempts < ${MAX_ATTEMPTS}`))
})

test('a poison row is isolated: the others are applied and only they leave the outbox', async () => {
  const { q, calls } = fake({
    claimed: [claim('a1'), claim('a2'), claim('a3')],
    assets: [asset('a1', 'good-1'), asset('a2', 'POISON'), asset('a3', 'good-3')],
    poison: 'POISON',
  })
  const r = await drainOutbox(q, env)
  assert.equal(r.processed, 2)
  const del = calls.find(c => c.text.includes('DELETE FROM kg_outbox'))!
  assert.deepEqual(del.params[1], ['a1', 'a3'])
})

test('requeue happens only when something was processed', async () => {
  const sent: unknown[] = []
  const idle = fake({ claimed: [], left: { n: 3, quarantined: 0 } })
  await runKgSync(idle.q, envWith(sent), async () => {})
  assert.equal(sent.length, 0)
  const busy = fake({ claimed: [claim('a1')], assets: [asset('a1', 'h')], left: { n: 3, quarantined: 0 } })
  await runKgSync(busy.q, envWith(sent), async () => {})
  assert.equal(sent.length, 1)
})

test('rows that only fail are not processed and do not requeue', async () => {
  const sent: unknown[] = []
  const f = fake({ claimed: [claim('a1')], assets: [asset('a1', 'POISON')], poison: 'POISON', left: { n: 1, quarantined: 0 } })
  await runKgSync(f.q, envWith(sent), async () => {})
  assert.equal(sent.length, 0)
})

test('remaining and quarantined come from the count query', async () => {
  const { q } = fake({ left: { n: 7, quarantined: 2 } })
  const r = await drainOutbox(q, env)
  assert.equal(r.remaining, 7)
  assert.equal(r.quarantined, 2)
})

test('the company of a deleted row is read before it goes, and refreshed', async () => {
  const { q, calls } = fake({ claimed: [claim('gone1')], assets: [], goneTenants: [B] })
  const r = await drainOutbox(q, env)
  assert.deepEqual(r.tenants, [B])
  const read = calls.findIndex(c => c.text.includes('SELECT DISTINCT tenant_id FROM kg_nodes'))
  const del = calls.findIndex(c => c.text.includes('DELETE FROM kg_nodes'))
  assert.ok(read >= 0 && read < del)
})

test('every drain refreshes the companies it touched, even with work remaining', async () => {
  const seen: string[] = []
  const { q } = fake({ claimed: [claim('a1', A)], assets: [asset('a1', 'h', A)], left: { n: 9, quarantined: 0 } })
  await runKgSync(q, env, async t => { seen.push(t) })
  assert.deepEqual(seen, [A])
})

test('a tenant drain claims only that company and counts it plus unresolved rows', async () => {
  const { q, calls } = fake({})
  await drainOutbox(q, env, 500, A)
  const c = calls.find(x => x.text.includes('UPDATE kg_outbox'))!
  assert.equal(c.params[1], A)
  assert.ok(c.text.includes('tenant_id = $2::uuid'))
  const count = calls.find(x => x.text.includes('count(*) FILTER'))!
  assert.deepEqual(count.params, [A])
  assert.ok(count.text.includes('tenant_id IS NULL'))
  const g = fake({})
  await drainOutbox(g.q, env)
  assert.equal(g.calls.find(x => x.text.includes('UPDATE kg_outbox'))!.params[1], null)
})

test('the relationship source query keeps same-company pairs only', async () => {
  const { q, calls } = fake({ claimed: [{ table_name: 'asset_relationships', row_pk: 'r1', tenant_id: null, changed_at: 'x' }] })
  await drainOutbox(q, env)
  const sql = calls.find(c => c.text.includes('FROM asset_relationships t'))!.text
  assert.ok(sql.includes('s.tenant_id IS NOT DISTINCT FROM d.tenant_id'))
})

test('a drain that finishes schedules one later sweep for what arrived during the debounce window', async () => {
  const sent: Array<{ m: unknown; o: { delaySeconds?: number } }> = []
  const e = { ...env, ADVISORY_QUEUE: { send: async (m: unknown, o: { delaySeconds?: number }) => { sent.push({ m, o }) } } } as unknown as Env
  const done = fake({ claimed: [claim('a1')], assets: [asset('a1', 'h')], left: { n: 0, quarantined: 0 } })
  await runKgSync(done.q, e, async () => {})
  assert.equal(sent.length, 1)
  assert.ok((sent[0]!.o.delaySeconds ?? 0) >= 120, 'the sweep runs after the signal debounce has expired')
  sent.length = 0
  const idle = fake({ claimed: [], left: { n: 0, quarantined: 0 } })
  await runKgSync(idle.q, e, async () => {})
  assert.equal(sent.length, 0, 'an idle sweep stops the chain')
})

test('a row whose extractor throws fails alone: the others are applied and it is not taken for deleted', async () => {
  const { q, calls } = fake({
    claimed: [claim('a1'), claim('a2'), claim('a3')],
    assets: [asset('a1', 'good-1'), { ...asset('a2', 'bad-date'), last_scanned: 'not a date' }, asset('a3', 'good-3')],
  })
  const r = await drainOutbox(q, env)
  assert.equal(r.processed, 2)
  assert.deepEqual(calls.find(c => c.text.includes('DELETE FROM kg_outbox'))!.params[1], ['a1', 'a3'])
  assert.ok(!calls.some(c => c.text.includes('claimed_until = NULL')), 'a row proven bad keeps its counted attempt')
  assert.ok(!calls.some(c => c.text.includes('DELETE FROM kg_nodes')), 'a row that exists must not be removed from the graph')
  const written = calls.filter(c => c.text.includes('INSERT INTO kg_nodes')).map(c => String(c.params[0]))
  assert.ok(written.some(p => p.includes('good-1') && p.includes('good-3')))
})

type Sent = { m: Record<string, unknown>; o: { delaySeconds?: number } }
const recording = (extra: Record<string, unknown> = {}) => {
  const sent: Sent[] = []
  return { sent, env: { ...env, ...extra, ADVISORY_QUEUE: { send: async (m: Record<string, unknown>, o: { delaySeconds?: number }) => { sent.push({ m, o }) } } } as unknown as Env }
}
const noRefresh = async () => {}
const ai = { AI: { run: async (_m: string, i: { text: string[] }) => ({ data: i.text.map(() => [0.1]) }) } }
const signal = { type: 'kg_sync' }

test('a signalled job that finds nothing still schedules one sweep, and that sweep stops the chain', async () => {
  const { sent, env: e } = recording()
  const idle = fake({ claimed: [], left: { n: 0, quarantined: 0 } })
  await runKgSync(idle.q, e, noRefresh, kgSyncFlags([signal]))
  assert.equal(sent.length, 1)
  assert.ok((sent[0]!.o.delaySeconds ?? 0) >= 120, 'the sweep runs after the signal debounce has expired')
  const sweep = sent.shift()!
  await runKgSync(idle.q, e, noRefresh, kgSyncFlags([sweep.m]))
  assert.equal(sent.length, 0)
})

test('a sweep that applied rows looks once more, because those rows prove writes are still arriving', async () => {
  const { sent, env: e } = recording()
  const busy = fake({ claimed: [claim('a1')], assets: [asset('a1', 'h')], left: { n: 0, quarantined: 0 } })
  await runKgSync(busy.q, e, noRefresh, kgSyncFlags([{ type: 'kg_sync', followUp: true }]))
  assert.equal(sent.length, 1)
  assert.ok((sent[0]!.o.delaySeconds ?? 0) >= 120)
})

test('filling embeddings does not cost the drain its sweep', async () => {
  const { sent, env: e } = recording(ai)
  const first = fake({ claimed: [claim('a1')], assets: [asset('a1', 'h')], left: { n: 0, quarantined: 0 }, unfilled: 1 })
  await runKgSync(first.q, e, noRefresh, kgSyncFlags([signal]))
  assert.equal(sent.length, 1)
  assert.equal(sent[0]!.o.delaySeconds, 1, 'more embeddings may be waiting, so it carries on at once')
  const next = sent.shift()!
  const idle = fake({ claimed: [], left: { n: 0, quarantined: 0 } })
  await runKgSync(idle.q, e, noRefresh, kgSyncFlags([next.m]))
  assert.equal(sent.length, 1, 'the sweep the drain owed is sent when the filling stops')
  assert.ok((sent[0]!.o.delaySeconds ?? 0) >= 120)
  await runKgSync(idle.q, e, noRefresh, kgSyncFlags([sent.shift()!.m]))
  assert.equal(sent.length, 0)
})

test('a backlog schedules one sweep at the end, not one per batch', async () => {
  const { sent, env: e } = recording()
  const more = fake({ claimed: [claim('a1')], assets: [asset('a1', 'h')], left: { n: 3, quarantined: 0 } })
  await runKgSync(more.q, e, noRefresh, kgSyncFlags([signal]))
  await runKgSync(more.q, e, noRefresh, kgSyncFlags([sent.shift()!.m]))
  assert.equal(sent.length, 1)
  assert.equal(sent[0]!.o.delaySeconds, 1)
  const done = fake({ claimed: [claim('a1')], assets: [asset('a1', 'h')], left: { n: 0, quarantined: 0 } })
  await runKgSync(done.q, e, noRefresh, kgSyncFlags([sent.shift()!.m]))
  assert.equal(sent.length, 1)
  assert.ok((sent[0]!.o.delaySeconds ?? 0) >= 120)
})

test('a chain cannot run forever on idle or on poison alone', async () => {
  for (const start of [fake({ claimed: [], left: { n: 0, quarantined: 0 } }), fake({ claimed: [claim('a1')], assets: [asset('a1', 'POISON')], poison: 'POISON', left: { n: 1, quarantined: 0 } })]) {
    const { sent, env: e } = recording()
    await runKgSync(start.q, e, noRefresh, kgSyncFlags([signal]))
    let steps = 0
    while (sent.length > 0 && steps++ < 10) await runKgSync(start.q, e, noRefresh, kgSyncFlags([sent.shift()!.m]))
    assert.equal(sent.length, 0, 'the chain ended')
    assert.equal(steps, 1, 'one sweep, then nothing')
  }
})

test('a run from the cron is not a signal: finding nothing schedules nothing', async () => {
  const { sent, env: e } = recording()
  await runKgSync(fake({ claimed: [], left: { n: 0, quarantined: 0 } }).q, e, noRefresh)
  assert.equal(sent.length, 0)
})

test('every kg_sync message in a queue batch shares one run', async () => {
  const log: string[] = []
  const msg = (body: unknown, id: string) => ({ body, ack: () => { log.push(`ack ${id}`) }, retry: () => { log.push(`retry ${id}`) } })
  const flags: unknown[] = []
  await handleKgSyncMessages(env, [msg({ type: 'kg_sync', followUp: true }, 'a'), msg(signal, 'b'), msg({ type: 'kg_sync', followUp: true, owesSweep: true }, 'c')], async (_e, f) => { flags.push(f) })
  assert.deepEqual(flags, [{ signalled: true, owesSweep: true }])
  assert.deepEqual(log, ['ack a', 'ack b', 'ack c'])
  log.length = 0
  await handleKgSyncMessages(env, [msg(signal, 'a'), msg(signal, 'b')], async () => { throw new Error('down') })
  assert.deepEqual(log, ['retry a', 'retry b'])
  await handleKgSyncMessages(env, [], async () => { log.push('ran') })
  assert.ok(!log.includes('ran'))
})
