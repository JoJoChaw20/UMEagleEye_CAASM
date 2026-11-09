import test from 'node:test'
import assert from 'node:assert/strict'
import { drainOutbox, runKgSync, MAX_ATTEMPTS } from './sync'
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
}) {
  const calls: Call[] = []
  const q: Q = async (text, params = []) => {
    calls.push({ text, params })
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
