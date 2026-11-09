import test from 'node:test'
import assert from 'node:assert/strict'
import type { Env } from '../types'
import { refreshPlatformProblems } from './problems'

const NOW = new Date('2026-11-09T12:00:00Z')
type Call = { text: string; params: unknown[] }

function setup(o: { windows?: object[]; outbox?: object; feeds?: object | null; old?: string[]; kvFails?: boolean }) {
  const calls: Call[] = []
  const q = async (text: string, params: unknown[] = []) => {
    calls.push({ text, params })
    if (text.includes("type = 'performance_window'")) return (o.windows ?? []).map(props => ({ props }))
    if (text.includes('FROM kg_outbox')) return [o.outbox ?? { n: 0, oldest: null, stuck: 0 }]
    if (text.includes("type = 'problem'") && text.startsWith('SELECT')) return (o.old ?? []).map(key => ({ key }))
    return []
  }
  const env = { KV_CACHE: { get: async () => { if (o.kvFails) throw new Error('kv down'); return o.feeds ?? null } } } as unknown as Env
  return { q, env, calls }
}
const win = (h: number, extra: object = {}) => ({
  start: `2026-11-09T0${h}:00:00.000Z`, end: `2026-11-09T0${h + 1}:00:00.000Z`, requests: 100, errors: 0, errorRate: 0, avgMs: 100, dbShare: 0.3,
  slowRoutes: [], jobs: [], scanRequests: 0, slow: false, ...extra,
})
const written = (calls: Call[]) => {
  const ins = calls.find(c => c.text.includes('INSERT INTO kg_nodes'))
  return ins ? JSON.parse(String(ins.params[0])) as Record<string, unknown>[] : []
}

test('stores platform problems with no tenant, platform visibility', async () => {
  const { q, env, calls } = setup({ feeds: { at: 'x', feeds: { otx: { ok: false, count: 0, last_ok_at: null } } } })
  await refreshPlatformProblems(q, env, NOW)
  const rows = written(calls)
  assert.equal(rows.length, 1)
  assert.equal(rows[0]!.key, 'problem:platform:feed:otx')
  assert.equal(rows[0]!.tenant_id, null)
  assert.equal(rows[0]!.visibility, 'platform')
  assert.equal(rows[0]!.type, 'problem')
})

test('removes platform problems that are no longer true, and only those of its own rules', async () => {
  const { q, env, calls } = setup({ old: ['problem:platform:feed:otx'] })
  await refreshPlatformProblems(q, env, NOW)
  const del = calls.find(c => c.text.startsWith('DELETE FROM kg_nodes WHERE key = ANY'))
  assert.deepEqual(del?.params[0], ['problem:platform:feed:otx'])
  const sel = calls.find(c => c.text.startsWith('SELECT key FROM kg_nodes') && c.text.includes("type = 'problem'"))!
  assert.match(sel.text, /tenant_id IS NULL/)
  assert.match(sel.text, /props ->> 'rule' = ANY/)
})

test('links a performance problem to its windows', async () => {
  const slow = (h: number) => win(h, { slow: true, slowRoutes: [{ route: '/api/v1/events', requests: 20, avgMs: 2500, maxMs: 6000, errorRate: 0, slow: true }] })
  const { q, env, calls } = setup({ windows: [slow(1), slow(2), slow(3)] })
  await refreshPlatformProblems(q, env, NOW)
  const edges = calls.find(c => c.text.includes('INSERT INTO kg_edges'))!
  const parsed = JSON.parse(String(edges.params[0])) as Record<string, unknown>[]
  assert.equal(parsed.length, 3)
  assert.equal(parsed[0]!.to_key, 'perf:window:2026-11-09T01:00:00.000Z')
  assert.equal(parsed[0]!.tenant_id, null)
})

test('a backlog is read from the outbox', async () => {
  const { q, env, calls } = setup({ outbox: { n: 900, oldest: '2026-11-09T10:00:00Z', stuck: 2 } })
  await refreshPlatformProblems(q, env, NOW)
  assert.deepEqual(written(calls).map(r => r.key), ['problem:platform:kg_backlog'])
})

test('an unreadable feed record raises nothing and does not throw', async () => {
  const { q, env, calls } = setup({ kvFails: true })
  await refreshPlatformProblems(q, env, NOW)
  assert.deepEqual(written(calls), [])
})
