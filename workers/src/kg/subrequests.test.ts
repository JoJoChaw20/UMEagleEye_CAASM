import test from 'node:test'
import assert from 'node:assert/strict'
import { DRAIN_REQUESTS, drainOutbox } from './sync'
import { refreshProblems } from './problems'
import { keywordQuery } from './retrieve'
import { classify, IDK, type ModelCall, type ModelReply, type ToolCall } from './guard'
import { runGraphAgent, type GraphCtx } from './agent'
import type { Q, Stmt } from './store'
import type { Env } from '../types'

const A = '22222222-2222-2222-2222-222222222222'
const env = { DATABASE_URL: 'x' } as unknown as Env

const TABLES = ['assets', 'asset_addresses', 'asset_software', 'asset_identifiers', 'asset_relationships', 'sboms', 'dependencies',
  'events', 'advisories', 'ti_events', 'agents', 'topology_nodes', 'network_links', 'scan_results', 'posture_metrics']

/** A driver that can run a whole batch as one request, like a real Neon transaction: it fails as a whole. */
function batching(opts: { poison?: string; rows?: Record<string, Array<Record<string, unknown>>>; claimed?: Array<Record<string, unknown>>; failRead?: string; writeError?: string } = {}) {
  let requests = 0
  const seen: string[] = []
  const calls: Array<{ text: string; params: unknown[] }> = []
  const answer = (text: string, params: unknown[] = []): Array<Record<string, unknown>> => {
    seen.push(text)
    calls.push({ text, params })
    if (text.includes('UPDATE kg_outbox')) return opts.claimed ?? []
    const reading = text.includes('= ANY($1::uuid[])') ? (params[0] as string[]) : null
    if (reading && opts.failRead && (opts.failRead === '*' || reading.includes(opts.failRead))) throw new Error('invalid input syntax for type uuid')
    if (text.includes('INSERT INTO kg_nodes') && opts.writeError) throw new Error(opts.writeError)
    if (text.includes('INSERT INTO kg_nodes') && opts.poison && String(params[0]).includes(opts.poison)) throw new Error('invalid input syntax')
    if (text.includes('count(*) FILTER')) return [{ n: 0, quarantined: 0, assets: 0, my_assets: 0, critical: 0, advisories: 0 }]
    for (const [name, rows] of Object.entries(opts.rows ?? {})) {
      if (text.includes(`FROM ${name}`)) return reading ? rows.filter(r => reading.includes(String(r.asset_id ?? r.agent_id))) : rows
    }
    return []
  }
  const q = (async (text: string, params?: unknown[]) => { requests++; return answer(text, params) }) as Q
  q.batch = async (stmts: Stmt[]) => { requests++; return stmts.map(s => answer(s.text, s.params)) }
  return { q, seen, calls, requests: () => requests }
}

const claim = (table: string, id: string, tenant: string | null = A) => ({ table_name: table, row_pk: id, tenant_id: tenant, changed_at: '2026-01-01 00:00:00+00' })
const asset = (id: string, hostname: string) => ({ asset_id: id, tenant_id: A, hostname, ip_address: '10.0.0.1' })

test('a drain of rows from every table costs a handful of requests, not one set per table', async () => {
  const claimed = TABLES.map((t, i) => claim(t, `id-${i}`))
  const { q, requests } = batching({ claimed })
  const r = await drainOutbox(q, env, 100)
  assert.equal(r.processed, TABLES.length)
  // claim, one read of all tables, known-text read (nothing to embed without AI is skipped), one write batch, one finish batch
  assert.ok(requests() <= 7, `expected a constant handful of requests, got ${requests()}`)
})

test('the request count stays constant as the number of rows grows', async () => {
  const claimed = Array.from({ length: 80 }, (_, i) => claim('assets', `a${i}`))
  const rows = { assets: claimed.map(c => asset(c.row_pk, `h${c.row_pk}`)) }
  const { q, requests } = batching({ claimed, rows })
  const r = await drainOutbox(q, env, 100)
  assert.equal(r.processed, 80)
  assert.ok(requests() <= 7, `got ${requests()}`)
})

test('in a batch, one poison row is isolated and every other row still lands', async () => {
  const claimed = Array.from({ length: 16 }, (_, i) => claim('assets', `a${i}`))
  const rows = { assets: claimed.map((c, i) => asset(c.row_pk, i === 11 ? 'POISON' : `h${i}`)) }
  const { q, seen } = batching({ claimed, rows, poison: 'POISON' })
  const r = await drainOutbox(q, env, 100)
  assert.equal(r.processed, 15)
  const failing = seen.filter(s => s.includes('DELETE FROM kg_outbox'))
  assert.ok(failing.length > 0)
  assert.ok(seen.filter(s => s.includes('INSERT INTO kg_nodes')).length <= 12, 'isolation needs only a few writes')
})

test('a URL path in a question is kept whole, because that is how it is indexed', () => {
  const q = keywordQuery('Which page calls POST /api/v1/chatbot/confirm?')!
  assert.ok(q.includes(`'/api/v1/chatbot/confirm'`), q)
  assert.ok(q.includes(`'confirm'`), 'the parts are searched too')
  assert.ok(!q.includes(`''`), 'no empty term')
})

test('classify leaves a reasoning model room to reply', async () => {
  let maxTokens = 0
  const ai: ModelCall = async (_m, _t, opts) => { maxTokens = opts?.maxTokens ?? 0; return { text: 'neither', toolCalls: [], truncated: false } }
  assert.equal(await classify(ai, 'a recipe for pasta'), 'neither')
  assert.ok(maxTokens >= 256, `classify allows ${maxTokens} tokens`)
})

test('a refresh reads everything in one request', async () => {
  const { q, requests, seen } = batching({})
  await refreshProblems(q, env, A)
  assert.ok(requests() <= 4, `expected at most 4 requests, got ${requests()}`)
  assert.ok(seen.some(s => s.includes('DELETE FROM kg_nodes n')), 'the cve and indicator cleanup still runs')
})

const assets = (n: number, poison: (i: number) => boolean) => {
  const claimed = Array.from({ length: n }, (_, i) => claim('assets', `a${i}`))
  return { claimed, rows: { assets: claimed.map((c, i) => asset(c.row_pk, poison(i) ? 'POISON' : `h${i}`)) } }
}
type Call = { text: string; params: unknown[] }
const released = (calls: Call[]) => calls.filter(c => c.text.includes('claimed_until = NULL')).flatMap(c => c.params[1] as string[])
const removed = (calls: Call[]) => calls.filter(c => c.text.includes('DELETE FROM kg_outbox')).flatMap(c => c.params[1] as string[])

test('many poison rows use a bounded number of requests, and the finish step still runs', async () => {
  const { q, requests, seen } = batching({ ...assets(500, i => i % 7 === 3), poison: 'POISON' })
  await drainOutbox(q, env)
  assert.ok(requests() <= DRAIN_REQUESTS, `expected at most ${DRAIN_REQUESTS} requests, got ${requests()}`)
  assert.ok(seen.some(s => s.includes('count(*) FILTER')), 'the finish step ran')
})

test('rows an exhausted budget left behind are released, with their attempt given back', async () => {
  const { claimed, rows } = assets(500, i => i % 7 === 3)
  const { q, calls } = batching({ claimed, rows, poison: 'POISON' })
  const r = await drainOutbox(q, env)
  const back = released(calls)
  const gone = removed(calls)
  assert.ok(back.length > 0, 'the budget ran out, so some rows wait for the next drain')
  assert.ok(calls.find(c => c.text.includes('claimed_until = NULL'))!.text.includes('attempts = GREATEST(o.attempts - 1, 0)'))
  assert.equal(r.processed, gone.length, 'a released row is not counted as processed')
  // Whatever is neither applied nor released was tried alone and failed, so only poison rows can be in it.
  const settled = new Set([...back, ...gone])
  for (const c of claimed.filter(x => !settled.has(x.row_pk))) assert.equal(Number(c.row_pk.slice(1)) % 7, 3, `${c.row_pk} was counted against without being proven bad`)
  assert.equal(new Set(back).size, back.length)
})

test('a subrequest-limit error is not evidence of poison: nothing is split, nothing is counted', async () => {
  for (const message of ['Too many subrequests.', 'Error connecting to database: Error: Too many subrequests.']) {
    const { claimed, rows } = assets(16, () => false)
    const { q, calls, seen } = batching({ claimed, rows, writeError: message })
    const r = await drainOutbox(q, env)
    assert.equal(r.processed, 0)
    assert.equal(seen.filter(s => s.includes('INSERT INTO kg_nodes')).length, 1, 'no splitting once the limit is hit')
    assert.equal(released(calls).length, 16, message)
    assert.deepEqual(removed(calls), [])
  }
})

test('one id whose read fails does not fail the others, and is not taken for a deleted row', async () => {
  const claimed = [claim('assets', 'g1'), claim('assets', 'bad'), claim('assets', 'g3'), claim('agents', 'ag1')]
  const rows = {
    assets: [asset('g1', 'one'), asset('bad', 'two'), asset('g3', 'three')],
    agents: [{ agent_id: 'ag1', tenant_id: A, name: 'probe', status: 'online', gateway_ip: '10.0.0.2', version: '1', retired_at: null, host_asset_id: null, kind: 'windows' }],
  }
  const { q, calls, seen } = batching({ claimed, rows, failRead: 'bad' })
  const r = await drainOutbox(q, env)
  assert.equal(r.processed, 3)
  assert.deepEqual(removed(calls).sort(), ['ag1', 'g1', 'g3'])
  assert.deepEqual(released(calls), [])
  assert.ok(!seen.some(s => s.includes('DELETE FROM kg_nodes')), 'a row that could not be read must not be removed from the graph')
})

test('a read that keeps failing is bounded too, and its rows wait instead of failing', async () => {
  const { claimed, rows } = assets(500, () => false)
  const { q, calls, seen, requests } = batching({ claimed, rows, failRead: '*' })
  const r = await drainOutbox(q, env)
  assert.ok(requests() <= DRAIN_REQUESTS, `got ${requests()}`)
  assert.equal(r.processed, 0)
  assert.ok(released(calls).length >= 490, 'only the few rows tried alone are counted against')
  assert.ok(!seen.some(s => s.includes('DELETE FROM kg_nodes')))
})

// ── Final review F2: one chat stays inside the free plan's 50 subrequests ──
// Cloudflare counts every KV read or write, Workers AI call, queue send, Neon query or batch, and
// fetch (the model and the analytics API) as a subrequest. The fakes below count each of these.

// Spent by the route before the agent runs (routes/chatbot.ts): the rate-limit KV read and write, and
// perfMiddleware's speed-history data point, counted although Analytics Engine may not count it.
const ROUTE_REQUESTS = 3
const CHAT_LIMIT = 45
const ADV = '7c9e6679-7425-40de-944b-e07fc1f90ae7'
const NODE = { key: 'asset:1', type: 'asset', title: 'web-01', body: 'Device web-01, IP 10.0.0.5.', props: {}, source_ref: null }

const reply = (t: string): ModelReply => ({ text: t, toolCalls: [], truncated: false })
const toolCall = (name: string, args: unknown, id: string): ToolCall => ({ id, type: 'function', function: { name, arguments: JSON.stringify(args) } })

/**
 * The dearest chat there is: a speed question (for a superadmin) that also asks to close an advisory (for a
 * tenant admin), a backlog with a poison row that makes the drain split all it may, more changed nodes than
 * one embedding call takes, a stale performance history, a model that asks for the two dearest lookups every
 * round, and an answer that fails verification twice, so it is regenerated and its proposal removed.
 */
async function worstCase(role: 'superadmin' | 'tenant_admin') {
  const counts: Record<string, number> = {}
  const tick = (what: string) => { counts[what] = (counts[what] ?? 0) + 1 }
  const total = () => Object.values(counts).reduce((a, b) => a + b, 0)

  const ids = Array.from({ length: 100 }, (_, i) => `e${String(i).padStart(3, '0')}`)
  const claimed = ids.map(id => ({ table_name: 'events', row_pk: id, tenant_id: A, changed_at: '2026-11-09 00:00:00+00' }))
  // Each alert has its own CVE, so two embedded nodes a row; two rows are gone; one row poisons every write it is in.
  const eventRows = ids.slice(2).map((id, i) => ({
    event_id: id, asset_id: `a${i}`, tenant_id: A, event_type: 'cve_detected', severity: 'high', status: 'open', occurrences: 1,
    details: { cve_id: `CVE-2024-${10000 + i}` }, timestamp: '2026-11-09T00:00:00Z', hostname: i === 50 ? 'POISON' : `h${i}`, ip_address: '10.0.0.1',
  }))
  // More problems than one embedding call takes.
  const assetFacts = Array.from({ length: 120 }, (_, i) => ({ key: `asset:${i}`, title: `web-${i}`, props: { internetFacing: true, ports: [3389], criticality: 1 } }))
  const windows = [1, 2, 3, 4].map(h => ({
    start: `2026-11-09T0${h}:00:00.000Z`, end: `2026-11-09T0${h + 1}:00:00.000Z`, requests: 40, errors: 20, errorRate: 0.5, avgMs: 2500, dbShare: 0.3,
    slowRoutes: [{ route: '/api/v1/events', requests: 20, avgMs: 2500, maxMs: 6000, errorRate: 0, slow: true }],
    jobs: [{ name: 'kg_sync', runs: 1, failed: 0, avgMs: 900, maxMs: 900 }], scanRequests: 3, slow: true,
  }))
  let link = 0
  const answer = (text: string, params: unknown[] = []): Array<Record<string, unknown>> => {
    if (text.includes('INSERT INTO kg_nodes') && String(params[0]).includes('POISON')) throw new Error('invalid input syntax')
    if (text.includes('UPDATE kg_outbox o SET claimed_until = now()')) return claimed
    if (text.includes('FROM events t')) return eventRows.filter(r => (params[0] as string[]).includes(r.event_id))
    if (text.includes('quarantined')) return [{ n: 40, quarantined: 0 }]
    if (text.includes("type = 'asset'") && text.includes('SELECT key, title, props')) return assetFacts
    if (text.includes('AS my_assets')) return [{ assets: 120, my_assets: 0, critical: 0, advisories: 0 }]
    if (text.includes('max(updated_at)')) return [{ at: null }]
    if (text.includes("props ->> 'start' <")) return [{ key: 'perf:window:2026-10-01T00:00:00.000Z' }]
    if (text.includes("props ->> 'start' >")) return windows.map(props => ({ props }))
    if (text.includes('AS start')) return windows.map(w => ({ start: w.start }))
    if (text.includes('FROM kg_outbox') && text.includes('stuck')) return [{ n: 900, oldest: '2026-11-09T00:00:00Z', stuck: 1 }]
    if (text.includes("props ->> 'rule' = ANY")) return [{ key: 'problem:platform:gone' }]
    if (text.includes('ts_rank') || text.includes('<=>') || text.includes('n.key = $1')) return [NODE]
    if (text.includes('FROM kg_edges e JOIN')) { link++; return [{ ...NODE, key: `asset:l${link}`, from_key: 'asset:1', to_key: `asset:l${link}`, relation: 'LINKS' }] }
    if (text.includes('FROM advisories adv')) return [{ advisory_id: ADV, summary: 'Patch web-01', status: 'open' }]
    return []
  }
  const q = (async (text: string, params?: unknown[]) => { tick('database'); return answer(text, params) }) as Q
  q.batch = async (stmts: Stmt[]) => { tick('database'); return stmts.map(s => answer(s.text, s.params)) }

  const kvStore = new Map<string, string>()
  const kvBinding = {
    get: async (k: string, type?: string) => { tick('kv'); return type === 'json' ? { feeds: { otx: { ok: false, count: 0, last_ok_at: null } } } : kvStore.get(k) ?? null },
    put: async (k: string, v: string) => { tick('kv'); kvStore.set(k, v) },
    delete: async (k: string) => { tick('kv'); kvStore.delete(k) },
  }
  const aiBinding = { run: async (_model: string, input: { text: string[] }) => { tick('ai'); return { data: input.text.map(() => [0.1, 0.2, 0.3]) } } }
  const queue = { send: async () => { tick('queue') } }
  const chatEnv = { DATABASE_URL: 'x', KV_CACHE: kvBinding, AI: aiBinding, ADVISORY_QUEUE: queue, CF_ACCOUNT_ID: 'acct', CF_ANALYTICS_TOKEN: 'tok' } as unknown as Env

  let classified = false, rounds = 0, corrected = false
  const ai: GraphCtx['ai'] = async (messages, offered) => {
    tick('model')
    if (!classified) { classified = true; return reply('system') }
    if (messages.some(m => m.role === 'user' && String(m.content).startsWith('That answer was rejected'))) corrected = true
    if (offered?.length) {
      rounds++
      const calls = [toolCall('search_graph', { query: 'web servers' }, `s${rounds}`), toolCall('follow_links', { key: 'asset:1', depth: 2 }, `f${rounds}`)]
      const names = (offered as Array<{ function: { name: string } }>).map(t => t.function.name)
      if (rounds === 1 && names.includes('propose_resolve_advisory')) calls.push(toolCall('propose_resolve_advisory', { advisory_id: ADV }, 'p1'))
      return { text: '', toolCalls: calls, truncated: false }
    }
    return reply('You have 99 critical alerts [S1].')
  }

  const analytics = [1, 2, 3, 4].map(h => ({ bucket: `2026-11-09 0${h}:00:00`, kind: 'req', name: '/api/v1/events', n: 20, errors: 10, total_ms: 50000, db_ms: 1000, max_ms: 6000 }))
  const realFetch = globalThis.fetch
  globalThis.fetch = (async () => { tick('fetch'); return new Response(JSON.stringify({ data: analytics })) }) as typeof fetch
  try {
    const ctx: GraphCtx = {
      query: q, env: chatEnv, ai,
      user: { userId: 'u1', role, tenantId: role === 'superadmin' ? null : A }, pickedTenant: role === 'superadmin' ? A : null,
    }
    const r = await runGraphAgent(ctx, 'Why was the site slow at 3pm on 2026-11-09? Also close advisory 7c9e6679.', [], async () => {})
    return { r, counts, total: ROUTE_REQUESTS + total(), corrected, proposalsLeft: [...kvStore.keys()].filter(k => k.startsWith('kg:proposal:')).length }
  } finally {
    globalThis.fetch = realFetch
  }
}

for (const role of ['superadmin', 'tenant_admin'] as const) {
  test(`F2: the dearest chat of a ${role} stays within ${CHAT_LIMIT} subrequests and still answers`, async t => {
    const err = console.error, warn = console.warn
    console.error = () => {}; console.warn = () => {}
    try {
      const w = await worstCase(role)
      const breakdown = `${w.total} subrequests: ${JSON.stringify({ route: ROUTE_REQUESTS, ...w.counts })}`
      t.diagnostic(breakdown)
      assert.ok(w.total <= CHAT_LIMIT, breakdown)
      assert.equal(w.r.failed, false)
      assert.equal(w.corrected, true, 'the answer still got its one regeneration')
      assert.ok(w.r.content.endsWith(IDK), w.r.content)
      assert.equal(w.proposalsLeft, 0, 'a refused answer still removes its proposal')
    } finally { console.error = err; console.warn = warn }
  })
}
