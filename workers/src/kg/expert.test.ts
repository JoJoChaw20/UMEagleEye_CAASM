// Project 2 Task 3: knowledge-base and live-lookup citations in the chat agent.
import test from 'node:test'
import assert from 'node:assert/strict'
import { LIVE_CVE_SUBREQUESTS, runGraphAgent, type GraphCtx } from './agent'
import { MIGRATION_ACTIONS } from '../lib/actions'
import { IDK, type ChatMessage, type ModelReply, type ToolCall } from './guard'
import type { Q } from './store'
import type { Env } from '../types'

const A = '22222222-2222-2222-2222-222222222222'
const NODE = { key: 'asset:1', type: 'asset', title: 'web-01', body: 'Device web-01, IP 10.0.0.5, port 22 open.', props: {}, source_ref: null }
const text = (t: string): ModelReply => ({ text: t, toolCalls: [], truncated: false })
const call = (name: string, args: unknown, id = 'c1'): ToolCall => ({ id, type: 'function', function: { name, arguments: JSON.stringify(args) } })
const tools = (...calls: ToolCall[]): ModelReply => ({ text: '', toolCalls: calls, truncated: false })

function setup(kind: string, replies: ModelReply[], opts: { role?: 'superadmin'; intel?: GraphCtx['intel'] } = {}) {
  const calls: Array<{ text: string; params: unknown[] }> = []
  const q: Q = async (sql, params = []) => {
    calls.push({ text: sql, params })
    if (sql.includes('count(*) FILTER')) return [{ n: 0, quarantined: 0 }]
    if (sql.includes('SELECT updated_at')) return [{ updated_at: new Date().toISOString() }]
    if (sql.includes('ts_rank')) return [NODE]
    return []
  }
  const seen: Array<{ messages: ChatMessage[]; tools?: unknown[] }> = []
  let classified = false, next = 0
  const ai: GraphCtx['ai'] = async (messages, t) => {
    if (!classified) { classified = true; return text(kind) }
    seen.push({ messages: messages.map(m => ({ ...m })) as ChatMessage[], tools: t })
    return replies[next++] ?? text("I don't know.")
  }
  const kv = new Map<string, string>()
  const env = { DATABASE_URL: 'x', KV_CACHE: { get: async (k: string) => kv.get(k) ?? null, put: async (k: string, v: string) => { kv.set(k, v) }, delete: async () => {} } } as unknown as Env
  const ctx: GraphCtx = {
    query: q, env, ai,
    user: opts.role === 'superadmin' ? { userId: 'u0', role: 'superadmin', tenantId: null, actions: [] } : { userId: 'u1', role: 'tenant_user', tenantId: A, actions: MIGRATION_ACTIONS.tenant_admin },
    pickedTenant: null, intel: opts.intel,
  }
  const events: Array<Record<string, unknown>> = []
  return { ctx, calls, seen, events, emit: async (e: Record<string, unknown>) => { events.push(e) } }
}
const names = (t?: unknown[]) => (t ?? []).map(x => (x as { function: { name: string } }).function.name)
const finalSources = (events: Array<Record<string, unknown>>) => (events.find(e => 'sources' in e) as { sources: Array<{ ref: string; type: string; url?: string }> }).sources

const answer = (expert: string) => [
  '## From your environment', 'Port 22 is open on `web-01` [S1].', '',
  '## Expert guidance', expert, '',
  'Confidence: High - the open port and the guidance are both cited.',
].join('\n')

test('expert: knowledge-base entries are K refs; a cited answer passes and lists K sources with their links', async () => {
  const s = setup('fix', [tools(call('search_graph', { query: 'web-01' }, 'a'), call('search_knowledge', { query: 'port 22 exposed' }, 'b')), text(answer('1. Allow SSH only from the admin network and use keys [K1].'))])
  const r = await runGraphAgent(s.ctx, 'how do I fix the open ssh port on web-01?', [], s.emit)
  assert.notEqual(r.content, IDK, r.content)
  assert.match(r.content, /## Expert guidance\n> General guidance from the cited references/)
  const k = finalSources(s.events).find(x => x.ref === 'K1')
  assert.equal(k?.type, 'knowledge')
  assert.match(String(k?.url), /^https:\/\//)
  // the knowledge search is local: it made no database read, and nothing about it was fetched
  const toolMsg = String(s.seen[1]!.messages.find(m => m.role === 'tool' && (m as { tool_call_id?: string }).tool_call_id === 'b')?.content)
  assert.match(toolMsg, /"ref":"K1"/)
  assert.ok(!s.calls.some(c => /knowledge/i.test(c.text)))
})

test('expert: an uncited expert paragraph is rejected, retried once, then IDK', async () => {
  const bad = answer('1. Just disable password logins everywhere.')
  const s = setup('fix', [tools(call('search_graph', { query: 'web-01' })), text(bad), text(bad)])
  const r = await runGraphAgent(s.ctx, 'how do I fix the open ssh port on web-01?', [], s.emit)
  assert.equal(r.content, IDK)
  const retry = s.seen[2]!.messages.at(-1)
  assert.match(String(retry?.content), /must cite a knowledge-base entry like \[K1\]/)
})

test('expert: a K ref that was never given is rejected', async () => {
  const bad = answer('1. Restrict SSH [K7].')
  const s = setup('fix', [tools(call('search_graph', { query: 'web-01' })), text(bad), text(bad)])
  assert.equal((await runGraphAgent(s.ctx, 'fix ssh on web-01', [], s.emit)).content, IDK)
})

test('expert: live lookups are offered only when wired, get L refs and a public link, and are counted before they run', async () => {
  const none = setup('fix', [text("I don't know.")])
  await runGraphAgent(none.ctx, 'fix CVE-2024-3094 on web-01', [], none.emit)
  assert.ok(!names(none.seen[0]!.tools).includes('lookup_cve'))
  assert.ok(names(none.seen[0]!.tools).includes('search_knowledge'))

  const sent: Array<{ name: string; args: unknown }> = []
  const intel: GraphCtx['intel'] = async (name, args) => { sent.push({ name, args }); return { cve_id: 'CVE-2024-3094', cisa_kev: { listed: true } } }
  const s = setup('fix', [tools(call('search_graph', { query: 'web-01' }, 'a'), call('lookup_cve', { cve_id: 'cve-2024-3094' }, 'b')), text(answer('1. The CVE is listed in CISA KEV, so patch it first [L1].'))], { intel })
  const r = await runGraphAgent(s.ctx, 'fix CVE-2024-3094 on web-01', [], s.emit)
  assert.notEqual(r.content, IDK, r.content)
  assert.deepEqual(sent, [{ name: 'lookup_cve', args: { cve_id: 'cve-2024-3094' } }], 'only the CVE id goes to the lookup')
  const l = finalSources(s.events).find(x => x.ref === 'L1')
  assert.equal(l?.url, 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094')
})

test('expert: live lookups stop once their reserved cost no longer fits', async () => {
  let runs = 0
  const intel: GraphCtx['intel'] = async () => { runs++; return { ok: true } }
  const many = Array.from({ length: 5 }, (_, i) => call('lookup_cve', { cve_id: `CVE-2024-000${i + 1}` }, `l${i}`))
  const s = setup('system', [tools(...many), text("I don't know.")], { intel })
  await runGraphAgent(s.ctx, 'what about these CVEs?', [], s.emit)
  // 45 - 3 route - 3 held back - sync reads leave room for at most 4 reserved lookups of 9
  assert.ok(runs * LIVE_CVE_SUBREQUESTS <= 45 - 3 - 3, `ran ${runs}`)
  assert.ok(runs < 5)
  const refused = s.seen[1]!.messages.filter(m => m.role === 'tool' && /No more lookups fit/.test(String(m.content)))
  assert.ok(refused.length >= 1)
})

test('expert: the superadmin may use the knowledge base', async () => {
  const s = setup('system', [text("I don't know.")], { role: 'superadmin' })
  await runGraphAgent(s.ctx, 'how should ssh be hardened in general on our platform?', [], s.emit)
  assert.ok(names(s.seen[0]!.tools).includes('search_knowledge'))
})

test('expert: a system answer without an Expert guidance section is unchanged', async () => {
  const s = setup('system', [tools(call('search_graph', { query: 'web-01' })), text('Port 22 is open on `web-01` [S1].')])
  assert.equal((await runGraphAgent(s.ctx, 'what is open on web-01?', [], s.emit)).content, 'Port 22 is open on `web-01` [S1].')
})
