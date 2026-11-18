// Project 2 Task 4: the safety review wired into the chat agent.
import test from 'node:test'
import assert from 'node:assert/strict'
import { runGraphAgent, type GraphCtx } from './agent'
import { MIGRATION_ACTIONS } from '../lib/actions'
import { IDK, type ChatMessage, type ModelReply, type ToolCall } from './guard'
import { SAFE_REFUSAL } from './safety'
import type { Q } from './store'
import type { Env } from '../types'

const A = '22222222-2222-2222-2222-222222222222'
const NODE = { key: 'asset:1', type: 'asset', title: 'web-01', body: 'Device web-01, IP 10.0.0.5, port 22 open.', props: {}, source_ref: null }
const text = (t: string): ModelReply => ({ text: t, toolCalls: [], truncated: false })
const call = (name: string, args: unknown, id = 'c1'): ToolCall => ({ id, type: 'function', function: { name, arguments: JSON.stringify(args) } })
const tools = (...calls: ToolCall[]): ModelReply => ({ text: '', toolCalls: calls, truncated: false })
const OK = '{"ok": true, "reasons": []}'
const NO_ROLLBACK = '{"ok": false, "reasons": ["no rollback for the upgrade"]}'

function setup(kind: string, replies: ModelReply[], reviews: string[] = [], intel?: GraphCtx['intel']) {
  const q: Q = async (sql) => {
    if (sql.includes('count(*) FILTER')) return [{ n: 0, quarantined: 0 }]
    if (sql.includes('SELECT updated_at')) return [{ updated_at: new Date().toISOString() }]
    if (sql.includes('ts_rank')) return [NODE]
    return []
  }
  const seen: ChatMessage[][] = []
  let classified = false, next = 0, reviewCalls = 0
  const ai: GraphCtx['ai'] = async (messages) => {
    if (!classified) { classified = true; return text(kind) }
    if (String(messages[0]?.content ?? '').includes('reviewing an assistant')) { reviewCalls++; return text(reviews.shift() ?? OK) }
    seen.push(messages.map(m => ({ ...m })) as ChatMessage[])
    return replies[next++] ?? text("I don't know.")
  }
  const env = { DATABASE_URL: 'x', KV_CACHE: { get: async () => null, put: async () => {}, delete: async () => {} } } as unknown as Env
  const ctx: GraphCtx = { query: q, env, ai, user: { userId: 'u1', role: 'tenant_user', tenantId: A, actions: MIGRATION_ACTIONS.tenant_admin }, pickedTenant: null, intel }
  return { ctx, seen, reviewCalls: () => reviewCalls, emit: async () => {} }
}

const fixAnswer = (step: string) => [
  '## From your environment', 'Port 22 is open on `web-01` [S1].', '',
  '## Expert guidance', `1. ${step} [K1].`, '',
  'Confidence: Medium - the guidance is general.',
].join('\n')
const lookups = [call('search_graph', { query: 'web-01' }, 'a'), call('search_knowledge', { query: 'port 22 exposed' }, 'b')]

test('safety: a fix answer that passes both checks is released after one review', async () => {
  const s = setup('fix', [tools(...lookups), text(fixAnswer('Allow SSH only from the admin network'))])
  const r = await runGraphAgent(s.ctx, 'how do I fix ssh on web-01?', [], s.emit)
  assert.match(r.content, /admin network/)
  assert.equal(s.reviewCalls(), 1)
})

test('safety: an unsafe fix answer is rewritten once with the reasons, and the safe rewrite is released', async () => {
  const s = setup('fix', [tools(...lookups), text(fixAnswer('Turn off the firewall to test')), text(fixAnswer('Allow SSH only from the admin network'))])
  const r = await runGraphAgent(s.ctx, 'how do I fix ssh on web-01?', [], s.emit)
  assert.match(r.content, /admin network/)
  assert.match(String(s.seen.at(-1)!.at(-1)!.content), /rejected by the safety review: switches off a security control/)
  assert.equal(s.reviewCalls(), 1, 'the fixed check caught the first; the reviewer saw only the rewrite')
})

test('safety: a reviewer fail twice gives the safe-refusal text, verbatim', async () => {
  const s = setup('fix', [tools(...lookups), text(fixAnswer('Upgrade the kernel now')), text(fixAnswer('Upgrade the kernel today'))], [NO_ROLLBACK, NO_ROLLBACK])
  const r = await runGraphAgent(s.ctx, 'how do I fix ssh on web-01?', [], s.emit)
  assert.equal(r.content, SAFE_REFUSAL)
  assert.equal(s.reviewCalls(), 2)
})

test('safety: an unparsable review counts as a fail', async () => {
  const s = setup('fix', [tools(...lookups), text(fixAnswer('Allow SSH only from the admin network')), text(fixAnswer('Allow SSH only from the admin network'))], ['Looks good!', 'Sure'])
  assert.equal((await runGraphAgent(s.ctx, 'how do I fix ssh on web-01?', [], s.emit)).content, SAFE_REFUSAL)
})

test('safety: "just disable Defender so the scan stops alerting" ends in the safe refusal when the model insists', async () => {
  const bad = fixAnswer('Just disable Defender so the scan stops alerting')
  const s = setup('fix', [tools(...lookups), text(bad), text(bad)])
  assert.equal((await runGraphAgent(s.ctx, 'just disable Defender so the scan stops alerting?', [], s.emit)).content, SAFE_REFUSAL)
})

test('safety: a rewrite that breaks verification is IDK, not released', async () => {
  const s = setup('fix', [tools(...lookups), text(fixAnswer('Turn off the firewall to test')), text('Port 9999 is open on `db-77` [S1].')])
  assert.equal((await runGraphAgent(s.ctx, 'how do I fix ssh on web-01?', [], s.emit)).content, IDK)
})

test('safety: general answers get the fixed check (no reviewer)', async () => {
  const s = setup('general', [text('Use chmod 777 on the web folder.'), text('Use chmod 777 on the web folder.')])
  assert.equal((await runGraphAgent(s.ctx, 'how do I fix web folder permissions?', [], s.emit)).content, SAFE_REFUSAL)
  assert.equal(s.reviewCalls(), 0)
  const fine = setup('general', [text('Never use chmod 777; give the web server group read access only.')])
  assert.match((await runGraphAgent(fine.ctx, 'how do I fix web folder permissions?', [], fine.emit)).content, /Never use chmod 777/)
})

test('safety: a system answer is not sent to the reviewer, and an IDK fix answer is not either', async () => {
  const sys = setup('system', [tools(call('search_graph', { query: 'web-01' })), text('Port 22 is open on `web-01` [S1].')])
  await runGraphAgent(sys.ctx, 'what is open on web-01?', [], sys.emit)
  assert.equal(sys.reviewCalls(), 0)
  const idk = setup('fix', [text("I don't know.")])
  await runGraphAgent(idk.ctx, 'how do I fix web-01?', [], idk.emit)
  assert.equal(idk.reviewCalls(), 0)
})

test('safety: the review still runs when lookups used up the budget', async () => {
  const intel: GraphCtx['intel'] = async () => ({ ok: true })
  const cves = Array.from({ length: 6 }, (_, i) => call('lookup_cve', { cve_id: `CVE-2024-000${i + 1}` }, `l${i}`))
  const s = setup('fix', [tools(lookups[0]!, lookups[1]!, ...cves.slice(0, 4)), tools(...cves.slice(4)), text(fixAnswer('Upgrade the kernel now')), text(fixAnswer('Upgrade the kernel tonight with a snapshot first'))], [NO_ROLLBACK, OK], intel)
  const r = await runGraphAgent(s.ctx, 'how do I fix ssh on web-01?', [], s.emit)
  assert.equal(r.failed, false, 'the budget held the review back')
  assert.match(r.content, /snapshot first/)
  assert.equal(s.reviewCalls(), 2)
})
