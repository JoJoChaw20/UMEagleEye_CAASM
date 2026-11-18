import test from 'node:test'
import assert from 'node:assert/strict'
import { alertWhat, buildOverview, tierOf, type OverviewRows } from './overview'
import { isOverviewQuestion } from './guard'
import { runGraphAgent, type GraphCtx } from './agent'
import { MIGRATION_ACTIONS } from '../lib/actions'
import type { ChatMessage, ModelReply, ToolCall } from './guard'
import type { Q } from './store'
import type { Env } from '../types'

const NOW = Date.parse('2026-11-18T12:00:00Z')
const rows = (over: Partial<OverviewRows> = {}): OverviewRows => ({
  assets: { total: 40, critical: 6, internet: 3 },
  agents: [{ kind: 'host', lastHeartbeat: new Date(NOW - 60_000) }, { kind: 'host', lastHeartbeat: new Date(NOW - 3 * 86_400_000) }, { kind: 'mobile', lastHeartbeat: new Date(NOW - 10 * 60_000) }],
  scans: { total: 12, failed: 1, running: 0, last: '2026-11-18T09:18:42.116Z' },
  alerts: { total: 25, critical: 2, high: 5, medium: 10, low: 8, newWeek: 4, p0: 1, p1: 2, p2: 3 },
  advisories: [{ status: 'open', n: 4 }, { status: 'in_progress', n: 1 }, { status: 'resolved', n: 9 }],
  top: [{ eventId: 'e1', type: 'cve_detected', severity: 'critical', status: 'open', details: { package_name: 'openssl', package_version: '1.0.0-1', cve_count: 2, kev_count: 1, fix_to: '1.0.1-1' }, firstSeen: new Date(NOW - 86_400_000), score: 145, hostname: 'web-01', ip: '10.0.0.5', internet: true, advisory: '7c9e6679-7425-40de-944b-e07fc1f90ae7' }],
  ...over,
})

test('tierOf follows the dashboard tiers', () => {
  assert.equal(tierOf('cti_match', { match_kind: 'ioc' }, 10), 'P0')
  assert.equal(tierOf('cti_match', { match_kind: 'watchlist' }, 110), 'P1')
  assert.equal(tierOf('port_opened', { has_cti_match: true }, 10), 'P0')
  assert.equal(tierOf('cve_detected', { has_cti_match: true }, 80), 'P2')
  assert.equal(tierOf('port_opened', {}, 100), 'P1')
  assert.equal(tierOf('port_opened', {}, 74.9), 'P3')
})

test('alertWhat describes an alert in one line', () => {
  assert.equal(alertWhat('cve_detected', { package_name: 'openssl', package_version: '1.0.0-1', cve_count: 2, kev_count: 1, fix_to: '1.0.1-1' }), 'openssl 1.0.0-1: 2 CVE(s), 1 known exploited, fixed in 1.0.1-1')
  assert.equal(alertWhat('port_opened', { port: 3389, service: 'ms-wbt-server' }), 'port 3389/tcp (ms-wbt-server) open')
  assert.equal(alertWhat('weird_type', {}), 'weird type')
})

test('buildOverview gives every dashboard area and the priorities, with the dashboard posture formula', () => {
  const o = buildOverview(rows(), { tenantId: 't', detail: true }, NOW)
  assert.deepEqual(o.assets, { total: 40, critical: 6, internet_facing: 3 })
  assert.deepEqual(o.agents, { total: 3, online: 2, degraded: 0, offline: 1 })
  assert.equal(o.open_alerts.total, 25)
  assert.equal(o.advisories.active, 5)
  assert.deepEqual(o.priority_tiers, { P0_investigate: 1, P1_urgent: 2, P2_high: 3, P3_routine: 19 })
  assert.equal(typeof o.posture_score, 'number')
  const top = (o as { top_priorities: Array<Record<string, unknown>> }).top_priorities
  assert.equal(top[0]!.tier, 'P1')
  assert.equal(top[0]!.device, 'web-01')
  assert.equal(top[0]!.advisory, '7c9e6679')
})

test('buildOverview with counts only never names a device or an alert', () => {
  const o = buildOverview(rows(), { detail: false }, NOW)
  assert.equal('top_priorities' in o, false)
  assert.doesNotMatch(JSON.stringify(o), /web-01|10\.0\.0\.5|openssl/)
  assert.equal(o.scope, 'all companies')
})

test('isOverviewQuestion recognises overall-situation questions', () => {
  for (const q of ['give me overall status of current scanning, is it all good? what should we priortize now', 'Summarise what is going on', "what's going on in my environment?", 'How are we doing?', 'What should I fix first?', 'Give me the big picture', 'what are our priorities this week'])
    assert.equal(isOverviewQuestion(q), true, q)
  for (const q of ['what is on web-01?', 'how do I restrict SSH?', 'explain CVE-2024-3094'])
    assert.equal(isOverviewQuestion(q), false, q)
})

// The agent: an overview question is answered from get_overview as a system answer, even when sorted as fix.
const text = (t: string): ModelReply => ({ text: t, toolCalls: [], truncated: false })
const call = (name: string, args: unknown): ToolCall => ({ id: 'o1', type: 'function', function: { name, arguments: JSON.stringify(args) } })

function setup(kind: string, replies: ModelReply[], overview?: GraphCtx['overview'], role: 'tenant' | 'superadmin' = 'tenant') {
  const q: Q = async (sql) => (sql.includes('count(*) FILTER') ? [{ n: 0, quarantined: 0 }] : sql.includes('SELECT updated_at') ? [{ updated_at: new Date().toISOString() }] : [])
  const seen: Array<{ messages: ChatMessage[]; tools?: unknown[] }> = []
  let classified = false, next = 0, reviews = 0
  const ai: GraphCtx['ai'] = async (messages, t) => {
    if (!classified) { classified = true; return text(kind) }
    if (String(messages[0]?.content ?? '').includes('reviewing an assistant')) { reviews++; return text('{"ok": true, "reasons": []}') }
    seen.push({ messages: messages.map(m => ({ ...m })) as ChatMessage[], tools: t })
    return replies[next++] ?? text("I don't know.")
  }
  const env = { DATABASE_URL: 'x', KV_CACHE: { get: async () => null, put: async () => {}, delete: async () => {} } } as unknown as Env
  const user = role === 'superadmin' ? { userId: 'u0', role: 'superadmin', tenantId: null, actions: [] } : { userId: 'u1', role: 'tenant_user', tenantId: '22222222-2222-2222-2222-222222222222', actions: MIGRATION_ACTIONS.tenant_admin }
  const ctx: GraphCtx = { query: q, env, ai, user, pickedTenant: null, overview }
  return { ctx, seen, reviews: () => reviews, emit: async () => {} }
}

test('overview: "what should we prioritise" is answered from get_overview, cited, with no fix format and no reviewer', async () => {
  const ov = buildOverview(rows(), { tenantId: 't', detail: true }, NOW)
  const answer = `## Overall status\n- Posture score: ${ov.posture_score} [S1]\n- Open alerts: 2 critical, 5 high [S1]\n- Priority tiers: P0 1, P1 2 [S1]\n\n## What to fix first\n1. P1: \`web-01\` openssl 1.0.0-1, advisory 7c9e6679 [S1].`
  const s = setup('fix', [{ text: '', toolCalls: [call('get_overview', {})], truncated: false }, text(answer)], async () => ov)
  const r = await runGraphAgent(s.ctx, 'give me overall status of current scanning, is it all good? what should we prioritize now', [], s.emit)
  assert.equal(r.kind, 'system')
  assert.equal(r.content, answer)
  assert.equal(r.sources[0]?.type, 'overview')
  assert.equal(s.reviews(), 0)
  assert.match(String(s.seen[0]!.messages[0]!.content), /Call get_overview first/)
  assert.ok((s.seen[0]!.tools as Array<{ function: { name: string } }>).some(t => t.function.name === 'get_overview'))
})

test('overview: an invented number is still refused', async () => {
  const ov = buildOverview(rows(), { tenantId: 't', detail: true }, NOW)
  const bad = '## Overall status\n- Open alerts: 777 critical [S1]'
  const s = setup('system', [{ text: '', toolCalls: [call('get_overview', {})], truncated: false }, text(bad), text(bad)], async () => ov)
  const r = await runGraphAgent(s.ctx, 'summarise what is going on', [], s.emit)
  assert.match(r.content, /I don't know/)
})

test('overview: not offered when the route did not wire it', async () => {
  const s = setup('system', [text("I don't know.")])
  await runGraphAgent(s.ctx, 'how are we doing?', [], s.emit)
  assert.ok(!(s.seen[0]!.tools as Array<{ function: { name: string } }>).some(t => t.function.name === 'get_overview'))
})
