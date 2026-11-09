import test from 'node:test'
import assert from 'node:assert/strict'
import { confirmAdvisory, type ConfirmKv, type ConfirmUser } from './confirm'
import { proposalKey } from './agent'
import type { Q } from './store'

const T = '11111111-1111-1111-1111-111111111111'
const OTHER_T = '99999999-9999-9999-9999-999999999999'
const ADV = '44444444-4444-4444-4444-444444444444'
const TOKEN = 'tok123'
const record = JSON.stringify({ userId: 'u1', tenantId: T, advisoryId: ADV })
const admin: ConfirmUser = { userId: 'u1', role: 'tenant_admin', tenantId: T }

function setup(opts: { raw?: string | null; rows?: Array<Record<string, unknown>> | 'once' } = {}) {
  const store = new Map<string, string>()
  if (opts.raw !== null) store.set(proposalKey(TOKEN), opts.raw ?? record)
  const deleted: string[] = []
  const kv: ConfirmKv = {
    get: async (k) => store.get(k) ?? null,
    delete: async (k) => { deleted.push(k); store.delete(k) },
  }
  const calls: Array<{ text: string; params: unknown[] }> = []
  let won = false
  const q: Q = async (text, params = []) => {
    calls.push({ text, params })
    if (opts.rows === 'once' || opts.rows === undefined) {
      if (won) return []
      won = true
      return [{ advisory_id: ADV, summary: 'Old OpenSSH on web-01', previous_status: 'open' }]
    }
    return opts.rows
  }
  return { kv, q, calls, deleted, store }
}

test('an unknown or expired token is refused and nothing is written', async () => {
  const s = setup({ raw: null })
  const r = await confirmAdvisory({ kv: s.kv, q: s.q, user: admin, token: TOKEN })
  assert.equal(r.ok, false)
  assert.equal(s.calls.length, 0)
})

test('a token that is not a whole record is refused', async () => {
  const s = setup({ raw: '{"userId":"u1"}' })
  const r = await confirmAdvisory({ kv: s.kv, q: s.q, user: admin, token: TOKEN })
  assert.equal(r.ok, false)
  assert.equal(s.calls.length, 0)
})

test('another user is refused and the token survives', async () => {
  const s = setup()
  const r = await confirmAdvisory({ kv: s.kv, q: s.q, user: { ...admin, userId: 'u2' }, token: TOKEN })
  assert.equal(r.ok, false)
  assert.equal(s.calls.length, 0)
  assert.deepEqual(s.deleted, [])
  assert.ok(s.store.has(proposalKey(TOKEN)))
})

test('a user from another company is refused', async () => {
  const s = setup()
  const r = await confirmAdvisory({ kv: s.kv, q: s.q, user: { ...admin, tenantId: OTHER_T }, token: TOKEN })
  assert.equal(r.ok, false)
  assert.equal(s.calls.length, 0)
})

test('a role that may not change advisories is refused', async () => {
  for (const role of ['business_owner', 'superadmin', 'analyst']) {
    const s = setup()
    const r = await confirmAdvisory({ kv: s.kv, q: s.q, user: { ...admin, role }, token: TOKEN })
    assert.equal(r.ok, false, role)
    assert.equal(s.calls.length, 0, role)
  }
})

test('success: one statement updates the advisory and writes the audit record', async () => {
  const s = setup()
  const r = await confirmAdvisory({ kv: s.kv, q: s.q, user: admin, token: TOKEN })
  assert.deepEqual(r, { ok: true, advisoryId: ADV, summary: 'Old OpenSSH on web-01' })
  assert.equal(s.calls.length, 1)
  const { text, params } = s.calls[0]
  assert.match(text, /UPDATE advisories/)
  assert.match(text, /status = 'resolved'/)
  assert.match(text, /status::text = ANY/)
  assert.match(text, /INSERT INTO audit_logs/)
  assert.match(text, /advisory_status_update/)
  assert.match(text, /"via":"chatbot"/)
  assert.deepEqual(params.slice(0, 3), [ADV, T, 'u1'])
  assert.deepEqual(params[3], ['open', 'acknowledged', 'in_progress'])
  assert.deepEqual(s.deleted, [proposalKey(TOKEN)])
})

test('an advisory already handled gives zero rows: refused, no audit, token deleted', async () => {
  const s = setup({ rows: [] })
  const r = await confirmAdvisory({ kv: s.kv, q: s.q, user: admin, token: TOKEN })
  assert.equal(r.ok, false)
  assert.equal(s.calls.length, 1)
  assert.deepEqual(s.deleted, [proposalKey(TOKEN)])
})

test('a used token cannot be replayed', async () => {
  const s = setup()
  assert.equal((await confirmAdvisory({ kv: s.kv, q: s.q, user: admin, token: TOKEN })).ok, true)
  const again = await confirmAdvisory({ kv: s.kv, q: s.q, user: admin, token: TOKEN })
  assert.equal(again.ok, false)
  assert.equal(s.calls.length, 1)
})

test('two concurrent requests with one token: only one wins', async () => {
  const s = setup()
  const [a, b] = await Promise.all([
    confirmAdvisory({ kv: s.kv, q: s.q, user: admin, token: TOKEN }),
    confirmAdvisory({ kv: s.kv, q: s.q, user: admin, token: TOKEN }),
  ])
  assert.equal([a, b].filter(r => r.ok).length, 1)
  assert.equal(s.calls.length, 2)
})

test('a database failure refuses cleanly and keeps the token for a retry', async () => {
  const s = setup()
  const q: Q = async () => { throw new Error('connection reset') }
  const r = await confirmAdvisory({ kv: s.kv, q, user: admin, token: TOKEN })
  assert.equal(r.ok, false)
  assert.deepEqual(s.deleted, [])
})
