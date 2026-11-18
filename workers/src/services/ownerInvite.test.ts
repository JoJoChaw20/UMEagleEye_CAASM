import { test } from 'node:test'
import assert from 'node:assert/strict'
import { sql } from 'drizzle-orm'
import { getDb } from '../db/client'
import { users } from '../db/schema'
import { candidateEligible, ownerInviteStatement } from './ownerInvite'

const db = getDb('postgres://u:p@localhost/none')   // builds queries only; nothing connects
const T = '11111111-1111-1111-1111-111111111111'
const NEW = { ok: true as const, existing: null, username: 'bob' }

test('new-owner insert is guarded: no owner left AND the caller guard', () => {
  const q = (ownerInviteStatement(db, NEW, T, 'b@x', sql`exists (select 1 from marker)`) as any).toSQL()
  assert.match(q.sql, /\(select \$\d+::varchar where \(not exists \(select 1 from users where tenant_id = \$\d+::uuid and role = 'tenant_superadmin'\) and exists \(select 1 from marker\)\)\)/)
})

test('promoting an existing account also clears its scheduled deactivation', () => {
  const existing = { userId: 'u1', tenantId: null, role: 'tenant_user', actions: [] } as any
  const q = (ownerInviteStatement(db, { ok: true, existing, username: 'x' }, T, 'b@x') as any).toSQL()
  assert.match(q.sql, /"scheduled_deactivation_at" = \$\d+/)
  assert.ok(q.params.includes(null))
})

test('promoting an existing account requires it active and not due (interim invite and restore)', () => {
  const existing = { userId: 'u1', tenantId: null, role: 'tenant_user', actions: [] } as any
  const q = (ownerInviteStatement(db, { ok: true, existing, username: 'x' }, T, 'b@x') as any).toSQL()
  assert.match(q.sql, /"is_active" = \$\d+/)
  assert.match(q.sql, /"scheduled_deactivation_at" is null or "users"."scheduled_deactivation_at" > now\(\)/)
  const c = db.select().from(users).where(candidateEligible('u1', T)).toSQL()
  assert.match(c.sql, /is_active = true and \(scheduled_deactivation_at is null or scheduled_deactivation_at > now\(\)\)/)
})
