import { test } from 'node:test'
import assert from 'node:assert/strict'
import { getDb } from '../db/client'
import { deleteUserStatements } from './userDelete'

const db = getDb('postgres://u:p@localhost/none')   // builds queries only; nothing connects
const stmts = deleteUserStatements(db, '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 'alice', '33333333-3333-3333-3333-333333333333')
const q = stmts.map((s) => (s as unknown as { toSQL(): { sql: string; params: unknown[] } }).toSQL())

test('the username is kept on the audit rows first, then the user is deleted', () => {
  assert.equal(q.length, 2)
  assert.match(q[0]!.sql, /^update "audit_logs" set "actor_username" = \$1 where "audit_logs"."user_id" = \$2/)
  assert.deepEqual(q[0]!.params, ['alice', '22222222-2222-2222-2222-222222222222'])
  assert.match(q[1]!.sql, /^delete from "users" where \("users"."user_id" = \$1 and "users"."tenant_id" = \$2 and "users"."role" = \$3 and exists/)
  assert.match(q[1]!.sql, /role = 'tenant_superadmin'\)\) returning "user_id"$/)
  assert.deepEqual(q[1]!.params, [
    '22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', 'tenant_user',
    '33333333-3333-3333-3333-333333333333', '11111111-1111-1111-1111-111111111111',
  ])
})
