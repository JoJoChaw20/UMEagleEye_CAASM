import { test } from 'node:test'
import assert from 'node:assert/strict'
import { getDb } from '../db/client'
import { applyStatements } from './breakGlass'

const db = getDb('postgres://u:p@localhost/none')   // builds queries only; nothing connects
const stmts = applyStatements(db, '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222')
const sqls = stmts.map((s) => (s as unknown as { toSQL(): { sql: string } }).toSQL().sql)

test('the status flip is first and checks confirmed and due', () => {
  assert.match(sqls[0]!, /^update "platform_mfa_resets" set "status"/)
  assert.match(sqls[0]!, /"status" = \$\d+/)
  assert.match(sqls[0]!, /"effective_at" <= now\(\)/)
})

test('both clearing statements are guarded by this transaction winning the flip', () => {
  assert.match(sqls[1]!, /^update "users"/)
  assert.match(sqls[2]!, /^delete from "mfa_recovery_codes"/)
  for (const q of [sqls[1]!, sqls[2]!]) {
    assert.match(q, /exists \(select 1 from platform_mfa_resets/)
    assert.match(q, /completed_at = now\(\)/)
  }
})
