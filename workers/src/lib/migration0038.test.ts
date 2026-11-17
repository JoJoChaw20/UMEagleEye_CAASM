import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const file = join(process.cwd(), 'drizzle/0038_audit_keeps_deleted_users.sql')
const code = existsSync(file)
  ? readFileSync(file, 'utf8').split('\n').filter((l) => !l.trim().startsWith('--')).join('\n')
  : ''

test('0038 replaces the audit_logs user FK with ON DELETE set null', () => {
  assert.match(code, /ALTER TABLE "audit_logs" DROP CONSTRAINT "audit_logs_user_id_users_user_id_fk"/)
  assert.match(
    code,
    /ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_user_id_users_user_id_fk" FOREIGN KEY \("user_id"\) REFERENCES "public"\."users"\("user_id"\) ON DELETE set null/,
  )
})

test('0038 touches no rows', () => {
  const stmts = code.replace(/ON (DELETE|UPDATE) (cascade|no action|set null)/gi, '')
  assert.doesNotMatch(stmts, /\b(TRUNCATE|UPDATE|DELETE)\b/i)
  assert.doesNotMatch(stmts, /DROP TABLE|DROP COLUMN/i)
})
