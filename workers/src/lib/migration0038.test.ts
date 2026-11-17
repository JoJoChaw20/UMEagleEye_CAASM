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

test('0038 adds the new FK NOT VALID, then validates it (short lock)', () => {
  const add = code.match(/ADD CONSTRAINT "audit_logs_user_id_users_user_id_fk"[^;]*;/)
  assert.ok(add, 'missing ADD CONSTRAINT')
  assert.match(add[0], /NOT VALID;$/)
  const validate = code.indexOf('ALTER TABLE "audit_logs" VALIDATE CONSTRAINT "audit_logs_user_id_users_user_id_fk";')
  assert.ok(validate > code.indexOf(add[0]), 'VALIDATE must come after the ADD')
})

test('0038 adds a nullable audit_logs.actor_username varchar(100)', () => {
  const m = code.match(/ALTER TABLE "audit_logs" ADD COLUMN "actor_username" [^;]*;/)
  assert.ok(m, 'missing actor_username')
  assert.match(m[0], /varchar\(100\)/)
  assert.doesNotMatch(m[0], /NOT NULL|DEFAULT/i)
})

test('0038 touches no rows', () => {
  const stmts = code.replace(/ON (DELETE|UPDATE) (cascade|no action|set null)/gi, '')
  assert.doesNotMatch(stmts, /\b(TRUNCATE|UPDATE|DELETE)\b/i)
  assert.doesNotMatch(stmts, /DROP TABLE|DROP COLUMN/i)
})
