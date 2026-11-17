import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const sqlText = readFileSync(join(process.cwd(), 'drizzle/0039_ownership.sql'), 'utf8')
const code = sqlText.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n')

test('0039 creates the four tables', () => {
  for (const t of ['ownership_transfers', 'tenant_recovery_plans', 'ownership_recoveries', 'tenant_notices']) {
    assert.match(code, new RegExp(`CREATE TABLE "${t}"`))
  }
})

test('0039 adds users.scheduled_deactivation_at, nullable', () => {
  const m = code.match(/ALTER TABLE "users" ADD COLUMN "scheduled_deactivation_at" [^;]*;/)
  assert.ok(m)
  assert.doesNotMatch(m[0], /NOT NULL/)
})

test('0039 has both partial unique indexes', () => {
  assert.match(code, /CREATE UNIQUE INDEX "[^"]+" ON "ownership_transfers" USING btree \("tenant_id"\) WHERE [^;]*'pending'/)
  assert.match(code, /CREATE UNIQUE INDEX "[^"]+" ON "ownership_recoveries" USING btree \("tenant_id"\) WHERE [^;]*'awaiting_approval'[^;]*'on_hold'/)
})

test('0039 never deletes users', () => {
  assert.doesNotMatch(code, /REFERENCES "users"[^,;]*ON DELETE cascade/i)
})

test('0039 is additive only', () => {
  const stmts = code.replace(/ON (DELETE|UPDATE) (cascade|no action|set null|restrict)/gi, '')
  assert.doesNotMatch(stmts, /\b(DROP|TRUNCATE|UPDATE|DELETE)\b/i)
})
