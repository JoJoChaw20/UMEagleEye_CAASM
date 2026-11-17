import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const sqlText = readFileSync(join(process.cwd(), 'drizzle/0037_mfa.sql'), 'utf8')
const code = sqlText.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n')

test('0037 creates both tables', () => {
  assert.match(code, /CREATE TABLE "mfa_recovery_codes"/)
  assert.match(code, /CREATE TABLE "platform_mfa_resets"/)
})

test('0037 adds the three user columns, all nullable', () => {
  for (const col of ['mfa_pending_secret', 'totp_last_step', 'sessions_valid_after']) {
    const m = code.match(new RegExp(`ALTER TABLE "users" ADD COLUMN "${col}" [^;]*;`))
    assert.ok(m, `missing column ${col}`)
    assert.doesNotMatch(m[0], /NOT NULL/)
  }
})

test('0037 is additive only', () => {
  // Foreign keys carry ON DELETE / ON UPDATE clauses; those are not statements.
  const stmts = code.replace(/ON (DELETE|UPDATE) (cascade|no action)/gi, '')
  assert.doesNotMatch(stmts, /\b(DROP|TRUNCATE|UPDATE|DELETE)\b/i)
})
