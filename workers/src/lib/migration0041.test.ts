import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const sqlText = readFileSync(join(process.cwd(), 'drizzle/0041_optional_email.sql'), 'utf8')
const code = sqlText.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n')

test('0041 makes users.email nullable and adds password_change_required defaulting to false', () => {
  assert.match(code, /ALTER TABLE "users" ALTER COLUMN "email" DROP NOT NULL;/)
  assert.match(code, /ALTER TABLE "users" ADD COLUMN "password_change_required" boolean DEFAULT false NOT NULL;/)
})

test('0041 changes no rows and drops nothing', () => {
  assert.doesNotMatch(code, /\b(TRUNCATE|UPDATE|DELETE|INSERT)\b/i)
  assert.doesNotMatch(code, /DROP (TABLE|COLUMN|CONSTRAINT|INDEX)/i)
})
