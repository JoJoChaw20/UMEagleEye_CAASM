import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const sqlText = readFileSync(join(process.cwd(), 'drizzle/0035_action_based_access.sql'), 'utf8')

test('0035 is additive: adds tenant_user and a nullable actions column', () => {
  assert.match(sqlText, /ALTER TYPE "public"\."user_role" ADD VALUE IF NOT EXISTS 'tenant_user';/)
  const col = sqlText.split('\n').find((l) => /ADD COLUMN IF NOT EXISTS actions text\[\]/.test(l))
  assert.ok(col, 'actions column line')
  assert.doesNotMatch(col!, /NOT NULL|DEFAULT/)
})
test('0035 changes no rows and removes nothing', () => {
  const code = sqlText.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n')
  assert.doesNotMatch(code, /\bUPDATE\b|\bDELETE\b|DROP TYPE|DROP DEFAULT|ALTER COLUMN role|CREATE UNIQUE INDEX/i)
})
