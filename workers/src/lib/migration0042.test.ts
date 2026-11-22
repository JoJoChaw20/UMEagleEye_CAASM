import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const sqlText = readFileSync(join(process.cwd(), 'drizzle/0042_alert_ranking_sla.sql'), 'utf8')
const code = sqlText.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n')

test('0042 adds the ranking and fix-time columns', () => {
  assert.match(code, /ALTER TABLE "events" ADD COLUMN "reopened_at" timestamp with time zone;/)
  assert.match(code, /ALTER TABLE "events" ADD COLUMN "reopen_count" integer DEFAULT 0 NOT NULL;/)
  assert.match(code, /ALTER TABLE "tenants" ADD COLUMN "sla_policy" jsonb DEFAULT '\{\}'::jsonb NOT NULL;/)
  assert.match(code, /ALTER TABLE "cve_findings" ADD COLUMN "epss_checked_at"/)
})

test('0042 makes EPSS nullable and turns the never-looked-up zeros into NULL, nothing else', () => {
  assert.match(code, /ALTER COLUMN "epss" DROP NOT NULL/)
  const updates = code.match(/^UPDATE\b[^;]*;/gm) ?? []
  assert.deepEqual(updates, ['UPDATE "cve_findings" SET "epss" = NULL WHERE "epss" = 0;'])
  assert.doesNotMatch(code, /\b(DELETE|TRUNCATE|DROP TABLE|DROP COLUMN)\b/i)
})

test('0042 reopen trigger: only a closed alert becoming open again moves the clock', () => {
  assert.match(code, /CREATE TRIGGER events_reopen BEFORE UPDATE OF status ON events/)
  assert.match(code, /OLD\.status IN \('resolved', 'false_positive', 'accepted_risk'\) AND NEW\.status IN \('open', 'in_progress'\)/)
  assert.match(code, /NEW\.reopen_count := OLD\.reopen_count \+ 1/)
})
