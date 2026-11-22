import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { PgDialect } from 'drizzle-orm/pg-core'
import { sql } from 'drizzle-orm'
import { eventAlertsSql, matchableSql } from '../services/threatIntel'

const sqlText = readFileSync(join(process.cwd(), 'drizzle/0043_shared_event_alerts.sql'), 'utf8')
const code = sqlText.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n')

test('0043 adds the tenant default (off) and the per-event choices, and changes no data', () => {
  assert.match(code, /ALTER TABLE "tenants" ADD COLUMN "shared_event_alerts" boolean DEFAULT false NOT NULL;/)
  assert.match(code, /CREATE TABLE IF NOT EXISTS "ti_event_alert_choices"/)
  assert.match(code, /PRIMARY KEY\("tenant_id","ti_event_id"\)/)
  assert.match(code, /REFERENCES "public"\."ti_events"\("ti_event_id"\) ON DELETE cascade/)
  assert.doesNotMatch(code, /^\s*(UPDATE|DELETE)\b/im)   // "ON UPDATE no action" of a foreign key is fine
  assert.doesNotMatch(code, /\b(TRUNCATE|DROP TABLE|DROP COLUMN)\b/i)
})

const render = (q: ReturnType<typeof sql>) => new PgDialect().sqlToQuery(q).sql

test('matching: a shared event needs the receiving tenant\'s opt-in; own and platform events do not', () => {
  const s = render(eventAlertsSql(sql.raw('a.tenant_id')))
  assert.match(s, /te\.tenant_id = a\.tenant_id OR te\.distribution = 'platform'/)
  assert.match(s, /te\.distribution = 'all_tenants' AND COALESCE\(/)
  assert.match(s, /FROM ti_event_alert_choices ch WHERE ch\.tenant_id = a\.tenant_id AND ch\.ti_event_id = te\.ti_event_id/)
  assert.match(s, /SELECT tn\.shared_event_alerts FROM tenants tn WHERE tn\.tenant_id = a\.tenant_id/)
  assert.match(s, /false\)\)\)$/)
  assert.ok(render(matchableSql(sql.raw('a.tenant_id'))).includes(s))
})
