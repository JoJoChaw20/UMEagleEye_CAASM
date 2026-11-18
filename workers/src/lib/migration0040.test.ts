import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { PgDialect } from 'drizzle-orm/pg-core'
import { insertAdvisoryIfNoneSql } from './advisoryScope'

const sqlText = readFileSync(join(process.cwd(), 'drizzle/0040_advisory_content.sql'), 'utf8')
const code = sqlText.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n')

test('0040 adds advisories.content as nullable jsonb', () => {
  const m = code.match(/ALTER TABLE "advisories" ADD COLUMN "content" jsonb[^;]*;/)
  assert.ok(m)
  assert.doesNotMatch(m[0], /NOT NULL/)
})

test('0040 is additive only', () => {
  assert.doesNotMatch(code, /\b(DROP|TRUNCATE|UPDATE|DELETE)\b/i)
})

test('insertAdvisoryIfNoneSql passes content as jsonb params', () => {
  const content = { kind: 'expert', steps: ['a'] }
  const q = new PgDialect().sqlToQuery(insertAdvisoryIfNoneSql('e1', 's', 'r', content))
  assert.match(q.sql, /::jsonb/)
  assert.ok(q.params.includes(JSON.stringify(content)))
})

test('insertAdvisoryIfNoneSql with null content passes null', () => {
  const q = new PgDialect().sqlToQuery(insertAdvisoryIfNoneSql('e1', 's', 'r', null))
  assert.ok(q.params.includes(null))
  assert.ok(!q.params.some((p) => p === 'null'))
})
