import { test } from 'node:test'
import assert from 'node:assert/strict'
import { sql } from 'drizzle-orm'
import { getDb } from '../db/client'
import { closeNoticesStatement } from './ownership'

const db = getDb('postgres://u:p@localhost/none')   // builds queries only; nothing connects
const T = '11111111-1111-1111-1111-111111111111'

test('closeNoticesStatement ends only open notices of the given kinds, under the guard', () => {
  const q = (closeNoticesStatement(db, T, ['recovery_request', 'recovery_hold'], sql`exists (select 1 from marker)`) as any).toSQL()
  assert.match(q.sql, /^update "tenant_notices" set "expires_at" = now\(\) where/)
  assert.match(q.sql, /"kind" in \(\$\d+, \$\d+\)/)
  assert.match(q.sql, /"expires_at" is null or "tenant_notices"."expires_at" > now\(\)/)
  assert.match(q.sql, /exists \(select 1 from marker\)/)
  assert.deepEqual(q.params, [T, 'recovery_request', 'recovery_hold'])
})
