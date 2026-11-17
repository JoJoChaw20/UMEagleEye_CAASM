import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ACTION_KEYS, MIGRATION_ACTIONS } from './actions'

const sqlText = readFileSync(join(process.cwd(), 'drizzle/0035_action_based_access.sql'), 'utf8')

function arrayOn(marker: string): string[] {
  const line = sqlText.split('\n').find((l) => l.includes(marker) && l.includes('ARRAY['))
  assert.ok(line, `no ARRAY line containing ${marker}`)
  const body = line.match(/ARRAY\[([^\]]*)\]/)![1]
  return [...body.matchAll(/'([^']+)'/g)].map((m) => m[1])
}

test('0035 arrays match the catalog', () => {
  assert.deepEqual(arrayOn("role='tenant_admin'").sort(), [...MIGRATION_ACTIONS.tenant_admin].sort())
  assert.deepEqual(arrayOn("role='business_owner'").sort(), [...MIGRATION_ACTIONS.business_owner].sort())
  assert.deepEqual(arrayOn('rn > 1').sort(), [...ACTION_KEYS].sort())
})
test('0035 creates the one-tenant-superadmin index and the three-value enum', () => {
  assert.match(sqlText, /CREATE UNIQUE INDEX IF NOT EXISTS uq_users_one_tenant_superadmin/)
  assert.match(sqlText, /ENUM \('superadmin','tenant_superadmin','tenant_user'\)/)
})
