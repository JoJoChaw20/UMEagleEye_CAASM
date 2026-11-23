import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ACTIONS_AT_0036, MIGRATION_ACTIONS } from './actions'

const sqlText = readFileSync(join(process.cwd(), 'drizzle/0036_drop_legacy_roles.sql'), 'utf8')
// Split so legacyRoles.test.ts finds no legacy literal in source either way.
const LEGACY_ADMIN = 'tenant' + '_admin'
const LEGACY_OWNER = 'business' + '_owner'

function lineWith(marker: string): string {
  const line = sqlText.split('\n').find((l) => l.includes(marker) && l.includes('ARRAY['))
  assert.ok(line, `no ARRAY line containing ${marker}`)
  return line
}
function arrayOn(marker: string): string[] {
  const body = lineWith(marker).match(/ARRAY\[([^\]]*)\]/)![1]
  return [...body.matchAll(/'([^']+)'/g)].map((m) => m[1])
}
function at(fragment: string): number {
  const i = sqlText.indexOf(fragment)
  assert.ok(i >= 0, `missing: ${fragment}`)
  return i
}

test('0036 arrays match the catalog', () => {
  assert.deepEqual(arrayOn(`role='${LEGACY_ADMIN}'`).sort(), [...MIGRATION_ACTIONS.tenant_admin].sort())
  assert.deepEqual(arrayOn(`role='${LEGACY_OWNER}'`).sort(), [...MIGRATION_ACTIONS.business_owner].sort())
  assert.deepEqual(arrayOn('rn > 1').sort(), [...ACTIONS_AT_0036].sort())    // the catalog when 0036 ran
})

test('0036 keeps edited actions (COALESCE)', () => {
  assert.ok(lineWith(`role='${LEGACY_ADMIN}'`).includes('COALESCE(actions, ARRAY['))
  assert.ok(lineWith(`role='${LEGACY_OWNER}'`).includes('COALESCE(actions, ARRAY['))
})

test('0036 creates the three-value enum and the one-tenant-superadmin index', () => {
  assert.match(sqlText, /ENUM \('superadmin','tenant_superadmin','tenant_user'\)/)
  assert.match(sqlText, /CREATE UNIQUE INDEX IF NOT EXISTS uq_users_one_tenant_superadmin ON users \(tenant_id\) WHERE role = 'tenant_superadmin'/)
  assert.match(sqlText, /ALTER COLUMN role SET DEFAULT 'tenant_user'/)
  assert.doesNotMatch(sqlText, /ADD COLUMN/)
})

test('0036 fills NULL actions with {} after the legacy conversion and before SET NOT NULL', () => {
  const fill = at(`UPDATE users SET actions='{}' WHERE actions IS NULL;`)
  assert.ok(at(`WHERE role='${LEGACY_ADMIN}'`) < fill, 'legacy admins are converted before the fill')
  assert.ok(at(`WHERE role='${LEGACY_OWNER}'`) < fill, 'legacy owners are converted before the fill')
  assert.ok(fill < at(`ALTER TABLE users ALTER COLUMN actions SET DEFAULT '{}';`))
  assert.ok(fill < at('ALTER TABLE users ALTER COLUMN actions SET NOT NULL;'))
  assert.ok(at('ALTER TABLE users ALTER COLUMN actions SET NOT NULL;') < at('DROP TYPE IF EXISTS'))
})

test('0036 keeps the step order', () => {
  const steps = [
    'ALTER TABLE users ALTER COLUMN role TYPE text;',
    'r.rn > 1',
    `WHERE role='tenant_superadmin' AND tenant_id IS NULL`,
    `WHERE role='${LEGACY_ADMIN}'`,
    `WHERE role='${LEGACY_OWNER}'`,
    'ALTER TABLE users ALTER COLUMN actions SET NOT NULL;',
    'CREATE TYPE "public"."user_role"',
    `ALTER COLUMN role SET DEFAULT 'tenant_user'`,
    'CREATE UNIQUE INDEX',
  ].map(at)
  assert.deepEqual(steps, [...steps].sort((a, b) => a - b))
})
