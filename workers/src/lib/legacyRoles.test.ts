import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'

// Legacy roles (tenant_admin, business_owner) are read only by normalizeAccount (lib/actions.ts) and
// declared only by the enum (db/schema.ts). Anywhere else a literal would compare, filter or return a
// role value that disappears in migration 0036.
const ALLOWED = new Set(['lib/actions.ts', 'db/schema.ts'])
const LEGACY_LITERAL = /['"`](tenant_admin|business_owner)['"`]/

const srcDir = join(process.cwd(), 'src')
const sources = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? sources(join(dir, e.name))
    : e.name.endsWith('.ts') && !e.name.endsWith('.test.ts') ? [join(dir, e.name)] : [])

test('no legacy role literal outside actions.ts and schema.ts', () => {
  const offenders = sources(srcDir)
    .map((f) => relative(srcDir, f).replace(/\\/g, '/'))
    .filter((rel) => !ALLOWED.has(rel) && LEGACY_LITERAL.test(readFileSync(join(srcDir, rel), 'utf8')))
  assert.deepEqual(offenders, [])
})
