import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'

// The legacy roles (tenant_admin, business_owner) left the enum in migration 0036. A literal anywhere
// in src would compare, filter or return a role value that no longer exists.
const LEGACY_LITERAL = /['"`](tenant_admin|business_owner)['"`]/

const srcDir = join(process.cwd(), 'src')
const sources = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? sources(join(dir, e.name))
    : e.name.endsWith('.ts') && !e.name.endsWith('.test.ts') ? [join(dir, e.name)] : [])

test('no legacy role literal in src', () => {
  const offenders = sources(srcDir)
    .map((f) => relative(srcDir, f).replace(/\\/g, '/'))
    .filter((rel) => LEGACY_LITERAL.test(readFileSync(join(srcDir, rel), 'utf8')))
  assert.deepEqual(offenders, [])
})
