import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

// Routes that need a login but no permission: they act only on the caller's own account.
const SELF_SERVICE = new Set([
  'auth.ts:/mfa/setup', 'auth.ts:/mfa/enable', 'auth.ts:/change-password', 'auth.ts:/set-password',
  'auth.ts:/me', 'auth.ts:/actions', 'auth.ts:/mfa/reset',
])

const routesDir = join(process.cwd(), 'src/routes')
const files = readdirSync(routesDir).filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))

test('every authenticated route checks a permission', () => {
  const offenders: string[] = []
  for (const file of files) {
    const src = readFileSync(join(routesDir, file), 'utf8')
    // The path must start with '/': otherwise c.get('user') in a handler body matches as a route
    // and swallows the next real one.
    const re = /\.(get|post|put|patch|delete|all)\(\s*'(\/[^']*)'([\s\S]*?)(?:async )?\(c\) =>/g
    for (const m of src.matchAll(re)) {
      const [, method, path, middle] = m
      if (!middle!.includes('authMiddleware')) continue
      if (/requireAction\(|requireTenantSuperadmin|requirePlatformSuperadmin/.test(middle!)) continue
      if (SELF_SERVICE.has(`${file}:${path}`)) continue
      offenders.push(`${file}:${path} (${method})`)
    }
  }
  assert.deepEqual(offenders, [])
})

test('no route still uses role lists', () => {
  const offenders = files.filter((f) => {
    const src = readFileSync(join(routesDir, f), 'utf8')
    return src.includes('requireRoles(') || src.includes('requireTenantAccess(')
  })
  assert.deepEqual(offenders, [])
})
