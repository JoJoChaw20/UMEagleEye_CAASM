import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

// Routes that need a login but no permission: they act only on the caller's own account.
const SELF_SERVICE = new Set([
  'auth.ts:/mfa/status', 'auth.ts:/mfa/recovery-codes', 'auth.ts:/change-password', 'auth.ts:/set-password',
  'auth.ts:/me', 'auth.ts:/actions',
  // Ownership handover: the caller's own tenant and own pending transfer are checked in the handler.
  'ownership.ts:/:tenantId/ownership', 'ownership.ts:/:tenantId/ownership/transfer/accept',
  'ownership.ts:/:tenantId/ownership/transfer/decline',
])

const routesDir = join(process.cwd(), 'src/routes')
const files = readdirSync(routesDir).filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))

// One route registration: a single-quoted path starting with '/', its middleware, then a (c) => handler.
// The path must start with '/': otherwise c.get('user') in a handler body matches as a route
// and swallows the next real one.
const ROUTE_RE = /\.(get|post|put|patch|delete|all)\(\s*'(\/[^']*)'([\s\S]*?)(?:async )?\(c\) =>/g

// Every registration on the file's Hono app(s), whatever its shape: `app.get(`, `router.post(`, ...
function registrationRe(src: string): RegExp | null {
  const apps = [...src.matchAll(/const (\w+) = new Hono\b/g)].map((m) => m[1])
  return apps.length ? new RegExp(String.raw`\b(?:${apps.join('|')})\.(?:get|post|put|patch|delete|all)\(`, 'g') : null
}

test('every authenticated route checks a permission', () => {
  const offenders: string[] = []
  for (const file of files) {
    const src = readFileSync(join(routesDir, file), 'utf8')
    for (const m of src.matchAll(ROUTE_RE)) {
      const [, method, path, middle] = m
      if (!middle!.includes('authMiddleware')) continue
      if (/requireAction\(|requireTenantSuperadmin|requirePlatformSuperadmin/.test(middle!)) continue
      if (SELF_SERVICE.has(`${file}:${path}`)) continue
      offenders.push(`${file}:${path} (${method})`)
    }
  }
  assert.deepEqual(offenders, [])
})

// The check above reads only one shape of registration. A route with a named handler, a
// double-quoted path or no (c) => would be skipped, or merge into the next match and hide it, so
// every registration in a file must be one the pattern read, and no match may span two.
test('the permission check reads every route registration', () => {
  const problems: string[] = []
  for (const file of files) {
    const src = readFileSync(join(routesDir, file), 'utf8')
    const reg = registrationRe(src)
    if (!reg) continue
    const registrations = src.match(reg)?.length ?? 0
    let read = 0
    for (const m of src.matchAll(ROUTE_RE)) {
      read++
      const swallowed = m[0].slice(1).match(new RegExp(reg.source))
      if (swallowed) problems.push(`${file}:${m[2]} runs into the next registration`)
    }
    if (read !== registrations) problems.push(`${file}: ${registrations} registrations, ${read} read by the check`)
  }
  assert.deepEqual(problems, [])
})

test('no route still uses role lists', () => {
  const offenders = files.filter((f) => {
    const src = readFileSync(join(routesDir, f), 'utf8')
    return src.includes('requireRoles(') || src.includes('requireTenantAccess(')
  })
  assert.deepEqual(offenders, [])
})

// The sign-in steps before an access token exists: they authenticate with the password, Google, or
// the mfa_token in the body. authMiddleware would refuse them (an mfa_token is not an access token).
test('the MFA sign-in steps do not use authMiddleware', () => {
  const src = readFileSync(join(routesDir, 'auth.ts'), 'utf8')
  const publicPaths = ['/login', '/google', '/mfa/verify', '/mfa/enrol/start', '/mfa/enrol/finish',
    '/mfa/break-glass/request', '/mfa/break-glass/confirm', '/mfa/break-glass/cancel']
  const seen = new Map([...src.matchAll(ROUTE_RE)].map((m) => [m[2]!, m[3]!.includes('authMiddleware')]))
  for (const path of publicPaths) assert.equal(seen.get(path), false, path)
  for (const gone of ['/mfa/setup', '/mfa/enable', '/mfa/reset']) assert.equal(seen.has(gone), false, gone)
})
