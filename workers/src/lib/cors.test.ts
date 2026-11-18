import test from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { CORS_METHODS, corsOrigins } from './cors'

// The dashboard is on another origin, so the browser sends a route's method only if CORS allows it.
// PUT was missing (staging, 19 Nov): Edit access and Save recovery plan failed in the browser while
// every API test passed, because those call the API from Node, where CORS does not apply.
test('CORS allows every HTTP method the API routes use', () => {
  const dir = path.join(process.cwd(), 'src', 'routes')
  const used = new Set<string>()
  for (const f of readdirSync(dir).filter(f => f.endsWith('.ts') && !f.endsWith('.test.ts'))) {
    const src = readFileSync(path.join(dir, f), 'utf8')
    for (const m of src.matchAll(/\.(get|post|put|patch|delete)\(\s*['"`/]/g)) used.add(m[1]!.toUpperCase())
  }
  assert.ok(used.has('PUT'), 'the routes use PUT (tenant user actions, recovery plan)')
  for (const m of used) assert.ok((CORS_METHODS as readonly string[]).includes(m), `CORS allows ${m}`)
  assert.ok((CORS_METHODS as readonly string[]).includes('OPTIONS'))
})

test('CORS origins: the two dashboards and FRONTEND_URL; localhost only outside production', () => {
  assert.deepEqual(corsOrigins({ APP_ENV: 'production' }), ['https://umeagleeye.csnet.my', 'https://umeagleeye.pages.dev'])
  assert.ok(corsOrigins({ APP_ENV: 'staging', FRONTEND_URL: 'https://staging.umeagleeye.pages.dev' }).includes('https://staging.umeagleeye.pages.dev'))
  assert.ok(corsOrigins({ APP_ENV: 'staging' }).includes('http://localhost:5173'))
  assert.ok(!corsOrigins({ APP_ENV: 'production', FRONTEND_URL: '' }).some(o => o.includes('localhost')))
})
