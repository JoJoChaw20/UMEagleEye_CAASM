// Calls every GET route on staging as a test Tenant Superadmin and a test Tenant user (Viewer preset)
// in a temporary tenant. Reports any 5xx. Cleans up the tenant and users at the end.
// Run from the workers folder: node scripts/smoke/api-sweep-mfa.mjs
import { neon } from '@neondatabase/serverless'
import { loadEnvFile } from '../db/lib.mjs'
import { randomBytes, pbkdf2Sync, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
const require = createRequire(import.meta.url)
const { authenticator } = require('otplib')

const sql = neon(loadEnvFile('staging').DATABASE_URL)
const V1 = 'https://umeagleeye-api-staging.syntaxch404.workers.dev/api/v1'
const SRC = fileURLToPath(new URL('../../src', import.meta.url))
const hash = (p) => { const s = randomBytes(16); return s.toString('base64') + ':' + pbkdf2Sync(p, s, 100000, 32, 'sha256').toString('base64') }

const mounts = {}
for (const m of readFileSync(`${SRC}/index.ts`, 'utf8').matchAll(/import (\w+) from '\.\/routes\/(\w+)'/g)) mounts[m[1]] = m[2]
const routes = []
for (const m of readFileSync(`${SRC}/index.ts`, 'utf8').matchAll(/api\.route\('([^']+)',\s*(\w+)\)/g)) {
  const file = readFileSync(`${SRC}/routes/${mounts[m[2]]}.ts`, 'utf8')
  for (const g of file.matchAll(/\b(?:app|router)\.get\(\s*'([^']*)'/g)) routes.push(m[1] + (g[1] === '/' ? '' : g[1]))
}

const api = async (t, r) => {
  try { const res = await fetch(V1 + r, { headers: t ? { Authorization: 'Bearer ' + t } : {} }); await res.arrayBuffer(); return res.status }
  catch (e) { return 'ERR ' + e.message }
}

const [{ tenant_id: T }] = await sql("insert into tenants (name, slug) values ('RBACTEST-sweep','rbactest-sweep') returning tenant_id")
const pw = { o: randomBytes(18).toString('base64url'), u: randomBytes(18).toString('base64url') }
try {
  await sql("insert into users (username,email,password_hash,role,tenant_id) values ('rbactest_s_owner','rbactest_s_owner@example.invalid',$1,'tenant_superadmin',$2)", [hash(pw.o), T])
  const viewer = ['dashboard.view','asset.view','scan.view','sbom.view','alert.view','advisory.view','cti.view','ti_event.view','network.view','relationship.view','report.view','agent.view','settings.view','chatbot.use','report.download']
  await sql("insert into users (username,email,password_hash,role,tenant_id,actions) values ('rbactest_s_user','rbactest_s_user@example.invalid',$1,'tenant_user',$2,$3)", [hash(pw.u), T, viewer])
  const post = async (p, b) => (await fetch(V1 + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })).json()
  const login = async (u, p) => {
    const l = await post('/auth/login', { username: u, password: p })
    if (l.access_token) return l.access_token
    if (l.stage !== 'enrol') throw new Error('unexpected login stage ' + l.stage)
    const s = await post('/auth/mfa/enrol/start', { mfa_token: l.mfa_token })
    const f = await post('/auth/mfa/enrol/finish', { mfa_token: l.mfa_token, code: authenticator.generate(s.totp_secret) })
    if (!f.access_token) throw new Error('enrol finish failed')
    return f.access_token
  }
  const tok = { owner: await login('rbactest_s_owner', pw.o), viewer: await login('rbactest_s_user', pw.u) }
  const tally = {}; const bad = []
  for (const r0 of routes) {
    if (r0.includes('*')) continue
    const r = r0.replace(':tenantId', T).replace(/:[A-Za-z_]+/g, randomUUID())
    for (const [who, t] of Object.entries(tok)) {
      const st = await api(t, r)
      tally[st] = (tally[st] ?? 0) + 1
      if (typeof st !== 'number' || st >= 500) bad.push(`${who} GET ${r0} -> ${st}`)
    }
  }
  console.log(`routes: ${routes.length}, calls: ${Object.values(tally).reduce((a, b) => a + b, 0)}, status tally: ${JSON.stringify(tally)}`)
  console.log(bad.length ? 'FAILURES:\n' + bad.join('\n') : 'no 5xx')
} finally {
  await sql('delete from audit_logs where tenant_id=$1', [T])
  await sql("delete from audit_logs where user_id in (select user_id from users where username like 'rbactest_s_%')")
  await sql("delete from users where tenant_id=$1 and username like 'rbactest_s_%'", [T])
  await sql('delete from tenants where tenant_id=$1', [T])
  console.log('cleanup left:', (await sql("select (select count(*) from users where username like 'rbactest_%') + (select count(*) from tenants where name like 'RBACTEST-%') n"))[0].n)
}
