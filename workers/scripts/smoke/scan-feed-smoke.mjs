// Staging smoke test: staging-only feed refresh (POST /cti/ingest) and the passive-scan agent choice.
// Temporary accounts tmpsf_*; removed at the end. Queues no scan on a real agent (preview and refusals only).
//   node scripts/smoke/scan-feed-smoke.mjs
import { createRequire } from 'node:module'
import { neon } from '@neondatabase/serverless'
import { loadEnvFile } from '../db/lib.mjs'
import { randomBytes, pbkdf2Sync } from 'node:crypto'
const require = createRequire(import.meta.url)
const { authenticator } = require('otplib')

const sql = neon(loadEnvFile('staging').DATABASE_URL)
const V1 = 'https://umeagleeye-api-staging.syntaxch404.workers.dev/api/v1'
const hash = (p) => { const s = randomBytes(16); return s.toString('base64') + ':' + pbkdf2Sync(p, s, 100000, 32, 'sha256').toString('base64') }
async function api(token, method, path, body) {
  const res = await fetch(V1 + path, { method, headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) })
  const t = await res.text(); let j = null; try { j = JSON.parse(t) } catch {}
  return { status: res.status, json: j }
}
const results = []
function check(name, ok, info = '') { results.push([ok ? 'PASS' : 'FAIL', name, info]); console.log(ok ? 'PASS' : 'FAIL', name, info) }
const pw = 'Tmp-' + randomBytes(9).toString('base64url') + '9!a'
const secret = authenticator.generateSecret()
const scanCountBefore = async (T) => (await sql("select count(*)::int n from scan_results where tenant_id=$1 and scan_type='passive'", [T]))[0].n

const [{ tenant_id: JO }] = await sql("select tenant_id from tenants where name = 'jo network'")
try {
  await sql("insert into users (username,email,password_hash,role,actions) values ('tmpsf_platform','tmpsf_platform@example.invalid',$1,'superadmin','{}')", [hash(pw)])
  await sql("insert into users (username,email,password_hash,role,tenant_id,actions,mfa_enabled,totp_secret) values ('tmpsf_user','tmpsf_user@example.invalid',$1,'tenant_user',$2,$3,true,$4)",
    [hash(pw), JO, ['scan.view', 'scan.passive.run', 'scan.route.view'], secret])

  // 1. Feeds: staging shows no schedule and lets the Platform Superadmin load them
  const TP = (await api(null, 'POST', '/auth/login', { username: 'tmpsf_platform', password: pw })).json?.access_token
  let r = await api(TP, 'GET', '/cti/stats')
  check('staging stats: no schedule, superadmin may load', r.json?.next_ingest_at === null && r.json?.can_ingest === true, JSON.stringify({ next: r.json?.next_ingest_at, can: r.json?.can_ingest }))
  r = await api(TP, 'POST', '/cti/ingest')
  check('superadmin queues a feed update', r.status === 200 && typeof r.json?.queued === 'boolean', JSON.stringify(r.json))

  // 2. Passive scan, Automatic: finds the listening agent or says why; never a record with no agent
  const mt = (await api(null, 'POST', '/auth/login', { username: 'tmpsf_user', password: pw })).json?.mfa_token
  const TU = (await api(null, 'POST', '/auth/mfa/verify', { mfa_token: mt, code: authenticator.generate(secret) })).json?.access_token
  check('tenant user signed in', !!TU)
  check('tenant user may not load feeds', (await api(TU, 'POST', '/cti/ingest')).status === 403)
  r = await api(TU, 'GET', '/scans/route?subnet=192.168.100.0/24&scan_type=passive')
  check('passive preview answers for the jo network', r.status === 200 && typeof r.json?.reason === 'string', `${r.json?.agent_id ? 'agent ' + r.json.name : 'none'}: ${r.json?.reason}`)
  r = await api(TU, 'GET', '/scans/route?subnet=10.99.0.0/24&scan_type=passive')
  check('passive preview off every network: no agent, no router offer', r.json?.agent_id === null && r.json?.routed === undefined, r.json?.reason)
  const before = await scanCountBefore(JO)
  r = await api(TU, 'POST', '/scans/active', { scan_type: 'passive', agent_id: 'auto', subnet: '10.99.0.0/24' })
  check('passive Automatic with no listening agent there -> 409', r.status === 409, r.json?.detail)
  r = await api(TU, 'POST', '/scans/active', { scan_type: 'passive', agent_id: 'auto' })
  check('passive Automatic without a network -> 400', r.status === 400, r.json?.detail)
  check('no passive record was created', (await scanCountBefore(JO)) === before)
} finally {
  await sql("delete from audit_logs where user_id in (select user_id from users where username like 'tmpsf_%') or actor_username like 'tmpsf_%'")
  await sql("delete from users where username like 'tmpsf_%'")
  console.log('cleanup left:', (await sql("select count(*)::int n from users where username like 'tmpsf_%'"))[0].n)
  console.log(`SUMMARY: ${results.filter((x) => x[0] === 'PASS').length} pass, ${results.filter((x) => x[0] === 'FAIL').length} fail`)
}
