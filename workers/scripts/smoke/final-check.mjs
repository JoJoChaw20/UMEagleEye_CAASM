// Staging MFA + delete-user smoke test (Task 9 Step 4). Temporary tenant MFATEST-smoke; removed at the end.
import { createRequire } from 'node:module'
import { neon } from '@neondatabase/serverless'
import { loadEnvFile } from '../db/lib.mjs'
import { randomBytes, pbkdf2Sync } from 'node:crypto'
const require = createRequire(import.meta.url)
const { authenticator } = require('otplib')

const sql = neon(loadEnvFile('staging').DATABASE_URL)
const V1 = 'https://umeagleeye-api-staging.syntaxch404.workers.dev/api/v1'
const hash = (p) => { const s = randomBytes(16); return s.toString('base64') + ':' + pbkdf2Sync(p, s, 100000, 32, 'sha256').toString('base64') }
const STEP = 30000
const code = (secret, ms = Date.now()) => authenticator.clone({ epoch: ms }).generate(secret)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
async function nextStep() { const ms = STEP - (Date.now() % STEP) + 1500; await sleep(ms) }
async function api(token, method, path, body) {
  const res = await fetch(V1 + path, { method, headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) })
  const t = await res.text(); let j = null; try { j = JSON.parse(t) } catch {}
  return { status: res.status, json: j }
}
const results = []
function check(name, ok, info = '') { results.push([ok ? 'PASS' : 'FAIL', name, info]); console.log(ok ? 'PASS' : 'FAIL', name, info) }

const lastStep = {}
async function fresh(secret) { if (lastStep[secret] === Math.floor(Date.now() / STEP)) await nextStep(); lastStep[secret] = Math.floor(Date.now() / STEP); return code(secret) }
const pws = {}; const pwf = (k) => (pws[k] ??= randomBytes(12).toString('base64url'))
const [{ tenant_id: TA }] = await sql("insert into tenants (name, slug) values ('FINALTEST-a','finaltest-a') returning tenant_id")
const [{ tenant_id: TB }] = await sql("insert into tenants (name, slug) values ('FINALTEST-b','finaltest-b') returning tenant_id")
try {
  const ids = {}, sec = {}
  const mk = async (k, tid, role) => { const u = 'finaltest_' + k; ids[k] = (await sql("insert into users (username,email,password_hash,role,tenant_id,actions) values ($1,$2,$3,$4,$5,$6) returning user_id", [u, u + '@example.invalid', hash(pwf(k)), role, tid, role === 'tenant_user' ? ['asset.view', 'scan.view'] : []]))[0].user_id }
  const un = (k) => 'finaltest_' + k
  await mk('o', TA, 'tenant_superadmin'); await mk('u', TA, 'tenant_user'); await mk('v', TA, 'tenant_user')
  await mk('p', TB, 'tenant_superadmin'); await mk('w', TB, 'tenant_user')
  const login = (k) => api(null, 'POST', '/auth/login', { username: un(k), password: pwf(k) })
  const enrol = async (k) => { let r = await login(k); if (r.json?.stage !== 'enrol') return null; const mt = r.json.mfa_token
    sec[k] = (await api(null, 'POST', '/auth/mfa/enrol/start', { mfa_token: mt })).json?.totp_secret
    r = await api(null, 'POST', '/auth/mfa/enrol/finish', { mfa_token: mt, code: await fresh(sec[k]) }); return r.json?.access_token }
  const signin = async (k) => { const r = await login(k); if (r.json?.stage !== 'verify') return { stage: r.json?.stage, status: r.status }
    const v = await api(null, 'POST', '/auth/mfa/verify', { mfa_token: r.json.mfa_token, code: await fresh(sec[k]) }); return { stage: 'verify', status: v.status, token: v.json?.access_token } }
  const tok = {}
  for (const k of ['u', 'o', 'v', 'p', 'w']) { tok[k] = await enrol(k) }
  const uEnrolAt = Date.now()
  check('setup: all 5 users enrolled', Object.values(tok).every(Boolean))
  const O = tok.o, base = (t) => `/tenants/${t}/users`
  // B4
  let r = await api(O, 'PATCH', `${base(TA)}/${ids.v}/deactivate`, { is_active: false })
  check('B4 deactivate V -> 200', r.status === 200, r.status + ' ' + (r.json?.detail ?? ''))
  r = await api(tok.v, 'GET', '/assets'); check('B4 V old token -> 401', r.status === 401, String(r.status))
  r = await login('v'); check('B4 V login refused', r.status === 401 || r.status === 403, String(r.status))
  // B5
  r = await api(O, 'PATCH', `${base(TA)}/${ids.v}/deactivate`, { is_active: true })
  check('B5 reactivate V -> 200', r.status === 200, r.status + ' ' + (r.json?.detail ?? ''))
  let s = await signin('v'); check('B5 V login stage verify + code -> 200', s.stage === 'verify' && s.status === 200 && !!s.token, JSON.stringify({ stage: s.stage, status: s.status }))
  tok.v = s.token
  // B6
  r = await api(O, 'PATCH', `${base(TA)}/${ids.o}/deactivate`, { is_active: false }); check('B6 O self-deactivate -> 403', r.status === 403, r.status + ' ' + (r.json?.detail ?? ''))
  r = await api(O, 'PATCH', `${base(TB)}/${ids.w}/deactivate`, { is_active: false }); check('B6 O deactivate tenant-B user (tenant B path) -> 404/403', [403, 404].includes(r.status), String(r.status))
  r = await api(O, 'PATCH', `${base(TA)}/${ids.w}/deactivate`, { is_active: false }); check('B6 O deactivate tenant-B user (own tenant path) -> 404/403', [403, 404].includes(r.status), String(r.status))
  r = await api(O, 'DELETE', `${base(TB)}/${ids.w}`, { password: pwf('o'), code: await fresh(sec.o), confirm_username: un('w') }); check('B6 O delete tenant-B user (B path) -> 404/403', [403, 404].includes(r.status), String(r.status))
  r = await api(O, 'DELETE', `${base(TA)}/${ids.w}`, { password: pwf('o'), code: await fresh(sec.o), confirm_username: un('w') }); check('B6 O delete tenant-B user (own path) -> 404/403', [403, 404].includes(r.status), String(r.status))
  r = await api(O, 'POST', `${base(TB)}/${ids.w}/mfa-reset`, { password: pwf('o'), code: await fresh(sec.o) }); check('B6 O reset MFA tenant-B user (B path) -> 404/403', [403, 404].includes(r.status), String(r.status))
  r = await api(O, 'POST', `${base(TA)}/${ids.w}/mfa-reset`, { password: pwf('o'), code: await fresh(sec.o) }); check('B6 O reset MFA tenant-B user (own path) -> 404', r.status === 404, String(r.status))
  check('B6 W unaffected (still active, MFA on)', (await api(tok.w, 'GET', '/assets')).status === 200)
  // C
  r = await api(O, 'GET', base(TB)); check('C O GET /tenants/B/users -> 403/404', [403, 404].includes(r.status), String(r.status))
  // wait for 6+ min since U enrol
  const wait = uEnrolAt + 6.2 * 60000 - Date.now(); console.log('waiting ms', Math.max(0, wait)); if (wait > 0) await new Promise((x) => setTimeout(x, wait))
  // A1
  s = await signin('u'); check('A1 U sign-in after >6min, same secret, stage verify -> 200 + token', s.stage === 'verify' && s.status === 200 && !!s.token, JSON.stringify({ stage: s.stage, status: s.status }))
  let TU = s.token
  // A2
  for (const n of [1, 2]) { s = await signin('u'); check('A2 U sign-in #' + n + ' -> 200 (verify stage)', s.stage === 'verify' && s.status === 200 && !!s.token, JSON.stringify({ stage: s.stage, status: s.status })); TU = s.token || TU }
  // A3
  r = await api(TU, 'GET', '/auth/mfa/status'); check('A3 mfa status enabled', r.status === 200 && r.json?.mfa_enabled === true, JSON.stringify(r.json))
  // B7
  r = await api(TU, 'PATCH', `${base(TA)}/${ids.v}/deactivate`, { is_active: false }); check('B7 tenant_user deactivate -> 403', r.status === 403, String(r.status))
  r = await api(TU, 'DELETE', `${base(TA)}/${ids.v}`, { password: pwf('u'), code: await fresh(sec.u), confirm_username: un('v') }); check('B7 tenant_user delete -> 403', r.status === 403, String(r.status))
  r = await api(TU, 'POST', `${base(TA)}/${ids.v}/mfa-reset`, { password: pwf('u'), code: await fresh(sec.u) }); check('B7 tenant_user reset MFA -> 403', r.status === 403, String(r.status))
  check('B7 V still intact', (await api(tok.v, 'GET', '/assets')).status === 200)
  // B8
  r = await api(O, 'DELETE', `${base(TA)}/${ids.v}`, { password: pwf('o'), code: await fresh(sec.o), confirm_username: un('v') }); check('B8 delete V with step-up -> 200', r.status === 200, r.status + ' ' + (r.json?.detail ?? ''))
  check('B8 V token -> 401', (await api(tok.v, 'GET', '/assets')).status === 401)
  const kept = await sql("select count(*)::int n from audit_logs where user_id is null and actor_username = $1", [un('v')])
  check('B8 V audit rows kept (user_id NULL, actor_username)', kept[0].n > 0, 'rows=' + kept[0].n)
} catch (e) { check('SCRIPT ERROR', false, String(e?.stack ?? e)) } finally {
  await sql('delete from audit_logs where tenant_id = any($1)', [[TA, TB]])
  await sql("delete from audit_logs where actor_username like 'finaltest_%' or user_id in (select user_id from users where username like 'finaltest_%')")
  await sql("delete from users where username like 'finaltest_%'")
  await sql('delete from tenants where tenant_id = any($1)', [[TA, TB]])
  const left = await sql("select (select count(*) from users where username like 'finaltest_%') + (select count(*) from tenants where name like 'FINALTEST-%') + (select count(*) from audit_logs where actor_username like 'finaltest_%') n")
  console.log('cleanup left:', left[0].n)
  console.log(`SUMMARY: ${results.filter((x) => x[0] === 'PASS').length} pass, ${results.filter((x) => x[0] === 'FAIL').length} fail`)
}
