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

const pw = { o: randomBytes(12).toString('base64url'), a: randomBytes(12).toString('base64url'), b: randomBytes(12).toString('base64url') }
const [{ tenant_id: T }] = await sql("insert into tenants (name, slug) values ('MFATEST-smoke','mfatest-smoke') returning tenant_id")
try {
  const ins = async (u, p, role) => (await sql("insert into users (username,email,password_hash,role,tenant_id,actions) values ($1,$2,$3,$4,$5,$6) returning user_id", [u, u + '@example.invalid', hash(p), role, T, role === 'tenant_user' ? ['asset.view', 'scan.view'] : []]))[0].user_id
  const O = await ins('mfatest_owner', pw.o, 'tenant_superadmin'), A = await ins('mfatest_a', pw.a, 'tenant_user'), B = await ins('mfatest_b', pw.b, 'tenant_user')
  const login = (u, p) => api(null, 'POST', '/auth/login', { username: u, password: p })

  // 1. owner enrols
  let r = await login('mfatest_owner', pw.o)
  check('password sign-in returns stage enrol, no access token', r.status === 200 && r.json?.stage === 'enrol' && !r.json?.access_token, JSON.stringify({ s: r.status, stage: r.json?.stage }))
  let mt = r.json.mfa_token
  r = await api(null, 'POST', '/auth/mfa/enrol/start', { mfa_token: mt }); const So = r.json?.totp_secret
  r = await api(null, 'POST', '/auth/mfa/enrol/finish', { mfa_token: mt, code: code(So) })
  check('enrol finish returns token + 10 recovery codes', r.status === 200 && !!r.json?.access_token && r.json?.recovery_codes?.length === 10, String(r.status))
  let To = r.json.access_token
  check('mfa_token as Bearer is refused', (await api(mt, 'GET', '/assets')).status === 401)
  r = await api(To, 'GET', '/auth/mfa/status'); check('status: enabled, 10 codes', r.json?.mfa_enabled === true && r.json?.recovery_codes_left === 10, JSON.stringify(r.json))
  check('owner token reaches data', (await api(To, 'GET', '/assets')).status === 200)

  // 2. user A: permanence of the pending secret across sign-ins
  r = await login('mfatest_a', pw.a); let mtA = r.json.mfa_token
  const s1 = (await api(null, 'POST', '/auth/mfa/enrol/start', { mfa_token: mtA })).json?.totp_secret
  r = await login('mfatest_a', pw.a); mtA = r.json.mfa_token
  const s2 = (await api(null, 'POST', '/auth/mfa/enrol/start', { mfa_token: mtA })).json?.totp_secret
  check('sign in again -> same QR secret', !!s1 && s1 === s2)
  const finishMs = Date.now(); const finishCode = code(s1, finishMs)
  r = await api(null, 'POST', '/auth/mfa/enrol/finish', { mfa_token: mtA, code: finishCode }); let TA = r.json?.access_token
  const codesA = r.json?.recovery_codes ?? []
  check('user A enrolled', r.status === 200 && !!TA)
  // 3. replay
  r = await login('mfatest_a', pw.a)
  const rep = await api(null, 'POST', '/auth/mfa/verify', { mfa_token: r.json.mfa_token, code: finishCode })
  check('reused code is refused 401', rep.status === 401, rep.json?.detail)
  // 4. previous-step code accepted (wait two steps after finish)
  await nextStep(); await nextStep()
  r = await login('mfatest_a', pw.a)
  const prev = await api(null, 'POST', '/auth/mfa/verify', { mfa_token: r.json.mfa_token, code: code(s1, Date.now() - STEP) })
  check('code from the previous 30 s accepted', prev.status === 200 && !!prev.json?.access_token, String(prev.status) + ' ' + (prev.json?.detail ?? ''))
  // 5. recovery code once
  r = await login('mfatest_a', pw.a)
  let rc = await api(null, 'POST', '/auth/mfa/verify', { mfa_token: r.json.mfa_token, recovery_code: codesA[0].toLowerCase() })
  check('recovery code works (case-insensitive), 9 left', rc.status === 200 && rc.json?.recovery_codes_left === 9, JSON.stringify({ s: rc.status, left: rc.json?.recovery_codes_left }))
  r = await login('mfatest_a', pw.a)
  rc = await api(null, 'POST', '/auth/mfa/verify', { mfa_token: r.json.mfa_token, recovery_code: codesA[0] })
  check('same recovery code refused second time', rc.status === 401, rc.json?.detail)
  // 6. step-up: wrong password keeps session; right one gives new codes
  await nextStep()
  r = await api(TA, 'POST', '/auth/mfa/recovery-codes', { password: 'wrong-' + pw.a, code: code(s1) })
  check('wrong step-up password -> 401', r.status === 401, r.json?.detail)
  check('session still works after wrong step-up', (await api(TA, 'GET', '/auth/mfa/status')).status === 200)
  await nextStep()
  r = await api(TA, 'POST', '/auth/mfa/recovery-codes', { password: pw.a, code: code(s1) })
  check('new recovery codes issued', r.status === 200 && r.json?.recovery_codes?.length === 10, String(r.status) + ' ' + (r.json?.detail ?? ''))
  // 7. owner resets A
  await nextStep()
  r = await api(To, 'POST', `/tenants/${T}/users/${A}/mfa-reset`, { password: pw.o, code: code(So) })
  check('owner resets user A MFA', r.status === 200 && r.json?.ok === true, String(r.status) + ' ' + (r.json?.detail ?? ''))
  check('user A old token -> 401 after reset', (await api(TA, 'GET', '/assets')).status === 401)
  r = await login('mfatest_a', pw.a); check('user A next sign-in -> enrol', r.json?.stage === 'enrol')
  // 8. delete B
  r = await login('mfatest_b', pw.b); const mtB = r.json.mfa_token
  const sB = (await api(null, 'POST', '/auth/mfa/enrol/start', { mfa_token: mtB })).json?.totp_secret
  r = await api(null, 'POST', '/auth/mfa/enrol/finish', { mfa_token: mtB, code: code(sB) }); const TB = r.json?.access_token
  check('user B enrolled (creates audit rows)', !!TB)
  r = await api(To, 'DELETE', `/tenants/${T}/users/${B}`, { password: pw.o, code: '000000', confirm_username: 'MFATEST_B' })
  check('delete: wrong-case username -> 400', r.status === 400, r.json?.detail)
  await nextStep()
  r = await api(To, 'DELETE', `/tenants/${T}/users/${B}`, { password: pw.o, code: code(So), confirm_username: 'mfatest_b' })
  check('delete: correct -> 200', r.status === 200, String(r.status) + ' ' + (r.json?.detail ?? ''))
  check('deleted user old token -> 401', (await api(TB, 'GET', '/assets')).status === 401)
  const kept = await sql("select count(*)::int n from audit_logs where user_id is null and actor_username = 'mfatest_b'")
  check('deleted user audit rows kept with actor_username', kept[0].n > 0, 'rows=' + kept[0].n)
  // 9. break-glass without email
  r = await api(null, 'POST', '/auth/mfa/break-glass/request', { email: 'x@example.invalid', password: 'x', reset_secret: 'x' })
  check('break-glass -> 503 without email', r.status === 503, r.json?.detail)
} finally {
  await sql('delete from audit_logs where tenant_id=$1', [T])
  await sql("delete from audit_logs where actor_username like 'mfatest_%' or user_id in (select user_id from users where username like 'mfatest_%')")
  await sql("delete from users where tenant_id=$1 and username like 'mfatest_%'", [T])
  await sql('delete from tenants where tenant_id=$1', [T])
  const left = await sql("select (select count(*) from users where username like 'mfatest_%') + (select count(*) from tenants where name like 'MFATEST-%') + (select count(*) from audit_logs where actor_username like 'mfatest_%') n")
  console.log('cleanup left:', left[0].n)
  console.log(`SUMMARY: ${results.filter((x) => x[0] === 'PASS').length} pass, ${results.filter((x) => x[0] === 'FAIL').length} fail`)
}
