// Staging smoke test: accounts without an email (username + starting password), the forced password change,
// and the Google connect route's guards. Temporary tenant ACCTTEST-smoke and accttest_* accounts; removed at the end.
//   node scripts/smoke/account-smoke.mjs
import { createRequire } from 'node:module'
import { neon } from '@neondatabase/serverless'
import { loadEnvFile } from '../db/lib.mjs'
import { randomBytes, pbkdf2Sync } from 'node:crypto'
const require = createRequire(import.meta.url)
const { authenticator } = require('otplib')

const sql = neon(loadEnvFile('staging').DATABASE_URL)
const V1 = 'https://umeagleeye-api-staging.syntaxch404.workers.dev/api/v1'
const hash = (p) => { const s = randomBytes(16); return s.toString('base64') + ':' + pbkdf2Sync(p, s, 100000, 32, 'sha256').toString('base64') }
const code = (secret) => authenticator.generate(secret)
async function api(token, method, path, body) {
  const res = await fetch(V1 + path, { method, headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) })
  const t = await res.text(); let j = null; try { j = JSON.parse(t) } catch {}
  return { status: res.status, json: j }
}
const results = []
function check(name, ok, info = '') { results.push([ok ? 'PASS' : 'FAIL', name, info]); console.log(ok ? 'PASS' : 'FAIL', name, info) }
const strong = () => 'Acct-' + randomBytes(9).toString('base64url') + '9!a'
const login = (u, p) => api(null, 'POST', '/auth/login', { username: u, password: p })
/** Password sign-in through MFA set-up: the access token. */
async function enrol(u, p) {
  const r = await login(u, p)
  const mt = r.json?.mfa_token
  const s = (await api(null, 'POST', '/auth/mfa/enrol/start', { mfa_token: mt })).json?.totp_secret
  return (await api(null, 'POST', '/auth/mfa/enrol/finish', { mfa_token: mt, code: code(s) })).json?.access_token
}

const pwPlatform = strong(), pwOwner = strong(), pwOwnerNew = strong(), pwUser = strong()
const [{ tenant_id: T }] = await sql("insert into tenants (name, slug) values ('ACCTTEST-smoke','accttest-smoke') returning tenant_id")
try {
  await sql("insert into users (username,email,password_hash,role,actions) values ('accttest_platform','accttest_platform@example.invalid',$1,'superadmin','{}')", [hash(pwPlatform)])

  // 1. A Platform Superadmin (MFA-exempt by role on staging) creates the first Tenant Superadmin with no email
  let r = await login('accttest_platform', pwPlatform)
  const TP = r.json?.access_token
  check('platform superadmin signs in without MFA', !!TP, String(r.status))
  r = await api(TP, 'POST', `/tenants/${T}/users/invite`, { email: 'x@example.invalid', username: 'accttest_owner', password: pwOwner, as_tenant_superadmin: true })
  check('email and password together -> 400', r.status === 400, r.json?.detail)
  r = await api(TP, 'POST', `/tenants/${T}/users/invite`, { username: 'accttest_owner', password: 'weak', as_tenant_superadmin: true })
  check('weak starting password -> 400', r.status === 400, r.json?.detail)
  r = await api(TP, 'POST', `/tenants/${T}/users/invite`, { username: 'accttest_owner', password: pwOwner, as_tenant_superadmin: true })
  check('owner created with username + starting password, no email', r.status === 201 && r.json?.email === null && r.json?.username === 'accttest_owner', JSON.stringify(r.json))

  // 2. The owner signs in: MFA set-up first, then everything outside /auth waits for their own password
  let TO = await enrol('accttest_owner', pwOwner)
  check('owner signs in with the starting password and sets MFA up', !!TO)
  r = await api(TO, 'GET', '/assets')
  check('data refused until the password is changed', r.status === 403 && r.json?.password_change_required === true, JSON.stringify(r.json))
  r = await api(TO, 'GET', '/auth/me')
  check('/auth/me: password_change_required, no email, Google not connected',
    r.json?.password_change_required === true && r.json?.email === null && r.json?.google_connected === false && !('googleId' in (r.json ?? {})), JSON.stringify({ pcr: r.json?.password_change_required, email: r.json?.email, g: r.json?.google_connected }))
  r = await api(TO, 'POST', '/auth/change-password', { current_password: pwOwner, new_password: pwOwner })
  check('keeping the starting password -> 400', r.status === 400, r.json?.detail)
  r = await api(TO, 'POST', '/auth/change-password', { current_password: pwOwner, new_password: pwOwnerNew })
  check('own password chosen', r.status === 200, r.json?.detail)
  check('data reachable after the change', (await api(TO, 'GET', '/assets')).status === 200)
  check('/auth/me no longer asks', (await api(TO, 'GET', '/auth/me')).json?.password_change_required === false)
  check('starting password no longer signs in', (await login('accttest_owner', pwOwner)).status === 401)

  // 3. The owner creates a tenant user the same way; by-email invites still work
  r = await api(TO, 'POST', `/tenants/${T}/users/invite`, { username: 'accttest_user', password: pwUser, actions: ['asset.view'] })
  check('tenant user created without email', r.status === 201 && r.json?.email === null, JSON.stringify(r.json))
  r = await api(TO, 'POST', `/tenants/${T}/users/invite`, { username: 'accttest_user', password: strong(), actions: [] })
  check('same username again -> 409', r.status === 409, r.json?.detail)
  r = await api(TO, 'POST', `/tenants/${T}/users/invite`, { email: 'accttest_mail@example.invalid', actions: [] })
  check('invite by email still works', r.status === 201 && r.json?.email === 'accttest_mail@example.invalid', JSON.stringify(r.json))
  r = await api(TO, 'GET', `/tenants/${T}/users`)
  const listed = (r.json?.users ?? []).find((u) => u.username === 'accttest_user')
  check('users list shows the new user with no email', !!listed && listed.email === null)
  const TU = await enrol('accttest_user', pwUser)
  check('tenant user must also change the password', (await api(TU, 'GET', '/assets')).json?.password_change_required === true)

  // 4. Google connect: needs a session and a real Google token; nothing changes otherwise
  check('connect without a session -> 401', (await api(null, 'POST', '/auth/google/connect', { access_token: 'x' })).status === 401)
  r = await api(TO, 'POST', '/auth/google/connect', { access_token: 'not-a-google-token', password: pwOwnerNew, code: '000000' })
  check('connect with a fake Google token is refused', r.status === 401 || r.status === 503, `${r.status} ${r.json?.detail}`)
  const [o] = await sql("select email, google_id from users where username = 'accttest_owner'")
  check('refused connect changed nothing', o.email === null && o.google_id === null)
} finally {
  await sql("delete from audit_logs where tenant_id=$1 or user_id in (select user_id from users where username like 'accttest_%') or actor_username like 'accttest_%'", [T])
  await sql("delete from mfa_recovery_codes where user_id in (select user_id from users where username like 'accttest_%')")
  await sql("delete from users where username like 'accttest_%'")
  await sql('delete from tenants where tenant_id=$1', [T])
  const left = await sql("select (select count(*) from users where username like 'accttest_%') + (select count(*) from tenants where name like 'ACCTTEST-%') n")
  console.log('cleanup left:', left[0].n)
  console.log(`SUMMARY: ${results.filter((x) => x[0] === 'PASS').length} pass, ${results.filter((x) => x[0] === 'FAIL').length} fail`)
}
