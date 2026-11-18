// STAGING ownership handover smoke test. Temp tenants HOTEST-*, users hotest_*; all removed at the end.
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
const code = (secret, ms) => authenticator.clone({ epoch: ms }).generate(secret)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
async function api(token, method, path, body) {
  const res = await fetch(V1 + path, { method, headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) })
  const t = await res.text(); let j = null; try { j = JSON.parse(t) } catch {}
  return { status: res.status, json: j }
}
const results = []
function check(name, ok, info = '') { results.push([ok ? 'PASS' : 'FAIL', name, info]); console.log(ok ? 'PASS' : 'FAIL', name, ok ? '' : info) }
const det = (r) => r.status + ' ' + (r.json?.detail ?? '')

// each call returns a code from a strictly later 30s step than the last one for that secret (window is +-1 step)
const last = {}
async function fresh(secret) {
  const cur = Math.floor(Date.now() / STEP)
  const want = Math.max(cur, (last[secret] ?? -1) + 1)
  if (want > cur + 1) await sleep((want - 1) * STEP - Date.now() + 1500)
  last[secret] = want
  return code(secret, want * STEP + 1000)
}
const pws = {}; const pwf = (k) => (pws[k] ??= randomBytes(12).toString('base64url'))
const tenants = []
const ids = {}, sec = {}, tok = {}
const un = (s, k) => `hotest_${s}_${k}`
async function mkTenant(s) {
  const [{ tenant_id }] = await sql('insert into tenants (name, slug) values ($1,$2) returning tenant_id', ['HOTEST-' + s, 'hotest-' + s.toLowerCase()])
  tenants.push(tenant_id); return tenant_id
}
async function mkUser(s, k, tid, role) {
  const u = un(s, k)
  ids[u] = (await sql('insert into users (username,email,password_hash,role,tenant_id,actions) values ($1,$2,$3,$4,$5,$6) returning user_id', [u, u + '@example.invalid', hash(pwf(u)), role, tid, role === 'tenant_user' ? ['asset.view', 'scan.view'] : []]))[0].user_id
  const r = await api(null, 'POST', '/auth/login', { username: u, password: pwf(u) })
  if (r.json?.stage !== 'enrol') throw new Error('no enrol stage for ' + u + ' ' + r.status)
  const mt = r.json.mfa_token
  sec[u] = (await api(null, 'POST', '/auth/mfa/enrol/start', { mfa_token: mt })).json?.totp_secret
  const f = await api(null, 'POST', '/auth/mfa/enrol/finish', { mfa_token: mt, code: await fresh(sec[u]) })
  tok[u] = f.json?.access_token
  if (!tok[u]) throw new Error('enrol finish failed for ' + u + ' ' + det(f))
}
async function setup(s, tid, spec) {
  for (const [k, role] of spec) await mkUser(s, k, tid, role)
}
const U = (s, k) => ({ u: un(s, k), id: ids[un(s, k)], t: () => tok[un(s, k)] })
const step = async (s, k) => ({ password: pwf(un(s, k)), code: await fresh(sec[un(s, k)]) })
const owners = async (tid) => (await sql("select count(*)::int n from users where tenant_id=$1 and role='tenant_superadmin'", [tid]))[0].n
const userRow = async (s, k) => (await sql('select role::text role, is_active, actions from users where user_id=$1', [ids[un(s, k)]]))[0]
const notices = async (tk) => { const r = await api(tk, 'GET', '/notices'); return Array.isArray(r.json) ? r.json : [] }
const O = (tid) => `/tenants/${tid}/ownership`
const SR = [['o', 'tenant_superadmin'], ['r', 'tenant_user']]
const FIVE = [['o', 'tenant_superadmin'], ['s', 'tenant_user'], ['a1', 'tenant_user'], ['a2', 'tenant_user']]

async function plan(s, tid) {
  const o = U(s, 'o')
  return api(o.t(), 'PUT', O(tid) + '/recovery-plan', { successor_id: U(s, 's').id, approver_ids: [U(s, 'a1').id, U(s, 'a2').id], ...(await step(s, 'o')) })
}
async function startRec(s, tid, reason) { return api(U(s, 's').t(), 'POST', O(tid) + '/recovery', { reason, ...(await step(s, 's')) }) }
async function approve(s, tid, k) { return api(U(s, k).t(), 'POST', O(tid) + '/recovery/approve', await step(s, k)) }

const before = await sql("select role::text role, count(*)::int n from users where username not like 'hotest_%' group by 1 order by 1")
console.log('BEFORE', JSON.stringify(before))

try {
  // ---------- Path A + notices ----------
  {
    const s = 'a', T = await mkTenant('A'); await setup(s, T, [...SR, ['x', 'tenant_user']])
    const o = U(s, 'o'), r = U(s, 'r'), x = U(s, 'x')
    let res = await api(o.t(), 'POST', O(T) + '/transfer', { to_user_id: r.id, after: { mode: 'stay', actions: ['asset.view'] }, ...(await step(s, 'o')) })
    check('A transfer start -> 201', res.status === 201, det(res))
    let n = await notices(r.t())
    const tr = n.find((z) => z.kind === 'transfer_request')
    check('Notices: recipient sees transfer_request', !!tr, JSON.stringify(n.map((z) => z.kind)))
    check('Notices: bystander sees no transfer_request', !(await notices(x.t())).some((z) => z.kind === 'transfer_request'))
    res = await api(r.t(), 'GET', O(T)); check('A recipient GET /ownership shows pending_transfer', res.status === 200 && !!res.json?.pending_transfer, det(res))
    res = await api(x.t(), 'GET', O(T)); check('A bystander GET /ownership hides pending_transfer', res.status === 200 && !res.json?.pending_transfer, det(res))
    res = await api(r.t(), 'POST', O(T) + '/transfer/accept', await step(s, 'r'))
    check('A accept -> 200', res.status === 200, det(res))
    check('A exactly one owner', (await owners(T)) === 1)
    const own = (await sql("select user_id from users where tenant_id=$1 and role='tenant_superadmin'", [T]))[0]
    check('A owner is recipient', own?.user_id === r.id)
    const fo = await userRow(s, 'o')
    check('A former owner tenant_user with chosen actions', fo.role === 'tenant_user' && fo.is_active && fo.actions.includes('asset.view'), JSON.stringify(fo))
    res = await api(r.t(), 'POST', O(T) + '/transfer/accept', await step(s, 'r'))
    check('A second accept -> 409', res.status === 409, det(res))
    n = await notices(r.t())
    const chk = n.find((z) => z.kind === 'owner_checklist')
    check('Notices: new owner sees owner_checklist (personal)', !!chk && chk.personal === true, JSON.stringify(n.map((z) => z.kind)))
    check('Notices: transfer_request ended after accept', !n.some((z) => z.kind === 'transfer_request'))
    const nx = await notices(x.t())
    const chg = nx.find((z) => z.kind === 'ownership_changed')
    check('Notices: bystander sees tenant-wide ownership_changed', !!chg, JSON.stringify(nx.map((z) => z.kind)))
    if (chk) {
      res = await api(r.t(), 'POST', `/notices/${chk.notice_id}/dismiss`)
      check('Notices: dismiss personal notice -> 200', res.status === 200, det(res))
      check('Notices: dismissed notice gone', !(await notices(r.t())).some((z) => z.notice_id === chk.notice_id))
      res = await api(r.t(), 'POST', `/notices/${chk.notice_id}/dismiss`)
      check('Notices: dismiss again -> 404', res.status === 404, det(res))
    } else check('Notices: dismiss personal notice -> 200', false, 'no checklist notice')
    if (chg) { res = await api(x.t(), 'POST', `/notices/${chg.notice_id}/dismiss`); check('Notices: tenant-wide notice dismiss -> 404 (per contract: personal only)', res.status === 404, det(res)) }
  }
  // ---------- Path A expiry ----------
  {
    const s = 'e', T = await mkTenant('E'); await setup(s, T, SR)
    const o = U(s, 'o'), r = U(s, 'r')
    let res = await api(o.t(), 'POST', O(T) + '/transfer', { to_user_id: r.id, after: { mode: 'stay' }, ...(await step(s, 'o')) })
    check('A-expiry transfer start -> 201', res.status === 201, det(res))
    await sql("update ownership_transfers set expires_at = now() - interval '1 hour' where tenant_id=$1", [T])
    res = await api(r.t(), 'POST', O(T) + '/transfer/accept', await step(s, 'r'))
    check('A-expiry expired accept -> 409', res.status === 409, det(res))
    check('A-expiry owner unchanged', (await owners(T)) === 1 && (await userRow(s, 'o')).role === 'tenant_superadmin')
    const st = (await sql('select status from ownership_transfers where tenant_id=$1', [T]))[0]?.status
    check('A-expiry transfer marked expired', st === 'expired', String(st))
  }
  // ---------- Path B terminated ----------
  {
    const s = 'bt', T = await mkTenant('BT'); await setup(s, T, FIVE)
    let res = await plan(s, T); check('B-term plan -> 200', res.status === 200, det(res))
    res = await startRec(s, T, 'terminated'); check('B-term start -> 201', res.status === 201, det(res))
    check('Notices: approver sees recovery_request', (await notices(U(s, 'a1').t())).some((z) => z.kind === 'recovery_request'))
    res = await approve(s, T, 'a1'); check('B-term approve #1 -> 200 awaiting', res.status === 200 && res.json?.status === 'awaiting_approval', JSON.stringify(res.json) + res.status)
    res = await approve(s, T, 'a2'); check('B-term approve #2 -> 200 completed', res.status === 200 && res.json?.status === 'completed', JSON.stringify(res.json) + res.status)
    const fo = await userRow(s, 'o'), ns = await userRow(s, 's')
    check('B-term former owner suspended + tenant_user', fo.role === 'tenant_user' && fo.is_active === false, JSON.stringify(fo))
    check('B-term successor is the one owner', ns.role === 'tenant_superadmin' && (await owners(T)) === 1)
    res = await api(U(s, 'o').t(), 'GET', '/assets'); check('B-term former owner old token -> 401', res.status === 401, det(res))
    const nn = await notices(U(s, 'a1').t())
    check('Notices: recovery_request ended after completion', !nn.some((z) => z.kind === 'recovery_request'))
    check('Notices: ownership_changed posted after recovery', nn.some((z) => z.kind === 'ownership_changed'))
    check('Notices: new owner checklist after recovery', (await notices(U(s, 's').t())).some((z) => z.kind === 'owner_checklist'))
  }
  // ---------- Path B resigned -> dispute ----------
  {
    const s = 'bd', T = await mkTenant('BD'); await setup(s, T, FIVE)
    await plan(s, T)
    let res = await startRec(s, T, 'resigned'); check('B-resign start -> 201', res.status === 201, det(res))
    check('Notices: former owner sees recovery_started', (await notices(U(s, 'o').t())).some((z) => z.kind === 'recovery_started'))
    await approve(s, T, 'a1')
    res = await approve(s, T, 'a2'); check('B-resign approve #2 -> on_hold', res.status === 200 && res.json?.status === 'on_hold', JSON.stringify(res.json) + res.status)
    check('Notices: former owner sees recovery_hold', (await notices(U(s, 'o').t())).some((z) => z.kind === 'recovery_hold'))
    res = await api(U(s, 'o').t(), 'POST', O(T) + '/recovery/cancel', await step(s, 'o'))
    check('B-resign owner cancel -> 200 disputed', res.status === 200 && res.json?.status === 'disputed', JSON.stringify(res.json) + res.status)
    const st = (await sql('select status from ownership_recoveries where tenant_id=$1', [T]))[0]?.status
    check('B-resign DB status disputed, owner unchanged', st === 'disputed' && (await userRow(s, 'o')).role === 'tenant_superadmin' && (await owners(T)) === 1, String(st))
    check('Notices: successor sees recovery_disputed', (await notices(U(s, 's').t())).some((z) => z.kind === 'recovery_disputed'))
  }
  // ---------- Path B resigned completion + enrolment tokens ----------
  {
    const s = 'bc', T = await mkTenant('BC'); await setup(s, T, FIVE)
    await plan(s, T)
    await startRec(s, T, 'resigned'); await approve(s, T, 'a1')
    let res = await approve(s, T, 'a2'); check('B-complete reached on_hold', res.json?.status === 'on_hold', JSON.stringify(res.json))
    for (const i of [1, 2]) await sql("insert into enrolment_tokens (tenant_id,name,token_hash,kind,uses,expires_at) values ($1,$2,$3,'host',0, now() + interval '7 days')", [T, 'hotest-tok' + i, randomBytes(32).toString('hex')])
    await sql("insert into enrolment_tokens (tenant_id,name,token_hash,kind,uses,expires_at) values ($1,'hotest-used',$2,'host',1, now() + interval '7 days')", [T, randomBytes(32).toString('hex')])
    const cnt = async () => (await sql("select count(*) filter (where uses=0)::int unused, count(*) filter (where uses>0)::int used from enrolment_tokens where tenant_id=$1", [T]))[0]
    const b4 = await cnt(); check('B-complete setup: 2 unused + 1 used tokens', b4.unused === 2 && b4.used === 1, JSON.stringify(b4))
    await sql("update ownership_recoveries set hold_until = now() - interval '1 hour' where tenant_id=$1", [T])
    res = await api(U(s, 's').t(), 'GET', O(T)); check('B-complete GET /ownership -> 200', res.status === 200, det(res))
    check('B-complete response owner is successor', res.json?.owner?.user_id === U(s, 's').id, JSON.stringify(res.json?.owner))
    const fo = await userRow(s, 'o')
    check('B-complete swap: one owner, former suspended', (await owners(T)) === 1 && fo.role === 'tenant_user' && fo.is_active === false, JSON.stringify(fo))
    res = await api(U(s, 'o').t(), 'GET', '/assets'); check('B-complete former owner old token -> 401', res.status === 401, det(res))
    const af = await cnt(); check('B-complete unused enrolment tokens gone (used one kept)', af.unused === 0 && af.used === 1, JSON.stringify(af))
    const st = (await sql('select status from ownership_recoveries where tenant_id=$1', [T]))[0]?.status
    check('B-complete recovery status completed', st === 'completed', String(st))
  }
  // ---------- Recovery expiry ----------
  {
    const s = 'rx', T = await mkTenant('RX'); await setup(s, T, FIVE)
    await plan(s, T)
    let res = await startRec(s, T, 'terminated'); check('Expiry recovery start -> 201', res.status === 201, det(res))
    await approve(s, T, 'a1')
    check('Expiry setup: approver2 has recovery_request notice', (await notices(U(s, 'a2').t())).some((z) => z.kind === 'recovery_request'))
    await sql("update ownership_recoveries set expires_at = now() - interval '1 hour' where tenant_id=$1", [T])
    res = await api(U(s, 'o').t(), 'GET', O(T)); check('Expiry GET /ownership -> 200', res.status === 200, det(res))
    const st = (await sql('select status from ownership_recoveries where tenant_id=$1', [T]))[0]?.status
    check('Expiry recovery marked expired', st === 'expired', String(st))
    check('Expiry owner unchanged', (await owners(T)) === 1 && (await userRow(s, 'o')).role === 'tenant_superadmin')
    const n2 = await notices(U(s, 'a2').t())
    check('Expiry notices ended (no recovery_request/recovery_started for approver/owner)', !n2.some((z) => z.kind === 'recovery_request') && !(await notices(U(s, 'o').t())).some((z) => z.kind === 'recovery_started'))
  }
  // ---------- Concurrency 1: two parallel accepts ----------
  {
    const s = 'c1', T = await mkTenant('C1'); await setup(s, T, SR)
    const o = U(s, 'o'), r = U(s, 'r')
    let res = await api(o.t(), 'POST', O(T) + '/transfer', { to_user_id: r.id, after: { mode: 'stay' }, ...(await step(s, 'o')) })
    check('Conc1 transfer start -> 201', res.status === 201, det(res))
    const sc = sec[r.u]
    const c1 = await fresh(sc), c2 = await fresh(sc)
    const rs = await Promise.all([c1, c2].map((cd) => api(r.t(), 'POST', O(T) + '/transfer/accept', { password: pwf(r.u), code: cd })))
    const ok = rs.filter((x) => x.status === 200).length
    check('Conc1 exactly one 200 of two parallel accepts', ok === 1, rs.map(det).join(' | '))
    check('Conc1 exactly one owner', (await owners(T)) === 1, 'count=' + (await owners(T)))
    console.log('  conc1 statuses:', rs.map(det).join(' | '))
  }
  // ---------- Concurrency 2: accept vs cancel ----------
  {
    const s = 'c2', T = await mkTenant('C2'); await setup(s, T, SR)
    const o = U(s, 'o'), r = U(s, 'r')
    let res = await api(o.t(), 'POST', O(T) + '/transfer', { to_user_id: r.id, after: { mode: 'stay' }, ...(await step(s, 'o')) })
    check('Conc2 transfer start -> 201', res.status === 201, det(res))
    const body = await step(s, 'r')
    const rs = await Promise.all([api(r.t(), 'POST', O(T) + '/transfer/accept', body), api(o.t(), 'DELETE', O(T) + '/transfer')])
    const ok = rs.filter((x) => x.status === 200).length
    check('Conc2 exactly one 200 (accept vs cancel)', ok === 1, rs.map(det).join(' | '))
    check('Conc2 exactly one owner', (await owners(T)) === 1, 'count=' + (await owners(T)))
    console.log('  conc2 statuses (accept, cancel):', rs.map(det).join(' | '))
  }
  // ---------- Scheduled deactivation ----------
  {
    const s = 'sd', T = await mkTenant('SD'); await setup(s, T, [['o', 'tenant_superadmin'], ['u', 'tenant_user']])
    const u = U(s, 'u')
    let res = await api(u.t(), 'GET', '/assets'); check('Sched setup: user token works first', res.status === 200, det(res))
    await sql("update users set scheduled_deactivation_at = now() - interval '1 minute' where user_id=$1", [u.id])
    res = await api(u.t(), 'GET', '/assets'); check('Sched user old token -> 401', res.status === 401, det(res))
    res = await api(null, 'POST', '/auth/login', { username: u.u, password: pwf(u.u) })
    check('Sched sign-in refused (401/403, no MFA stage)', [401, 403].includes(res.status) && !res.json?.mfa_token, det(res))
    const row = (await sql('select is_active from users where user_id=$1', [u.id]))[0]
    check('Sched is_active flipped to false', row.is_active === false, JSON.stringify(row))
  }
} catch (e) { check('SCRIPT ERROR', false, String(e?.stack ?? e)) } finally {
  let left = '?'
  try {
    await sql("delete from audit_logs where tenant_id in (select tenant_id from tenants where name like 'HOTEST-%')")
    if (tenants.length) await sql('delete from audit_logs where tenant_id = any($1)', [tenants])
    if (tenants.length) await sql('delete from tenants where tenant_id = any($1)', [tenants])
    await sql("delete from tenants where name like 'HOTEST-%'")
    await sql("delete from audit_logs where user_id in (select user_id from users where username like 'hotest_%')")
    if (tenants.length) await sql('delete from audit_logs where tenant_id = any($1)', [tenants])
    await sql("delete from audit_logs where actor_username like 'hotest_%'")
    await sql("delete from users where username like 'hotest_%'")
    const l = await sql(`select
      (select count(*) from users where username like 'hotest_%')::int u,
      (select count(*) from tenants where name like 'HOTEST-%')::int t,
      (select count(*) from ownership_transfers where tenant_id = any($1))::int ot,
      (select count(*) from ownership_recoveries where tenant_id = any($1))::int orr,
      (select count(*) from tenant_recovery_plans where tenant_id = any($1))::int pl,
      (select count(*) from tenant_notices where tenant_id = any($1))::int nt,
      (select count(*) from enrolment_tokens where tenant_id = any($1))::int et,
      (select count(*) from audit_logs where actor_username like 'hotest_%')::int au`, [tenants])
    left = JSON.stringify(l[0])
  } catch (e) { left = 'CLEANUP ERROR ' + e }
  console.log('CLEANUP LEFT:', left)
  const after = await sql("select role::text role, count(*)::int n from users where username not like 'hotest_%' group by 1 order by 1")
  console.log('AFTER', JSON.stringify(after), 'UNCHANGED:', JSON.stringify(after) === JSON.stringify(before))
  console.log(`SUMMARY: ${results.filter((x) => x[0] === 'PASS').length} pass, ${results.filter((x) => x[0] === 'FAIL').length} fail`)
  for (const r of results.filter((x) => x[0] === 'FAIL')) console.log('FAILED:', r[1], r[2])
}
