// Staging smoke test: alerts from another tenant's shared threat-intel event are opt-in for the receiving
// tenant (migration 0043, services/threatIntel.ts eventAlertsSql): off by default, on per event or for all
// shared events, a per-event "off" beats the default, and the alert says who shared it.
// Temporary tenants SHARETEST-A (shares) and SHARETEST-B (receives, one asset); removed at the end.
//   node scripts/smoke/shared-events-smoke.mjs
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

const DOMAIN = 'sharetest-smoke-c2.top'
async function owner(T, name) {
  const pw = 'Share-' + randomBytes(9).toString('base64url') + '9!a'
  const secret = authenticator.generateSecret()
  await sql("insert into users (username,email,password_hash,role,tenant_id,actions,mfa_enabled,totp_secret) values ($1,$2,$3,'tenant_superadmin',$4,'{}',true,$5)",
    [name, `${name}@example.invalid`, hash(pw), T, secret])
  const mt = (await api(null, 'POST', '/auth/login', { username: name, password: pw })).json?.mfa_token
  return (await api(null, 'POST', '/auth/mfa/verify', { mfa_token: mt, code: authenticator.generate(secret) })).json?.access_token
}

const [{ tenant_id: TA }] = await sql("insert into tenants (name, slug) values ('SHARETEST-A','sharetest-a') returning tenant_id")
const [{ tenant_id: TB }] = await sql("insert into tenants (name, slug) values ('SHARETEST-B','sharetest-b') returning tenant_id")
try {
  const A = await owner(TA, 'sharetest_a')
  const B = await owner(TB, 'sharetest_b')
  check('both owners signed in', !!A && !!B)
  const [{ asset_id: asset }] = await sql("insert into assets (tenant_id, ip_address, hostname) values ($1, '10.98.0.5', $2) returning asset_id", [TB, `web.${DOMAIN}`])
  const alert = async () => (await sql(
    "select event_id, status, details from events where asset_id=$1 and event_type='cti_match' order by first_seen desc limit 1", [asset]))[0]

  // A shares an event naming B's domain
  let r = await api(A, 'POST', '/cti/events', { title: 'Sharetest campaign', distribution: 'all_tenants', threat_level: 'high' })
  const E = r.json?.event_id
  r = await api(A, 'POST', `/cti/events/${E}/attributes`, { text: DOMAIN })
  check('A adds the domain', r.status === 201 && r.json?.added === 1)
  r = await api(A, 'POST', `/cti/events/${E}/publish`)
  check('A publishes, shared with all tenants', r.status === 200 && r.json?.status === 'published')

  // 1. Off by default in B
  check('B: no alert by default', !(await alert()))
  r = await api(B, 'GET', '/cti/events')
  const listed = (r.json?.items ?? []).find((e) => e.event_id === E)
  check('B sees it as shared, alerts off, default off', listed?.shared_in === true && listed?.alerts_here === false && r.json?.shared_event_alerts === false && r.json?.can_set_shared_default === true,
    JSON.stringify({ s: listed?.shared_in, a: listed?.alerts_here, d: r.json?.shared_event_alerts }))
  r = await api(A, 'GET', `/cti/events/${E}`)
  check('A: own event, alerts on, no choice', r.json?.alerts_here === true && r.json?.shared_in === false)

  // 2. B turns it on for this event
  r = await api(B, 'PUT', `/cti/events/${E}/alerts`, { alerts: true })
  check('B turns it on for the event', r.status === 200 && r.json?.alerts_here === true && r.json?.alerts_choice === true && r.json?.alerts_updated >= 1, JSON.stringify({ s: r.status, u: r.json?.alerts_updated }))
  let a = await alert()
  check('B: alert raised, says shared by SHARETEST-A', a?.status === 'open' && JSON.stringify(a?.details?.shared_by) === '["SHARETEST-A"]', JSON.stringify(a?.details?.shared_by))
  r = await api(B, 'GET', `/events/${a?.event_id}`)
  check('alert detail: indicator shared by SHARETEST-A', (r.json?.cti_indicators ?? []).some((i) => i.shared_by === 'SHARETEST-A' && i.event_title === 'Sharetest campaign'))

  // 3. Back to the default (off): resolved
  r = await api(B, 'PUT', `/cti/events/${E}/alerts`, { alerts: null })
  a = await alert()
  check('back to the default: alert auto-resolved', r.status === 200 && r.json?.alerts_choice === null && a?.status === 'resolved', a?.status)

  // 4. Default on for every shared event: reopened
  r = await api(B, 'PUT', `/tenants/${TB}/shared-event-alerts`, { alerts: true })
  a = await alert()
  check('default on: alert reopened', r.status === 200 && r.json?.shared_event_alerts === true && a?.status === 'open', a?.status)

  // 5. A per-event "off" beats the default
  r = await api(B, 'PUT', `/cti/events/${E}/alerts`, { alerts: false })
  a = await alert()
  check('event off while default on: resolved', r.json?.alerts_here === false && a?.status === 'resolved', a?.status)

  // 6. Refusals
  r = await api(A, 'PUT', `/cti/events/${E}/alerts`, { alerts: false })
  check('A cannot choose for its own event', r.status === 400, r.json?.detail)
  r = await api(B, 'PUT', `/tenants/${TA}/shared-event-alerts`, { alerts: true })
  check('B cannot change A\'s default', r.status === 403 || r.status === 404, String(r.status))

  // 7. A makes it private: B's choice no longer applies
  await api(B, 'PUT', `/cti/events/${E}/alerts`, { alerts: true })
  check('B on again', (await alert())?.status === 'open')
  r = await api(A, 'PATCH', `/cti/events/${E}`, { distribution: 'organisation' })
  a = await alert()
  check('A makes it private: B\'s alert resolved', r.status === 200 && a?.status === 'resolved', a?.status)
  r = await api(B, 'GET', `/cti/events/${E}`)
  check('B can no longer open it', r.status === 404)
} finally {
  for (const T of [TA, TB]) {
    await sql('delete from audit_logs where tenant_id=$1', [T])
    await sql('delete from tenants where tenant_id=$1', [T])
    await sql('delete from kg_outbox where tenant_id=$1', [T])
  }
  await sql("delete from audit_logs where user_id in (select user_id from users where username like 'sharetest_%')")
  await sql("delete from users where username like 'sharetest_%'")
  await sql("delete from kg_outbox where tenant_id is null and changed_at > now() - interval '10 minutes' and table_name in ('events','assets')")
  console.log('cleanup left:', (await sql("select (select count(*) from tenants where name like 'SHARETEST-%') + (select count(*) from users where username like 'sharetest_%') + (select count(*) from ti_events where title = 'Sharetest campaign') n"))[0].n)
  console.log(`SUMMARY: ${results.filter((x) => x[0] === 'PASS').length} pass, ${results.filter((x) => x[0] === 'FAIL').length} fail`)
}
