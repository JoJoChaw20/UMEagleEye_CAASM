// Staging smoke test: alert tiers, scores, fix-time targets (lib/alertRank.ts) through the API, the tenant's
// own targets (GET/PUT /tenants/:id/sla-policy), and the reopen trigger of migration 0042.
// Temporary tenant RANKTEST-smoke with one asset and four alerts; removed at the end.
//   node scripts/smoke/ranking-smoke.mjs
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
const DAY = 86400000

const pw = 'Rank-' + randomBytes(9).toString('base64url') + '9!a'
const secret = authenticator.generateSecret()
const [{ tenant_id: T }] = await sql("insert into tenants (name, slug) values ('RANKTEST-smoke','ranktest-smoke') returning tenant_id")
try {
  await sql("insert into users (username,email,password_hash,role,tenant_id,actions,mfa_enabled,totp_secret) values ('ranktest_owner','ranktest_owner@example.invalid',$1,'tenant_superadmin',$2,'{}',true,$3)", [hash(pw), T, secret])
  const [{ asset_id: A }] = await sql("insert into assets (tenant_id, ip_address, hostname, criticality_score, is_internet_facing) values ($1, '10.99.0.5', 'ranktest-host', 5, false) returning asset_id", [T])
  const ev = async (type, severity, details, score, ageDays) => (await sql(
    "insert into events (asset_id, event_type, severity, details, composite_risk_score, first_seen, last_seen) values ($1,$2,$3,$4,$5, now() - make_interval(days => $6), now()) returning event_id",
    [A, type, severity, JSON.stringify(details), score, ageDays]))[0].event_id
  const sighting = await ev('cti_match', 'critical', { match_kind: 'sighting', rule: 'R7', indicator_type: 'domain', indicator_value: 'bad.example' }, null, 0)
  const kev = await ev('cve_detected', 'critical', { shape: 'package', package_name: 'openssl', kev: true, kev_count: 1, fixable_count: 1 }, 60, 20)
  const crit = await ev('cve_detected', 'critical', { shape: 'package', package_name: 'zlib', fixable_count: 1 }, 51, 5)
  const mac = await ev('config_change', 'high', { changed_attribute: 'mac_address' }, null, 1)

  const mt = (await api(null, 'POST', '/auth/login', { username: 'ranktest_owner', password: pw })).json?.mfa_token
  const TO = (await api(null, 'POST', '/auth/mfa/verify', { mfa_token: mt, code: authenticator.generate(secret) })).json?.access_token
  check('owner signed in', !!TO)

  // 1. The queue: tiers in order, scores within, due dates
  let r = await api(TO, 'GET', '/events?status=open&sort=priority&page_size=10')
  const items = r.json?.items ?? []
  const order = items.map((i) => i.event_id)
  check('queue order: sighting, exploited, critical CVE, then the MAC change', JSON.stringify(order) === JSON.stringify([sighting, kev, crit, mac]),
    items.map((i) => `${i.event_type}:${i.tier}`).join(' '))
  const byId = Object.fromEntries(items.map((i) => [i.event_id, i]))
  check('tiers 1 / 2 / 3 / 4', [sighting, kev, crit, mac].map((id) => byId[id]?.tier).join() === '1,2,3,4')
  check('a MAC change no longer outranks a critical CVE', byId[crit]?.priority_score > byId[mac]?.priority_score)
  check('sighting due in 24 hours', byId[sighting]?.sla_hours === 24 && !!byId[sighting]?.due_at)
  check('exploited, internal: 14 days; 20 days old so overdue', byId[kev]?.sla_hours === 336 && byId[kev]?.due_status === 'overdue', byId[kev]?.due_status)
  check('critical: 15 days; 5 days old so on track', byId[crit]?.sla_hours === 360 && byId[crit]?.due_status === 'on_track', byId[crit]?.due_status)
  r = await api(TO, 'GET', '/events?status=open&tier=2')
  check('tier filter', (r.json?.items ?? []).length === 1 && r.json.items[0].event_id === kev)
  r = await api(TO, 'GET', '/events?status=open&overdue=true')
  check('overdue filter: only the exploited CVE', (r.json?.items ?? []).map((i) => i.event_id).join() === kev)
  r = await api(TO, 'GET', '/events/stats/summary')
  check('summary: 1 overdue and the targets in force', r.json?.sla_breaches === 1 && r.json?.sla_policy?.critical === 360, JSON.stringify({ b: r.json?.sla_breaches }))
  r = await api(TO, 'GET', `/events/${kev}`)
  check('detail carries tier and due date', r.json?.tier === 2 && r.json?.due_status === 'overdue')

  // 2. The tenant's own targets
  r = await api(TO, 'GET', `/tenants/${T}/sla-policy`)
  check('policy: defaults, no overrides, editable by the owner', r.json?.effective?.critical === 360 && Object.keys(r.json?.overrides ?? {}).length === 0 && r.json?.can_edit === true)
  r = await api(TO, 'PUT', `/tenants/${T}/sla-policy`, { targets: { critical: 72 } })
  check('critical set to 3 days', r.status === 200 && r.json?.overrides?.critical === 72)
  r = await api(TO, 'GET', '/events?status=open&overdue=true')
  check('the 5-day-old critical CVE is now overdue', (r.json?.items ?? []).some((i) => i.event_id === crit))
  r = await api(TO, 'PUT', `/tenants/${T}/sla-policy`, { targets: { critical: 0 } })
  check('out of range refused', r.status === 400, r.json?.detail)
  r = await api(TO, 'PUT', `/tenants/${T}/sla-policy`, { targets: { bogus: 5 } })
  check('unknown target refused', r.status === 400, r.json?.detail)
  r = await api(TO, 'PUT', `/tenants/${T}/sla-policy`, { targets: { critical: null } })
  check('back to the default', r.status === 200 && r.json?.overrides?.critical === undefined && r.json?.effective?.critical === 360)

  // 3. Reopen trigger: a resolved alert that opens again restarts its clock
  await sql("update events set status='resolved', resolved_at=now() where event_id=$1", [kev])
  await sql("update events set status='open', resolved_at=null where event_id=$1", [kev])
  const [re] = await sql("select reopen_count, reopened_at > now() - interval '1 minute' as fresh from events where event_id=$1", [kev])
  check('reopen trigger: count 1, clock restarted', re.reopen_count === 1 && re.fresh === true)
  r = await api(TO, 'GET', `/events/${kev}`)
  check('after reopening, the exploited CVE is no longer overdue', r.json?.due_status !== 'overdue' && r.json?.reopen_count === 1, r.json?.due_status)
} finally {
  await sql('delete from audit_logs where tenant_id=$1', [T])
  await sql("delete from audit_logs where user_id in (select user_id from users where username like 'ranktest_%')")
  await sql("delete from users where username like 'ranktest_%'")
  await sql('delete from tenants where tenant_id=$1', [T])
  await sql("delete from kg_outbox where tenant_id=$1 or (tenant_id is null and changed_at > now() - interval '10 minutes' and table_name in ('events','assets'))", [T])
  console.log('cleanup left:', (await sql("select (select count(*) from tenants where name like 'RANKTEST-%') + (select count(*) from users where username like 'ranktest_%') n"))[0].n)
  console.log(`SUMMARY: ${results.filter((x) => x[0] === 'PASS').length} pass, ${results.filter((x) => x[0] === 'FAIL').length} fail`)
}
