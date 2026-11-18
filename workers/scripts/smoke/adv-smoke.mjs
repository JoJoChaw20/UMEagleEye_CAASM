import { neon } from '@neondatabase/serverless'
import { loadEnvFile } from '../db/lib.mjs'
import { randomBytes, pbkdf2Sync } from 'node:crypto'
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)
const { authenticator } = require('otplib')
const sql = neon(loadEnvFile('staging').DATABASE_URL)
const V1 = 'https://umeagleeye-api-staging.syntaxch404.workers.dev/api/v1'
const hash = (p) => { const s = randomBytes(16); return s.toString('base64') + ':' + pbkdf2Sync(p, s, 100000, 32, 'sha256').toString('base64') }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const results = []
const check = (n, ok, i = '') => { results.push(ok); console.log(ok ? 'PASS' : 'FAIL', n, i) }
async function api(t, method, path, body) {
  const res = await fetch(V1 + path, { method, headers: { ...(t ? { Authorization: 'Bearer ' + t } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) })
  const x = await res.text(); let j = null; try { j = JSON.parse(x) } catch {}
  return { status: res.status, json: j }
}
const roleCounts = async () => JSON.stringify(await sql("select role::text r, count(*)::int n from users where username not like 'advtest_%' group by 1 order by 1"))
const beforeRoles = await roleCounts()
console.log('roles before', beforeRoles)
const hbBefore = await sql("select agent_id::text id, last_heartbeat from agents where name not like 'advtest_%'")
const hbAt = Date.now()

const [{ tenant_id: T }] = await sql("insert into tenants (name, slug) values ('ADVTEST-smoke','advtest-smoke') returning tenant_id")
const pw = {}; const pwf = (k) => (pw[k] ??= randomBytes(14).toString('base64url'))
try {
  const mk = async (k, role, actions) => sql("insert into users (username,email,password_hash,role,tenant_id,actions) values ($1,$2,$3,$4,$5,$6)", ['advtest_' + k, 'advtest_' + k + '@example.invalid', hash(pwf(k)), role, T, actions])
  await mk('owner', 'tenant_superadmin', [])
  await mk('gen', 'tenant_user', ['advisory.generate', 'advisory.view', 'alert.view'])
  await mk('view', 'tenant_user', ['advisory.view'])
  const tok = {}
  for (const k of ['owner', 'gen', 'view']) {
    const l = await api(null, 'POST', '/auth/login', { username: 'advtest_' + k, password: pwf(k) })
    if (l.json?.access_token) { tok[k] = l.json.access_token; continue }
    if (l.json?.stage !== 'enrol') throw new Error('login stage ' + l.json?.stage + ' ' + l.status)
    const s = await api(null, 'POST', '/auth/mfa/enrol/start', { mfa_token: l.json.mfa_token })
    const f = await api(null, 'POST', '/auth/mfa/enrol/finish', { mfa_token: l.json.mfa_token, code: authenticator.generate(s.json.totp_secret) })
    tok[k] = f.json?.access_token
    await sleep(1000)
  }
  check('setup: 3 users signed in', Object.values(tok).every(Boolean))

  const mkAsset = async (host, ip, dt = 'server') => (await sql("insert into assets (tenant_id,hostname,ip_address,device_type) values ($1,$2,$3,$4) returning asset_id", [T, host, ip, dt]))[0].asset_id
  const A1 = await mkAsset('advtest-agent', '10.77.0.1'), A2 = await mkAsset('advtest-noagent', '10.77.0.2')
  const [{ agent_id: AG }] = await sql("insert into agents (tenant_id,name,api_key_hash,status,last_heartbeat,host_asset_id,kind) values ($1,'advtest_agent',$2,'online',now(),$3,'host') returning agent_id", [T, randomBytes(16).toString('hex'), A1])
  const mkEv = async (asset, type, sev, d) => (await sql("insert into events (asset_id,event_type,severity,details) values ($1,$2,$3,$4::jsonb) returning event_id", [asset, type, sev, JSON.stringify(d)]))[0].event_id
  const pkgD = { shape: 'package', package_name: 'openssl', package_version: '1.0.0-1', package_type: 'deb', fix_to: '1.0.1-1' }
  const mkCve = async (asset) => {
    const e = await mkEv(asset, 'cve_detected', 'high', pkgD)
    for (const c of ['CVE-2099-0001', 'CVE-2099-0002'])
      await sql("insert into cve_findings (event_id,asset_id,cve_id,package_type,package_name,package_version,severity,cvss,epss,fix_versions,fixed_at,dismissed) values ($1,$2,$3,'deb','openssl','1.0.0-1','high',7.5,0.01,$4,null,false)", [e, asset, c, ['1.0.1-1']])
    return e
  }
  const eCveA = await mkCve(A1), eCveN = await mkCve(A2)
  const ePort = async (asset, p) => mkEv(asset, 'port_opened', 'medium', { port: p, protocol: 'tcp' })
  const e8080 = await ePort(A1, 8080), e22 = await ePort(A1, 22), e5985 = await ePort(A1, 5985), eNull = await ePort(A1, 9999)
  const [{ advisory_id: nullAdv }] = await sql("insert into advisories (event_id,summary,recommended_action,content) values ($1,'old summary','old action',null) returning advisory_id", [eNull])
  check('seed done', true)

  let r = await api(tok.view, 'POST', `/events/${eCveA}/advisory`); check('view-only POST generate -> 403', r.status === 403, String(r.status))
  r = await api(tok.gen, 'POST', `/events/${e5985}/advisory`); check('generate user POST -> 2xx', r.status === 200 || r.status === 202, String(r.status))
  const owner = tok.owner
  for (const e of [eCveA, eCveN, e22, e8080]) { r = await api(owner, 'POST', `/events/${e}/advisory`); if (![200, 202].includes(r.status)) check('owner POST ' + e, false, r.status + JSON.stringify(r.json)) }
  const advOf = {}
  const t0 = Date.now()
  while (Date.now() - t0 < 300000) {
    const rows = await sql("select event_id::text e, advisory_id::text a from advisories where event_id = any($1)", [[eCveA, eCveN, e22, e8080, e5985]])
    for (const x of rows) advOf[x.e] = x.a
    if (Object.keys(advOf).length === 5) break
    await sleep(3000)
  }
  check('5 advisories generated', Object.keys(advOf).length === 5, `got ${Object.keys(advOf).length} in ${Math.round((Date.now() - t0) / 1000)}s`)
  const get = async (id, t = owner) => api(t, 'GET', '/advisories/' + id)
  const g = {}
  for (const [n, e] of [['cveA', eCveA], ['cveN', eCveN], ['p22', e22], ['p8080', e8080], ['p5985', e5985]]) { if (advOf[e]) g[n] = (await get(advOf[e])).json }
  for (const [n, a] of Object.entries(g)) console.log(n, 'label=', a?.automation?.label, '| reason=', a?.automation?.reason, '| steps=', JSON.stringify((a?.content?.steps ?? []).map(s => ({ k: s.kind, a: s.action?.key, t: s.text.slice(0, 70) }))))
  console.log('BASIS', JSON.stringify([...new Set(Object.values(g).map(a => a?.content?.basis))]))
  check('content present on all', Object.values(g).length === 5 && Object.values(g).every(a => a?.content?.steps?.length > 0))
  check('cveA label Auto/Partly + not-switched-on reason', ['Auto-fixable', 'Partly auto-fixable'].includes(g.cveA?.automation?.label) && g.cveA?.automation?.reason === 'Automatic fixing is not switched on yet.', JSON.stringify(g.cveA?.automation))
  check('cveN label Needs outside support', g.cveN?.automation?.label === 'Needs outside support', JSON.stringify(g.cveN?.automation))
  const noAuto = (a) => (a?.content?.steps ?? []).every(s => s.kind !== 'auto')
  check('port 22 no auto step', !!g.p22 && noAuto(g.p22))
  check('port 5985 no auto step', !!g.p5985 && noAuto(g.p5985))
  const st = g.p8080?.content?.steps ?? []; const last = st[st.length - 1]
  const blk = st.filter(s => s.action)
  console.log("STEPS8080", JSON.stringify(st.map((s, i) => ({ i, kind: s.kind, a: s.action?.key || null, t: s.text }))))
  check('8080 block step is last and conditional', blk.length === 1 && blk[0] === last && /^\s*if\b/i.test(last.text) && /not needed/i.test(last.text), JSON.stringify({ n: st.length, last: last && { a: last.action?.key, t: last.text } }))
  const gn = await get(nullAdv); check('NULL-content advisory loads (200, content null)', gn.status === 200 && gn.json?.content == null, String(gn.status))
  const lab = async () => (await get(advOf[eCveA])).json?.automation?.label
  await sql("update agents set retired_at=now() where agent_id=$1", [AG]); const l1 = await lab()
  await sql("update agents set retired_at=null where agent_id=$1", [AG]); const l2 = await lab()
  check('label flips to Needs outside support on retire', l1 === 'Needs outside support', l1)
  check('label flips back on clear', ['Auto-fixable', 'Partly auto-fixable'].includes(l2), l2)
  r = await api(owner, 'GET', '/advisories?limit=100')
  const items = r.json?.items ?? []
  check('list: 200, automation_label key on all, no content', r.status === 200 && items.length >= 6 && items.every(i => 'automation_label' in i && !('content' in i)), `n=${items.length}`)
  const li = items.find(i => i.advisoryId === advOf[eCveN]); check('list label for cveN', li?.automation_label === 'Needs outside support', String(li?.automation_label))
  r = await get(advOf[eCveA], tok.view); check('view-only GET advisory -> 200', r.status === 200, String(r.status))
  r = await api(owner, 'GET', '/events/' + eCveA); check('GET /events/:id -> 200', r.status === 200, String(r.status))

  const hbLeft = 65000 - (Date.now() - hbAt); if (hbLeft > 0) await sleep(hbLeft)
  const hbAfter = await sql("select agent_id::text id, last_heartbeat from agents where name not like 'advtest_%'")
  const bm = new Map(hbBefore.map(x => [x.id, x.last_heartbeat]))
  const adv = hbAfter.filter(x => bm.has(x.id) && new Date(x.last_heartbeat) > new Date(bm.get(x.id)))
  check('real agent heartbeat advancing (>=1)', adv.length >= 1 || hbAfter.length === 0, `advanced ${adv.length}/${hbAfter.length}`)
  const sr = await sql("select count(*)::int n, max(started_at) m from scan_results where started_at > '2026-11-18'")
  const sb = await sql("select column_name c from information_schema.columns where table_name='sboms'")
  const tc = ['created_at', 'uploaded_at', 'generated_at'].find(c => sb.some(x => x.c === c))
  const sbn = tc ? await sql(`select count(*)::int n, max(${tc}) m from sboms where ${tc} > '2026-11-18'`) : [{ n: 'n/a' }]
  console.log('scan_results since deploy', JSON.stringify(sr[0]), '| sboms since deploy', tc, JSON.stringify(sbn[0]))
} catch (e) { check('SCRIPT ERROR', false, String(e?.stack ?? e)) } finally {
  await sql('delete from audit_logs where tenant_id=$1', [T])
  await sql('delete from tenants where tenant_id=$1', [T])
  const casc = await sql("select (select count(*) from events where asset_id in (select asset_id from assets where hostname like 'advtest-%'))::int e, (select count(*) from assets where hostname like 'advtest-%')::int a, (select count(*) from agents where name like 'advtest_%')::int g, (select count(*) from advisories where summary='old summary' and event_id in (select event_id from events where asset_id not in (select asset_id from assets where tenant_id is not null)))::int adv, (select count(*) from cve_findings where cve_id like 'CVE-2099-%')::int cf")
  await sql("delete from audit_logs where actor_username like 'advtest_%' or user_id in (select user_id from users where username like 'advtest_%')")
  await sql("delete from users where username like 'advtest_%'")
  const left = await sql("select (select count(*) from users where username like 'advtest_%')::int u,(select count(*) from tenants where name like 'ADVTEST-%')::int t,(select count(*) from audit_logs where actor_username like 'advtest_%')::int a")
  console.log('cleanup left', JSON.stringify(left[0]), 'cascade leftovers', JSON.stringify(casc[0]))
  const afterRoles = await roleCounts(); console.log('roles after', afterRoles, afterRoles === beforeRoles ? 'UNCHANGED' : 'CHANGED')
  console.log(`SUMMARY: ${results.filter(Boolean).length} pass, ${results.filter((x) => !x).length} fail`)
}
