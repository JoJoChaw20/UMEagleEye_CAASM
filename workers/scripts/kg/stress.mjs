// Stress test of the staging API, in rising steps of simultaneous users: mixed dashboard reads,
// scan-ingest bursts and chat, with DB-level graph retrieval measured alongside.
//
//   node scripts/kg/stress.mjs
//
// Chat is rationed: paid model calls are capped at 200 for the whole test run (lib.mjs). Retrieval
// beyond the cap runs src/kg/retrieve.ts locally against the staging database; those figures are
// "DB retrieval from this machine", not the Worker round trip.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import { STATE_DIR, AiCapReached, api, assertGraphDeployed, assertStagingBranch, budgetSpent, chat, guardTarget, loadCreds, loadSeed, login, logRecord, percentile, scrub, sessionId, sleep } from './lib.mjs'

const { query, db: dbDesc } = guardTarget()
await assertStagingBranch(query)
const SESSION = sessionId('stress')
const HERE = path.dirname(fileURLToPath(import.meta.url))
const WORKERS = path.resolve(HERE, '../..')
const creds = loadCreds(), seed = loadSeed()
if (!creds || !seed) { console.error('No test data. Run seed-test.mjs first.'); process.exit(1) }

const STEPS = [1, 5, 10, 25]
const STEP_SECONDS = 25
const CHATS = { 1: 1, 5: 1, 10: 2, 25: 3 }
const READS = ['/assets?limit=50', '/events?page_size=50', '/advisories?limit=50', '/dashboard/summary', '/posture/current']
const OTHER = { alpha: ['10.88.', 'CVE-2099-888', 'KGTEST-BRAVO', 'KGTEST-bravo'], bravo: ['10.77.1.1', '10.77.2.', 'CVE-2099-777', 'KGTEST-alpha', 'hunter2'] }

async function loadRetrieve() {
  const dir = mkdtempSync(path.join(tmpdir(), 'kg-stress-'))
  const out = path.join(dir, 'lib.mjs')
  const src = (p) => JSON.stringify(path.join(WORKERS, 'src/kg', p).split(path.sep).join('/'))
  await build({ stdin: { contents: `export { searchGraph, getNode, followLinks, countNodes } from ${src('retrieve.ts')}\nexport { accessFor } from ${src('access.ts')}`, resolveDir: WORKERS, loader: 'ts' },
    bundle: true, platform: 'node', format: 'esm', outfile: out, logLevel: 'error',
    banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" } })
  const mod = await import(pathToFileURL(out).href)
  rmSync(dir, { recursive: true, force: true })
  return mod
}

const R = await loadRetrieve()
const [vecRow] = await query(`SELECT embedding::text AS v FROM kg_nodes WHERE embedding IS NOT NULL LIMIT 1`)
const vector = vecRow ? vecRow.v.replace(/^\[|\]$/g, '').split(',').map(Number) : null
const fakeEnv = { AI: { run: async () => ({ data: [vector] }) } }

const tenantKeys = { alpha: new Set(), bravo: new Set() }
for (const [t, id] of Object.entries(seed.tenants)) for (const r of await query(`SELECT key FROM kg_nodes WHERE tenant_id = $1::uuid`, [id])) tenantKeys[t].add(r.key)

const seen = (data, marks) => { const s = JSON.stringify(data ?? ''); return marks.some(m => s.includes(m)) }

const sample = () => ({ reads: [], ingests: [], chats: [], retrieval: [], errors: 0, requests: 0, rate429: 0, leaks: 0, leakDetail: [] })

function buildUsers(n) {
  const alpha = Object.keys(creds.users).filter(k => k.startsWith('alpha-stress-')).sort()
  const bravo = Object.keys(creds.users).filter(k => k.startsWith('bravo-stress-')).sort()
  const out = []
  for (let i = 0; i < n; i++) {
    const t = i % 2 === 0 ? 'alpha' : 'bravo'
    const list = t === 'alpha' ? alpha : bravo
    out.push({ key: list[Math.floor(i / 2) % list.length], tenant: t })
  }
  return out
}

const tokens = {}
async function tokenFor(key) { if (!tokens[key]) tokens[key] = await login(creds.users[key].username, creds.users[key].password); return tokens[key] }

async function readOnce(user, s) {
  const route = READS[Math.floor(Math.random() * READS.length)]
  const t0 = Date.now()
  try {
    const r = await api(await tokenFor(user.key), 'GET', route)
    s.requests++
    if (r.status >= 500) s.errors++
    if (r.status === 429) s.rate429++
    s.reads.push(Date.now() - t0)
    if (seen(r.text, OTHER[user.tenant])) { s.leaks++; s.leakDetail.push(`read ${route} by ${user.tenant}`) }
  } catch { s.requests++; s.errors++ }
}

async function ingestOnce(user, s) {
  const agent = creds.agents[`${user.tenant}-agent-1`]
  const hosts = seed.stressHosts[user.tenant].sort(() => Math.random() - 0.5).slice(0, 4)
  const t0 = Date.now()
  try {
    const r = await api(agent.apiKey, 'POST', '/scans/ingest', {
      agent_id: agent.agentId, scan_type: 'passive',
      hosts: hosts.map(h => ({ ip: h.ip, hostname: h.hostname, mac: h.mac, mac_vendor: seed.stressVendor, ports: [] })),
      network: { subnet: `${hosts[0].ip.split('.').slice(0, 3).join('.')}.0/24`, lan_subnet: `${hosts[0].ip.split('.').slice(0, 3).join('.')}.0/24` },
    })
    s.requests++
    if (r.status >= 500) s.errors++
    s.ingests.push(Date.now() - t0)
  } catch { s.requests++; s.errors++ }
}

async function chatOnce(user, s) {
  const q = user.tenant === 'alpha' ? 'What is the IP address of KGTEST-alpha-db-01?' : 'What is the IP address of KGTEST-bravo-db-01?'
  const expect = user.tenant === 'alpha' ? '10.77.1.11' : '10.88.1.11'
  const t0 = Date.now()
  try {
    const r = await chat(await tokenFor(user.key), q, { scenario: `stress-${user.tenant}` })
    s.requests++
    if (r.status >= 500 || r.status === 0 || r.error) s.errors++
    s.chats.push({ ms: Date.now() - t0, ok: r.answer.includes(expect), ai: r.aiCalls, status: r.status })
    if (seen({ answer: r.answer, sources: r.sources }, OTHER[user.tenant])) { s.leaks++; s.leakDetail.push(`chat by ${user.tenant}`) }
  } catch (err) {
    if (err instanceof AiCapReached) { s.skippedChat = (s.skippedChat ?? 0) + 1; return }
    s.requests++; s.errors++
  }
}

async function retrievalLoop(user, s, deadline) {
  const tenantId = seed.tenants[user.tenant]
  const access = R.accessFor({ role: 'tenant_admin', tenantId })
  const q = (t, p) => query(t, p)
  const other = user.tenant === 'alpha' ? tenantKeys.bravo : tenantKeys.alpha
  const texts = ['critical alerts web server', 'kgtest db apache port', 'advisory patch', 'open critical cve', 'what should I fix first']
  while (Date.now() < deadline) {
    const t0 = Date.now()
    try {
      const nodes = await R.searchGraph(q, fakeEnv, access, texts[Math.floor(Math.random() * texts.length)], { limit: 12 })
      const counted = await R.countNodes(q, access, { type: 'event', where: { severity: 'critical' } })
      const anchor = nodes.find(n => !n.key.startsWith('system:'))?.key
      const links = anchor ? await R.followLinks(q, access, anchor, 1) : []
      s.retrieval.push(Date.now() - t0)
      const keys = [...nodes.map(n => n.key), ...links.map(l => l.node.key), ...(counted.items ?? []).map(i => i.key)]
      const bad = keys.filter(k => other.has(k))
      if (bad.length) { s.leaks++; s.leakDetail.push(`retrieval ${bad[0]}`) }
    } catch (err) { s.errors++; s.requests++; s.retrievalError = err.message; console.error(scrub(`retrieval error: ${err.message}`)) }
  }
}

async function runStep(n) {
  const users = buildUsers(n)
  const s = sample()
  for (const u of users) await tokenFor(u.key)
  const deadline = Date.now() + STEP_SECONDS * 1000
  let chatsLeft = CHATS[n]
  const workers = users.map(async (user, i) => {
    if (chatsLeft > 0 && i < CHATS[n]) { chatsLeft--; await chatOnce(user, s) }
    let n2 = 0
    while (Date.now() < deadline) {
      await readOnce(user, s)
      if (n2 % 5 === 4) await ingestOnce(user, s)
      n2++
    }
  })
  const retrieval = users.map(u => retrievalLoop(u, s, deadline + 2000))
  const backlogBefore = (await query(`SELECT count(*)::int AS n FROM kg_outbox`))[0].n
  await Promise.all([...workers, ...retrieval])
  const dur = STEP_SECONDS
  const rate = s.requests ? s.errors / s.requests : 0
  return {
    n, backlogBefore, reqs: s.requests, errors: s.errors, rate429: s.rate429, errorRate: `${(rate * 100).toFixed(2)}%`, rps: (s.requests / dur).toFixed(1),
    readsP50: percentile(s.reads, 50), readsP95: percentile(s.reads, 95), ingests: s.ingests.length, ingestP50: percentile(s.ingests, 50), ingestP95: percentile(s.ingests, 95),
    chats: s.chats.length, chatsCorrect: s.chats.filter(c => c.ok).length, chatMs: s.chats.map(c => c.ms), chatAi: s.chats.map(c => c.ai), skippedChat: s.skippedChat ?? 0,
    retrievalOps: s.retrieval.length, retrievalP50: percentile(s.retrieval, 50), retrievalP95: percentile(s.retrieval, 95), retrievalError: s.retrievalError,
    leaks: s.leaks, leakDetail: Object.entries(s.leakDetail.reduce((a, d) => ({ ...a, [d]: (a[d] ?? 0) + 1 }), {})),
  }
}

console.log(`Stress session ${SESSION}. Staging DB ${dbDesc}. AI calls so far: ${budgetSpent()}`)
await assertGraphDeployed(await tokenFor('alpha-stress-01'))
logRecord({ session: SESSION, scenario: 'stress-start', result: 'INFO', input: `steps ${STEPS.join(',')}, ${STEP_SECONDS}s each; chats ${JSON.stringify(CHATS)}`, notes: `ai_spent_before=${budgetSpent()}` })

const rows = []
for (const n of STEPS) {
  const row = await runStep(n)
  rows.push(row)
  console.log(JSON.stringify(row))
  logRecord({ session: SESSION, scenario: `stress-step-${n}`, result: row.leaks ? 'FAIL' : 'INFO', input: `${n} simultaneous users: dashboard reads, scan ingest, ${CHATS[n]} chat(s); DB retrieval measured locally`, ms: STEP_SECONDS * 1000, ai: row.chatAi.reduce((a, b) => a + b, 0), notes: JSON.stringify(row) })
  await sleep(5000)
}

// Outbox after the last burst: time until the test companies' rows are gone (queue job, oldest first).
const burstEnd = Date.now()
let drained = null, lastRows = null, series = []
for (let i = 0; i < 48; i++) {
  await sleep(5000)
  const [r] = await query(`SELECT count(*)::int AS n FROM kg_outbox WHERE tenant_id = ANY($1::uuid[])`, [[seed.tenants.alpha, seed.tenants.bravo]])
  lastRows = r.n; series.push(r.n)
  if (r.n === 0) { drained = Date.now() - burstEnd; break }
}
const total = (await query(`SELECT count(*)::int AS n FROM kg_outbox`))[0].n
const drainNote = `test-company rows after the 25-user burst: ${series.join(',')}; drained ${drained === null ? `not within ${Math.round((Date.now() - burstEnd) / 1000)}s (rows left ${lastRows})` : `in ${Math.round(drained / 1000)}s`}; all outbox rows now ${total}`
console.log(drainNote)
logRecord({ session: SESSION, scenario: 'stress-outbox-drain', result: drained !== null && drained < 180_000 ? 'PASS' : 'FAIL', input: 'outbox rows for the test companies after the burst, drained by the queue job', ms: drained, notes: drainNote })
const summary = { steps: rows, drainNote, drainedMs: drained }
writeFileSync(path.join(STATE_DIR, 'stress-results.json'), JSON.stringify(summary, null, 1))
logRecord({ session: SESSION, scenario: 'stress-end', result: 'INFO', input: '', notes: `ai_spent_after=${budgetSpent()}` })
console.log(`Done. AI calls so far: ${budgetSpent()}`)
