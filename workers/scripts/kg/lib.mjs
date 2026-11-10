// Shared helpers for the knowledge-graph QA and stress scripts (seed-test, qa, stress).
//
// Target guard: every script calls guardTarget() first. It refuses to start unless the API is the
// staging Worker, workers/.env.staging says DB_TARGET=staging, and the database host differs from
// production's. Nothing here can be pointed anywhere else: there is no flag or variable for it.
// Credentials stay in an OS temp file (see STATE_DIR) and never reach log.txt.
import { neon } from '@neondatabase/serverless'
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { pbkdf2Sync, randomBytes } from 'node:crypto'
import os from 'node:os'
import path from 'node:path'
import { ROOT, describe, die, loadEnvFile, productionHost } from '../db/lib.mjs'

export const STAGING_API = 'https://umeagleeye-api-staging.syntaxch404.workers.dev'
export const STAGING_API_HOST = new URL(STAGING_API).host
export const V1 = `${STAGING_API}/api/v1`
export const REPO = path.resolve(ROOT, '..')
export const LOG_FILE = path.join(REPO, 'log.txt')
export const MARKER = 'KGTEST-'
export const AI_CAP = 200
export const STATE_DIR = process.env.KG_TEST_STATE_DIR || path.join(os.tmpdir(), 'umeagleeye-kg-test')
const CREDS = path.join(STATE_DIR, 'creds.json')
const SEED = path.join(STATE_DIR, 'seed.json')
const BUDGET = path.join(STATE_DIR, 'ai-budget.json')

// Anything that looks like a way to re-point the scripts is refused, not ignored.
const OVERRIDE_ARGS = /^--(api|url|host|db|database|target|env|staging|prod|production)\b/i
const OVERRIDE_ENV = ['API_URL', 'KG_API', 'KG_API_URL', 'KG_API_HOST', 'UMEAGLEEYE_API', 'KG_TARGET', 'KG_DB', 'KG_DATABASE_URL']

function refuse(msg) {
  console.error(`\nREFUSED: ${msg}`)
  console.error('These scripts only run against staging, and take no target override.')
  process.exit(2)
}

export function guardTarget() {
  for (const a of process.argv.slice(2)) if (OVERRIDE_ARGS.test(a)) refuse(`target override argument "${a.split('=')[0]}" is not allowed.`)
  for (const v of OVERRIDE_ENV) if (process.env[v]) refuse(`environment variable ${v} is set; a target override is not allowed.`)
  // A developer shell often has DATABASE_URL set (from the root .env, which is production). The scripts
  // read the database only from .env.staging; it is cleared so nothing can pick it up by accident.
  if (process.env.DATABASE_URL) delete process.env.DATABASE_URL
  if (process.env.DB_TARGET) delete process.env.DB_TARGET
  if (new URL(STAGING_API).host !== 'umeagleeye-api-staging.syntaxch404.workers.dev') refuse('the API constant is not the staging Worker.')
  const vars = loadEnvFile('staging')       // dies unless DB_TARGET=staging
  if (vars.DB_TARGET !== 'staging') refuse('DB_TARGET is not staging.')
  const dbHost = new URL(vars.DATABASE_URL).hostname
  const prod = productionHost()
  if (!prod) refuse('.env.production not found, so the database cannot be checked against production.')
  if (dbHost === prod) refuse('workers/.env.staging points at the PRODUCTION database host.')
  const sql = neon(vars.DATABASE_URL)
  const query = (text, params = []) => sql(text, params)
  return { sql, query, db: describe(vars.DATABASE_URL), dbHost }
}

/** The staging branch carries a marker table; a final check before any write. */
export async function assertStagingBranch(query) {
  const [{ marker }] = await query(`select to_regclass('public.staging_marker') as marker`)
  if (!marker) refuse('no staging_marker table on this database.')
  const [{ value }] = await query(`select value from public.staging_marker limit 1`)
  if (value !== 'staging') refuse(`staging_marker holds "${value}", expected "staging".`)
}

// ── temp state (never in the repo) ──────────────────────────────

export function ensureState() { mkdirSync(STATE_DIR, { recursive: true }) }
const readJson = (f, fallback) => (existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')) : fallback)
const writeJson = (f, v) => { ensureState(); writeFileSync(f, JSON.stringify(v, null, 1), { mode: 0o600 }) }

export const loadCreds = () => readJson(CREDS, null)
export const saveCreds = (c) => writeJson(CREDS, c)
export const loadSeed = () => readJson(SEED, null)
export const saveSeed = (s) => writeJson(SEED, s)
export function clearState() {
  for (const f of [CREDS, SEED]) if (existsSync(f)) rmSync(f)
}

/** Hashes a password the way lib/auth.ts hashPassword does: PBKDF2-SHA256, 100000 rounds, salt:hash in base64. */
export function hashPassword(password) {
  const salt = randomBytes(16)
  const hash = pbkdf2Sync(password, salt, 100_000, 32, 'sha256')
  return `${salt.toString('base64')}:${hash.toString('base64')}`
}

export const randomPassword = () => `Kg${randomBytes(18).toString('base64url')}9!`

// ── AI budget: one persisted count across every script of the run ──

function loadBudget() { return readJson(BUDGET, { cap: AI_CAP, spent: 0, entries: [] }) }
function saveBudget(b) { writeJson(BUDGET, b) }
export function budgetSpent() { return loadBudget().spent }

/** Holds `n` model calls before work starts. Refuses (throws) when the cap would be passed. */
export function reserveAi(n, why) {
  const b = loadBudget()
  if (b.spent + n > AI_CAP) throw new AiCapReached(`AI cap ${AI_CAP}: spent ${b.spent}, need ${n} for ${why}`)
  b.spent += n
  b.entries.push({ at: new Date().toISOString(), n, why, reserved: true })
  saveBudget(b)
  return { n, why }
}

/** Releases a reservation down to the honest figure (never more than was held). */
export function settleAi(ticket, actual) {
  const b = loadBudget()
  const used = Math.min(ticket.n, Math.max(0, actual))
  b.spent += used - ticket.n
  b.entries.push({ at: new Date().toISOString(), n: used, why: `${ticket.why} (settled)`, reserved: false })
  saveBudget(b)
}

export class AiCapReached extends Error {}

// ── API calls ───────────────────────────────────────────────────

export async function api(token, method, route, body, extraHeaders = {}) {
  const t0 = Date.now()
  const res = await fetch(`${V1}${route}`, {
    method,
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...extraHeaders },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  })
  const ms = Date.now() - t0
  const text = await res.text()
  let json = null
  try { json = text ? JSON.parse(text) : null } catch { /* not JSON */ }
  return { status: res.status, json, text, ms }
}

export async function login(username, password) {
  const r = await api(null, 'POST', '/auth/login', { username, password })
  if (r.status !== 200 || !r.json?.access_token) throw new Error(`login failed for ${username}: HTTP ${r.status}`)
  return r.json.access_token
}

/** Upper bound on the model calls one chat made, from its progress events. See agent.ts for the path taken. */
export function estimateChatCalls(events) {
  if (events.rateLimited) return 0
  if (!events.kind) return 6            // failed or malformed: assume the maximum
  if (events.kind === 'neither') return 1
  if (events.restricted) return 1
  if (events.kind === 'general') return 2
  const toolCalls = events.tools.filter(t => t.name !== 'sync_graph').length
  const rounds = Math.min(4, toolCalls + 1)
  // Regeneration is invisible in the event stream, so it is always counted (the agreed maximum).
  return 1 + rounds + 1
}

/** One chat question over the real SSE route. Holds the worst case, settles to the honest figure. */
export async function chat(token, message, opts = {}) {
  const { tenantId, history, scenario = 'chat', max = 6 } = opts
  const ticket = reserveAi(max, `chat:${scenario}`)
  const t0 = Date.now()
  let res, text = ''
  try {
    res = await fetch(`${V1}/chatbot`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, stream: true, ...(tenantId ? { tenant_id: tenantId } : {}), ...(history ? { history } : {}) }),
    })
    text = await res.text()
  } catch (err) {
    settleAi(ticket, max)
    return { status: 0, error: err.message, answer: '', tools: [], sources: [], ms: Date.now() - t0, aiCalls: max, proposal: null }
  }
  const ms = Date.now() - t0
  const out = { status: res.status, answer: '', tools: [], toolRunning: [], sources: [], proposal: null, kind: null, catchingUp: false, error: null, ms, rateLimited: false, restricted: false }
  for (const block of text.split('\n\n')) {
    const line = block.trim()
    if (!line.startsWith('data:')) continue
    const payload = line.slice(5).trim()
    if (!payload || payload === '[DONE]') continue
    let ev
    try { ev = JSON.parse(payload) } catch { continue }
    if (ev.token !== undefined) out.answer += ev.token
    if (ev.tool) {
      if (ev.tool.status === 'running') out.toolRunning.push(ev.tool.name)
      if (ev.tool.status === 'done') out.tools.push({ name: ev.tool.name, ok: ev.tool.ok })
    }
    if (ev.sources !== undefined) { out.sources = ev.sources; out.kind = ev.kind; out.catchingUp = !!ev.catching_up; if (ev.proposal) out.proposal = ev.proposal }
    if (ev.error) out.error = ev.error
  }
  if (out.error && /lot of questions/i.test(out.error)) out.rateLimited = true
  if (res.status === 429) out.rateLimited = true
  if (/role only has access/.test(out.answer)) out.restricted = true
  out.aiCalls = out.rateLimited ? 0 : estimateChatCalls(out)
  settleAi(ticket, out.aiCalls)
  return out
}

/**
 * Confirms staging runs the graph chatbot, not older code: POST /chatbot/confirm exists only there
 * and answers a forged token with a JSON error. Somebody else can deploy the shared staging Worker,
 * and a test against old code proves nothing.
 */
export async function assertGraphDeployed(token) {
  const r = await api(token, 'POST', '/chatbot/confirm', { token: 'f'.repeat(64) })
  if (r.status !== 404 || !r.json?.error) throw new Error(`staging is not running the graph chatbot code (confirm route gave ${r.status})`)
}

export const isIdk = (answer) => /(?:^|\n)\s*(?:>[^\n]*\n\s*)*I (?:don['’]?t|do not) know/i.test(answer)

// ── logging ─────────────────────────────────────────────────────

const SECRET_SHAPES = [
  /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g,
  /\b[0-9a-f]{64}\b/gi,
  /Bearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /postgres(?:ql)?:\/\/[^\s"']+/gi,
]
let knownSecrets = null
function secrets() {
  if (knownSecrets) return knownSecrets
  const c = loadCreds()
  knownSecrets = c ? [...Object.values(c.users ?? {}).map(u => u.password), ...Object.values(c.agents ?? {}).map(a => a.apiKey)].filter(Boolean) : []
  return knownSecrets
}

/** Masks anything shaped like a credential. Applied to every line written to log.txt. */
export function scrub(text) {
  let s = String(text ?? '')
  for (const re of SECRET_SHAPES) s = s.replace(re, '[REDACTED]')
  for (const v of secrets()) if (v && s.includes(v)) s = s.split(v).join('[REDACTED]')
  return s
}

/** Appends one record to log.txt. Called for every scenario outcome, pass or fail. */
export function logRecord(rec) {
  const lines = [
    `=== ${new Date().toISOString()} | ${rec.session} | ${rec.scenario} | ${rec.result}`,
    ...(rec.user ? [`user: ${rec.user}`] : []),
    ...(rec.tenant ? [`tenant: ${rec.tenant}`] : []),
    `input: ${rec.input ?? ''}`,
    ...(rec.tools ? [`tools: ${JSON.stringify(rec.tools)}`] : []),
    ...(rec.sources ? [`sources: ${JSON.stringify(rec.sources)}`] : []),
    ...(rec.answer !== undefined ? [`answer: ${rec.answer}`] : []),
    `timing_ms: ${rec.ms ?? ''}`,
    ...(rec.ai !== undefined ? [`ai_calls_counted: ${rec.ai}`] : []),
    ...(rec.checks ? [`checks: ${rec.checks}`] : []),
    ...(rec.notes ? [`notes: ${rec.notes}`] : []),
    '',
  ]
  appendFileSync(LOG_FILE, `${scrub(lines.join('\n'))}\n`)
}

export const sessionId = (prefix) => `${prefix}-${new Date().toISOString().replace(/[:.]/g, '-')}`

export function percentile(values, p) {
  if (!values.length) return 0
  const s = [...values].sort((a, b) => a - b)
  return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)]
}

export const sleep = (ms) => new Promise(r => setTimeout(r, ms))

export { die, ROOT }
export { spawnSync }
