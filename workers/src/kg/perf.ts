/**
 * kg/perf.ts — performance history. Records how long API requests and background jobs take
 * (Workers Analytics Engine, fire-and-forget), and turns that history into PerformanceWindow
 * nodes in the shared graph layer so the chatbot can answer "why was it slow at 3pm?".
 *
 * Recorded per request: route pattern, status, total time, database wait. Never the real URL,
 * a query string, an id, a hostname or an IP. A recording failure never touches a request.
 *
 * Data point layout (one per request or job):
 *   index1 = route or job name   blob1 = 'req' | 'job'   blob2 = route or job name
 *   blob3  = 'ok' | 'error'      double1 = status (0 for jobs)   double2 = total ms   double3 = database ms
 */
import { AsyncLocalStorage } from 'node:async_hooks'
import type { MiddlewareHandler } from 'hono'
import { matchedRoutes } from 'hono/route'
import type { Env } from '../types'
import { deleteNodes, upsertNodes, type Q } from './store'
import type { KgNode } from './extract'

// ── Database wait, kept per request ─────────────────────────────────
// A Worker isolate serves many requests at once, so the total lives in the request's own
// AsyncLocalStorage store (nodejs_compat is on), never in a module-level counter.

interface RequestTiming { dbMs: number }
const timing = new AsyncLocalStorage<RequestTiming>()

/** Adds time spent waiting on the database to the request now running (no-op outside one). */
export function addDbWait(ms: number): void {
  const t = timing.getStore()
  if (t && Number.isFinite(ms) && ms > 0) t.dbMs += ms
}

// ── Paths ───────────────────────────────────────────────────────────

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/
const NAME_MAX = 96
export const UNMATCHED_ROUTE = 'unmatched'

/** A path with its variable parts replaced by :id or :ip. Query string and fragment are dropped. */
export function normalisePath(p: string): string {
  const path = String(p ?? '').split(/[?#]/)[0] ?? ''
  const out = path.split('/').map(seg => {
    if (!seg || seg.startsWith(':')) return seg
    if (IPV4.test(seg)) return ':ip'
    if (UUID.test(seg) || /^\d+$/.test(seg) || /^[0-9a-f]{8,}$/i.test(seg)) return ':id'
    // IPv6 and MAC addresses, hostnames, e-mail addresses, encoded text: never a fixed route word.
    if (/[:.@%]/.test(seg)) return ':id'
    if (/\d/.test(seg) && seg.length >= 12) return ':id'
    return seg
  }).join('/')
  return out.slice(0, NAME_MAX) || '/'
}

function routeLabel(c: Parameters<MiddlewareHandler>[0]): string {
  try {
    const found = matchedRoutes(c).filter(r => !r.path.endsWith('*'))
    const last = found[found.length - 1]
    return last ? last.path.slice(0, NAME_MAX) : UNMATCHED_ROUTE
  } catch {
    // No route table to read: fall back to the cleaned path, never the raw one.
    try { return normalisePath(c.req.path) } catch { return UNMATCHED_ROUTE }
  }
}

// ── Recording ───────────────────────────────────────────────────────

function write(env: Env, kind: 'req' | 'job', name: string, ok: boolean, status: number, ms: number, dbMs: number): void {
  try {
    env.PERF?.writeDataPoint({
      indexes: [name.slice(0, NAME_MAX)],
      blobs: [kind, name.slice(0, NAME_MAX), ok ? 'ok' : 'error'],
      doubles: [status, Math.round(ms), Math.round(dbMs)],
    })
  } catch { /* recording must never affect the work being timed */ }
}

/** Records one API request: route pattern, status, total ms, database ms. Errors count too. */
export const perfMiddleware: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
  const store: RequestTiming = { dbMs: 0 }
  const start = performance.now()
  let threw = false
  try {
    await timing.run(store, () => next())
  } catch (err) {
    threw = true
    throw err
  } finally {
    try {
      const status = threw ? 500 : c.res.status
      const failed = threw || status >= 500 || c.error !== undefined
      write(c.env, 'req', routeLabel(c), !failed, status, performance.now() - start, store.dbMs)
    } catch { /* never fail the request */ }
  }
}

/** Records one queue job or cron step: name, duration, outcome. */
export function recordJob(env: Env, name: string, ms: number, ok: boolean): void {
  write(env, 'job', name, ok, 0, ms, 0)
}

/** Runs `run`, records it as a job, and passes its result or error on unchanged. */
export async function timedJob<T>(env: Env, name: string, run: () => Promise<T>): Promise<T> {
  const start = performance.now()
  try {
    const result = await run()
    recordJob(env, name, performance.now() - start, true)
    return result
  } catch (err) {
    recordJob(env, name, performance.now() - start, false)
    throw err
  }
}

// ── Summaries ───────────────────────────────────────────────────────

/** One aggregated row from the SQL API: an hour, a route or job, and its sums. */
export interface PerfRow {
  bucket: string      // start of the hour, ISO UTC
  kind: 'req' | 'job'
  name: string
  n: number           // sample-weighted count
  errors: number
  totalMs: number     // sample-weighted sum
  dbMs: number
  maxMs: number
}

export interface RouteStat { route: string; requests: number; avgMs: number; maxMs: number; errorRate: number; slow: boolean }
export interface JobStat { name: string; runs: number; failed: number; avgMs: number; maxMs: number }
export interface PerfWindow {
  start: string
  end: string
  requests: number
  errors: number
  errorRate: number
  avgMs: number
  dbShare: number       // share of request time spent waiting on the database, 0 to 1
  slowRoutes: RouteStat[]
  jobs: JobStat[]
  scanRequests: number  // requests to scan routes in this hour
  slow: boolean
}

export const SLOW_ROUTE_MS = 1000
export const MIN_ROUTE_REQUESTS = 5
const TOP_ROUTES = 5
const HOUR = 3_600_000
const round = (n: number, d = 0) => { const f = 10 ** d; return Math.round(n * f) / f }
const safe = (n: unknown) => (typeof n === 'number' && Number.isFinite(n) ? n : 0)

/** One summary per hour: slowest routes, error rate, volume, database share, jobs that ran. */
export function buildWindows(rows: PerfRow[]): PerfWindow[] {
  const byBucket = new Map<string, PerfRow[]>()
  for (const r of rows) {
    const t = Date.parse(r.bucket)
    if (!Number.isFinite(t)) continue
    const k = new Date(t).toISOString()
    byBucket.set(k, [...(byBucket.get(k) ?? []), r])
  }
  const windows: PerfWindow[] = []
  for (const [start, group] of byBucket) {
    const reqs = group.filter(r => r.kind === 'req' && safe(r.n) > 0)
    const jobs = group.filter(r => r.kind === 'job' && safe(r.n) > 0)
    const requests = reqs.reduce((a, r) => a + safe(r.n), 0)
    const errors = reqs.reduce((a, r) => a + safe(r.errors), 0)
    const totalMs = reqs.reduce((a, r) => a + safe(r.totalMs), 0)
    const dbMs = reqs.reduce((a, r) => a + safe(r.dbMs), 0)
    const stats: RouteStat[] = reqs.map(r => {
      const avg = safe(r.totalMs) / r.n
      return {
        route: r.name, requests: round(r.n), avgMs: round(avg), maxMs: round(safe(r.maxMs)),
        errorRate: round(safe(r.errors) / r.n, 3), slow: r.n >= MIN_ROUTE_REQUESTS && avg >= SLOW_ROUTE_MS,
      }
    }).sort((a, b) => b.avgMs - a.avgMs)
    windows.push({
      start, end: new Date(Date.parse(start) + HOUR).toISOString(),
      requests: round(requests), errors: round(errors),
      errorRate: requests > 0 ? round(errors / requests, 3) : 0,
      avgMs: requests > 0 ? round(totalMs / requests) : 0,
      // Concurrent queries add up, so the sum can pass the request time: cap the share at 1.
      dbShare: totalMs > 0 ? round(Math.min(1, dbMs / totalMs), 2) : 0,
      slowRoutes: stats.slice(0, TOP_ROUTES),
      jobs: jobs.map(r => ({
        name: r.name, runs: round(r.n), failed: round(safe(r.errors)),
        avgMs: round(safe(r.totalMs) / r.n), maxMs: round(safe(r.maxMs)),
      })).sort((a, b) => b.avgMs * b.runs - a.avgMs * a.runs),
      scanRequests: round(reqs.filter(r => /scan/i.test(r.name)).reduce((a, r) => a + r.n, 0)),
      slow: stats.some(s => s.slow),
    })
  }
  return windows.sort((a, b) => a.start.localeCompare(b.start))
}

// ── Pulling the history ─────────────────────────────────────────────

export const HISTORY_DAYS = 14
export const PERF_LIMITS_NOTE =
  'Performance history limits: nothing was recorded before recording was switched on; it measures the UMEagleEye API and background jobs, not the speed of a person\'s browser or network; and history is kept for about 3 months (summaries here cover the last ' + HISTORY_DAYS + ' days).'

const datasetFor = (env: Env) => (env.APP_ENV === 'staging' ? 'umeagleeye_perf_staging' : 'umeagleeye_perf')

/** The Analytics Engine SQL query: one row per hour and route or job, weighted by sampling. */
export const ROW_LIMIT = 10_000
const REFRESH_TIMEOUT_MS = 5000

export function perfQuery(dataset: string, limit = ROW_LIMIT): string {
  return `SELECT toStartOfInterval(timestamp, INTERVAL '1' HOUR) AS bucket, blob1 AS kind, blob2 AS name,
  SUM(_sample_interval) AS n,
  SUM(_sample_interval * if(blob3 = 'error', 1, 0)) AS errors,
  SUM(_sample_interval * double2) AS total_ms,
  SUM(_sample_interval * double3) AS db_ms,
  MAX(double2) AS max_ms
FROM ${dataset}
WHERE timestamp > NOW() - INTERVAL '${HISTORY_DAYS}' DAY
GROUP BY bucket, kind, name
ORDER BY bucket DESC
LIMIT ${limit}
FORMAT JSON`
}

/** The SQL API stamps hours as "2026-11-09 15:00:00" (UTC). */
function isoBucket(v: unknown): string {
  const s = String(v ?? '')
  const t = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s.replace(' ', 'T')}Z`)
  return Number.isFinite(t) ? new Date(t).toISOString() : ''
}

export function parsePerfRows(body: unknown): PerfRow[] {
  const data = (body as { data?: unknown })?.data
  if (!Array.isArray(data)) throw new Error('unexpected response from the analytics query')
  const rows: PerfRow[] = []
  for (const d of data as Record<string, unknown>[]) {
    const kind = d.kind === 'job' ? 'job' : d.kind === 'req' ? 'req' : null
    const bucket = isoBucket(d.bucket)
    if (!kind || !bucket) continue
    rows.push({ bucket, kind, name: String(d.name ?? ''), n: Number(d.n), errors: Number(d.errors), totalMs: Number(d.total_ms), dbMs: Number(d.db_ms), maxMs: Number(d.max_ms) })
  }
  return rows
}

export const windowKey = (start: string) => `perf:window:${start}`

function windowNode(w: PerfWindow): KgNode {
  const routes = w.slowRoutes.length
    ? w.slowRoutes.map(r => `${r.route} averaged ${r.avgMs} ms over ${r.requests} request(s)`).join('; ')
    : 'no API requests were recorded'
  const jobs = w.jobs.length
    ? w.jobs.map(j => `${j.name} ran ${j.runs} time(s) (average ${j.avgMs} ms${j.failed ? `, ${j.failed} failed` : ''})`).join('; ')
    : 'no background jobs were recorded'
  return {
    key: windowKey(w.start), tenantId: null, visibility: 'platform', roleGroup: 'analyst', type: 'performance_window',
    title: `Performance ${w.start} to ${w.end}`,
    body: `Performance window (API speed and slowness) from ${w.start} to ${w.end}: ${w.requests} API request(s), ${w.errors} server error(s) (error rate ${round(w.errorRate * 100, 1)}%), average ${w.avgMs} ms, `
      + `${round(w.dbShare * 100)}% of request time spent waiting on the database${w.slow ? ', flagged slow' : ''}. Slowest routes: ${routes}. Jobs that ran in this hour: ${jobs}. `
      + `Scan requests in this hour: ${w.scanRequests}. This shows what lined up in time, not proof of cause.`,
    props: { ...w },
  }
}

let warnedNoSecrets = false

export interface PerfRefresh { ok: boolean; windows: number; reason?: string }

/**
 * Pulls the last days of history and stores one PerformanceWindow node per hour (shared layer,
 * `platform` visibility). Never throws: missing secrets (logged once) or a failed call leave the
 * graph as it was.
 */
export async function refreshPerf(
  q: Q, env: Env, fetchFn: typeof fetch = fetch, opts: { timeoutMs?: number; rowLimit?: number } = {},
): Promise<PerfRefresh> {
  if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) {
    if (!warnedNoSecrets) { warnedNoSecrets = true; console.warn('[perf] CF_ACCOUNT_ID or CF_ANALYTICS_TOKEN is not set: performance history is not pulled') }
    return { ok: false, windows: 0, reason: 'not configured' }
  }
  const limit = opts.rowLimit ?? ROW_LIMIT
  const abort = new AbortController()
  const timer = setTimeout(() => abort.abort(), opts.timeoutMs ?? REFRESH_TIMEOUT_MS)
  try {
    // The abort signal also covers reading the body, so a hung API cannot stall the caller.
    const res = await fetchFn(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(env.CF_ACCOUNT_ID)}/analytics_engine/sql`, {
      method: 'POST', headers: { Authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}` }, body: perfQuery(datasetFor(env), limit),
      signal: abort.signal,
    })
    if (!res.ok) throw new Error(`analytics query returned HTTP ${res.status}`)
    let rows = parsePerfRows(await res.json())
    // An empty answer is not proof the history is gone (an outage looks the same): change nothing.
    if (rows.length === 0) return { ok: true, windows: 0 }
    const truncated = rows.length >= limit
    if (truncated) {
      // Newest first, so the cut fell on the oldest hours. Its oldest hour may be partial: leave it out.
      console.warn(`[perf] analytics pull hit the row limit (${limit}): older hours are left out`)
      const oldest = rows.reduce((a, r) => (r.bucket < a ? r.bucket : a), rows[0]!.bucket)
      rows = rows.filter(r => r.bucket !== oldest)
    }
    const windows = buildWindows(rows)
    await upsertNodes(q, env, windows.map(windowNode))
    // Only windows past the history limit are removed. One merely missing from this pull stays.
    if (!truncated) {
      const cutoff = new Date(Date.now() - HISTORY_DAYS * 86_400_000).toISOString()
      const old = await q(`SELECT key FROM kg_nodes WHERE tenant_id IS NULL AND type = 'performance_window' AND props ->> 'start' < $1`, [cutoff])
      await deleteNodes(q, old.map(o => String(o.key)))
    }
    return { ok: true, windows: windows.length }
  } catch (err) {
    console.error('[perf] refresh failed:', err instanceof Error ? err.message : err)
    return { ok: false, windows: 0, reason: 'failed' }
  } finally {
    clearTimeout(timer)
  }
}

/** For tests: lets the "log once" check run again. */
export function resetPerfWarning(): void { warnedNoSecrets = false }

// ── Asked times and coverage ────────────────────────────────────────

const MYT_OFFSET_H = 8
const pad = (n: number) => String(n).padStart(2, '0')

const MONTH_NAME = '(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)'
const ORDINAL = '(?:st|nd|rd|th)?'
const OPTIONAL_YEAR = '(?:,?\\s+(\\d{4}))?'
// The lookarounds keep the minutes of a clock time, as in 15:30 March 3, from being read as a day.
const DAY_MONTH = new RegExp(`(?<![:\\d])\\b(\\d{1,2})${ORDINAL}(?:\\s+of)?\\s+${MONTH_NAME}\\b\\.?${OPTIONAL_YEAR}(?![:\\d])`, 'i')
const MONTH_DAY = new RegExp(`\\b${MONTH_NAME}\\b\\.?\\s+(\\d{1,2})${ORDINAL}(?![:\\d])\\b${OPTIONAL_YEAR}`, 'i')
const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']
const monthIndex = (name: string) => MONTHS.indexOf(name.slice(0, 3).toLowerCase())

// Ways of naming a day that are not read: a month with no day, a day with no month, numeric dates
// whose day and month order is unknown, and relative days. "May" alone is an ordinary word, so a
// month counts here on its own only when spelled in full and not "May", and otherwise needs a
// word such as "in", or a year, beside it.
const UNREADABLE_DATE = new RegExp([
  '\\b(?:january|february|march|april|june|july|august|september|october|november|december)\\b',
  `\\b(?:in|during|of)\\s+${MONTH_NAME}\\b`,
  `\\b${MONTH_NAME}\\s+\\d{4}\\b`,
  '\\bthe\\s+\\d{1,2}(?:st|nd|rd|th)\\b',
  '(?<![\\d.])\\d{1,2}/\\d{1,2}(?:/\\d{2,4})?(?![\\d/])',
  '\\b\\d{1,2}\\.\\d{1,2}\\.\\d{4}\\b',
  '(?<![\\w-])\\d{1,2}-\\d{1,2}-\\d{2,4}\\b',
  '\\b(?:mon|tues|wednes|thurs|fri|satur|sun)day\\b',
  '\\b(?:last|next|previous)\\s+(?:week|month|year)\\b',
  '\\b\\d+\\s+(?:days?|weeks?|months?|years?)\\s+ago\\b',
  '\\bday\\s+before\\b',
  '\\bthe\\s+other\\s+day\\b',
].join('|'), 'i')

/** The calendar date a question states. A null year means none was given. */
function statedDate(question: string): { year: number | null; month: number; day: number } | 'unreadable' | null {
  const iso = /\b(\d{4})-(\d{2})-(\d{2})\b/.exec(question)
  if (iso) return { year: Number(iso[1]), month: Number(iso[2]) - 1, day: Number(iso[3]) }
  const dm = DAY_MONTH.exec(question)
  if (dm) return { year: dm[3] ? Number(dm[3]) : null, month: monthIndex(dm[2]!), day: Number(dm[1]) }
  const md = MONTH_DAY.exec(question)
  if (md) return { year: md[3] ? Number(md[3]) : null, month: monthIndex(md[1]!), day: Number(md[2]) }
  return UNREADABLE_DATE.test(question) ? 'unreadable' : null
}

/**
 * The clock time a question names, as an instant. A bare time is Malaysia time (UTC+8, the zone
 * the product shows) unless the user says UTC/GMT; any other named zone gives null (the model is
 * told to convert it). The day is a date stated in the question (3 March 2026, March 3 2026 or
 * 2026-03-03, the year being optional), "yesterday", or today; a time still ahead today means the
 * last time it happened, and so does a date with no year that is still ahead this year. A date
 * that is named but cannot be read gives null, because assuming today would answer for the wrong day.
 */
export function resolveAskedTime(question: string, now: Date): { utc: Date; label: string } | null {
  const ampm = /\b(1[0-2]|0?[1-9])(?::([0-5]\d))?\s*(am|pm)\b/i.exec(question)
  const h24 = /\b([01]?\d|2[0-3]):([0-5]\d)\b/.exec(question)
  let hour: number, minute: number
  if (ampm) {
    hour = Number(ampm[1]) % 12 + (ampm[3]!.toLowerCase() === 'pm' ? 12 : 0)
    minute = Number(ampm[2] ?? 0)
  } else if (h24) {
    hour = Number(h24[1]); minute = Number(h24[2])
  } else return null
  const isUtc = /\b(utc|gmt)\b/i.test(question)
  if (!isUtc && /\b(est|edt|pst|pdt|cst|cdt|mst|mdt|cet|cest|bst|ist|jst|aest|[+-]\d{2}:?\d{2}|z)\b/i.test(question.replace(/\d{1,2}:\d{2}/g, ''))) return null
  const offset = isUtc ? 0 : MYT_OFFSET_H
  const local = new Date(now.getTime() + offset * 3_600_000)
  let y = local.getUTCFullYear(), m = local.getUTCMonth(), d = local.getUTCDate()
  const instant = (year: number) => Date.UTC(year, m, d, hour, minute) - offset * 3_600_000
  const stated = statedDate(question)
  if (stated === 'unreadable') return null
  let explicitDay = false
  if (stated) {
    m = stated.month; d = stated.day; explicitDay = true
    if (stated.year !== null) y = stated.year
    else if (instant(y) > now.getTime()) y -= 1
    // A date that does not exist, such as 31 February, would otherwise roll into the next month.
    const check = new Date(Date.UTC(y, m, d))
    if (check.getUTCMonth() !== m || check.getUTCDate() !== d) return null
  } else if (/\byesterday\b/i.test(question)) { d -= 1; explicitDay = true }
  let utcMs = instant(y)
  if (!explicitDay && utcMs > now.getTime()) utcMs -= 86_400_000
  const utc = new Date(utcMs)
  const at = new Date(utcMs + offset * 3_600_000)
  const day = `${at.getUTCFullYear()}-${pad(at.getUTCMonth() + 1)}-${pad(at.getUTCDate())}`
  const zone = isUtc ? 'UTC' : 'Malaysia time (UTC+8)'
  const label = isUtc
    ? `${pad(hour)}:${pad(minute)} UTC on ${day}`
    : `${pad(hour)}:${pad(minute)} ${zone} on ${day}, which is ${pad(utc.getUTCHours())}:${pad(utc.getUTCMinutes())} UTC`
  return { utc, label }
}

/** Runs of hours with no window between the first and last stored window (UTC, "A to B"). */
export function gapRanges(starts: string[], max = 10): string[] {
  const times = [...new Set(starts.map(s => Date.parse(s)).filter(Number.isFinite))].sort((a, b) => a - b)
  if (times.length < 2) return []
  const have = new Set(times)
  const out: string[] = []
  let runStart: number | null = null
  for (let t = times[0]!, n = 0; t <= times[times.length - 1]! && n < 5000; t += HOUR, n++) {
    if (!have.has(t)) { if (runStart === null) runStart = t }
    else if (runStart !== null) { out.push(`${new Date(runStart).toISOString()} to ${new Date(t).toISOString()}`); runStart = null }
  }
  return out.slice(0, max)
}

/** What the stored windows say about the time a question names, or null if it names none. */
export function askedTimeNote(question: string, now: Date, starts: string[]): string | null {
  const asked = resolveAskedTime(question, now)
  if (!asked) return null
  const hour = new Date(Math.floor(asked.utc.getTime() / HOUR) * HOUR)
  const times = starts.map(s => Date.parse(s)).filter(Number.isFinite)
  const head = `You asked about ${asked.label}; its window is the hour starting ${hour.toISOString()} (all window times are UTC).`
  if (times.length === 0) return `${head} There is no history for that time.`
  if (hour.getTime() < Math.min(...times) || hour.getTime() > Math.max(...times)) return `${head} That hour is outside the recorded range, so there is no history for that time.`
  if (!times.includes(hour.getTime())) return `${head} That hour has no window (nothing was recorded or pulled for it), so there is no history for that time.`
  return `${head} That hour is covered by a window.`
}
