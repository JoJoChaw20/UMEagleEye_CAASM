/**
 * Threat sightings (rule R7) — PURE (no DB).
 *
 * The host agent keeps a copy of its tenant's matchable bad domains and IPs (the same
 * indicators as R5: services/threatIntel.ts matchableSql), checks its own computer's DNS
 * answers and outbound connections against them ON THE COMPUTER, and uploads only the
 * hits. The server re-checks every hit against the current indicators and keeps one
 * `cti_match` alert per (asset, listed value) with match_kind 'sighting'.
 *
 *   listItem()      an indicator as the agent's list holds it: {k: 'd'|'i', v}
 *   cursor          keyset (last_seen, indicator_id) over feed entries, as text both ways
 *   cleanHits()     what an agent uploaded, within limits (its clock is not trusted)
 *   matchHits()     hits against the indicator rows that name them (the server re-check)
 *   planSightings() new alerts, and updates of the ones that exist
 *
 * A URL indicator names one file on its host, and a named host is often a shared platform,
 * so only a URL on an IPv4 address counts (its address), one severity step lower than a
 * listed IP.
 * Sightings are closed by people (S4): never auto-resolved; a contact after an alert was
 * resolved reopens it, while false positives and accepted risks stay closed (still counted).
 */

export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type IndicatorType = 'ip' | 'domain' | 'url'
export type Via = 'dns' | 'connection'

const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical']
const OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
const IPV4 = new RegExp(`^${OCTET}(\\.${OCTET}){3}$`)
const IPV6 = /^[0-9a-f:.]+$/
const DOMAIN = /^(?=.{3,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
// timestamptz as Postgres prints it: 2026-11-16 21:04:05.123456+00
const PG_TIME = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d{1,6})?[+-]\d{2}(:\d{2})?$/

export const MAX_HITS = 200
export const LIST_PAGE = 2000
// Which values go on the agents' list (listItem). Raised when that changes: an agent seeing another
// number fetches the whole list again. 2: URLs only on IPv4 hosts (17 Nov 2026).
export const LIST_RULES = 2
const MAX_COUNT = 1_000_000
const HIT_WINDOW_MS = 7 * 86400_000

export function isIp(value: string): boolean {
  return IPV4.test(value) || (value.includes(':') && IPV6.test(value))
}

/** A domain or IP as both sides compare it: lower case, no trailing dot, IPv6 without brackets. */
export function normalValue(raw: string): string {
  return raw.trim().toLowerCase().replace(/^\[(.*)\]$/, '$1').replace(/\.$/, '')
}

function urlHost(url: string): string | null {
  try { return normalValue(new URL(url).hostname) } catch { return null }
}

// ── The agent's list ─────────────────────────────────────────────────
export interface ListItem { k: 'd' | 'i'; v: string }

/** An indicator as the agent's list holds it, or null when it cannot be seen in traffic. */
export function listItem(type: string, value: string): ListItem | null {
  const v = type === 'url' ? urlHost(value) : normalValue(value)
  if (!v) return null
  if (type === 'ip') return isIp(v) ? { k: 'i', v } : null
  if (type === 'url') {
    // Only a URL on an IPv4 address counts (a server set up for the malware). A URL on a named host
    // is one file on a host that is often a shared platform (Vidar's t.me and steamcommunity.com
    // profiles, Discord webhooks, GitLab raw files: 7 false alerts on the lab VM, 17 Nov), and a
    // lookup or connection never shows the path. An IPv6 host is left out (the re-check reads hosts in SQL).
    return IPV4.test(v) ? { k: 'i', v } : null
  }
  if (type === 'domain') return !isIp(v) && DOMAIN.test(v) ? { k: 'd', v } : null
  return null
}

/** One page of the list: indicator rows to items, each value once. */
export function listItems(rows: { type: string; value: string }[]): ListItem[] {
  const seen = new Set<string>()
  const out: ListItem[] = []
  for (const r of rows) {
    const item = listItem(r.type, r.value)
    if (!item || seen.has(item.k + item.v)) continue
    seen.add(item.k + item.v)
    out.push(item)
  }
  return out
}

/** The paging cursor: the last row's last_seen exactly as Postgres printed it, and its id. */
export function encodeCursor(seenText: string, id: string): string {
  return btoa(`${seenText}|${id}`).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function decodeCursor(raw: string | null | undefined): { seen: string; id: string } | null {
  if (!raw || raw.length > 200) return null
  let text: string
  try { text = atob(raw.replace(/-/g, '+').replace(/_/g, '/')) } catch { return null }
  const [seen, id, extra] = text.split('|')
  if (extra !== undefined || !seen || !id || !UUID.test(id) || !PG_TIME.test(seen)) return null
  return { seen, id }
}

/** The names a looked-up domain is listed under: itself and each parent with two or more labels. */
export function domainCandidates(name: string): string[] {
  const labels = name.split('.')
  const out: string[] = []
  for (let i = 0; i <= labels.length - 2; i++) out.push(labels.slice(i).join('.'))
  return out
}

// ── Hits (agent → server) ────────────────────────────────────────────
export interface Hit {
  value: string            // what this computer looked up or connected to
  type: 'domain' | 'ip'
  via: Via
  count: number
  firstSeen: Date
  lastSeen: Date
  process: string | null   // image name only, never its path
  port: number | null
}

function clampTime(raw: unknown, now: Date): Date {
  const t = typeof raw === 'string' ? new Date(raw) : null
  if (!t || isNaN(t.getTime()) || t > now || now.getTime() - t.getTime() > HIT_WINDOW_MS) return now
  return t
}

/** Uploaded hits within limits; anything malformed is dropped (counted in `rejected`). */
export function cleanHits(raw: unknown, now: Date): { hits: Hit[]; rejected: number } {
  const list = Array.isArray(raw) ? raw.slice(0, MAX_HITS) : []
  const hits: Hit[] = []
  let rejected = Array.isArray(raw) ? Math.max(0, raw.length - MAX_HITS) : 0
  for (const r of list) {
    const h = (r && typeof r === 'object' ? r : {}) as Record<string, unknown>
    const value = typeof h.value === 'string' ? normalValue(h.value) : ''
    const type = h.type === 'ip' || h.type === 'domain' ? h.type : null
    const via = h.via === 'dns' || h.via === 'connection' ? h.via : null
    if (!type || !via || !(type === 'ip' ? isIp(value) : DOMAIN.test(value))) { rejected++; continue }
    const count = typeof h.count === 'number' && Number.isInteger(h.count) && h.count >= 1 ? Math.min(h.count, MAX_COUNT) : 1
    const lastSeen = clampTime(h.last_seen, now)
    let firstSeen = clampTime(h.first_seen, now)
    if (firstSeen > lastSeen) firstSeen = lastSeen
    const proc = typeof h.process === 'string' ? h.process.split(/[\\/]/).pop()!.trim().slice(0, 120) : ''
    const port = typeof h.port === 'number' && Number.isInteger(h.port) && h.port >= 1 && h.port <= 65535 ? h.port : null
    hits.push({ value, type, via, count, firstSeen, lastSeen, process: proc || null, port })
  }
  return { hits, rejected }
}

/** What to look up for the re-check: every IP, and every name a domain may be listed under. */
export function lookupValues(hits: Hit[]): { ips: string[]; names: string[] } {
  const ips = new Set<string>()
  const names = new Set<string>()
  for (const h of hits) {
    if (h.type === 'ip') ips.add(h.value)
    else for (const n of domainCandidates(h.value)) names.add(n)
  }
  return { ips: [...ips], names: [...names] }
}

// ── The re-check ─────────────────────────────────────────────────────
export interface IndicatorRow {
  indicatorId: string
  type: IndicatorType
  value: string
  source: string
  tiEventId: string | null
  title: string | null
  level: string | null      // the event's threat level; null for a feed entry
}

export interface Matched {
  listed: string            // the listed domain or IP (a URL indicator: its host)
  itype: IndicatorType      // 'url' only when no domain or IP indicator lists it
  hits: Hit[]
  indicators: IndicatorRow[]
}

/** Group hits by the listed value they match. A domain listed at several levels
 *  (a.evil.com and evil.com) counts once, under the most specific listing. */
export function matchHits(hits: Hit[], rows: IndicatorRow[]): { matched: Matched[]; dropped: Hit[] } {
  const byListed = new Map<string, IndicatorRow[]>()
  for (const r of rows) {
    const item = listItem(r.type, r.value)
    if (!item) continue
    const key = `${item.k}:${item.v}`
    byListed.set(key, [...(byListed.get(key) ?? []), r])
  }
  const groups = new Map<string, Matched>()
  const dropped: Hit[] = []
  for (const h of hits) {
    const keys = h.type === 'ip' ? [`i:${h.value}`] : domainCandidates(h.value).map(n => `d:${n}`)
    const key = keys.find(k => byListed.has(k))
    if (!key) { dropped.push(h); continue }
    const indicators = byListed.get(key)!
    const g = groups.get(key) ?? {
      listed: key.slice(2),
      itype: indicators.some(i => i.type !== 'url') ? indicators.find(i => i.type !== 'url')!.type : 'url',
      hits: [], indicators,
    }
    g.hits.push(h)
    groups.set(key, g)
  }
  return { matched: [...groups.values()], dropped }
}

/** S1: a contact is stronger evidence than R5's listing. Feed entries and high-level events
 *  give critical, medium events high, low events medium; a URL's host one step lower. */
export function sightingSeverity(indicators: IndicatorRow[]): Severity {
  const rank = (r: IndicatorRow) =>
    (r.tiEventId === null ? 4 : r.level === 'high' ? 4 : r.level === 'medium' ? 3 : 2) - (r.type === 'url' ? 1 : 0)
  const best = Math.max(1, ...indicators.map(rank))
  return SEVERITIES[best - 1]!
}

// ── The plan ─────────────────────────────────────────────────────────
export interface ExistingSighting {
  eventId: string
  status: 'open' | 'in_progress' | 'resolved' | 'false_positive' | 'accepted_risk'
  resolvedAt: Date | null
  details: Record<string, unknown>
}

export interface SightingWrite {
  eventId: string
  severity: Severity
  details: Record<string, unknown>
  firstSeen: Date
  lastSeen: Date
  indicatorIds: string[]
}

export interface SightingPlan {
  insert: SightingWrite[]
  update: (SightingWrite & { reopen: boolean; prevStatus: ExistingSighting['status'] })[]
}

const iso = (d: Date) => d.toISOString()
const dateOf = (v: unknown): Date | null => (typeof v === 'string' && !isNaN(Date.parse(v)) ? new Date(v) : null)
const uniq = <T>(xs: T[]) => [...new Set(xs)]

/** New alerts and updates, one per (asset, listed value). Counts add up across uploads
 *  (the agent sends what it saw since its last upload). */
export function planSightings(input: {
  matched: Matched[]
  existing: ExistingSighting[]
  newId: () => string
}): SightingPlan {
  const plan: SightingPlan = { insert: [], update: [] }
  const byKey = new Map(input.existing.map(e => [String(e.details.indicator_value ?? ''), e]))
  for (const m of input.matched) {
    const latest = m.hits.reduce((a, b) => (b.lastSeen > a.lastSeen ? b : a))
    const first = m.hits.reduce((a, b) => (b.firstSeen < a.firstSeen ? b : a)).firstSeen
    const count = m.hits.reduce((n, h) => n + h.count, 0)
    const withProcess = m.hits.filter(h => h.process).sort((a, b) => b.lastSeen.getTime() - a.lastSeen.getTime())[0]
    const withPort = m.hits.filter(h => h.port).sort((a, b) => b.lastSeen.getTime() - a.lastSeen.getTime())[0]
    const titles = uniq(m.indicators.map(i => i.title).filter((t): t is string => !!t))
    const knowledge = {
      indicator_type: m.itype, indicator_value: m.listed, match_kind: 'sighting', rule: 'R7',
      sources: uniq(m.indicators.map(i => i.title ?? i.source)),
      ti_event_titles: titles,
      ti_event_ids: uniq(m.indicators.map(i => i.tiEventId).filter((t): t is string => !!t)),
      ...(m.itype === 'url' ? { listed_urls: uniq(m.indicators.map(i => i.value)).slice(0, 5) } : {}),
    }
    const severity = sightingSeverity(m.indicators)
    const indicatorIds = m.indicators.map(i => i.indicatorId)
    const prev = byKey.get(m.listed)

    if (!prev) {
      plan.insert.push({
        eventId: input.newId(), severity, firstSeen: first, lastSeen: latest.lastSeen, indicatorIds,
        details: {
          ...knowledge, matched_on: latest.via, seen_via: uniq(m.hits.map(h => h.via)).sort(), observed: latest.value,
          count, first_seen_at: iso(first), last_seen_at: iso(latest.lastSeen),
          process: withProcess?.process ?? null, port: withPort?.port ?? null,
        },
      })
      continue
    }

    const d = prev.details
    const prevFirst = dateOf(d.first_seen_at)
    const prevLast = dateOf(d.last_seen_at)
    const newer = !prevLast || latest.lastSeen >= prevLast
    const lastSeen = prevLast && prevLast > latest.lastSeen ? prevLast : latest.lastSeen
    const firstSeen = prevFirst && prevFirst < first ? prevFirst : first
    // A contact after the alert was resolved is new evidence; one from before is a late upload.
    const reopen = prev.status === 'resolved' && (!prev.resolvedAt || latest.lastSeen > prev.resolvedAt)
    plan.update.push({
      eventId: prev.eventId, severity, firstSeen, lastSeen, indicatorIds, reopen, prevStatus: prev.status,
      details: {
        ...d, ...knowledge,
        matched_on: newer ? latest.via : d.matched_on ?? latest.via,
        seen_via: uniq([...(Array.isArray(d.seen_via) ? (d.seen_via as string[]) : []), ...m.hits.map(h => h.via)]).sort(),
        observed: newer ? latest.value : d.observed ?? latest.value,
        count: (typeof d.count === 'number' ? d.count : 0) + count,
        first_seen_at: iso(firstSeen), last_seen_at: iso(lastSeen),
        process: (newer ? withProcess?.process : null) ?? d.process ?? withProcess?.process ?? null,
        port: (newer ? withPort?.port : null) ?? d.port ?? withPort?.port ?? null,
      },
    })
  }
  return plan
}
