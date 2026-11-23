// The organisation's public addresses (D4, docs/plans/2026-11-23-public-addresses.md): which address a
// heartbeat came from, when to store it, and what an address's status may be. Pure; the database side
// is services/publicAddresses.ts.
import { inSpecialRange } from './warninglist'

export const PUBLIC_ADDRESS_STATUSES = ['unconfirmed', 'ours', 'not_ours'] as const
export type PublicAddressStatus = typeof PUBLIC_ADDRESS_STATUSES[number]

export function isPublicAddressStatus(v: unknown): v is PublicAddressStatus {
  return typeof v === 'string' && (PUBLIC_ADDRESS_STATUSES as readonly string[]).includes(v)
}

// A heartbeat from the same address stores it again (last seen) at most this often.
export const REFRESH_MS = 60 * 60 * 1000

// Phones are left out: on mobile data they report the carrier's address, shared by thousands.
export const RECORDED_KINDS: ReadonlySet<string> = new Set(['host', 'network'])

const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

/** The address in canonical form when it is a public unicast address (IPv4, or IPv6 global unicast
 *  2000::/3 outside the documentation range), else null: private, special and malformed values. */
export function publicIpOf(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  let v = raw.trim().toLowerCase()
  if (!v || v.length > 45) return null
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(v)
  if (mapped) v = mapped[1]!
  if (V4.test(v)) return inSpecialRange(v) ? null : v
  if (!v.includes(':') || !/^[0-9a-f:.]+$/.test(v)) return null
  let canon: string
  try {
    canon = new URL(`http://[${v}]/`).hostname.slice(1, -1)
  } catch {
    return null
  }
  if (!/^[23]/.test(canon) || canon.startsWith('2001:db8:')) return null
  return canon
}

// ── R11: the organisation's own address on a blocklist ────────────────────────────────
// What lists say about an address. 'c2': a botnet command-and-control or malware-server list (Feodo
// Tracker, ThreatFox) with at least medium confidence; 'malware': a malware download site's host
// (URLhaus); 'range': a network range Spamhaus DROP lists (hijacked or run by criminals); 'event': a
// published threat-intel event names it.
export type ListKind = 'c2' | 'malware' | 'range' | 'event'
export interface Listing {
  kind: ListKind
  source: string              // "Feodo Tracker", "Spamhaus DROP", an event's title
  value: string               // the listed value: the IP, the URL, the range
  confidence: number | null   // 0-1, the feed's own; null for ranges and events
  family: string | null
  ref: string | null          // DROP's SBL id, the event id
}

export const C2_SOURCES: ReadonlySet<string> = new Set(['Feodo Tracker', 'ThreatFox'])
const C2_MIN_CONFIDENCE = 0.5

/** How a matched feed indicator counts: an IP on a C2 / malware-server feed, a URLhaus URL on the IP. */
export function listKindOf(source: string, indicatorType: string, confidence: number | null, fromEvent: boolean): ListKind {
  if (fromEvent) return 'event'
  if (indicatorType === 'ip' && C2_SOURCES.has(source) && (confidence ?? 1) >= C2_MIN_CONFIDENCE) return 'c2'
  return 'malware'
}

export type Severity = 'low' | 'medium' | 'high' | 'critical'

/** The R11 alert's severity, or null for no alert: an address marked "not ours" never alerts, and an
 *  unconfirmed one is a review item (it may be a laptop's home network or a shared campus address). */
export function r11Severity(status: PublicAddressStatus, listings: readonly Listing[]): Severity | null {
  if (status === 'not_ours' || listings.length === 0) return null
  const c2 = listings.some((l) => l.kind === 'c2')
  if (status === 'ours') return c2 ? 'critical' : 'high'
  return c2 ? 'medium' : 'low'
}

export interface R11Want { assetId: string; ip: string; severity: Severity; details: Record<string, unknown> }
export interface R11Have { eventId: string; assetId: string; ip: string; status: string; severity: string; details: Record<string, unknown> }
export interface R11Plan {
  create: R11Want[]
  update: { eventId: string; want: R11Want; reopen: boolean }[]
  resolve: string[]
}

/** Listings compared by content: the database returns JSON with its keys in another order. */
function listingsKey(v: unknown): string {
  if (!Array.isArray(v)) return ''
  return v.map((l: Partial<Listing>) => [l.kind, l.source, l.value, l.ref, l.confidence, l.family].join('|')).sort().join('\n')
}

/** One alert per (asset, address). False positives and accepted risks stay closed. */
export function planR11(want: readonly R11Want[], have: readonly R11Have[]): R11Plan {
  const plan: R11Plan = { create: [], update: [], resolve: [] }
  const key = (assetId: string, ip: string) => `${assetId}|${ip}`
  const wanted = new Map(want.map((w) => [key(w.assetId, w.ip), w]))
  const seen = new Set<string>()
  for (const h of have) {
    const k = key(h.assetId, h.ip)
    const w = wanted.get(k)
    if (seen.has(k)) continue
    seen.add(k)
    if (h.status === 'false_positive' || h.status === 'accepted_risk') continue
    if (!w) {
      if (h.status === 'open' || h.status === 'in_progress') plan.resolve.push(h.eventId)
      continue
    }
    const reopen = h.status === 'resolved'
    if (reopen || h.severity !== w.severity || listingsKey(h.details.listings) !== listingsKey(w.details.listings)
      || h.details.address_status !== w.details.address_status) {
      plan.update.push({ eventId: h.eventId, want: w, reopen })
    }
  }
  for (const [k, w] of wanted) if (!seen.has(k)) plan.create.push(w)
  return plan
}

/** The alert's details: shaped like the other threat-intel matches (indicator, matched on, rule). */
export function r11Details(ip: string, publicAddressId: string, status: PublicAddressStatus, listings: Listing[]): Record<string, unknown> {
  return {
    indicator_type: 'ip', indicator_value: ip, matched_on: 'public_ip', observed: ip,
    match_kind: 'public_address', rule: 'R11', public_address_id: publicAddressId, address_status: status,
    sources: [...new Set(listings.map((l) => l.source))], listings,
  }
}

/** Whether a heartbeat stores the agent's public address: it changed, or the stored one is REFRESH_MS old. */
export function shouldRecordPublicIp(prev: { ip: string | null; at: Date | null }, ip: string, now: Date): boolean {
  if (prev.ip !== ip || !prev.at) return true
  return now.getTime() - prev.at.getTime() >= REFRESH_MS
}
