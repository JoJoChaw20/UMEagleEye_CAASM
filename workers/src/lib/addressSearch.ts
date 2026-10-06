/**
 * addressSearch.ts — PURE helpers for Inventory search over current + historical
 * addresses (asset_addresses). No DB, no Hono. Tested by inventory-search-demo.ts.
 *
 * The list route builds the SQL match condition (EXISTS over asset_addresses) and
 * fetches the page's address rows in ONE extra query; these helpers then decide,
 * in memory, WHY each returned asset matched and cap the history it reports. The
 * JS matchers mirror the SQL exactly so the "why" never disagrees with the "what":
 *   - IP  : case-insensitive substring (ILIKE %term%)
 *   - MAC : full term → normalizeMac equality; fragment → separator-insensitive
 *           contains (compare with ':', '-', '.' stripped, lowercased)
 */
import { normalizeMac } from './mac'

export type MatchField = 'hostname' | 'current_ip' | 'current_mac' | 'vendor' | 'other' | 'address_history'

export interface AddrRow {
  addressId: string
  assetId: string
  networkKey: string | null
  ipAddress: string
  macAddress: string | null
  firstSeen: string | Date | null
  lastSeen: string | Date | null
  endedAt: string | Date | null
}

export interface MatchEntry {
  field: MatchField
  ip: string | null
  mac: string | null
  networkKey: string | null
  firstSeen: string | Date | null
  lastSeen: string | Date | null
  endedAt: string | Date | null
  isCurrent: boolean
  addressId?: string
}

export interface MatchAsset {
  assetId: string
  hostname: string | null
  ipAddress: string
  macAddress: string | null
  hardwareVendor: string | null
}

const ms = (v: string | Date | null | undefined): number => (v ? new Date(v).getTime() : 0)
const strip = (s: string): string => s.toLowerCase().replace(/[:.\-]/g, '')

/** A term "looks like a MAC fragment" if it carries a hex letter or a MAC separator
 *  (':' or '-'). Pure-numeric/dotted fragments (e.g. "192.168.0.") are treated as
 *  IP only, so an IP search never spuriously scans MAC columns. */
export function looksMacFragment(term: string): boolean {
  return /[a-f]/i.test(term) || /[:\-]/.test(term)
}

export function ipMatches(ip: string | null | undefined, term: string): boolean {
  if (!ip) return false
  return ip.toLowerCase().includes(term.toLowerCase())
}

export function textMatches(s: string | null | undefined, term: string): boolean {
  if (!s) return false
  return s.toLowerCase().includes(term.toLowerCase())
}

export function macMatches(mac: string | null | undefined, term: string): boolean {
  if (!mac) return false
  const nm = normalizeMac(term)
  if (nm) return mac.toLowerCase() === nm            // full MAC → exact (normalized)
  if (!looksMacFragment(term)) return false          // pure IP-ish fragment → not a MAC search
  const frag = strip(term)
  if (!/^[0-9a-f]+$/.test(frag) || frag.length < 2) return false
  return strip(mac).includes(frag)                   // fragment → separator-insensitive contains
}

/** An address row matches the term if its IP or MAC matches. */
export function addressRowMatches(row: AddrRow, term: string): boolean {
  return ipMatches(row.ipAddress, term) || macMatches(row.macAddress, term)
}

/**
 * Explain why `asset` matched `term`, using the asset row plus its own address
 * rows (caller passes only this asset's rows; foreign rows are ignored defensively).
 * Returns the ordered match reasons and the total count of matching history rows
 * (so the UI can show "+N more" when it exceeds the cap).
 */
export function computeMatches(
  asset: MatchAsset,
  addrRows: AddrRow[],
  term: string,
  cap = 5,
): { matches: MatchEntry[]; matchedAddressCount: number } {
  const matches: MatchEntry[] = []
  const base = { networkKey: null, firstSeen: null, lastSeen: null, endedAt: null, isCurrent: true } as const

  const currentIp = ipMatches(asset.ipAddress, term)
  if (textMatches(asset.hostname, term)) matches.push({ field: 'hostname', ip: null, mac: null, ...base })
  if (currentIp) matches.push({ field: 'current_ip', ip: asset.ipAddress, mac: asset.macAddress ?? null, ...base })
  if (macMatches(asset.macAddress, term)) matches.push({ field: 'current_mac', ip: asset.ipAddress, mac: asset.macAddress, ...base })
  if (textMatches(asset.hardwareVendor, term)) matches.push({ field: 'vendor', ip: null, mac: null, ...base })

  // History: matching rows belonging to THIS asset, excluding the live address
  // (ended_at NULL and IP == the asset's current IP) — it's the device's current
  // location, already reported as current_ip/current_mac, not "history".
  const history = addrRows
    .filter(r => r.assetId === asset.assetId && addressRowMatches(r, term))
    .filter(r => !(r.endedAt == null && r.ipAddress === asset.ipAddress))
    .sort((a, b) => ms(b.lastSeen) - ms(a.lastSeen))

  for (const r of history.slice(0, cap)) {
    matches.push({
      field: 'address_history', ip: r.ipAddress, mac: r.macAddress ?? null, networkKey: r.networkKey ?? null,
      firstSeen: r.firstSeen ?? null, lastSeen: r.lastSeen ?? null, endedAt: r.endedAt ?? null,
      isCurrent: r.endedAt == null, addressId: r.addressId,
    })
  }
  return { matches, matchedAddressCount: history.length }
}

/** Ordering rank for a term search: 0 = matched on a current searchable field
 *  (hostname / vendor / current IP / current MAC), 1 = matched only through address
 *  history. Lower sorts first (ties: last_scanned desc, applied by the caller).
 *  Mirrors the SQL ORDER BY CASE in the list route (rowFieldMatch includes vendor). */
const RANK0: ReadonlySet<MatchField> = new Set<MatchField>(['hostname', 'vendor', 'current_ip', 'current_mac'])
export function matchRank(matches: MatchEntry[]): 0 | 1 {
  return matches.some(m => RANK0.has(m.field)) ? 0 : 1
}
