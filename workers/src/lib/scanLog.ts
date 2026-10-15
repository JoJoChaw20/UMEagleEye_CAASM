/**
 * Discovery log (scan_results.raw_results) housekeeping. PURE (no DB); tested by
 * scripts/scan-log-demo.ts.
 *
 *  - mergePassiveHosts: an agent's passive uploads within an hour are folded into ONE
 *    Discovery record instead of one record per upload (about one a minute).
 *  - planScanLogPurge: when an asset is deleted, its host entries leave the Discovery
 *    log too, and records left with no hosts by that are deleted.
 */
import { normalizeMac } from './mac'

/** Passive uploads from one agent within this window share one Discovery record. */
export const PASSIVE_FOLD_MINUTES = 60

type HostEntry = Record<string, unknown>

const entryIp = (h: HostEntry): string | null => (typeof h['ip'] === 'string' && h['ip'] ? h['ip'] : null)
const entryMac = (h: HostEntry): string | null => normalizeMac(typeof h['mac'] === 'string' ? h['mac'] : null)
const asEntries = (raw: unknown): HostEntry[] =>
  Array.isArray(raw) ? raw.filter((h): h is HostEntry => typeof h === 'object' && h !== null) : []

/**
 * Hosts already in an open passive record plus a new upload. A host is the same entry
 * when IP and MAC both match; the newer upload replaces it in place (latest names and
 * services). The same IP with another MAC is another device (DHCP reuse): both stay.
 * New hosts are appended, so the record reads in the order hosts were first heard.
 */
export function mergePassiveHosts(existing: unknown, incoming: HostEntry[]): HostEntry[] {
  const key = (h: HostEntry) => `${entryIp(h) ?? ''}|${entryMac(h) ?? ''}`
  const merged = asEntries(existing)
  const index = new Map(merged.map((h, i) => [key(h), i]))
  for (const h of incoming) {
    const k = key(h)
    const at = index.get(k)
    if (at !== undefined) merged[at] = h
    else { index.set(k, merged.length); merged.push(h) }
  }
  return merged
}

export interface ScanLogRow {
  scanId: string
  status: string
  rawResults: unknown
}
export interface ScanLogPurge {
  updates: { scanId: string; rawResults: HostEntry[]; hostsDiscovered: number }[]
  deletes: string[]
  entriesRemoved: number
}

/**
 * The deleted asset's entries in the Discovery log. An entry is the asset's only when
 * its IP is one the asset had AND its MAC is one of the asset's MACs or absent. A MAC
 * alone is not enough (shared virtual MACs such as the KM-TEST loopback 02:00:4c:4f:4f:50
 * are the same on every PC) and neither is an IP alone (DHCP gives it to another device).
 * Records still in progress are left alone. A record that this empties is deleted; one
 * that never had hosts ("Completed / 0 hosts") is not touched.
 */
export function planScanLogPurge(rows: ScanLogRow[], asset: { ips: string[]; macs: (string | null)[] }): ScanLogPurge {
  const ips = new Set(asset.ips.filter(Boolean))
  const macs = new Set(asset.macs.map(m => normalizeMac(m)).filter((m): m is string => !!m))
  const isAssets = (h: HostEntry) => {
    const ip = entryIp(h)
    if (!ip || !ips.has(ip)) return false
    const mac = entryMac(h)
    return mac === null || macs.has(mac)
  }
  const out: ScanLogPurge = { updates: [], deletes: [], entriesRemoved: 0 }
  for (const row of rows) {
    if (row.status === 'pending' || row.status === 'running') continue
    const hosts = asEntries(row.rawResults)
    const kept = hosts.filter(h => !isAssets(h))
    const removed = hosts.length - kept.length
    if (removed === 0) continue
    out.entriesRemoved += removed
    if (kept.length === 0) out.deletes.push(row.scanId)
    else out.updates.push({ scanId: row.scanId, rawResults: kept, hostsDiscovered: kept.length })
  }
  return out
}
