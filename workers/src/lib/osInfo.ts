/**
 * Additive merge of scan-observed os_info onto an asset's stored os_info.
 *
 * Production incident this guards against: a passive scan POSTed os_info = {},
 * the upsert did a wholesale `EXCLUDED.os_info` replace, and an active scan's
 * rich os_info (ports/products + SNMP facts) was wiped — which also dropped the
 * criticality score because scoring reads osInfo.ports.
 *
 * Rules:
 *  a) Keys the scan did not observe are preserved (snmp_*, dhcp_*, fingerbank_*,
 *     ai_description, ai_suggestion, name, version, …). They are simply omitted
 *     from `incoming`, so the SQL `||` merge leaves the stored value untouched.
 *  b) Passive scans never touch the port-derived keys (ports/products/versions).
 *  c) Active scans are authoritative for ports/products/versions and always
 *     write all three — an empty array clears stale values.
 *  d) For every other key, a non-empty incoming value wins; an empty incoming
 *     value is dropped so the existing value survives.
 *  e) Ports are kept per scanned address (ports_by_ip). A device with two network cards
 *     (a Docker port bound to one) is scanned through either; each scan replaces only that
 *     address's ports, and the device's ports/services are the union. So a scan through the
 *     other card no longer "closes" ports and flaps their alerts. An address that is no
 *     longer one of the device's (`currentIps`) is dropped.
 */

/** Port-derived keys only an active (port-scanning) ingest may author. */
const PORT_KEYS = ['ports', 'products', 'versions', 'services'] as const

function isEmptyValue(v: unknown): boolean {
  if (v === null || v === undefined) return true
  if (typeof v === 'string') return v.trim() === ''
  if (Array.isArray(v)) return v.length === 0
  if (typeof v === 'object') return Object.keys(v as Record<string, unknown>).length === 0
  return false
}

export interface MergedOsInfo {
  /**
   * The subset to write as the INSERT ... VALUES os_info, so that the SQL
   * `COALESCE(assets.os_info, '{}'::jsonb) || EXCLUDED.os_info` upsert produces
   * the correct additive merge. Omitted keys fall through to the stored value.
   */
  incoming: Record<string, unknown>
  /**
   * Full shallow merge of existing + incoming — identical to what the jsonb `||`
   * operator produces — used for criticality scoring and the first-discovery
   * baseline (where `existing` is null, so this equals `incoming`).
   */
  merged: Record<string, unknown>
}

/** What an active scan saw at one address: its ports ("22/tcp") and when. */
export interface AddressPorts { ports: string[]; seen_at: string }

const portKey = (s: Record<string, unknown>) => `${s.port}/${s.protocol ?? 'tcp'}`

function addressPortsOf(v: unknown): Record<string, AddressPorts> {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return {}
  const out: Record<string, AddressPorts> = {}
  for (const [ip, e] of Object.entries(v as Record<string, unknown>)) {
    const r = e as Record<string, unknown> | null
    if (r && Array.isArray(r.ports) && typeof r.seen_at === 'string') {
      out[ip] = { ports: r.ports.filter((p): p is string => typeof p === 'string'), seen_at: r.seen_at }
    }
  }
  return out
}

export function mergeOsInfo(
  existing: Record<string, unknown> | null | undefined,
  incoming: Record<string, unknown> | null | undefined,
  isPassive: boolean,
  // the address an active scan reached, and the device's current addresses when known (rule e)
  scanned?: { ip: string; currentIps?: string[] | null; now?: Date },
): MergedOsInfo {
  const base = (existing ?? {}) as Record<string, unknown>
  const src = (incoming ?? {}) as Record<string, unknown>

  const filtered: Record<string, unknown> = {}

  // Non-port keys: incoming wins only when non-empty (rule d); port keys are
  // handled separately below so passive input can never reach them (rule b).
  for (const [key, value] of Object.entries(src)) {
    if ((PORT_KEYS as readonly string[]).includes(key)) continue
    if (!isEmptyValue(value)) filtered[key] = value
  }

  if (!isPassive) {
    // Rule (c): active owns the port-derived keys and always writes them,
    // using [] when the scan found none so stale values are cleared.
    for (const key of PORT_KEYS) {
      const v = src[key]
      filtered[key] = Array.isArray(v) ? v : []
    }
    if (scanned?.ip) {
      // Rule (e): this address's ports replaced; the other addresses' kept (while they are
      // still the device's), and the device's ports and services are the union.
      const byIp: Record<string, AddressPorts> = {}
      for (const [ip, e] of Object.entries(addressPortsOf(base.ports_by_ip))) {
        if (ip !== scanned.ip && (!scanned.currentIps || scanned.currentIps.includes(ip))) byIp[ip] = e
      }
      const here = (filtered.ports as unknown[]).filter((p): p is string => typeof p === 'string')
      byIp[scanned.ip] = { ports: here, seen_at: (scanned.now ?? new Date()).toISOString() }
      const elsewhere = new Set(Object.entries(byIp).filter(([ip]) => ip !== scanned.ip).flatMap(([, e]) => e.ports))
      const seenHere = new Set(here)
      const kept = (Array.isArray(base.services) ? base.services as Record<string, unknown>[] : [])
        .filter((s) => s && elsewhere.has(portKey(s)) && !seenHere.has(portKey(s)))
      const services = [...(filtered.services as unknown[]), ...kept]
      filtered.services = services
      filtered.ports = [...new Set([...here, ...elsewhere])]
      filtered.products = [...new Set([...(filtered.products as unknown[]), ...kept.map((s) => s.product).filter(Boolean)])]
      filtered.versions = [...new Set([...(filtered.versions as unknown[]), ...kept.map((s) => s.version).filter(Boolean)])]
      filtered.ports_by_ip = byIp
    }
  }
  // Rule (b): passive → port keys omitted entirely, stored values survive.

  return { incoming: filtered, merged: { ...base, ...filtered } }
}
