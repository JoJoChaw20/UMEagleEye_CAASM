/**
 * Discovery page: which network each scan record belongs to, what kind of scan it was,
 * and the per-network summary cards. PURE (no DB); tested by scripts/pages-redesign-demo.ts.
 *
 * scan_results.network_info (from the agent, see routes/scans.ts ingest) holds
 *   subnet      the LAN the agent listens on for a passive record; the scanned range for an active one
 *   lan_subnet  the LAN the agent listens on (agent 2.2.4+), on both
 *   gateway_ip  the LAN's router
 *   trigger     'new_device' on an automatic new-device check (services/autoInvestigate.ts)
 */

export type ScanKind = 'passive' | 'investigation' | 'network' | 'host'

export interface ScanRecordFacts {
  scanType: string
  subnet: string | null
  networkInfo: unknown
}

const CIDR = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/

function info(r: ScanRecordFacts): Record<string, unknown> {
  return r.networkInfo && typeof r.networkInfo === 'object' ? (r.networkInfo as Record<string, unknown>) : {}
}
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null)

export function isCidr(v: string | null | undefined): boolean {
  const m = v ? CIDR.exec(v) : null
  return !!m && Number(m[2]) <= 32 && m[1]!.split('.').every((o) => Number(o) <= 255)
}

export function scanKind(r: ScanRecordFacts): ScanKind {
  if (r.scanType === 'passive') return 'passive'
  if (info(r)['trigger'] === 'new_device') return 'investigation'
  return isCidr(r.subnet) && !r.subnet!.endsWith('/32') ? 'network' : 'host'
}

/**
 * The network a record belongs to: a full scan's own range; otherwise the LAN the agent
 * was on. Null when the record says nothing about it (agents before 2.2.4 on single-host
 * scans, old passive records).
 */
export function networkOf(r: ScanRecordFacts): { subnet: string; gateway: string | null } | null {
  const i = info(r)
  const gateway = str(i['gateway_ip'])
  const kind = scanKind(r)
  const subnet = kind === 'network'
    ? r.subnet
    : kind === 'passive'
      ? str(i['lan_subnet']) ?? str(i['subnet'])
      : str(i['lan_subnet'])
  if (!subnet || !isCidr(subnet)) return null
  // A full scan of another range than the agent's own LAN: the LAN's gateway is not this range's.
  const sameLan = kind !== 'network' || str(i['lan_subnet']) === subnet
  return { subnet, gateway: sameLan ? gateway : null }
}

/** The passive network a record was heard on (folding key, see routes/scans.ts ingest). */
export function passiveNetworkOf(network: { subnet?: string | null; lan_subnet?: string | null } | null | undefined): string | null {
  return str(network?.lan_subnet) ?? str(network?.subnet)
}

function ipToInt(ip: string): number | null {
  if (!IPV4.test(ip)) return null
  const parts = ip.split('.').map(Number)
  if (parts.some((p) => p > 255)) return null
  return ((parts[0]! << 24) >>> 0) + (parts[1]! << 16) + (parts[2]! << 8) + parts[3]!
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const m = CIDR.exec(cidr)
  const addr = ipToInt(ip)
  if (!m || addr === null) return false
  const base = ipToInt(m[1]!)
  const bits = Number(m[2])
  if (base === null || bits > 32) return false
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
  return ((addr & mask) >>> 0) === ((base & mask) >>> 0)
}

export interface NetworkRecord extends ScanRecordFacts {
  scanId: string
  agentId: string | null
  status: string
  hostsDiscovered: number
  startedAt: Date | string
  completedAt: Date | string | null
}

export interface NetworkSummary {
  subnet: string
  gateway: string | null
  agent_ids: string[]
  /** Last passive upload heard on it, and that record (its hosts) */
  last_heard_at: string | null
  last_heard_scan_id: string | null
  /** Last completed full scan of the range, and how many hosts it found */
  last_full_scan: { scan_id: string; at: string; hosts: number } | null
  /** Distinct IPs seen on it (any scan) in the last 24 hours */
  hosts_24h: number
  /** Open new-device alerts whose IP is in the range */
  new_devices: number
  /** Agent that was on it most recently (the one "Scan this network" uses) */
  latest_agent_id: string | null
  latest_at: string
}

const iso = (v: Date | string | null): string | null => (v == null ? null : new Date(v).toISOString())

/**
 * One summary per network, most recently active first. ipsByScan: the IPs in each record
 * of the last 24 hours. newDeviceIps: the IPs of open new-device alerts.
 */
export function buildNetworks(
  records: NetworkRecord[], ipsByScan: Map<string, string[]>, newDeviceIps: string[],
): NetworkSummary[] {
  const nets = new Map<string, NetworkSummary & { ips: Set<string>; agents: Set<string>; latestTs: number }>()
  for (const r of records) {
    const net = networkOf(r)
    if (!net) continue
    const when = new Date(r.completedAt ?? r.startedAt).getTime()
    let n = nets.get(net.subnet)
    if (!n) {
      n = {
        subnet: net.subnet, gateway: net.gateway, agent_ids: [], last_heard_at: null, last_heard_scan_id: null, last_full_scan: null,
        hosts_24h: 0, new_devices: 0, latest_agent_id: null, latest_at: new Date(when).toISOString(),
        ips: new Set(), agents: new Set(), latestTs: -Infinity,
      }
      nets.set(net.subnet, n)
    }
    if (!n.gateway && net.gateway) n.gateway = net.gateway
    if (r.agentId) n.agents.add(r.agentId)
    if (when > n.latestTs) {
      n.latestTs = when
      n.latest_at = new Date(when).toISOString()
      if (r.agentId) n.latest_agent_id = r.agentId
    }
    const kind = scanKind(r)
    if (kind === 'passive' && (!n.last_heard_at || when > Date.parse(n.last_heard_at))) {
      n.last_heard_at = iso(new Date(when))
      n.last_heard_scan_id = r.scanId
    }
    if (kind === 'network' && r.status === 'completed' && (!n.last_full_scan || when > Date.parse(n.last_full_scan.at))) {
      n.last_full_scan = { scan_id: r.scanId, at: new Date(when).toISOString(), hosts: r.hostsDiscovered }
    }
    for (const ip of ipsByScan.get(r.scanId) ?? []) if (ipInCidr(ip, net.subnet)) n.ips.add(ip)
  }
  return [...nets.values()]
    .map(({ ips, agents, latestTs: _latest, ...n }) => ({
      ...n,
      agent_ids: [...agents],
      hosts_24h: ips.size,
      new_devices: newDeviceIps.filter((ip) => ipInCidr(ip, n.subnet)).length,
    }))
    .sort((a, b) => Date.parse(b.latest_at) - Date.parse(a.latest_at))
}
