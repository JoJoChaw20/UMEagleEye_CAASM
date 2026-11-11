// The tenant's networks as its agents see them, for the Network map (GET /network/map
// `networks`): one entry per network (an address range, asset_addresses.network_key), with its
// gateway, the agents that watch it and the devices on it. Pure; services/networkMap.ts loads
// the inputs. The measured layer (routers, switches, cables: lib/networkMap.ts) stays as it is;
// a device placed on a measured switch port is counted here but drawn there.
//
// A network is identified by its range. When two gateways with different MACs answer at the
// same gateway address in one range, it is probably two sites using the same range (a home and
// an office on 192.168.0.0/24): the entry says so (`gateway_macs`) instead of guessing which
// device is where.

import { cidrContainsIp, cidrStrictlyContains, parseCidr, parseIpv4, type Cidr } from './networkScope'
import { normalizeMac } from './mac'

/** A current address of a device (asset_addresses, ended_at null), with its asset's facts. */
export interface NetAddress {
  asset_id: string
  network_key: string
  ip: string
  mac: string | null
  last_seen: string
  label: string
  device_type: string | null
  criticality: number | null
  in_my_assets: boolean
  measured: boolean                 // placed on a switch port by a network agent (drawn in the measured layer)
}

export interface NetAgent {
  agent_id: string
  name: string
  kind: string                      // host | mobile | network
  networks: string[]                // reported CIDRs (host agents)
  default_gateway: string | null
  host_asset_id: string | null
  listens: boolean                  // passive listening on
  scans: boolean                    // runs the dashboard's scans
}

/** A gateway an agent reported with an upload (scan_results.network_info). */
export interface GatewaySighting { subnet: string | null; gateway_ip: string; gateway_mac: string | null; at: string }

export interface AssetAlerts {
  cve_open: number; cve_critical: number; cve_high: number; kev: number
  exposure_open: number; exposure_severity: string | null
}

export interface NetworkDevice {
  asset_id: string; label: string; ip: string; mac: string | null; device_type: string | null
  criticality: number | null; in_my_assets: boolean; last_seen: string; measured: boolean
  agent: 'host' | 'mobile' | null    // an EagleEye agent runs on it (a computer's or the phone app)
  alerts: AssetAlerts
}

export interface MapNetwork {
  key: string
  gateway: { ip: string; mac: string | null; asset_id: string | null; label: string | null } | null
  gateway_macs: string[]            // more than one: probably two sites on the same range
  agents: { agent_id: string; name: string; listens: boolean; scans: boolean }[]
  phones: { agent_id: string; name: string }[]
  coverage: 'watched' | 'listen_only' | 'scan_only' | 'none'
  device_count: number
  measured_count: number
  devices: NetworkDevice[]          // at most MAX_DEVICES, most important first
  last_seen: string | null
}

export const MAX_DEVICES = 500
const NO_ALERTS: AssetAlerts = { cve_open: 0, cve_critical: 0, cve_high: 0, kev: 0, exposure_open: 0, exposure_severity: null }
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }

const overlaps = (a: Cidr, b: Cidr) =>
  (a.net === b.net && a.prefix === b.prefix) || cidrStrictlyContains(a, b) || cidrStrictlyContains(b, a)
const later = (a: string | null, b: string | null) => (!a ? b : !b ? a : a > b ? a : b)

/** The importance order of a network's devices: an agent's own computer, then open alerts, then name. */
function rank(d: NetworkDevice): number[] {
  const a = d.alerts
  return [d.agent ? 0 : 1, -a.cve_critical, -(SEVERITY_RANK[a.exposure_severity ?? ''] ?? 0), -a.cve_open, d.in_my_assets ? 0 : 1]
}
function byImportance(x: NetworkDevice, y: NetworkDevice): number {
  const rx = rank(x), ry = rank(y)
  for (let i = 0; i < rx.length; i++) if (rx[i] !== ry[i]) return rx[i]! - ry[i]!
  return x.label.localeCompare(y.label) || x.ip.localeCompare(y.ip)
}

export function buildMapNetworks(
  addresses: NetAddress[], agents: NetAgent[], sightings: GatewaySighting[], alerts: Map<string, AssetAlerts>,
): MapNetwork[] {
  const hostAgents = agents.filter((a) => a.kind === 'host')
  const agentOf = new Map<string, 'host' | 'mobile'>()
  for (const a of agents) {
    if (a.host_asset_id && (a.kind === 'host' || a.kind === 'mobile')) {
      if (agentOf.get(a.host_asset_id) !== 'host') agentOf.set(a.host_asset_id, a.kind)
    }
  }

  // The networks: every range a device has a current address in, and every range a computer
  // agent reports it is on (an agent's network with nothing found yet still shows).
  const keys = new Map<string, Cidr | null>()
  for (const r of addresses) if (!keys.has(r.network_key)) keys.set(r.network_key, parseCidr(r.network_key))
  for (const a of hostAgents) {
    for (const n of a.networks) {
      const c = parseCidr(n)
      if (!c || [...keys.values()].some((k) => k && overlaps(k, c))) continue
      keys.set(n, c)
    }
  }

  const out: MapNetwork[] = []
  for (const [key, cidr] of keys) {
    const rows = addresses.filter((r) => r.network_key === key)
    const inRange = (ip: string | null | undefined) => {
      const n = parseIpv4(ip)
      return cidr !== null && n !== null && cidrContainsIp(cidr, n)
    }

    const watchers = hostAgents.filter((a) => cidr && a.networks.some((n) => {
      const c = parseCidr(n)
      return c !== null && overlaps(c, cidr)
    }))
    const phones = agents.filter((a) => a.kind === 'mobile' && a.host_asset_id && rows.some((r) => r.asset_id === a.host_asset_id))

    // The gateway: the one the agents here report, else the one their uploads named for this range.
    const votes = new Map<string, number>()
    for (const a of watchers) if (inRange(a.default_gateway)) votes.set(a.default_gateway!, (votes.get(a.default_gateway!) ?? 0) + 2)
    const seen = sightings.filter((s) => s.subnet === key || inRange(s.gateway_ip))
    for (const s of seen) if (inRange(s.gateway_ip)) votes.set(s.gateway_ip, (votes.get(s.gateway_ip) ?? 0) + 1)
    const gatewayIp = [...votes.entries()].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]))[0]?.[0] ?? null
    const gatewayRow = gatewayIp ? rows.find((r) => r.ip === gatewayIp) : undefined
    const gatewayMacs = [...new Set(seen.filter((s) => s.gateway_ip === gatewayIp)
      .sort((x, y) => (x.at < y.at ? 1 : -1))
      .map((s) => normalizeMac(s.gateway_mac)).filter((m): m is string => !!m))]
    const gatewayMac = gatewayMacs[0] ?? normalizeMac(gatewayRow?.mac) ?? null

    const devices: NetworkDevice[] = rows.filter((r) => r.ip !== gatewayIp).map((r) => ({
      asset_id: r.asset_id, label: r.label, ip: r.ip, mac: r.mac, device_type: r.device_type, criticality: r.criticality,
      in_my_assets: r.in_my_assets, last_seen: r.last_seen, measured: r.measured,
      agent: agentOf.get(r.asset_id) ?? null, alerts: alerts.get(r.asset_id) ?? NO_ALERTS,
    })).sort(byImportance)

    const listens = watchers.some((a) => a.listens), scans = watchers.some((a) => a.scans)
    out.push({
      key,
      gateway: gatewayIp ? { ip: gatewayIp, mac: gatewayMac, asset_id: gatewayRow?.asset_id ?? null, label: gatewayRow?.label ?? null } : null,
      gateway_macs: gatewayMacs,
      agents: watchers.map((a) => ({ agent_id: a.agent_id, name: a.name, listens: a.listens, scans: a.scans })),
      phones: phones.map((a) => ({ agent_id: a.agent_id, name: a.name })),
      coverage: listens && scans ? 'watched' : listens ? 'listen_only' : scans ? 'scan_only' : 'none',
      device_count: devices.length,
      measured_count: devices.filter((d) => d.measured).length,
      devices: devices.slice(0, MAX_DEVICES),
      last_seen: rows.reduce<string | null>((m, r) => later(m, r.last_seen), null),
    })
  }
  // Networks an agent watches first, then the biggest.
  return out.sort((x, y) => Number(y.agents.length > 0) - Number(x.agents.length > 0)
    || y.device_count - x.device_count || x.key.localeCompare(y.key))
}
