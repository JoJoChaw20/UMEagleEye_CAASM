// A network agent's crawl (agent-gui/eagleeye/netagent), stored by routes/network.ts: the
// cables between routers and switches (network_links), what each polled device is
// (assets.network_device) and where every other device is plugged in
// (assets.network_location). PURE: no database; tested by networkTopology.test.ts.
//
// The agent has already decided what a location is: a MAC on a switch's edge port (not a
// trunk, no CDP/LLDP neighbour on it). Here the crawl is only matched to the tenant's assets.

import { z } from 'zod'
import { normalizeMac } from './mac'

const name = z.string().trim().min(1).max(255)
const port = z.string().trim().min(1).max(64)
const ipv4 = z.string().max(45)
const iface = z.object({
  index: z.number().int(), name: z.string().max(64), alias: z.string().max(255).optional(),
  mac: z.string().max(17).nullish(), up: z.boolean().nullish(), trunk: z.boolean().nullish(),
  vlan: z.number().int().nullish(),
})
const deviceSchema = z.object({
  address: ipv4, name: z.string().max(255), label: name,
  descr: z.string().max(2000).optional(), object_id: z.string().max(200).optional(),
  vendor: z.string().max(100).optional(), os: z.string().max(100).optional(), version: z.string().max(100).optional(),
  uptime_seconds: z.number().int().nullish(), found_via: z.string().max(200).optional(),
  bridge_mac: z.string().max(17).nullish(),
  interfaces: z.array(iface).max(2000),
  addresses: z.array(z.object({ ip: ipv4, prefix: z.number().int().nullish(), network: z.string().max(50).nullish(),
    if_index: z.number().int().nullish() })).max(1000),
  vlans: z.array(z.number().int()).max(4096).optional(),
  notes: z.array(z.string().max(500)).max(50).optional(),
  errors: z.array(z.string().max(500)).max(50).optional(),
})
/** What POST /network/topology takes (the agent: netagent/upload.py topology_payload). */
export const topologySchema = z.object({
  scan_id: z.string().uuid().optional(),
  devices: z.array(deviceSchema).max(500),
  links: z.array(z.object({
    a: z.object({ device: name, port }), b: z.object({ device: name, port }),
    protocols: z.array(z.enum(['cdp', 'lldp'])).max(2),
  })).max(5000),
  hosts: z.array(z.object({
    ip: ipv4.nullable(), mac: z.string().max(17), vlan: z.number().int().nullable(),
    interface: z.string().max(64), seen_by: z.array(z.string().max(255)).max(20), device: z.string().max(255).nullable(),
    location: z.object({ switch: name, port, vlan: z.number().int().nullable(), ambiguous: z.boolean() }).nullable(),
  })).max(50000),
  stats: z.object({
    seconds: z.number().optional(), requests: z.number().int().optional(), bytes_received: z.number().int().optional(),
    unreachable: z.array(z.object({ address: z.string().max(45), error: z.string().max(300) })).max(500).optional(),
    skipped: z.number().int().optional(),
  }).optional(),
})

export interface LinkEnd { device: string; port: string }
export interface CrawlLink { a: LinkEnd; b: LinkEnd; protocols: string[] }
export interface LinkRow { aName: string; aPort: string; bName: string; bPort: string; protocols: string[] }

const endKey = (e: LinkEnd) => `${e.device.toLowerCase()}\u0000${e.port.toLowerCase()}`

const ipNum = (ip: string) => ip.split('.').reduce((n, o) => n * 256 + Number(o), 0)

/** The networks a crawl reached: the subnets of the polled devices' own addresses (/8 to /30;
 *  not loopback or self-assigned), each with the lowest device address on it as its gateway (the
 *  router's .1 on the lab's VLANs). Kept on the crawl's Discovery record for the Networks list. */
export function crawlSubnets(devices: { addresses: { ip: string; prefix?: number | null; network?: string | null }[] }[]): { subnet: string; gateway: string }[] {
  const out = new Map<string, string>()
  for (const d of devices) {
    for (const a of d.addresses) {
      if (!a.network || a.prefix == null || a.prefix < 8 || a.prefix > 30) continue
      if (!/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(a.network) || /^(127|169\.254)\./.test(a.network)) continue
      const gw = out.get(a.network)
      if (!gw || ipNum(a.ip) < ipNum(gw)) out.set(a.network, a.ip)
    }
  }
  return [...out].map(([subnet, gateway]) => ({ subnet, gateway }))
    .sort((x, y) => ipNum(x.subnet.split('/')[0]!) - ipNum(y.subnet.split('/')[0]!)).slice(0, 64)
}

/** One row per cable: the ends in a fixed order, so the cable seen from either of its
 *  devices (or by two agents) is the same row; reports of one cable are merged. */
export function linkRows(links: CrawlLink[]): LinkRow[] {
  const rows = new Map<string, LinkRow>()
  for (const l of links) {
    const [a, b] = endKey(l.a) <= endKey(l.b) ? [l.a, l.b] : [l.b, l.a]
    const key = `${endKey(a)}\u0001${endKey(b)}`
    const row = rows.get(key) ?? { aName: a.device, aPort: a.port, bName: b.device, bPort: b.port, protocols: [] }
    row.protocols = [...new Set([...row.protocols, ...l.protocols])].sort()
    rows.set(key, row)
  }
  return [...rows.values()]
}

/** A current address of one of the tenant's assets (asset_addresses, or the asset itself). */
export interface AssetRef { assetId: string; ip: string | null; mac: string | null }

export interface AssetIndex { byIp: Map<string, string>; byMac: Map<string, string> }

export function assetIndex(refs: AssetRef[]): AssetIndex {
  const byIp = new Map<string, string>()
  const byMac = new Map<string, string>()
  for (const r of refs) {
    if (r.ip && !byIp.has(r.ip)) byIp.set(r.ip, r.assetId)
    const mac = normalizeMac(r.mac)
    if (mac && !byMac.has(mac)) byMac.set(mac, r.assetId)
  }
  return { byIp, byMac }
}

export interface CrawlInterface {
  index: number; name: string; alias?: string; mac?: string | null; up?: boolean | null
  trunk?: boolean | null; vlan?: number | null
}
export interface CrawlDevice {
  address: string; label: string; interfaces: CrawlInterface[]; addresses: { ip: string }[]
}

/** The asset of each polled device, by label: its polled address, then any of its own
 *  addresses, then any of its interfaces' MACs. */
export function deviceAssets(devices: CrawlDevice[], index: AssetIndex): Map<string, string> {
  const out = new Map<string, string>()
  for (const d of devices) {
    const ips = [d.address, ...d.addresses.map((a) => a.ip)]
    const macs = d.interfaces.map((i) => normalizeMac(i.mac)).filter((m): m is string => !!m)
    const id = ips.map((ip) => index.byIp.get(ip)).find(Boolean) ?? macs.map((m) => index.byMac.get(m)).find(Boolean)
    if (id) out.set(d.label, id)
  }
  return out
}

export interface CrawlHost {
  ip: string | null
  mac: string
  vlan: number | null
  interface: string
  seen_by: string[]
  device: string | null                       // set when the address is a polled device's own
  location: { switch: string; port: string; vlan: number | null; ambiguous: boolean } | null
}

export interface NetworkLocation {
  switch: string | null
  switch_asset_id: string | null
  port: string | null
  vlan: number | null
  ambiguous: boolean
  router: string | null                       // the router whose ARP table has it
  interface: string | null                    // that router's interface (a subinterface names the VLAN)
  agent_id: string
  seen_at: string
}

/** What to store as each asset's network_location: hosts matched by MAC, then IP. The
 *  polled devices are left out (their place is their links). When one asset has several
 *  entries (several addresses), one with a switch port wins. */
export function planLocations(
  hosts: CrawlHost[], index: AssetIndex, deviceAssetByLabel: Map<string, string>, agentId: string, seenAt: string,
): { assetId: string; location: NetworkLocation }[] {
  const polled = new Set(deviceAssetByLabel.values())
  const out = new Map<string, NetworkLocation>()
  for (const h of hosts) {
    if (h.device) continue
    const mac = normalizeMac(h.mac)
    const assetId = (mac && index.byMac.get(mac)) || (h.ip && index.byIp.get(h.ip)) || null
    if (!assetId || polled.has(assetId)) continue
    const loc = h.location
    const location: NetworkLocation = {
      switch: loc?.switch ?? null,
      switch_asset_id: loc ? deviceAssetByLabel.get(loc.switch) ?? null : null,
      port: loc?.port ?? null,
      vlan: loc?.vlan ?? h.vlan ?? null,
      ambiguous: loc?.ambiguous ?? false,
      router: h.seen_by[0] ?? null,
      interface: h.interface || null,
      agent_id: agentId,
      seen_at: seenAt,
    }
    const prior = out.get(assetId)
    if (!prior || (!prior.port && location.port)) out.set(assetId, location)
  }
  return [...out.entries()].map(([assetId, location]) => ({ assetId, location }))
}
