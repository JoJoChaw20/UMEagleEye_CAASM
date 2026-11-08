// The network map (GET /network/map, the dashboard's Network map page): what the network
// agents measured, as one graph. PURE: no database; tested by networkMap.test.ts.
//
//   routers and switches   the devices a network agent polled (assets.network_device)
//   neighbours             a cable's far end the agent did not poll (outside its ranges)
//   devices                every other asset it placed (assets.network_location): under the
//                          switch port it is plugged into, or, when no switch said where,
//                          under its router in a VLAN group ("VLAN 10, port not known")
//
// The graph is also a tree, rooted at a router (the device that routes the most networks),
// so the page can draw it top-down and relationship inference can turn it into measured
// connects_to edges (parent -> child = downstream). A cable that closes a loop stays an edge
// but not a tree edge.

export type MapNodeKind = 'router' | 'switch' | 'neighbour' | 'vlan' | 'device'

export interface MapNode {
  id: string
  kind: MapNodeKind
  label: string
  asset_id: string | null
  ip: string | null
  mac: string | null
  device_type: string | null
  detail: string | null              // OS for a polled device, "VLAN 10" etc. for a group
  vlan: number | null
  criticality: number | null
  seen_at: string | null
  parent: string | null              // tree parent
  depth: number
}

export interface MapEdge {
  from: string
  to: string
  kind: 'cable' | 'port' | 'vlan'
  from_port: string | null
  to_port: string | null
  protocols: string[]
  ambiguous: boolean
  tree: boolean                      // part of the tree the page draws top-down
}

export interface MapDevice {
  asset_id: string
  ip: string
  network_device: {
    label?: string; name?: string; os?: string | null; version?: string | null; vendor?: string | null
    bridge_mac?: string | null; vlans?: number[]; addresses?: { ip: string }[]
    interfaces?: { trunk?: boolean | null }[]; seen_at?: string
  }
}
export interface MapLink {
  a_name: string; a_port: string; a_asset_id: string | null
  b_name: string; b_port: string; b_asset_id: string | null
  protocols: string[]
}
export interface MapHost {
  asset_id: string; label: string; ip: string | null; mac: string | null
  device_type: string | null; criticality: number | null
  location: {
    switch: string | null; switch_asset_id: string | null; port: string | null; vlan: number | null
    ambiguous?: boolean; router: string | null; interface: string | null; seen_at?: string
  }
}

const lower = (s: string) => s.trim().toLowerCase()

/** A polled device is a switch when it answered the bridge MIB or reports trunks/VLANs. */
function isSwitch(d: MapDevice['network_device']): boolean {
  return !!d.bridge_mac || (d.vlans?.length ?? 0) > 0 || (d.interfaces ?? []).some((i) => i.trunk != null)
}

export function buildNetworkMap(devices: MapDevice[], links: MapLink[], hosts: MapHost[]): { nodes: MapNode[]; edges: MapEdge[] } {
  const nodes = new Map<string, MapNode>()
  const byName = new Map<string, string>()          // lowercased device name -> node id
  const node = (n: Omit<MapNode, 'parent' | 'depth'>) => {
    if (!nodes.has(n.id)) nodes.set(n.id, { ...n, parent: null, depth: 0 })
    return nodes.get(n.id)!
  }

  for (const d of devices) {
    const nd = d.network_device
    const label = nd.label || nd.name || d.ip
    node({
      id: d.asset_id, kind: isSwitch(nd) ? 'switch' : 'router', label, asset_id: d.asset_id, ip: d.ip, mac: null,
      device_type: 'network', detail: [nd.os, nd.version].filter(Boolean).join(' ') || null, vlan: null,
      criticality: null, seen_at: nd.seen_at ?? null,
    })
    byName.set(lower(label), d.asset_id)
    if (nd.name) byName.set(lower(nd.name), d.asset_id)
  }
  const deviceNode = (name: string, assetId: string | null): string => {
    if (assetId && nodes.has(assetId)) return assetId
    const known = byName.get(lower(name))
    if (known) return known
    const id = `name:${lower(name)}`
    node({ id, kind: 'neighbour', label: name, asset_id: assetId, ip: null, mac: null, device_type: null,
           detail: 'Not read by a network agent', vlan: null, criticality: null, seen_at: null })
    byName.set(lower(name), id)
    return id
  }

  const edges: MapEdge[] = []
  for (const l of links) {
    const a = deviceNode(l.a_name, l.a_asset_id), b = deviceNode(l.b_name, l.b_asset_id)
    if (a === b) continue
    edges.push({ from: a, to: b, kind: 'cable', from_port: l.a_port, to_port: l.b_port, protocols: l.protocols,
                 ambiguous: false, tree: false })
  }

  for (const h of hosts) {
    if (nodes.has(h.asset_id)) continue                 // a polled device: placed by its cables
    const loc = h.location
    node({ id: h.asset_id, kind: 'device', label: h.label, asset_id: h.asset_id, ip: h.ip, mac: h.mac,
           device_type: h.device_type, detail: null, vlan: loc.vlan, criticality: h.criticality, seen_at: loc.seen_at ?? null })
    if (loc.switch && loc.port) {
      edges.push({ from: deviceNode(loc.switch, loc.switch_asset_id), to: h.asset_id, kind: 'port', from_port: loc.port,
                   to_port: null, protocols: [], ambiguous: !!loc.ambiguous, tree: false })
    } else if (loc.router) {
      const router = deviceNode(loc.router, null)
      const groupKey = loc.vlan != null ? `vlan ${loc.vlan}` : (loc.interface ?? 'unknown')
      const group = `vlan:${router}:${lower(groupKey)}`
      node({ id: group, kind: 'vlan', label: loc.vlan != null ? `VLAN ${loc.vlan}` : (loc.interface ?? 'Network'),
             asset_id: null, ip: null, mac: null, device_type: null, detail: 'Switch port not known', vlan: loc.vlan,
             criticality: null, seen_at: null })
      if (!edges.some((e) => e.to === group)) {
        edges.push({ from: router, to: group, kind: 'vlan', from_port: loc.interface, to_port: null, protocols: [],
                     ambiguous: false, tree: false })
      }
      edges.push({ from: group, to: h.asset_id, kind: 'vlan', from_port: null, to_port: null, protocols: [],
                   ambiguous: false, tree: false })
    }
  }

  markTree(nodes, edges)
  return { nodes: [...nodes.values()], edges }
}

/** Parents and depths from a breadth-first walk of each connected part, started at its
 *  router (the most addresses, then the most cables, then the name); devices and VLAN groups
 *  hang below their switch or router. */
function markTree(nodes: Map<string, MapNode>, edges: MapEdge[]): void {
  const adjacent = new Map<string, MapEdge[]>()
  for (const e of edges) {
    for (const end of [e.from, e.to]) {
      if (!adjacent.has(end)) adjacent.set(end, [])
      adjacent.get(end)!.push(e)
    }
  }
  const infraRank = (n: MapNode) => [n.kind === 'router' ? 0 : n.kind === 'switch' ? 1 : n.kind === 'neighbour' ? 2 : 3,
    -(adjacent.get(n.id)?.length ?? 0), n.label.toLowerCase()] as const
  const order = [...nodes.values()].sort((x, y) => {
    const a = infraRank(x), b = infraRank(y)
    return a[0] - b[0] || a[1] - b[1] || a[2].localeCompare(b[2])
  })
  const seen = new Set<string>()
  for (const root of order) {
    if (seen.has(root.id)) continue
    seen.add(root.id)
    root.parent = null
    root.depth = 0
    const queue = [root.id]
    while (queue.length) {
      const id = queue.shift()!
      // cables first, so the infrastructure forms the trunk and devices hang off it
      const next = [...(adjacent.get(id) ?? [])].sort((a, b) => (a.kind === 'cable' ? 0 : 1) - (b.kind === 'cable' ? 0 : 1))
      for (const e of next) {
        const other = e.from === id ? e.to : e.from
        if (seen.has(other)) continue
        seen.add(other)
        const child = nodes.get(other)!
        child.parent = id
        child.depth = nodes.get(id)!.depth + 1
        e.tree = true
        queue.push(other)
      }
    }
  }
}

/** Measured downstream edges between assets (parent -> child of the tree), for relationship
 *  inference: a VLAN group is skipped (router -> device). */
export function measuredEdges(map: { nodes: MapNode[] }): { source: string; target: string }[] {
  const byId = new Map(map.nodes.map((n) => [n.id, n]))
  const out: { source: string; target: string }[] = []
  for (const n of map.nodes) {
    if (!n.asset_id || !n.parent) continue
    let parent = byId.get(n.parent)
    while (parent && !parent.asset_id && parent.parent) parent = byId.get(parent.parent)
    if (parent?.asset_id && parent.asset_id !== n.asset_id) out.push({ source: parent.asset_id, target: n.asset_id })
  }
  return out
}
