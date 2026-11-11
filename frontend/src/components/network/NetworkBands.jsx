// The Network page's pieces (pages/NetworkMapPage.jsx; data: GET /network/map, workers/src/lib/mapNetworks.ts).
// One network is drawn as a single top-down tree: the internet, its gateway (or the measured router
// that is its gateway), the routers and switches a network agent read, and the devices under each
// in one box (solid line: a measured cable or switch port; dashed: a VLAN whose switch port is not
// known, or devices an agent saw on the network; dotted: the route to the internet). The panels
// describe what was picked: a network, a device, or a router or switch.
import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle, CircleDashed, Cpu, ExternalLink, Eye, Globe, HelpCircle, Layers, Monitor,
  Network, Router, Server, Smartphone, X, Zap,
} from 'lucide-react'
import { TONE } from '../common/alertMeta'
import { formatSeen } from '../../utils/time'
import { BOX_HEAD, BOX_ROW, BOX_W, NODE_H, NODE_W, layoutTree } from '../../utils/networkTreeLayout'

export const COLOUR_MODES = [
  { id: 'kind', label: 'Kind' },
  { id: 'cves', label: 'Open CVEs' },
  { id: 'exposure', label: 'Exposure' },
]

const TYPE_ICON = { server: Server, workstation: Monitor, network: Network, mobile: Smartphone, iot: Cpu }
const TYPE_TONE = {
  server: 'text-series-3', workstation: 'text-series-2', network: 'text-series-1', mobile: 'text-series-6', iot: 'text-series-5',
}
const NODE_META = {
  internet: { icon: Globe, tone: 'text-dark-400', label: 'Internet' },
  gateway: { icon: Router, tone: 'text-series-1', label: 'Gateway' },
  nogateway: { icon: Router, tone: 'text-dark-400', label: 'Gateway not known', dashed: true },
  router: { icon: Router, tone: 'text-series-1', label: 'Router' },
  switch: { icon: Network, tone: 'text-series-2', label: 'Switch' },
  neighbour: { icon: CircleDashed, tone: 'text-dark-400', label: 'Not read (neighbour)', dashed: true },
  vlan: { icon: Layers, tone: 'text-series-5', label: 'VLAN, switch port not known', dashed: true },
}
const NO_ALERTS = { cve_open: 0, cve_critical: 0, cve_high: 0, kev: 0, exposure_open: 0, exposure_severity: null }
export const fmt = (n) => Number(n).toLocaleString()
export const plural = (n, one, many = `${one}s`) => `${fmt(n)} ${n === 1 ? one : many}`

/** How a device looks in a colour mode: its tone (TONE entry or null), a line of text, a dashed outline. */
export function deviceLook(d, mode) {
  const a = d.alerts
  if (mode === 'cves') {
    if (a.cve_critical > 0) return { tone: TONE.critical, line: `${fmt(a.cve_open)} open · ${fmt(a.cve_critical)} critical` }
    if (a.cve_high > 0) return { tone: TONE.serious, line: `${fmt(a.cve_open)} open · ${fmt(a.cve_high)} high` }
    if (a.cve_open > 0) return { tone: TONE.warning, line: `${fmt(a.cve_open)} open` }
    // CVEs come from the SBOM a computer's agent builds: without one, nothing was checked
    return d.agent === 'host' ? { tone: null, line: 'No open CVEs' } : { tone: null, line: 'Not checked: no SBOM', dashed: true }
  }
  if (mode === 'exposure') {
    if (!a.exposure_open) return { tone: null, line: 'No exposure alerts' }
    const sev = a.exposure_severity
    const tone = sev === 'critical' ? TONE.critical : sev === 'high' ? TONE.serious : TONE.warning
    return { tone, line: `${plural(a.exposure_open, 'exposure alert')}${sev ? ` (${sev})` : ''}` }
  }
  return { tone: null, line: null }
}

/** The measured trees as the page needs them: nodes by id, children by parent, the edge between
 *  a parent and a child, and each tree's node ids by its root. */
export function treeIndex(map) {
  const nodes = new Map(map.nodes.map((n) => [n.id, n]))
  const children = new Map()
  for (const n of map.nodes) if (n.parent && nodes.has(n.parent)) children.set(n.parent, [...(children.get(n.parent) ?? []), n.id])
  const byLabel = (a, b) => nodes.get(a).label.localeCompare(nodes.get(b).label, undefined, { numeric: true })
  for (const list of children.values()) list.sort(byLabel)
  const edge = new Map()
  for (const e of map.edges) {
    edge.set(`${e.from}>${e.to}`, { kind: e.kind, parentPort: e.from_port, childPort: e.to_port })
    edge.set(`${e.to}>${e.from}`, { kind: e.kind, parentPort: e.to_port, childPort: e.from_port })
  }
  const members = new Map()
  const rootOf = (n) => { let c = n; for (let i = 0; i < 64 && c.parent && nodes.has(c.parent); i++) c = nodes.get(c.parent); return c.id }
  for (const n of map.nodes) { const r = rootOf(n); members.set(r, [...(members.get(r) ?? []), n.id]) }
  return { nodes, children, edge, members }
}

// A measured tree, drawn top-down like the routers and switches are cabled (utils/networkTreeLayout.js):
// routers, switches and VLAN groups as nodes, the devices under each in one box. Solid lines are
// measured cables and switch ports, dashed ones a VLAN whose switch port is not known.
function Topology({ roots, ctx }) {
  // a box lists everything when the network is open, when it was opened, or when it holds a search match
  const openBoxes = { has: (id) => ctx.open || ctx.openBoxes.has(id) || (ctx.tree.children.get(id) ?? []).some((k) => ctx.matches.has(k)) }
  const layout = layoutTree(roots, ctx.tree, openBoxes)
  return (
    <div className="overflow-x-auto pb-1">
      <div className="relative" style={{ width: layout.width, height: layout.height }}>
        <svg className="absolute inset-0" width={layout.width} height={layout.height} aria-hidden="true">
          {layout.edges.map((e, i) => {
            const mid = (e.y1 + e.y2) / 2
            const stroke = e.kind === 'cable' ? 'rgb(var(--eagle-500))' : e.kind === 'port' ? 'rgb(var(--series-2) / 0.85)' : 'rgb(var(--dark-400) / 0.8)'
            const dash = e.kind === 'internet' ? '1 5' : e.kind === 'vlan' || e.kind === 'seen' ? '5 4' : undefined
            return (
              <g key={i}>
                <path d={`M${e.x1},${e.y1} V${mid} H${e.x2} V${e.y2}`} fill="none" stroke={stroke}
                  strokeWidth={e.kind === 'cable' || e.kind === 'internet' ? 2 : 1.5} strokeDasharray={dash} strokeLinecap="round" />
                {e.ports && <text x={e.x2 + 6} y={e.y2 - 8} fontSize="10" fill="rgb(var(--dark-300))" className="font-mono">{e.ports}</text>}
              </g>
            )
          })}
        </svg>
        {layout.nodes.map((p) => {
          const n = ctx.tree.nodes.get(p.id)
          const meta = NODE_META[n.kind] ?? NODE_META.neighbour
          const selected = (ctx.selection?.type === 'node' && ctx.selection.id === p.id)
            || (n.kind === 'gateway' && n.asset_id && ctx.selection?.type === 'device' && ctx.selection.asset_id === n.asset_id)
          return (
            <button key={p.id} type="button" onClick={() => ctx.onSelectNode(n)} aria-label={`${meta.label} ${n.label}`}
              style={{ left: p.left, top: p.top, width: NODE_W, height: NODE_H }}
              className={`absolute flex items-center gap-2.5 px-3 rounded-lg border bg-dark-800 text-left hover:border-eagle-500/70
                ${selected ? 'border-eagle-500 ring-2 ring-eagle-500/30' : ctx.matches.has(p.id) ? 'ring-2 ring-accent-amber/60 border-dark-700/80'
                  : meta.dashed ? 'border-dashed border-series-5/70' : 'border-eagle-500/40'}`}>
              <meta.icon className={`w-5 h-5 flex-shrink-0 ${meta.tone}`} aria-hidden="true" />
              <span className="min-w-0">
                <span className="block text-sm font-semibold text-dark-50 truncate">{n.label}</span>
                <span className={`block text-[11px] text-dark-400 truncate ${n.ip ? 'font-mono' : ''}`}>{n.ip ?? n.detail}</span>
              </span>
            </button>
          )
        })}
        {layout.boxes.map((b) => {
          const parent = ctx.tree.nodes.get(b.parent)
          const ports = new Set(b.devices.map((k) => ctx.tree.edge.get(`${b.parent}>${k}`)?.parentPort).filter(Boolean))
          return (
            <div key={b.parent} style={{ left: b.left, top: b.top, width: BOX_W, height: b.height }}
              className="absolute rounded-lg border border-dark-700/80 bg-dark-850 p-1 flex flex-col">
              <p className="px-2 text-[11px] text-dark-400 flex-shrink-0" style={{ height: BOX_HEAD - 4, lineHeight: `${BOX_HEAD - 4}px` }}>
                <b className="text-dark-200">{plural(b.devices.length, 'device')}</b>
                {ctx.tree.edge.get(`${b.parent}>${b.devices[0]}`)?.kind === 'seen' ? ' · seen on the network'
                  : parent.kind === 'vlan' ? ' · port not known' : ports.size > 0 ? ` · on ${plural(ports.size, 'port')}` : ''}
              </p>
              {b.devices.slice(0, b.shown).map((k) => {
                const node = ctx.tree.nodes.get(k)
                const d = ctx.deviceOf(node)
                return <DeviceRow key={k} d={d} mode={ctx.mode} port={ctx.tree.edge.get(`${b.parent}>${k}`)?.parentPort}
                  selected={ctx.selection?.type === 'device' && ctx.selection.asset_id === d.asset_id}
                  match={ctx.matches.has(k)} onSelect={ctx.onSelectDevice} />
              })}
              {(b.hidden > 0 || ctx.openBoxes.has(b.parent)) && !ctx.open && (
                <button type="button" onClick={() => ctx.toggleBox(b.parent)} style={{ height: BOX_ROW - 6 }}
                  className="mx-1 mt-auto text-xs text-eagle-400 hover:underline text-left px-1">
                  {b.hidden > 0 ? `+${fmt(b.hidden)} more` : 'Show fewer'}
                </button>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// One device in a box: its name, its address and the switch port it is on.
function DeviceRow({ d, mode, port, selected, match, onSelect }) {
  const look = deviceLook(d, mode)
  const Icon = TYPE_ICON[d.device_type] ?? HelpCircle
  return (
    <button type="button" onClick={() => onSelect(d)} aria-pressed={selected} style={{ height: BOX_ROW - 2 }}
      title={look.line ? `${d.label}: ${look.line}` : d.label}
      className={`flex-shrink-0 w-full flex items-center gap-2 px-2 mb-0.5 rounded-md text-left border ${look.tone ? `${look.tone.bg} ${look.tone.border}` : 'border-transparent'}
        ${selected ? 'ring-2 ring-eagle-500/50' : match ? 'ring-2 ring-accent-amber/60' : ''} hover:bg-dark-800`}>
      <Icon className={`w-4 h-4 flex-shrink-0 ${look.tone ? look.tone.text : TYPE_TONE[d.device_type] ?? 'text-dark-400'}`} aria-hidden="true" />
      <span className="min-w-0 flex-1">
        <span className="block text-xs font-semibold text-dark-50 truncate">{d.label}</span>
        <span className="block text-[10.5px] text-dark-400 truncate">
          <span className="font-mono">{d.ip}</span>{look.line ? ` · ${look.line}` : d.agent === 'host' ? ' · its own agent' : ''}
        </span>
      </span>
      {port && <span className="font-mono text-[10.5px] text-dark-400 flex-shrink-0">{port}</span>}
    </button>
  )
}

function coverageChips(net) {
  const chips = []
  if (net.agents.length > 0) {
    const what = net.coverage === 'watched' ? 'listens and scans' : net.coverage === 'listen_only' ? 'listens only' : net.coverage === 'scan_only' ? 'scans only' : 'neither'
    chips.push({ text: `${plural(net.agents.length, 'agent')} · ${what}`, cls: 'text-eagle-400 bg-eagle-500/10 border-eagle-500/30', Icon: Eye })
  }
  if (net.measured_roots.length > 0) chips.push({ text: 'Measured by a network agent', cls: 'text-eagle-400 bg-eagle-500/10 border-eagle-500/30', Icon: Network })
  if (chips.length === 0) chips.push({ text: 'No computer agent on this network', cls: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/40', Icon: AlertTriangle })
  return chips
}

/** One network as a single top-down tree: the internet, its gateway (or the measured router that
 *  is its gateway), the measured routers and switches, and the devices the agents saw on it in one
 *  box under the gateway. Built over the page's measured-tree index without changing it. */
function bandTree(net, tree, seen) {
  const nodes = new Map(tree.nodes), children = new Map(tree.children), edge = new Map(tree.edge)
  const link = (parent, child, kind) => {
    children.set(parent, [...(children.get(parent) ?? []), child])
    edge.set(`${parent}>${child}`, { kind, parentPort: null, childPort: null })
  }
  const internet = `internet:${net.key}`
  nodes.set(internet, { id: internet, kind: 'internet', label: 'Internet', ip: null, detail: null, asset_id: null })
  const roots = net.measured_roots
  const gw = net.gateway
  const gwRoot = gw ? roots.find((r) => {
    const n = tree.nodes.get(r)
    return n && (n.ip === gw.ip || (gw.asset_id && n.asset_id === gw.asset_id))
  }) : undefined
  let gateway = gwRoot ?? null
  if (!gateway && (gw || roots.length === 0)) {
    gateway = `gateway:${net.key}`
    nodes.set(gateway, {
      id: gateway, kind: gw ? 'gateway' : 'nogateway', asset_id: gw?.asset_id ?? null, ip: gw?.ip ?? null,
      label: gw ? (gw.label && gw.label !== gw.ip ? gw.label : 'Gateway') : 'Gateway not known', detail: gw ? null : 'no agent reported one',
    })
  }
  if (gateway) link(internet, gateway, 'internet')
  for (const r of roots) if (r !== gateway) link(gateway && !gwRoot ? gateway : internet, r, gateway && !gwRoot ? 'seen' : 'internet')
  const under = gateway ?? roots[0] ?? internet
  for (const d of seen) {
    nodes.set(d.asset_id, { id: d.asset_id, kind: 'device', label: d.label, ip: d.ip, asset_id: d.asset_id, device_type: d.device_type })
    link(under, d.asset_id, 'seen')
  }
  return { root: internet, tree: { ...tree, nodes, children, edge } }
}

/** One network's drawing. Its boxes list BOX_MAX devices until opened. */
export function NetworkTopology({ net, devices, mode, selection, onSelectNetwork, onSelectDevice, onSelectNode, tree, deviceOf, matches }) {
  const [openBoxes, setOpenBoxes] = useState(() => new Set())
  // devices drawn in this network's measured trees are not listed again with the ones the agents saw
  const inTrees = new Set(net.measured_roots.flatMap((r) => (tree.members.get(r) ?? []).map((id) => tree.nodes.get(id)?.asset_id)).filter(Boolean))
  const band = bandTree(net, tree, devices.filter((d) => !inTrees.has(d.asset_id)))
  // A device's facts (alerts, its address ON this network) from this network's own list first.
  const own = new Map(net.devices.map((d) => [d.asset_id, d]))
  const ctx = {
    tree: band.tree, mode, open: false, openBoxes, matches, selection,
    netSelected: selection?.type === 'network' && selection.key === net.key,
    deviceOf: (node) => own.get(node.asset_id) ?? deviceOf(node),
    toggleBox: (id) => setOpenBoxes((s) => { const t = new Set(s); if (t.has(id)) t.delete(id); else t.add(id); return t }),
    // the gateway is a device like any other when it is a recorded asset; the internet stands for the network
    onSelectNode: (n) => (n.kind === 'gateway' && net.gateway?.device ? onSelectDevice(net, net.gateway.device)
      : ['internet', 'gateway', 'nogateway'].includes(n.kind) ? onSelectNetwork(net) : onSelectNode(net, n)),
    onSelectDevice: (d) => onSelectDevice(net, d),
  }
  return (
    <div className="space-y-2">
      <Topology roots={[band.root]} ctx={ctx} />
      {net.device_count > net.devices.length && (
        <p className="text-xs text-dark-400">Showing {fmt(net.devices.length)} of {fmt(net.device_count)} devices: find the others with the search above.</p>
      )}
    </div>
  )
}

/** The chips that say who watches a network. */
export function CoverageChips({ net, small = false }) {
  return coverageChips(net).map((c) => (
    <span key={c.text} className={`inline-flex items-center gap-1.5 font-medium rounded-full border ${small ? 'text-[11px] px-2 py-0.5' : 'text-xs px-2.5 py-1'} ${c.cls}`}>
      <c.Icon className="w-3.5 h-3.5" aria-hidden="true" /> {c.text}
    </span>
  ))
}

export function Row({ k, children }) {
  return (
    <div className="grid grid-cols-[6.5rem_1fr] gap-3">
      <dt className="text-dark-400">{k}</dt>
      <dd className="text-dark-100 min-w-0 break-words">{children}</dd>
    </div>
  )
}

// The details of what was picked, in the page's side column.
export function PanelShell({ kind, title, onClose, children }) {
  return (
    <aside className="glass-card p-4 space-y-4" aria-label={`${kind} details`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-dark-400">{kind}</p>
          <p className="text-base font-semibold text-dark-50 break-all">{title}</p>
        </div>
        {onClose && <button type="button" onClick={onClose} className="text-dark-400 hover:text-dark-50" aria-label="Close"><X className="w-4 h-4" /></button>}
      </div>
      {children}
    </aside>
  )
}

function AssetButtons({ assetId, onBlast }) {
  return (
    <div className="flex flex-wrap gap-2">
      <Link to={`/inventory/${assetId}`} className="btn-primary text-sm inline-flex items-center gap-2">Open asset <ExternalLink className="w-3.5 h-3.5" /></Link>
      <button type="button" onClick={() => onBlast(assetId)} className="btn-secondary text-sm inline-flex items-center gap-2"
        title="What would be affected if this device were compromised or went down">
        <Zap className="w-3.5 h-3.5" /> Blast radius
      </button>
    </div>
  )
}

export function NetworkPanel({ net, onClose }) {
  const cves = net.devices.reduce((s, d) => s + d.alerts.cve_open, 0)
  const critical = net.devices.reduce((s, d) => s + d.alerts.cve_critical, 0)
  const exposures = net.devices.reduce((s, d) => s + d.alerts.exposure_open, 0)
  const withAgent = net.devices.filter((d) => d.agent).length
  return (
    <PanelShell kind="Network" title={net.title ?? net.key} onClose={onClose}>
      <dl className="text-sm space-y-2">
        {net.subnets.length > 0 && <Row k="Also">{net.subnets.map((k) => <span key={k} className="block font-mono">{k}</span>)}</Row>}
        <Row k="Gateway">
          {net.gateway ? <><span className="font-mono">{net.gateway.ip}</span>
            {net.gateway.mac && <span className="block font-mono text-xs text-dark-400 lowercase">{net.gateway.mac}</span>}</> : 'Not known'}
        </Row>
        <Row k="Devices">{fmt(net.device_count)}{withAgent > 0 && <span className="text-dark-400">, {withAgent} with an agent</span>}</Row>
        <Row k="Watched by">
          {net.agents.length === 0
            ? <span className={net.measured_roots.length ? 'text-dark-300' : 'text-yellow-400'}>
              {net.measured_roots.length ? 'A network agent reads its routers and switches; no computer agent listens or scans here' : 'No computer agent: nothing listens or scans here'}</span>
            : net.agents.map((a) => (
              <span key={a.agent_id} className="block">{a.name}{' '}
                <span className="text-dark-400">{a.listens && a.scans ? 'listens and scans' : a.listens ? 'listens' : a.scans ? 'scans' : 'neither (both off)'}</span>
              </span>
            ))}
        </Row>
        {net.phones.length > 0 && <Row k="Phone apps">{net.phones.map((p) => p.name).join(', ')}</Row>}
        <Row k="Open CVEs">{cves > 0 ? <><b className="text-red-400">{fmt(cves)}</b>{critical > 0 && <span className="text-dark-400">, {fmt(critical)} critical</span>}</> : 'None'}</Row>
        <Row k="Exposure">{exposures > 0 ? plural(exposures, 'open alert') : 'None'}</Row>
        {net.last_seen && <Row k="Last seen">{formatSeen(net.last_seen).text}</Row>}
      </dl>
      {net.gateway_macs.length > 1 && (
        <p className="text-xs text-yellow-400 bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-2.5">
          Gateways with {net.gateway_macs.length} different MAC addresses answered at {net.gateway?.ip}. This range is probably used at
          more than one site; its devices are shown together.
        </p>
      )}
      <div className="flex flex-col gap-2">
        {!net.title && <Link to={`/discovery?scan=${encodeURIComponent(net.key)}`} className="btn-primary text-sm text-center">New scan of this network</Link>}
      </div>
    </PanelShell>
  )
}

export function DevicePanel({ net, device: d, onClose, onBlast }) {
  const a = d.alerts ?? NO_ALERTS
  return (
    <PanelShell kind={d.device_type ? `Device (${d.device_type})` : 'Device'} title={d.label} onClose={onClose}>
      <dl className="text-sm space-y-2">
        <Row k="Address"><span className="font-mono">{d.ip ?? '—'}</span>{d.mac && <span className="block font-mono text-xs text-dark-400 lowercase">{d.mac}</span>}</Row>
        <Row k="Network"><span className={net.title ? '' : 'font-mono'}>{net.title ?? net.key}</span>{net.gateway && <span className="text-dark-400"> via {net.gateway.ip}</span>}</Row>
        <Row k="Agent">{d.agent === 'host' ? 'Its own agent (inventory and SBOM)' : d.agent === 'mobile' ? 'The EagleEye phone app' : 'None: seen on the network'}</Row>
        <Row k="Open CVEs">{a.cve_open > 0
          ? <><b className="text-red-400">{fmt(a.cve_open)}</b><span className="text-dark-400">{a.cve_critical > 0 && `, ${fmt(a.cve_critical)} critical`}{a.kev > 0 && `, ${fmt(a.kev)} known exploited`}</span></>
          : d.agent === 'host' ? 'None' : 'Not checked (no SBOM)'}</Row>
        <Row k="Exposure">{a.exposure_open > 0 ? `${plural(a.exposure_open, 'open alert')}${a.exposure_severity ? ` (${a.exposure_severity})` : ''}` : 'None'}</Row>
        {d.criticality != null && <Row k="Criticality">{d.criticality}/10</Row>}
        {d.last_seen && <Row k="Last seen">{formatSeen(d.last_seen).text}</Row>}
      </dl>
      {d.asset_id && <AssetButtons assetId={d.asset_id} onBlast={onBlast} />}
    </PanelShell>
  )
}

/** A router, switch, neighbour or VLAN group of a measured tree, with its connections. */
export function NodePanel({ node, tree, map, onClose, onBlast }) {
  const meta = NODE_META[node.kind] ?? NODE_META.neighbour
  const connections = map.edges.filter((e) => e.from === node.id || e.to === node.id).map((e) => {
    const mine = e.from === node.id
    return { other: tree.nodes.get(mine ? e.to : e.from), myPort: mine ? e.from_port : e.to_port, theirPort: mine ? e.to_port : e.from_port, kind: e.kind, ambiguous: e.ambiguous }
  })
  return (
    <PanelShell kind={meta.label} title={node.label} onClose={onClose}>
      <dl className="text-sm space-y-2">
        {node.ip && <Row k="Address"><span className="font-mono">{node.ip}</span></Row>}
        {node.mac && <Row k="MAC"><span className="font-mono lowercase">{node.mac}</span></Row>}
        {node.detail && <Row k={node.kind === 'router' || node.kind === 'switch' ? 'System' : 'Note'}>{node.detail}</Row>}
        {node.vlan != null && <Row k="VLAN">{node.vlan}</Row>}
        {node.seen_at && <Row k="Read">{formatSeen(node.seen_at).text}</Row>}
      </dl>
      {connections.length > 0 && (
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wide text-dark-400 mb-1">Connections</p>
          <ul className="space-y-1 text-sm max-h-64 overflow-y-auto">
            {connections.map((c, i) => (
              <li key={i} className="text-dark-200">
                {c.myPort && <span className="font-mono text-xs text-dark-400">{c.myPort} → </span>}
                {c.other?.label ?? '?'}
                {c.theirPort && <span className="font-mono text-xs text-dark-400"> {c.theirPort}</span>}
                {c.kind === 'vlan' && <span className="text-xs text-dark-400"> (routed, port not known)</span>}
                {c.ambiguous && <span className="text-xs text-yellow-400"> (seen on two switches)</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {node.asset_id && <AssetButtons assetId={node.asset_id} onBlast={onBlast} />}
    </PanelShell>
  )
}

export { NO_ALERTS }
