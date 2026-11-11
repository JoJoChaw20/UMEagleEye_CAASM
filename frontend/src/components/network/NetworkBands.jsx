// Every network the tenant's agents see (GET /network/map `networks`, workers/src/lib/mapNetworks.ts),
// one band each, stacked: the internet, the network's gateway, then what is on it. Where a network
// agent reads the routers and switches, their tree is drawn top-down in the band of the network the
// router is on, each parent's devices in one box (solid line: a measured cable or switch port;
// dashed: a VLAN whose switch port is not known, or a device an agent saw on the network; dotted:
// the route to the internet). A band opens in place to show all its devices.
import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle, ChevronDown, ChevronRight, CircleDashed, Cpu, ExternalLink, Eye, Globe, HelpCircle, Layers, Monitor,
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

const COLLAPSED = 3                      // devices a closed band (or switch) shows
const TYPE_ORDER = ['server', 'workstation', 'network', 'mobile', 'iot', 'unknown']
const TYPE_LABEL = {
  server: 'Servers', workstation: 'Workstations', network: 'Network devices', mobile: 'Phones and tablets',
  iot: 'IoT devices', unknown: 'Not identified yet',
}
const TYPE_ICON = { server: Server, workstation: Monitor, network: Network, mobile: Smartphone, iot: Cpu }
const TYPE_TONE = {
  server: 'text-series-3', workstation: 'text-series-2', network: 'text-series-1', mobile: 'text-series-6', iot: 'text-series-5',
}
const NODE_META = {
  router: { icon: Router, tone: 'text-series-1', label: 'Router' },
  switch: { icon: Network, tone: 'text-series-2', label: 'Switch' },
  neighbour: { icon: CircleDashed, tone: 'text-dark-400', label: 'Not read (neighbour)', dashed: true },
  vlan: { icon: Layers, tone: 'text-series-5', label: 'VLAN, switch port not known', dashed: true },
}
const NO_ALERTS = { cve_open: 0, cve_critical: 0, cve_high: 0, kev: 0, exposure_open: 0, exposure_severity: null }
const fmt = (n) => Number(n).toLocaleString()
const plural = (n, one, many = `${one}s`) => `${fmt(n)} ${n === 1 ? one : many}`
const GRID = 'grid gap-2 [grid-template-columns:repeat(auto-fill,minmax(min(200px,100%),1fr))]'

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

function NodeBox({ icon: Icon, tone = 'text-dark-400', title, sub, mono = true, onClick, selected, dashed, label, extra }) {
  const body = (
    <>
      <Icon className={`w-5 h-5 flex-shrink-0 ${tone}`} aria-hidden="true" />
      <span className="min-w-0 text-left">
        <span className="block text-sm font-semibold text-dark-50 truncate">{title}</span>
        {sub && <span className={`block text-[11px] text-dark-400 truncate ${mono ? 'font-mono' : ''}`}>{sub}</span>}
        {extra && <span className="block text-[11px] text-dark-400 truncate font-mono">{extra}</span>}
      </span>
    </>
  )
  const cls = `w-full flex items-center gap-2.5 px-3 py-2 rounded-lg border bg-dark-800 ${selected ? 'border-eagle-500 ring-2 ring-eagle-500/30'
    : dashed ? 'border-dashed border-dark-500/70' : 'border-dark-700/80'}`
  return onClick
    ? <button type="button" onClick={onClick} aria-label={label} className={`${cls} hover:border-eagle-500/60`}>{body}</button>
    : <div className={cls}>{body}</div>
}

function DeviceCard({ d, mode, selected, onSelect, port, match }) {
  const look = deviceLook(d, mode)
  const Icon = TYPE_ICON[d.device_type] ?? HelpCircle
  const border = look.tone ? look.tone.border : look.dashed ? 'border-dashed border-dark-500/70' : 'border-dark-700/80'
  const tags = [port && `port ${port}`, d.agent === 'host' && 'its own agent', d.agent === 'mobile' && 'phone app'].filter(Boolean)
  return (
    <button type="button" onClick={() => onSelect(d)} aria-pressed={selected}
      className={`w-full text-left flex items-start gap-2.5 px-3 py-2 rounded-lg border ${look.tone ? look.tone.bg : 'bg-dark-800'} ${border}
        ${selected ? 'ring-2 ring-eagle-500/50' : match ? 'ring-2 ring-accent-amber/60' : ''} hover:border-eagle-500/60`}>
      <Icon className={`w-[18px] h-[18px] mt-0.5 flex-shrink-0 ${look.tone ? look.tone.text : TYPE_TONE[d.device_type] ?? 'text-dark-400'}`} aria-hidden="true" />
      <span className="min-w-0">
        <span className="block text-sm font-semibold text-dark-50 truncate" title={d.label}>{d.label}</span>
        {look.line && <span className={`block text-xs ${look.tone ? look.tone.text : 'text-dark-300'}`}>{look.line}</span>}
        <span className="block text-[11px] text-dark-400 truncate">
          <span className="font-mono">{d.ip}</span>{tags.length > 0 && ` · ${tags.join(' · ')}`}
        </span>
      </span>
    </button>
  )
}

function MoreButton({ count, sub, onClick }) {
  return (
    <button type="button" onClick={onClick}
      className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg border border-dashed border-dark-500/70 bg-dark-800 hover:border-eagle-500/60 text-left">
      <Layers className="w-[18px] h-[18px] text-dark-400" aria-hidden="true" />
      <span><span className="block text-sm font-semibold text-dark-50">{count}</span><span className="block text-xs text-dark-400">{sub}</span></span>
    </button>
  )
}

// A measured tree, drawn top-down like the routers and switches are cabled (utils/networkTreeLayout.js):
// routers, switches and VLAN groups as nodes, the devices under each in one box. Solid lines are
// measured cables and switch ports, dashed ones a VLAN whose switch port is not known.
function Topology({ roots, ctx }) {
  const wanted = (id) => (ctx.tree.children.get(id) ?? []).some((k) => ctx.matches.has(k))
  const allIds = roots.flatMap((r) => ctx.tree.members.get(r) ?? [])
  const openBoxes = new Set(allIds.filter((id) => ctx.open || ctx.openBoxes.has(id) || wanted(id)))
  const layout = layoutTree(roots, ctx.tree, openBoxes)
  return (
    <div className="overflow-x-auto pb-1">
      <div className="relative" style={{ width: layout.width, height: layout.height }}>
        <svg className="absolute inset-0" width={layout.width} height={layout.height} aria-hidden="true">
          {layout.edges.map((e, i) => {
            const mid = (e.y1 + e.y2) / 2
            const stroke = e.kind === 'cable' ? 'rgb(var(--eagle-500))' : e.kind === 'port' ? 'rgb(var(--series-2) / 0.85)' : 'rgb(var(--dark-400) / 0.8)'
            return (
              <g key={i}>
                <path d={`M${e.x1},${e.y1} V${mid} H${e.x2} V${e.y2}`} fill="none" stroke={stroke}
                  strokeWidth={e.kind === 'cable' ? 2 : 1.5} strokeDasharray={e.kind === 'vlan' ? '5 4' : undefined} />
                {e.ports && <text x={e.x2 + 6} y={e.y2 - 8} fontSize="10" fill="rgb(var(--dark-300))" className="font-mono">{e.ports}</text>}
              </g>
            )
          })}
        </svg>
        {layout.nodes.map((p) => {
          const n = ctx.tree.nodes.get(p.id)
          const meta = NODE_META[n.kind] ?? NODE_META.neighbour
          const selected = ctx.selection?.type === 'node' && ctx.selection.id === p.id
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
                {parent.kind === 'vlan' ? ' · port not known' : ports.size > 0 ? ` · on ${plural(ports.size, 'port')}` : ''}
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

export function NetworkBand({ net, devices, mode, open, onToggle, selection, onSelectNetwork, onSelectDevice, onSelectNode, tree, deviceOf, matches }) {
  const [openBoxes, setOpenBoxes] = useState(() => new Set())
  const netSelected = selection?.type === 'network' && selection.key === net.key
  // devices drawn in this network's measured trees are not listed again as loose cards
  const inTrees = new Set(net.measured_roots.flatMap((r) => (tree.members.get(r) ?? []).map((id) => tree.nodes.get(id)?.asset_id)).filter(Boolean))
  const loose = devices.filter((d) => !inTrees.has(d.asset_id))
  const shown = open ? loose : loose.slice(0, COLLAPSED)
  const hidden = loose.length - shown.length
  const groups = open
    ? TYPE_ORDER.map((t) => ({ t, items: loose.filter((d) => (TYPE_LABEL[d.device_type] ? d.device_type : 'unknown') === t) })).filter((g) => g.items.length)
    : [{ t: null, items: shown }]
  const ctx = {
    tree, mode, open, openBoxes, matches, selection, deviceOf,
    toggleBox: (id) => setOpenBoxes((s) => { const t = new Set(s); if (t.has(id)) t.delete(id); else t.add(id); return t }),
    onSelectNode: (n) => onSelectNode(net, n), onSelectDevice: (d) => onSelectDevice(net, d),
  }
  const title = net.title ?? net.key
  const unwatched = net.coverage === 'none' && net.measured_roots.length === 0

  return (
    <section aria-label={`Network ${title}`}
      className={`rounded-xl border p-4 space-y-3 ${netSelected ? 'border-eagle-500 ring-1 ring-eagle-500/30 bg-eagle-500/5'
        : unwatched ? 'border-dashed border-yellow-500/50 bg-dark-800' : 'border-dark-700/80 bg-dark-850'}`}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <button type="button" onClick={() => onSelectNetwork(net)} className="text-left group min-w-0">
          <span className={`block text-sm font-semibold text-dark-50 group-hover:text-eagle-400 ${net.title ? '' : 'font-mono'}`}>{title}</span>
          <span className="block text-xs text-dark-400">
            {plural(net.device_count, 'device')}
            {net.subnets.length > 0 && <> · with <span className="font-mono">{net.subnets.join(', ')}</span></>}
            {net.last_seen && ` · seen ${formatSeen(net.last_seen).text}`}
          </span>
        </button>
        <div className="flex items-center gap-2 flex-wrap">
          {coverageChips(net).map((c) => (
            <span key={c.text} className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full border ${c.cls}`}>
              <c.Icon className="w-3.5 h-3.5" aria-hidden="true" /> {c.text}
            </span>
          ))}
          {net.device_count > 0 && (
            <button type="button" onClick={() => onToggle(net.key)} aria-expanded={open} className="btn-secondary text-xs inline-flex items-center gap-1">
              {open ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              {open ? 'Close' : 'Open'}
            </button>
          )}
        </div>
      </div>

      <div className="flex flex-wrap gap-x-6 gap-y-3 items-start">
        <div className="w-44 flex-shrink-0 flex flex-col items-stretch">
          <NodeBox icon={Globe} title="Internet" />
          {(net.gateway || net.measured_roots.length === 0) && (
            <>
              <div className="mx-auto h-4 border-l-2 border-dotted border-dark-500" aria-hidden="true" />
              {net.gateway ? (
                <NodeBox icon={Router} tone="text-series-1" sub={net.gateway.ip} onClick={() => onSelectNetwork(net)} label={`Gateway ${net.gateway.ip}`}
                  title={net.gateway.label && net.gateway.label !== net.gateway.ip ? net.gateway.label : 'Gateway'} />
              ) : <NodeBox icon={Router} title="Gateway not known" sub="no agent reported one" mono={false} dashed />}
            </>
          )}
          {net.gateway_macs.length > 1 && (
            <p className="mt-2 text-[11px] text-yellow-400 flex gap-1"><AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
              Two gateways answer at this address: maybe two sites on one range</p>
          )}
        </div>

        <div className="flex-1 min-w-[16rem] space-y-3">
          {net.measured_roots.length > 0 && <Topology roots={net.measured_roots} ctx={ctx} />}
          {(loose.length > 0 || net.measured_roots.length === 0) && (
            <div className="border-l-2 border-dashed border-dark-500/50 pl-4 space-y-3">
              {net.device_count === 0 && net.measured_roots.length === 0 && <p className="text-sm text-dark-400 py-1">Nothing found here yet.</p>}
              {groups.map((g) => g.items.length > 0 && (
                <div key={g.t ?? 'all'} className="space-y-1.5">
                  {g.t && <h4 className="text-xs font-semibold text-dark-300">{TYPE_LABEL[g.t]} <span className="font-normal text-dark-400">{g.items.length}</span></h4>}
                  <div className={GRID}>
                    {g.items.map((d) => (
                      <DeviceCard key={d.asset_id} d={d} mode={mode} onSelect={ctx.onSelectDevice}
                        selected={selection?.type === 'device' && selection.key === net.key && selection.asset_id === d.asset_id} />
                    ))}
                    {!open && hidden > 0 && <MoreButton count={`+${fmt(hidden)} more`} sub="Open the network" onClick={() => onToggle(net.key)} />}
                  </div>
                </div>
              ))}
              {open && net.device_count > net.devices.length && (
                <p className="text-xs text-dark-400">Showing {fmt(net.devices.length)} of {fmt(net.device_count)}: find the others with the search above.</p>
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

function Row({ k, children }) {
  return (
    <div className="grid grid-cols-[6.5rem_1fr] gap-3">
      <dt className="text-dark-400">{k}</dt>
      <dd className="text-dark-100 min-w-0 break-words">{children}</dd>
    </div>
  )
}

// The details of what was picked: a panel fixed to the right edge, over the page but not blocking it.
function PanelShell({ kind, title, onClose, children }) {
  return (
    <aside className="fixed right-4 top-20 bottom-4 z-30 w-[22rem] max-w-[calc(100vw-2rem)] overflow-y-auto glass-card p-4 space-y-4 shadow-2xl"
      aria-label={`${kind} details`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-dark-400">{kind}</p>
          <p className="text-base font-semibold text-dark-50 break-all">{title}</p>
        </div>
        <button type="button" onClick={onClose} className="text-dark-400 hover:text-dark-50" aria-label="Close"><X className="w-4 h-4" /></button>
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
        title="What would be affected if this device were compromised or went down (assets in My Assets)">
        <Zap className="w-3.5 h-3.5" /> Blast radius
      </button>
    </div>
  )
}

export function NetworkPanel({ net, open, onToggle, onClose }) {
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
        {net.device_count > 0 && <button type="button" onClick={() => onToggle(net.key)} className="btn-primary text-sm">{open ? 'Close this network' : 'Open this network'}</button>}
        {!net.title && <Link to={`/discovery?scan=${encodeURIComponent(net.key)}`} className="btn-secondary text-sm text-center">New scan of this network</Link>}
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
