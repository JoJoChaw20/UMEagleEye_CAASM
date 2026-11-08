// The network as the network agents measured it (GET /network/map): routers and switches
// joined by their cables (port at each end), every device under the switch port it is
// plugged into, and devices whose port is not known grouped by VLAN under their router.
// Layout: utils/networkMapLayout.js. Unlike the Inventory graph, nothing here is guessed.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Router, Network, Monitor, Server, Smartphone, Cpu, HelpCircle, Layers, CircleDashed, Search,
  ZoomIn, ZoomOut, Maximize2, RefreshCw, X, ExternalLink, Share2,
} from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'
import { layoutNetworkMap, NODE_W, NODE_H } from '../utils/networkMapLayout'
import { formatSeen } from '../utils/time'

const KIND = {
  router:    { icon: Router,       label: 'Router',            tone: 'series-1' },
  switch:    { icon: Network,      label: 'Switch',            tone: 'series-2' },
  neighbour: { icon: CircleDashed, label: 'Not read (neighbour)', tone: 'dark-400' },
  vlan:      { icon: Layers,       label: 'VLAN, port not known', tone: 'series-5' },
  more:      { icon: Layers,       label: 'More devices',      tone: 'dark-400' },
}
const DEVICE_ICON = { server: Server, workstation: Monitor, mobile: Smartphone, iot: Cpu, network: Network }
const rgb = (v, a = 1) => (a === 1 ? `rgb(var(--${v}))` : `rgb(var(--${v}) / ${a})`)
const plural = (n, one, many = `${one}s`) => (n === 1 ? one : many)
const cut = (s, n) => (s && s.length > n ? `${s.slice(0, n - 1)}…` : s ?? '')
// A cable: both ends' ports; a device: the switch port it is on; a VLAN group: the router's
// interface for it. A collapsed "+N devices" line has no single port.
const portLabel = (e) => {
  if (e.collapsed) return null
  if (e.kind === 'cable') return e.from_port || e.to_port ? `${e.from_port ?? '?'} – ${e.to_port ?? '?'}` : null
  return e.from_port
}

function useMap(tenantId, enabled) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const load = useCallback(async () => {
    if (!enabled) { setData(null); return }
    setLoading(true); setError(null)
    try {
      const { data: d } = await client.get('/network/map', { params: tenantId ? { tenant_id: tenantId } : {} })
      setData(d)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Could not load the network map')
    } finally { setLoading(false) }
  }, [tenantId, enabled])
  useEffect(() => { load() }, [load])
  return { data, error, loading, load }
}

export default function NetworkMapPage() {
  const { user } = useAuth()
  const isSuperadmin = user?.role === 'superadmin'
  const [tenantId, setTenantId] = useState('')
  const { data, error, loading, load } = useMap(tenantId, !isSuperadmin || !!tenantId)
  const [expanded, setExpanded] = useState(() => new Set())
  const [selected, setSelected] = useState(null)
  const [query, setQuery] = useState('')
  const [vlan, setVlan] = useState('')

  const map = data ?? { nodes: [], edges: [], agents: [] }
  const vlans = useMemo(() => [...new Set(map.nodes.map((n) => n.vlan).filter((v) => v != null))].sort((a, b) => a - b), [map])
  const q = query.trim().toLowerCase()
  const matches = useMemo(() => new Set(q ? map.nodes.filter((n) =>
    [n.label, n.ip, n.mac].some((v) => v && String(v).toLowerCase().includes(q))).map((n) => n.id) : []), [map, q])
  // a match hidden in a "+N devices" group opens that group
  const open = useMemo(() => {
    const s = new Set(expanded)
    for (const id of matches) {
      const n = map.nodes.find((x) => x.id === id)
      if (n?.parent) s.add(n.parent)
    }
    return s
  }, [expanded, matches, map])
  const layout = useMemo(() => layoutNetworkMap(map, open), [map, open])
  const dimmed = (n) => (vlan !== '' && n.kind === 'device' && String(n.vlan) !== vlan) || (q && !matches.has(n.id) && n.kind === 'device')

  const counts = useMemo(() => {
    const viaVlan = new Set(map.edges.filter((e) => e.kind === 'vlan').map((e) => e.to))
    return {
      routers: map.nodes.filter((n) => n.kind === 'router').length,
      switches: map.nodes.filter((n) => n.kind === 'switch').length,
      onPorts: map.edges.filter((e) => e.kind === 'port').length,
      noPort: map.nodes.filter((n) => n.kind === 'device' && viaVlan.has(n.id)).length,
      cables: map.edges.filter((e) => e.kind === 'cable').length,
    }
  }, [map])

  const clickNode = (n) => {
    if (n.kind === 'more') {
      setExpanded((s) => new Set(s).add(n.parent))
      return
    }
    setSelected(map.nodes.find((x) => x.id === n.id) ?? null)
  }

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="page-title">Network map</h1>
          <p className="text-dark-400 text-sm mt-1 max-w-3xl">
            The routers and switches your network agents read, the cables between them, and the switch port every
            device is plugged into. Measured, not guessed: it comes from the devices' own CDP/LLDP, MAC and ARP tables.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {isSuperadmin && <TenantSelector value={tenantId} onChange={(id) => { setTenantId(id); setSelected(null) }} />}
          <button onClick={load} className="btn-secondary flex items-center gap-2 text-sm" disabled={loading}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      {error && <div className="glass-card p-4 border border-red-500/30 text-red-400 text-sm">{error}</div>}
      {isSuperadmin && !tenantId && <div className="glass-card p-6 text-sm text-dark-300">Pick a tenant to see its network.</div>}

      {data && map.nodes.length === 0 && <EmptyMap agents={map.agents} days={map.days} />}

      {data && map.nodes.length > 0 && (
        <>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Stat label={plural(counts.routers, 'router')} value={counts.routers} />
            <Stat label={plural(counts.switches, 'switch', 'switches')} value={counts.switches} />
            <Stat label={plural(counts.cables, 'cable')} value={counts.cables} />
            <Stat label={`${plural(counts.onPorts, 'device')} on switch ports`} value={counts.onPorts} />
            {counts.noPort > 0 && <Stat label={`${plural(counts.noPort, 'device')} with no known port`} value={counts.noPort} tone="text-yellow-400"
              title="Their router knows them, but no switch's MAC table placed them (e.g. a switch that keeps no table per VLAN)" />}
            <span className="text-dark-500 ml-auto">
              {map.agents.length} network agent{map.agents.length === 1 ? '' : 's'} · last {map.days} days
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-4 h-4 text-dark-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Find a device, IP or MAC"
                className="input-field pl-9 text-sm w-64" aria-label="Find a device" />
            </div>
            {vlans.length > 0 && (
              <select value={vlan} onChange={(e) => setVlan(e.target.value)} className="input-field text-sm w-40" aria-label="VLAN">
                <option value="">All VLANs</option>
                {vlans.map((v) => <option key={v} value={String(v)}>VLAN {v}</option>)}
              </select>
            )}
            {expanded.size > 0 && (
              <button onClick={() => setExpanded(new Set())} className="btn-secondary text-xs">Collapse device groups</button>
            )}
            {q && <span className="text-xs text-dark-400">{matches.size} match{matches.size === 1 ? '' : 'es'}</span>}
          </div>

          <div className="relative">
            <MapCanvas layout={layout} selectedId={selected?.id} matches={matches} dimmed={dimmed} onClickNode={clickNode} />
            {selected && <Details node={selected} map={map} onClose={() => setSelected(null)} />}
          </div>
          <Legend />
        </>
      )}
    </div>
  )
}

function Stat({ label, value, tone = 'text-dark-50', title }) {
  return (
    <span title={title} className="px-3 py-1 rounded-full border border-dark-600/40 bg-dark-800/40 text-dark-300">
      <span className={`font-semibold ${tone}`}>{value}</span> {label}
    </span>
  )
}

function EmptyMap({ agents, days }) {
  return (
    <div className="glass-card p-10 text-center space-y-3">
      <Share2 className="w-12 h-12 mx-auto text-dark-500" />
      {agents.length === 0 ? (
        <>
          <p className="text-dark-100 font-medium">No network agent yet</p>
          <p className="text-sm text-dark-400 max-w-xl mx-auto">
            The map comes from a network agent reading your routers and switches over SNMP. Register one on the
            Agents page, install it next to your network equipment (Docker or a Linux service), then set the devices it
            starts from in its Settings.
          </p>
          <Link to="/agents" className="btn-primary inline-flex items-center gap-2 text-sm">Go to Agents</Link>
        </>
      ) : (
        <>
          <p className="text-dark-100 font-medium">Nothing measured in the last {days} days</p>
          <p className="text-sm text-dark-400 max-w-xl mx-auto">
            {agents.map((a) => a.name).join(', ')} {agents.length === 1 ? 'has' : 'have'} not sent a crawl yet. Check that
            its Settings give the routers or switches to start from, then use Run now on the Agents page.
          </p>
        </>
      )}
    </div>
  )
}

// ── the drawing: SVG, wheel to zoom, drag to move ─────────────────────
function MapCanvas({ layout, selectedId, matches, dimmed, onClickNode }) {
  const ref = useRef(null)
  const [view, setView] = useState({ x: 0, y: 0, k: 1 })
  const drag = useRef(null)
  const fit = useCallback(() => {
    const el = ref.current
    if (!el) return
    const k = Math.min(1.2, (el.clientWidth - 20) / layout.width, 640 / layout.height)
    setView({ k, x: Math.max(10, (el.clientWidth - layout.width * k) / 2), y: 10 })
  }, [layout.width, layout.height])
  useEffect(() => { fit() }, [fit])

  useEffect(() => {
    const el = ref.current
    if (!el) return undefined
    const onWheel = (e) => {
      e.preventDefault()
      const rect = el.getBoundingClientRect()
      const px = e.clientX - rect.left, py = e.clientY - rect.top
      setView((v) => {
        const k = Math.max(0.2, Math.min(3, v.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12)))
        return { k, x: px - ((px - v.x) * k) / v.k, y: py - ((py - v.y) * k) / v.k }
      })
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [])

  const zoom = (f) => setView((v) => ({ ...v, k: Math.max(0.2, Math.min(3, v.k * f)) }))
  const half = NODE_H / 2
  return (
    <div className="glass-card overflow-hidden relative">
      <div className="absolute right-3 top-3 z-10 flex gap-1">
        <IconButton onClick={() => zoom(1.2)} label="Zoom in"><ZoomIn className="w-4 h-4" /></IconButton>
        <IconButton onClick={() => zoom(1 / 1.2)} label="Zoom out"><ZoomOut className="w-4 h-4" /></IconButton>
        <IconButton onClick={fit} label="Fit"><Maximize2 className="w-4 h-4" /></IconButton>
      </div>
      <svg ref={ref} className="w-full h-[640px] cursor-grab active:cursor-grabbing select-none" role="img"
        aria-label="Network map"
        onMouseDown={(e) => { drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y, moved: false } }}
        onMouseMove={(e) => {
          const d = drag.current
          if (!d) return
          if (Math.abs(e.clientX - d.x) + Math.abs(e.clientY - d.y) > 3) d.moved = true
          setView((v) => ({ ...v, x: d.vx + e.clientX - d.x, y: d.vy + e.clientY - d.y }))
        }}
        onMouseUp={() => { setTimeout(() => { drag.current = null }, 0) }}
        onMouseLeave={() => { drag.current = null }}>
        <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
          {layout.edges.map((e, i) => {
            const mid = (e.y1 + half + e.y2 - half) / 2
            const path = e.tree
              ? `M${e.x1},${e.y1 + half} V${mid} H${e.x2} V${e.y2 - half}`
              : `M${e.x1},${e.y1 + half} C${e.x1},${e.y1 + 90} ${e.x2},${e.y2 - 90} ${e.x2},${e.y2 - half}`
            const stroke = e.kind === 'cable' ? rgb('eagle-500') : e.kind === 'port' ? rgb('series-2', 0.8) : rgb('dark-400', 0.7)
            return (
              <g key={i}>
                <path d={path} fill="none" stroke={stroke} strokeWidth={e.kind === 'cable' ? 2 : 1.4}
                  strokeDasharray={e.kind === 'vlan' || !e.tree || e.ambiguous ? '5 4' : undefined} />
                {/* the ports, at the child's end of the line (one label per line, never stacked at the parent) */}
                {portLabel(e) && (
                  <text x={e.tree ? e.x2 + 5 : (e.x1 + e.x2) / 2 + 5} y={e.tree ? e.y2 - half - 6 : (e.y1 + e.y2) / 2}
                    fontSize="10" fill={rgb('dark-300')} className="font-mono">{portLabel(e)}</text>
                )}
              </g>
            )
          })}
          {layout.nodes.map((n) => (
            <MapNode key={n.id} n={n} selected={n.id === selectedId} match={matches.has(n.id)} dim={dimmed(n)}
              onClick={() => { if (!drag.current?.moved) onClickNode(n) }} />
          ))}
        </g>
      </svg>
    </div>
  )
}

function MapNode({ n, selected, match, dim, onClick }) {
  const meta = KIND[n.kind]
  const Icon = meta?.icon ?? DEVICE_ICON[n.device_type] ?? HelpCircle
  const tone = meta?.tone ?? (n.criticality >= 7 ? 'sev-high' : 'dark-300')
  const x = n.x - NODE_W / 2, y = n.y - NODE_H / 2
  const sub = n.kind === 'device' ? n.ip : n.kind === 'more' ? 'click to show' : (n.ip ?? n.detail)
  return (
    <g transform={`translate(${x},${y})`} onClick={onClick} className="cursor-pointer" opacity={dim ? 0.25 : 1}
      role="button" aria-label={`${meta?.label ?? 'Device'} ${n.label}`}>
      <rect width={NODE_W} height={NODE_H} rx="10" fill={rgb('dark-850')}
        stroke={selected ? rgb('eagle-400') : match ? rgb('accent-amber') : rgb(tone, n.kind === 'device' ? 0.45 : 0.9)}
        strokeWidth={selected || match ? 2.5 : 1.5}
        strokeDasharray={n.kind === 'neighbour' || n.kind === 'vlan' || n.kind === 'more' ? '5 4' : undefined} />
      <Icon x={10} y={14} width={20} height={20} color={rgb(tone)} />
      <text x={38} y={21} fontSize="12" fontWeight="600" fill={rgb('dark-50')}>{cut(n.label, 16)}</text>
      <text x={38} y={36} fontSize="10" fill={rgb('dark-400')} className={n.kind === 'device' ? 'font-mono' : ''}>{cut(sub, 22)}</text>
      <title>{[n.label, n.ip, n.detail].filter(Boolean).join(' · ')}</title>
    </g>
  )
}

function IconButton({ onClick, label, children }) {
  return (
    <button type="button" onClick={onClick} title={label} aria-label={label}
      className="p-1.5 rounded-lg border border-dark-600/50 bg-dark-850/90 text-dark-300 hover:text-dark-50">{children}</button>
  )
}

function Details({ node, map, onClose }) {
  const byId = new Map(map.nodes.map((n) => [n.id, n]))
  const connections = map.edges.filter((e) => e.from === node.id || e.to === node.id).map((e) => {
    const mine = e.from === node.id
    const other = byId.get(mine ? e.to : e.from)
    return { other, myPort: mine ? e.from_port : e.to_port, theirPort: mine ? e.to_port : e.from_port, kind: e.kind, ambiguous: e.ambiguous }
  })
  const meta = KIND[node.kind]
  return (
    <aside className="absolute top-3 left-3 z-10 w-80 max-h-[610px] overflow-y-auto glass-card p-4 space-y-3 shadow-xl" aria-label="Details">
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="text-xs text-dark-400">{meta?.label ?? (node.device_type ? `Device (${node.device_type})` : 'Device')}</p>
          <p className="text-base font-semibold text-dark-50 break-all">{node.label}</p>
        </div>
        <button onClick={onClose} className="text-dark-400 hover:text-dark-50" aria-label="Close"><X className="w-4 h-4" /></button>
      </div>
      <dl className="text-sm space-y-1">
        {node.ip && <Row k="IP address" v={<span className="font-mono">{node.ip}</span>} />}
        {node.mac && <Row k="MAC" v={<span className="font-mono lowercase">{node.mac}</span>} />}
        {node.detail && <Row k={node.kind === 'router' || node.kind === 'switch' ? 'System' : 'Note'} v={node.detail} />}
        {node.vlan != null && <Row k="VLAN" v={node.vlan} />}
        {node.criticality != null && <Row k="Criticality" v={`${node.criticality}/10`} />}
        {node.seen_at && <Row k="Seen" v={formatSeen(node.seen_at).text} />}
      </dl>
      {connections.length > 0 && (
        <div>
          <p className="text-[11px] uppercase tracking-wide text-dark-500 mb-1">Connections</p>
          <ul className="space-y-1 text-sm">
            {connections.map((c, i) => (
              <li key={i} className="text-dark-200">
                {c.myPort && <span className="font-mono text-xs text-dark-400">{c.myPort} → </span>}
                {c.other?.label ?? '?'}
                {c.theirPort && <span className="font-mono text-xs text-dark-400"> {c.theirPort}</span>}
                {c.kind === 'vlan' && <span className="text-xs text-dark-500"> (routed, port not known)</span>}
                {c.ambiguous && <span className="text-xs text-yellow-400"> (seen on two switches)</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {node.asset_id && (
        <Link to={`/inventory/${node.asset_id}`} className="btn-secondary text-sm inline-flex items-center gap-2">
          Open asset <ExternalLink className="w-3.5 h-3.5" />
        </Link>
      )}
    </aside>
  )
}

const Row = ({ k, v }) => (
  <div className="flex justify-between gap-3"><dt className="text-dark-400">{k}</dt><dd className="text-dark-100 text-right">{v}</dd></div>
)

function Legend() {
  const items = [
    ['Router', 'series-1', false], ['Switch', 'series-2', false], ['Not read by an agent', 'dark-400', true],
    ['VLAN group: router knows them, no switch port', 'series-5', true],
  ]
  return (
    <div className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-dark-400">
      {items.map(([label, tone, dashed]) => (
        <span key={label} className="inline-flex items-center gap-1.5">
          <span className="inline-block w-3 h-3 rounded" style={{ border: `2px ${dashed ? 'dashed' : 'solid'} ${rgb(tone)}` }} />{label}
        </span>
      ))}
      <span className="inline-flex items-center gap-1.5"><span className="inline-block w-5 border-t-2" style={{ borderColor: rgb('eagle-500') }} />cable (CDP/LLDP)</span>
      <span className="inline-flex items-center gap-1.5"><span className="inline-block w-5 border-t-2 border-dashed" style={{ borderColor: rgb('eagle-500') }} />cable that closes a loop</span>
      <span>Wheel to zoom, drag to move, click a device for its details.</span>
    </div>
  )
}
