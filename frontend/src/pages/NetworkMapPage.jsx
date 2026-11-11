// The tenant's whole network (GET /network/map): every network its agents see, one band each
// (components/network/NetworkBands.jsx), stacked: the internet, the gateway, what is on it and
// which agent watches it. Where a network agent reads the routers and switches, their tree (the
// cables, the switch port each device is plugged into, devices whose port is not known grouped by
// VLAN) is drawn in the band of the network the router is on. Nothing here is guessed: each line
// was measured or seen by an agent.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, Search, Share2 } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'
import BlastRadiusModal from '../components/common/BlastRadiusModal'
import {
  COLOUR_MODES, DevicePanel, NO_ALERTS, NetworkBand, NetworkPanel, NodePanel, treeIndex,
} from '../components/network/NetworkBands'

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

const has = (q) => (v) => v && String(v).toLowerCase().includes(q)

export default function NetworkMapPage() {
  const { user } = useAuth()
  const isSuperadmin = user?.role === 'superadmin'
  const [tenantId, setTenantId] = useState('')
  const { data, error, loading, load } = useMap(tenantId, !isSuperadmin || !!tenantId)
  const [query, setQuery] = useState('')
  const [mode, setMode] = useState('kind')                  // colour devices by kind, open CVEs or exposure
  const [openNets, setOpenNets] = useState(() => new Set())
  const [pick, setPick] = useState(null)                    // {type: network | device | node, key, ...}
  const [blastOf, setBlastOf] = useState(null)

  const map = data ?? { nodes: [], edges: [], agents: [], networks: [] }
  const networks = map.networks ?? []
  const tree = useMemo(() => treeIndex(map), [map])
  const byAsset = useMemo(() => new Map(networks.flatMap((n) => n.devices.map((d) => [d.asset_id, d]))), [networks])
  // A tree node as a device card: the network's facts about it when it has any (alerts, agent).
  // Its address is the one in the tree (a device on several networks has one on each).
  const deviceOf = useCallback((node) => (byAsset.has(node.asset_id) ? { ...byAsset.get(node.asset_id), ip: node.ip ?? byAsset.get(node.asset_id).ip } : {
    asset_id: node.asset_id, label: node.label, ip: node.ip, mac: node.mac, device_type: node.device_type,
    criticality: node.criticality, in_my_assets: false, last_seen: node.seen_at, measured: true, agent: null, alerts: NO_ALERTS,
  }), [byAsset])

  const q = query.trim().toLowerCase()
  const matches = useMemo(() => new Set(q ? map.nodes.filter((n) => [n.label, n.ip, n.mac].some(has(q))).map((n) => n.id) : []), [map, q])
  // Search narrows each network to its matching devices (a network whose range matches keeps them all).
  const netDevices = useMemo(() => new Map(networks.map((n) => [n.key, !q || n.key.includes(q) ? n.devices
    : n.devices.filter((d) => [d.label, d.ip, d.mac].some(has(q)))])), [networks, q])
  const treeHit = (n) => n.measured_roots.some((r) => (tree.members.get(r) ?? []).some((id) => matches.has(id)))
  const shownNets = q ? networks.filter((n) => n.key.includes(q) || netDevices.get(n.key).length > 0 || treeHit(n)) : networks

  useEffect(() => {
    if (!pick) return undefined
    const onKey = (e) => { if (e.key === 'Escape') setPick(null) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [pick])

  const toggleNet = (key) => setOpenNets((s) => { const t = new Set(s); if (t.has(key)) t.delete(key); else t.add(key); return t })
  const pickedNet = pick ? networks.find((n) => n.key === pick.key) : null

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="page-title">Network map</h1>
          <p className="text-dark-400 text-sm mt-1 max-w-3xl">
            Every network your agents are on: its gateway, its devices, which agent watches it, and the routers and switches
            your network agents read. Nothing is guessed: each line was measured or seen by an agent in the last {map.days ?? 30} days.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {isSuperadmin && <TenantSelector value={tenantId} onChange={(id) => { setTenantId(id); setPick(null) }} />}
          <button onClick={load} className="btn-secondary flex items-center gap-2 text-sm" disabled={loading}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      {error && <div className="glass-card p-4 border border-red-500/30 text-red-400 text-sm">{error}</div>}
      {isSuperadmin && !tenantId && <div className="glass-card p-6 text-sm text-dark-300">Pick a tenant to see its network.</div>}

      {data && networks.length === 0 && <EmptyMap />}

      {data && networks.length > 0 && (
        <>
          <div className="glass-card px-3 py-2.5 flex flex-wrap items-center gap-x-4 gap-y-2">
            <div className="relative">
              <Search className="w-4 h-4 text-dark-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Find a device, IP, MAC or network"
                className="input-field pl-9 text-sm w-72" aria-label="Find a device or network" />
            </div>
            <div className="flex items-center gap-2" role="group" aria-label="Colour devices by">
              <span className="text-xs text-dark-400">Colour by</span>
              <div className="inline-flex rounded-lg border border-dark-700/80 overflow-hidden">
                {COLOUR_MODES.map((m) => (
                  <button key={m.id} type="button" onClick={() => setMode(m.id)} aria-pressed={mode === m.id}
                    className={`px-3 py-1.5 text-xs border-l border-dark-700/80 first:border-l-0 ${mode === m.id
                      ? 'bg-eagle-500 text-white font-semibold' : 'bg-dark-800 text-dark-300 hover:text-dark-50'}`}>
                    {m.label}
                  </button>
                ))}
              </div>
            </div>
            <LineLegend />
          </div>

          <Summary networks={networks} map={map} />

          <div className="space-y-3">
            {shownNets.map((n) => (
              <NetworkBand key={n.key} net={n} devices={netDevices.get(n.key)} mode={mode} tree={tree} deviceOf={deviceOf} matches={matches}
                open={openNets.has(n.key) || (!!q && !n.key.includes(q))} onToggle={toggleNet} selection={pick}
                onSelectNetwork={(x) => setPick({ type: 'network', key: x.key })}
                onSelectDevice={(x, d) => setPick({ type: 'device', key: x.key, asset_id: d.asset_id, device: d })}
                onSelectNode={(x, node) => setPick({ type: 'node', key: x.key, id: node.id })} />
            ))}
            {q && shownNets.length === 0 && <p className="text-sm text-dark-400">Nothing matches.</p>}
          </div>

          {pick?.type === 'device' && pickedNet && <DevicePanel net={pickedNet} device={pick.device} onClose={() => setPick(null)} onBlast={setBlastOf} />}
          {pick?.type === 'node' && tree.nodes.get(pick.id) && <NodePanel node={tree.nodes.get(pick.id)} tree={tree} map={map} onClose={() => setPick(null)} onBlast={setBlastOf} />}
          {pick?.type === 'network' && pickedNet && <NetworkPanel net={pickedNet} open={openNets.has(pickedNet.key)} onToggle={toggleNet} onClose={() => setPick(null)} />}
        </>
      )}
      {blastOf && <BlastRadiusModal assetId={blastOf} onClose={() => setBlastOf(null)} />}
    </div>
  )
}

// The tenant at a glance, above the map.
function Summary({ networks, map }) {
  const unwatched = networks.filter((n) => n.agents.length === 0 && n.measured_roots.length === 0).length
  const devices = networks.reduce((s, n) => s + n.device_count, 0)
  const infra = map.nodes.filter((n) => n.kind === 'router' || n.kind === 'switch').length
  const chip = 'px-3 py-1 rounded-full border border-dark-600/40 bg-dark-800/40 text-dark-300'
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <span className={chip}><b className="text-dark-50">{networks.length}</b> network{networks.length === 1 ? '' : 's'}</span>
      <span className={chip}><b className="text-dark-50">{devices.toLocaleString()}</b> device{devices === 1 ? '' : 's'} on them</span>
      {infra > 0 && <span className={chip}><b className="text-dark-50">{infra}</b> router{infra === 1 ? '' : 's'} and switches read</span>}
      <span className={chip} title="No computer agent listens or scans there, and no network agent reads its routers">
        <b className={unwatched ? 'text-yellow-400' : 'text-dark-50'}>{unwatched}</b> not watched by any agent</span>
    </div>
  )
}

function LineLegend() {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 ml-auto text-xs text-dark-400">
      <span className="inline-flex items-center gap-1.5"><span className="w-6 border-t-2 border-eagle-500" aria-hidden="true" />Measured cable or port</span>
      <span className="inline-flex items-center gap-1.5"><span className="w-6 border-t-2 border-dashed border-dark-400" aria-hidden="true" />Seen by an agent</span>
      <span className="inline-flex items-center gap-1.5"><span className="w-6 border-t-2 border-dotted border-dark-400" aria-hidden="true" />Route to the internet</span>
    </div>
  )
}

function EmptyMap() {
  return (
    <div className="glass-card p-10 text-center space-y-3">
      <Share2 className="w-12 h-12 mx-auto text-dark-500" />
      <p className="text-dark-100 font-medium">No network seen yet</p>
      <p className="text-sm text-dark-400 max-w-xl mx-auto">
        The map shows the networks your agents are on. Install the agent on a computer (it reports the network it is on
        and the devices it hears), or a network agent next to your routers and switches to add the cables and switch ports.
      </p>
      <Link to="/agents" className="btn-primary inline-flex items-center gap-2 text-sm">Go to Agents</Link>
    </div>
  )
}
