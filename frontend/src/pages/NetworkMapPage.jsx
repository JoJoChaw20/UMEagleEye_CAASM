// The Network page (GET /network/map). First the whole picture (components/network/NetworkOverview.jsx):
// the internet, each network's gateway and the network as a card, with the tenant at a glance beside
// it. Picking a network shows only that network's map (components/network/NetworkBands.jsx): its
// gateway, the routers and switches a network agent read (cables, switch ports, VLAN groups) and
// every device on it, with its details beside it. Nothing here is guessed: each line was measured or
// seen by an agent. ?net=<range> opens a network, so the browser's Back returns to the overview.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ArrowLeft, RefreshCw, Search, Share2 } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'
import BlastRadiusModal from '../components/common/BlastRadiusModal'
import {
  COLOUR_MODES, CoverageChips, DevicePanel, NO_ALERTS, NetworkPanel, NetworkTopology, NodePanel, plural, treeIndex,
} from '../components/network/NetworkBands'
import { NetworksOverview, OverviewPanel } from '../components/network/NetworkOverview'

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
  const canInfer = user?.role === 'tenant_superadmin' || user?.role === 'tenant_admin'
  const [tenantId, setTenantId] = useState('')
  const { data, error, loading, load } = useMap(tenantId, !isSuperadmin || !!tenantId)
  const [searchParams, setSearchParams] = useSearchParams()
  const openKey = searchParams.get('net')
  const [query, setQuery] = useState('')
  const [mode, setMode] = useState('kind')                  // colour devices by kind, open CVEs or exposure
  const [pick, setPick] = useState(null)                    // {type: device | node, ...} in the open network
  const [blastOf, setBlastOf] = useState(null)

  const map = data ?? { nodes: [], edges: [], agents: [], networks: [] }
  const networks = map.networks ?? []
  const tree = useMemo(() => treeIndex(map), [map])
  const byAsset = useMemo(() => new Map(networks.flatMap((n) => n.devices.map((d) => [d.asset_id, d]))), [networks])
  // A tree node as a device: the network's facts about it when it has any (alerts, agent).
  const deviceOf = useCallback((node) => (byAsset.has(node.asset_id) ? { ...byAsset.get(node.asset_id), ip: node.ip ?? byAsset.get(node.asset_id).ip } : {
    asset_id: node.asset_id, label: node.label, ip: node.ip, mac: node.mac, device_type: node.device_type,
    criticality: node.criticality, in_my_assets: false, last_seen: node.seen_at, measured: true, agent: null, alerts: NO_ALERTS,
  }), [byAsset])

  const q = query.trim().toLowerCase()
  const matches = useMemo(() => new Set(q ? map.nodes.filter((n) => [n.label, n.ip, n.mac].some(has(q))).map((n) => n.id) : []), [map, q])
  // Search narrows each network to its matching devices (a network whose range matches keeps them all).
  const netDevices = useMemo(() => new Map(networks.map((n) => [n.key, !q || n.key.includes(q) ? n.devices
    : n.devices.filter((d) => [d.label, d.ip, d.mac].some(has(q)))])), [networks, q])
  const treeHits = (n) => n.measured_roots.reduce((s, r) => s + (tree.members.get(r) ?? []).filter((id) => matches.has(id)).length, 0)
  const matchCount = (n) => (!q || n.key.includes(q) ? 0 : netDevices.get(n.key).length + treeHits(n))
  const shownNets = q ? networks.filter((n) => n.key.includes(q) || matchCount(n) > 0) : networks

  const net = openKey ? networks.find((n) => n.key === openKey) : null
  const openNet = (key) => { setPick(null); setSearchParams({ net: key }) }
  const backToAll = () => { setPick(null); setSearchParams({}) }

  useEffect(() => {
    if (!pick) return undefined
    const onKey = (e) => { if (e.key === 'Escape') setPick(null) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [pick])

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="page-title">Network</h1>
          <p className="text-dark-400 text-sm mt-1 max-w-3xl">
            Every network your agents are on, from the internet down: each gateway, the routers and switches your network agents
            read, and the devices on each network. Nothing is guessed: each line was measured or seen by an agent in the last {map.days ?? 30} days.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {isSuperadmin && <TenantSelector value={tenantId} onChange={(id) => { setTenantId(id); backToAll() }} />}
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
            {net && (
              <button type="button" onClick={backToAll} className="btn-secondary text-sm inline-flex items-center gap-1.5">
                <ArrowLeft className="w-4 h-4" /> All networks
              </button>
            )}
            <div className="relative">
              <Search className="w-4 h-4 text-dark-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input value={query} onChange={(e) => setQuery(e.target.value)}
                placeholder={net ? 'Find a device, IP or MAC' : 'Find a device, IP, MAC or network'}
                className="input-field pl-9 text-sm w-72" aria-label="Find a device or network" />
            </div>
            {net && (
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
            )}
            <LineLegend />
          </div>

          {openKey && !net && (
            <div className="glass-card p-4 text-sm text-dark-300">
              No agent has seen {openKey} in the last {map.days ?? 30} days. <button type="button" onClick={backToAll} className="text-eagle-400 hover:underline">Show all networks</button>
            </div>
          )}

          <div className="grid gap-4 items-start lg:grid-cols-[minmax(0,1fr)_22rem]">
            <div className="glass-card p-4 min-w-0 space-y-3">
              {net ? (
                <>
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <h2 className={`text-base font-semibold text-dark-50 ${net.title ? '' : 'font-mono'}`}>{net.title ?? net.key}</h2>
                      <p className="text-xs text-dark-400">
                        {plural(net.device_count, 'device')}
                        {net.subnets.length > 0 && <> · with <span className="font-mono">{net.subnets.join(', ')}</span></>}
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2"><CoverageChips net={net} /></div>
                  </div>
                  <NetworkTopology key={net.key} net={net} devices={netDevices.get(net.key)} mode={mode} tree={tree} deviceOf={deviceOf} matches={matches}
                    selection={pick ?? { type: 'network', key: net.key }}
                    onSelectNetwork={() => setPick(null)}
                    onSelectDevice={(x, d) => setPick({ type: 'device', key: x.key, asset_id: d.asset_id, device: d })}
                    onSelectNode={(x, node) => setPick({ type: 'node', key: x.key, id: node.id })} />
                  {q && netDevices.get(net.key).length === 0 && treeHits(net) === 0 && <p className="text-sm text-dark-400">Nothing on this network matches.</p>}
                </>
              ) : (
                <>
                  <NetworksOverview networks={shownNets} map={map} matchCount={matchCount} onOpen={openNet} />
                  {q && shownNets.length === 0 && <p className="text-sm text-dark-400 text-center">Nothing matches.</p>}
                </>
              )}
            </div>

            <div className="lg:sticky lg:top-4 min-w-0">
              {net && pick?.type === 'device' ? <DevicePanel net={net} device={pick.device} onClose={() => setPick(null)} onBlast={setBlastOf} />
                : net && pick?.type === 'node' && tree.nodes.get(pick.id) ? <NodePanel node={tree.nodes.get(pick.id)} tree={tree} map={map} onClose={() => setPick(null)} onBlast={setBlastOf} />
                  : net ? <NetworkPanel net={net} />
                    : <OverviewPanel networks={networks} map={map} canInfer={canInfer} />}
            </div>
          </div>
        </>
      )}
      {blastOf && <BlastRadiusModal assetId={blastOf} onClose={() => setBlastOf(null)} />}
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
        This page shows the networks your agents are on. Install the agent on a computer (it reports the network it is on
        and the devices it hears), or a network agent next to your routers and switches to add the cables and switch ports.
      </p>
      <Link to="/agents" className="btn-primary inline-flex items-center gap-2 text-sm">Go to Agents</Link>
    </div>
  )
}
