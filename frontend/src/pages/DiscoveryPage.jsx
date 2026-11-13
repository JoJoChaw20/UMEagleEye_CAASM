import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Plus, RefreshCw, Network, Radio, ScanLine, ChevronRight, Wifi, AlertTriangle, Router } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'
import { Tabs, Toast, useToast, Spinner, Pager, ago } from '../components/common/PageParts'
import HostsPanel from '../components/discovery/HostsPanel'
import NewScanModal from '../components/discovery/NewScanModal'
import { KIND_LABEL, KIND_HINT, crawlSummary } from '../components/discovery/discoveryMeta'

// Asset Discovery: the networks the agents have been on (and whether each has been
// fully scanned), each network agent's crawls once (with the networks they reached), and
// the history of every scan. Server: GET /scans/networks, GET /scans (paged), GET /scans/:id/hosts.

const PAGE_SIZE = 25
const QUIET_MINUTES = 15       // passive records arrive about every 5 min while an agent is on the network

const STATUS_CLS = {
  pending:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  running:   'bg-eagle-500/15 text-eagle-400 border-eagle-500/30',
  completed: 'bg-green-500/20 text-green-400 border-green-500/30',
  failed:    'bg-red-500/20 text-red-400 border-red-500/30',
  cancelled: 'bg-dark-600/40 text-dark-400 border-dark-500/30',
}
function StatusBadge({ status }) {
  return <span className={`text-xs px-2 py-0.5 rounded-md border font-medium capitalize ${STATUS_CLS[status] ?? STATUS_CLS.cancelled}`}>{status}</span>
}

// How the agents on a network cover it (GET /scans/networks coverage; lib/agentRouting.ts):
// a sensor notices new devices between scans, a scanner runs the scans sent to it.
const COVERAGE = {
  covered: ['Covered', 'border-green-500/30 bg-green-500/10 text-green-400', 'An agent listens and an agent scans here'],
  scan_only: ['Scan only', 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400', 'No agent listens here: new devices are noticed only by scans. Turn on the Sensor role of an agent on it.'],
  listen_only: ['Listen only', 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400', 'No agent here runs scans: turn on the Scanner role of an agent on it.'],
  left: ['Agent moved away', 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400', 'The agent that was on this network is on another one now (a laptop that moved): nothing listens to or scans this network until an agent is on it again.'],
  offline: ['Agents offline', 'border-red-500/30 bg-red-500/10 text-red-400', 'The agents on this network have not checked in for over 10 minutes: check that the computer is on and the agent is running.'],
  no_agent: ['No agent', 'border-red-500/30 bg-red-500/10 text-red-400', 'No agent is on this network: install one on a computer here.'],
}

// No computer agent on it, but a network agent reads its routers: devices still appear, nothing listens or port-scans
const ROUTERS_ONLY = ['No computer agent', 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400',
  'No computer agent is on this network, so nothing listens to it or port-scans it. A network agent reads it from its routers and switches every 15 minutes: devices appear from their ARP tables.']

function Coverage({ n, agentName }) {
  const c = n.coverage
  if (!c) return null
  const [label, cls, help] = c.state === 'no_agent' && n.mapped_by?.length ? ROUTERS_ONLY : COVERAGE[c.state] ?? COVERAGE.no_agent
  const names = (list) => list.map((a) => `${a.name || agentName(a.agent_id)}${a.late ? ' (late)' : ''}`).join(', ')
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
      <span title={help} className={`px-2 py-0.5 rounded-full border ${cls}`}>{label}</span>
      {c.late && (
        <span className="px-2 py-0.5 rounded-full border border-yellow-500/30 bg-yellow-500/10 text-yellow-400"
          title="Its agents last checked in 2 to 10 minutes ago (a paused VM, a sleeping laptop). They still count; after 10 minutes they are offline.">
          Reporting late
        </span>
      )}
      {c.sensors.length > 0 && <span className="text-dark-300">Listening: {names(c.sensors)}</span>}
      {c.scanners.length > 0 && <span className="text-dark-300">Scans: {names(c.scanners)}</span>}
      {c.left?.length > 0 && (
        <span className="text-dark-300">
          {c.left.map((a) => `${a.name} was here ${ago(a.at)}${a.now_on ? ` · now on ${a.now_on}` : ''}`).join('; ')}
        </span>
      )}
      {c.offline?.length > 0 && (
        <span className="text-dark-400">
          Not checking in: {c.offline.map((a) => `${a.name}${a.last_heartbeat ? ` (${ago(a.last_heartbeat)})` : ''}`).join(', ')}
        </span>
      )}
      {c.duplicate_sensors && (
        <span className="text-dark-400" title="Each sensor uploads what it hears; one is enough per network">
          {c.sensors.length} agents listen here: one can stop (Agents page, Sensor role)
        </span>
      )}
      {n.unmanaged_hosts > 0 && (
        <Link to="/inventory" className="text-amber-400 hover:underline" title="PCs and servers on this network with no EagleEye agent">
          {n.unmanaged_hosts} PC{n.unmanaged_hosts > 1 ? 's/servers' : '/server'} without an agent
        </Link>
      )}
    </div>
  )
}

function NetworkCard({ n, agentName, canScan, onScan, onHosts, onHistory }) {
  // Listening now: heard lately AND a listening agent is checking in on time (its last upload can
  // be minutes old while the agent itself has stopped)
  const heardLately = n.last_heard_at && (Date.now() - new Date(n.last_heard_at).getTime()) < QUIET_MINUTES * 60000
  const listening = heardLately && (!n.coverage || n.coverage.sensors.some((s) => !s.late))
  return (
    <div className="glass-card p-4 space-y-3">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h3 className="font-mono text-base text-dark-50">{n.subnet}</h3>
          <p className="text-xs text-dark-400 mt-0.5">
            {n.gateway ? <>gateway <span className="font-mono">{n.gateway}</span></> : 'gateway unknown'}
            {' · '}{n.agent_ids.map(agentName).join(', ')}
          </p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <span className={`inline-flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full border ${listening
            ? 'border-green-500/30 bg-green-500/10 text-green-400' : 'border-dark-600/50 text-dark-400'}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${listening ? 'bg-green-400 animate-pulse' : 'bg-dark-500'}`} />
            {listening ? 'Agent listening now' : n.last_heard_at ? `Last heard ${ago(n.last_heard_at)}` : 'Not heard passively'}
          </span>
          {n.mapped_by?.length > 0 && (
            <span className="text-xs text-dark-400" title="A network agent also reads this network from its routers (its card below)">
              Also mapped by {n.mapped_by.map(agentName).join(', ')}
            </span>
          )}
        </div>
      </div>

      <Coverage n={n} agentName={agentName} />

      <dl className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
        <div className="bg-dark-800/60 rounded-lg p-2.5">
          <dt className="text-dark-400">Last full scan</dt>
          <dd className={`mt-0.5 ${n.last_full_scan ? 'text-dark-100' : 'text-amber-400'}`}>
            {n.last_full_scan ? <>{ago(n.last_full_scan.at)} · {n.last_full_scan.hosts} hosts</> : 'Never'}
          </dd>
        </div>
        <div className="bg-dark-800/60 rounded-lg p-2.5">
          <dt className="text-dark-400">Hosts seen (24 h)</dt>
          <dd className="mt-0.5 text-dark-100">{n.hosts_24h}</dd>
        </div>
        <div className="bg-dark-800/60 rounded-lg p-2.5">
          <dt className="text-dark-400">New devices</dt>
          <dd className="mt-0.5">
            {n.new_devices > 0
              ? <Link to="/alerts?view=new_devices" className="text-amber-400 hover:underline">{n.new_devices} to review</Link>
              : <span className="text-dark-100">0</span>}
          </dd>
        </div>
        <div className="bg-dark-800/60 rounded-lg p-2.5">
          <dt className="text-dark-400">Last activity</dt>
          <dd className="mt-0.5 text-dark-100">{ago(n.latest_at)}</dd>
        </div>
      </dl>

      <div className="flex flex-wrap gap-2 justify-end">
        <button onClick={onHistory} className="btn-secondary text-xs py-1 px-2.5">Scan history</button>
        {n.last_heard_scan_id && <button onClick={onHosts} className="btn-secondary text-xs py-1 px-2.5">Latest hosts</button>}
        {canScan && (
          <button onClick={onScan} className="btn-primary text-xs py-1 px-2.5 inline-flex items-center gap-1.5">
            <Wifi className="w-3.5 h-3.5" /> Scan this network
          </button>
        )}
      </div>
    </div>
  )
}

const routerCount = (n) => `${n} router${n === 1 ? '' : 's'} and switch${n === 1 ? '' : 'es'}`

// One network agent: its crawls once, with the networks they reached. A network a computer
// agent is also on keeps its own card (named here); the others are rows in this card.
function CrawlCard({ c, netsBySubnet, agentName, canScan, onScan, onHosts, onHistory }) {
  const reached = c.subnets.map((s) => netsBySubnet.get(s.subnet)
    ?? { subnet: s.subnet, gateway: s.gateway, hosts_24h: 0, new_devices: 0, last_full_scan: null, crawl_only: true })
  const rows = reached.filter((n) => n.crawl_only)
  const ownCards = reached.filter((n) => !n.crawl_only)
  const last = c.last_crawl
  const failed = c.latest.status === 'failed'
  return (
    <div className="glass-card p-4 space-y-3">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h3 className="text-base text-dark-50 inline-flex items-center gap-2">
            <Router className="w-4 h-4 text-eagle-400" /> Network agent · {agentName(c.agent_id)}
          </h3>
          <p className="text-xs text-dark-400 mt-0.5 max-w-xl">
            Reads the routers and switches; the devices on the networks below come from their ARP tables. No port scans.
          </p>
        </div>
        <div className="flex flex-col items-end gap-1 text-xs">
          {last
            ? (
              <span className="text-dark-200" title={new Date(last.at).toLocaleString()}>
                Last crawl {ago(last.at)} · {routerCount(last.devices)} · {last.links} link{last.links === 1 ? '' : 's'}
              </span>
            )
            : <span className="text-amber-400">No completed crawl yet</span>}
          {failed && <span className="text-red-400">Latest crawl failed {ago(c.latest.at)}</span>}
          <span className="text-dark-400">{c.subnets.length} network{c.subnets.length === 1 ? '' : 's'} reached</span>
        </div>
      </div>

      {rows.length > 0 && (
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr><th>Network</th><th>Gateway</th><th>Hosts seen (24 h)</th><th>New devices</th><th>Last full scan</th><th className="w-px" /></tr>
            </thead>
            <tbody>
              {rows.map((n) => (
                <tr key={n.subnet}>
                  <td className="font-mono text-xs text-dark-50">{n.subnet}</td>
                  <td className="font-mono text-xs text-dark-300">{n.gateway ?? '—'}</td>
                  <td className="text-xs text-dark-100">{n.hosts_24h}</td>
                  <td className="text-xs">
                    {n.new_devices > 0
                      ? <Link to="/alerts?view=new_devices" className="text-amber-400 hover:underline">{n.new_devices} to review</Link>
                      : <span className="text-dark-100">0</span>}
                  </td>
                  <td className={`text-xs ${n.last_full_scan ? 'text-dark-100' : 'text-amber-400'}`}>
                    {n.last_full_scan ? <>{ago(n.last_full_scan.at)} · {n.last_full_scan.hosts} hosts</> : 'Never'}
                  </td>
                  <td>
                    {canScan && (
                      <button onClick={() => onScan(n.subnet)} title="A full scan by a computer agent that can reach this network"
                        className="btn-secondary text-xs py-1 px-2.5 inline-flex items-center gap-1.5 whitespace-nowrap">
                        <Wifi className="w-3.5 h-3.5" /> Scan
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {ownCards.length > 0 && (
        <p className="text-xs text-dark-400">
          Also reached {ownCards.map((n) => n.subnet).join(', ')}, which {ownCards.length === 1 ? 'has its own card' : 'have their own cards'} above: a computer agent is on {ownCards.length === 1 ? 'it' : 'them'}.
        </p>
      )}

      <div className="flex flex-wrap gap-2 justify-end">
        <button onClick={onHistory} className="btn-secondary text-xs py-1 px-2.5">Crawl history</button>
        {last && <button onClick={onHosts} className="btn-secondary text-xs py-1 px-2.5">Latest crawl</button>}
      </div>
    </div>
  )
}

export default function DiscoveryPage() {
  const { user } = useAuth()
  const isSuperadmin = user?.role === 'superadmin'
  const canScan = ['tenant_superadmin', 'tenant_admin'].includes(user?.role)
  const { toast, show: showToast } = useToast()
  const [tab, setTab] = useState('networks')
  const [tenantFilter, setTenantFilter] = useState('')
  const [agents, setAgents] = useState([])
  const [networks, setNetworks] = useState(null)
  const [crawls, setCrawls] = useState([])
  const [networkDays, setNetworkDays] = useState(30)
  const [scans, setScans] = useState(null)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [kind, setKind] = useState('')
  const [status, setStatus] = useState('')
  const [networkFilter, setNetworkFilter] = useState('')
  const [loading, setLoading] = useState(false)
  const [hostsOf, setHostsOf] = useState(null)        // { scanId, agentName }
  const [searchParams, setSearchParams] = useSearchParams()
  // ?scan=<range> (the Network page's "New scan of this network") opens New scan for that range
  const [newScan, setNewScan] = useState(() => (searchParams.get('scan') ? { subnet: searchParams.get('scan'), agentId: 'auto' } : null))

  const tParams = useMemo(() => (tenantFilter ? { tenant_id: tenantFilter } : {}), [tenantFilter])

  const loadNetworks = useCallback(async () => {
    const [agentsRes, netRes] = await Promise.all([
      client.get('/agents'),
      client.get('/scans/networks', { params: tParams }),
    ])
    setAgents((agentsRes.data.agents || []).filter((a) => a.status !== 'retired' && (!tenantFilter || a.tenant_id === tenantFilter)))
    setNetworks(netRes.data.networks || [])
    setCrawls(netRes.data.crawls || [])
    setNetworkDays(netRes.data.days ?? 30)
  }, [tParams, tenantFilter])

  const loadScans = useCallback(async () => {
    const params = { ...tParams, page, page_size: PAGE_SIZE }
    if (kind) params.kind = kind
    if (status) params.status = status
    if (networkFilter) params.network = networkFilter
    const res = await client.get('/scans', { params })
    setScans(res.data.scans || [])
    setTotal(res.data.total || 0)
  }, [tParams, page, kind, status, networkFilter])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      await Promise.all([loadNetworks(), tab === 'history' ? loadScans() : null])
    } catch (err) {
      showToast(err?.response?.data?.detail || 'Failed to load discovery data', 'error')
      setNetworks((cur) => cur ?? [])
      setScans((cur) => cur ?? [])
    } finally {
      setLoading(false)
    }
  }, [loadNetworks, loadScans, tab, showToast])
  useEffect(() => { load() }, [load])

  // Refresh every 10 s while a scan on this page is queued or running
  const active = (scans ?? []).some((s) => s.status === 'pending' || s.status === 'running')
  useEffect(() => {
    if (!active) return undefined
    const t = setInterval(() => { loadScans().catch(() => {}) }, 10000)
    return () => clearInterval(t)
  }, [active, loadScans])

  const agentName = useCallback((id) => agents.find((a) => a.agent_id === id)?.name ?? (id ? `${id.slice(0, 8)}…` : '—'), [agents])

  const startScan = async ({ subnet, agent_id }) => {
    await client.post('/scans/active', { subnet, agent_id, scan_type: 'active' })
    showToast(`Full scan of ${subnet} queued`, 'success')
    setKind(''); setStatus(''); setNetworkFilter(''); setPage(1)
    setTab('history')
  }

  const showHistory = (subnet) => { setNetworkFilter(subnet); setKind(''); setStatus(''); setPage(1); setTab('history') }
  const showCrawls = () => { setNetworkFilter(''); setKind('snmp'); setStatus(''); setPage(1); setTab('history') }
  const netsBySubnet = useMemo(() => new Map((networks ?? []).map((n) => [n.subnet, n])), [networks])
  // Networks known only from crawls are rows in their network agent's card
  const ownNetworks = (networks ?? []).filter((n) => !n.crawl_only)
  const clearFilters = () => { setKind(''); setStatus(''); setNetworkFilter(''); setPage(1) }
  const hasFilters = kind || status || networkFilter
  const neverScanned = (networks ?? []).filter((n) => !n.last_full_scan).length

  return (
    <div className="space-y-6">
      <Toast toast={toast} />

      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="page-title">Asset Discovery</h1>
          <p className="text-dark-400 text-sm mt-1 max-w-2xl">
            The networks your agents are on: agents listen to them all the time, and a full scan finds what listening misses.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {isSuperadmin && <TenantSelector value={tenantFilter} onChange={(id) => { setTenantFilter(id); setPage(1) }} />}
          <button onClick={load} disabled={loading} className="btn-secondary flex items-center gap-2 text-sm">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
          {canScan && (
            <button onClick={() => setNewScan({})} className="btn-primary flex items-center gap-2 text-sm">
              <Plus className="w-4 h-4" /> New scan
            </button>
          )}
        </div>
      </div>

      <Tabs label="Discovery views" active={tab} onChange={setTab} tabs={[
        { id: 'networks', label: 'Networks', count: networks?.length },
        { id: 'history', label: 'Scan history' },
      ]} />

      {tab === 'networks' && (
        networks === null ? <Spinner className="py-20" /> : networks.length === 0 ? (
          <div className="glass-card text-center py-16 px-4 text-dark-400">
            <Network className="w-14 h-14 mx-auto mb-4 opacity-20" />
            <p className="font-medium text-dark-200 mb-1">No networks yet</p>
            <p className="text-sm max-w-md mx-auto">
              Install the EagleEye agent on a computer (Agents page). As soon as it runs, it reports the network it is on.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-dark-400">
              Networks seen in the last {networkDays} days, most recent first.
              {neverScanned > 0 && <span className="text-amber-400"> {neverScanned} never had a full scan.</span>}
            </p>
            {ownNetworks.map((n) => (
              <NetworkCard key={n.subnet} n={n} agentName={agentName} canScan={canScan}
                onScan={() => setNewScan({ subnet: n.subnet, agentId: 'auto' })}
                onHosts={() => setHostsOf({ scanId: n.last_heard_scan_id, agentName: agentName(n.latest_agent_id) })}
                onHistory={() => showHistory(n.subnet)} />
            ))}
            {crawls.map((c) => (
              <CrawlCard key={c.agent_id ?? 'unknown'} c={c} netsBySubnet={netsBySubnet} agentName={agentName} canScan={canScan}
                onScan={(subnet) => setNewScan({ subnet, agentId: 'auto' })}
                onHosts={() => setHostsOf({ scanId: c.last_crawl.scan_id, agentName: agentName(c.agent_id) })}
                onHistory={showCrawls} />
            ))}
          </div>
        )
      )}

      {tab === 'history' && (
        <div className="space-y-4">
          <div className="flex items-center gap-2 flex-wrap">
            <select value={kind} onChange={(e) => { setKind(e.target.value); setPage(1) }} className="input-field text-sm py-1.5 w-48" aria-label="Kind">
              <option value="">All kinds</option>
              {Object.entries(KIND_LABEL).map(([k, label]) => <option key={k} value={k}>{label}</option>)}
            </select>
            <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1) }} className="input-field text-sm py-1.5 w-40" aria-label="Status">
              <option value="">All statuses</option>
              {['pending', 'running', 'completed', 'failed', 'cancelled'].map((s) => <option key={s} value={s} className="capitalize">{s}</option>)}
            </select>
            <select value={networkFilter} onChange={(e) => { setNetworkFilter(e.target.value); setPage(1) }} className="input-field text-sm py-1.5 w-48" aria-label="Network">
              <option value="">All networks</option>
              {(networks ?? []).map((n) => <option key={n.subnet} value={n.subnet}>{n.subnet}</option>)}
            </select>
            {hasFilters && <button onClick={clearFilters} className="text-xs text-dark-400 hover:text-dark-200 underline underline-offset-2">Clear</button>}
            <span className="text-dark-400 text-sm ml-auto">{total.toLocaleString()} records</span>
          </div>

          <div className="glass-card overflow-hidden">
            {scans === null ? <Spinner className="py-20" /> : scans.length === 0 ? (
              <div className="text-center py-16 text-dark-400 px-4">
                <ScanLine className="w-14 h-14 mx-auto mb-4 opacity-20" />
                <p className="font-medium text-dark-200">{hasFilters ? 'No scans match these filters' : 'No scans yet'}</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr><th>When</th><th>Kind</th><th>Target</th><th>Network</th><th>Agent</th><th>Status</th><th>Hosts</th><th className="w-px" /></tr>
                  </thead>
                  <tbody>
                    {scans.map((s) => {
                      const clickable = s.hostsDiscovered > 0
                      const open = () => clickable && setHostsOf({ scanId: s.scanId, agentName: agentName(s.agentId) })
                      return (
                        <tr key={s.scanId} className={clickable ? 'cursor-pointer hover:bg-dark-700/30' : ''} onClick={open}
                          tabIndex={clickable ? 0 : undefined} onKeyDown={(e) => { if (e.key === 'Enter') open() }}>
                          <td className="text-xs text-dark-300 whitespace-nowrap" title={new Date(s.startedAt).toLocaleString()}>{ago(s.completedAt ?? s.startedAt)}</td>
                          <td className="text-xs text-dark-200 whitespace-nowrap" title={KIND_HINT[s.kind]}>
                            <span className="inline-flex items-center gap-1.5">
                              {s.kind === 'passive' ? <Radio className="w-3.5 h-3.5 text-dark-400" /> : <ScanLine className="w-3.5 h-3.5 text-dark-400" />}
                              {KIND_LABEL[s.kind] ?? s.kind}
                            </span>
                          </td>
                          <td className={`text-xs ${s.kind === 'snmp' ? 'text-dark-300' : 'font-mono text-accent-cyan'}`}>
                            {s.kind === 'snmp' ? (crawlSummary(s) ?? '—') : s.kind === 'passive' ? '—' : s.subnet}
                          </td>
                          <td className="font-mono text-xs text-dark-300">
                            {s.kind === 'snmp'
                              ? (
                                <span className="text-dark-400 font-sans" title={(s.networks_reached ?? []).join(', ') || 'A crawl reads every network its routers know'}>
                                  {s.networks_reached?.length ? `${s.networks_reached.length} network${s.networks_reached.length === 1 ? '' : 's'}` : 'all it reached'}
                                </span>
                              )
                              : s.network ?? <span className="text-dark-500">unknown</span>}
                          </td>
                          <td className="text-xs text-dark-300">{agentName(s.agentId)}</td>
                          <td>
                            <StatusBadge status={s.status} />
                            {s.status === 'failed' && s.failureReason && (
                              <p className="text-[11px] text-red-400/80 mt-1 max-w-xs truncate" title={s.failureReason}>
                                <AlertTriangle className="w-3 h-3 inline mr-1" />{s.failureReason}
                              </p>
                            )}
                          </td>
                          <td className="text-sm text-dark-100">
                            {s.hostsDiscovered}
                            {s.kind === 'investigation' && s.event_id && (
                              <Link to={`/alerts?event=${s.event_id}`} onClick={(e) => e.stopPropagation()} className="block text-[11px] text-eagle-400 hover:underline">alert</Link>
                            )}
                          </td>
                          <td>{clickable && <ChevronRight className="w-4 h-4 text-dark-400" />}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          <Pager page={page} totalPages={Math.ceil(total / PAGE_SIZE)} onChange={setPage} />
        </div>
      )}


      {hostsOf && (
        <HostsPanel scanId={hostsOf.scanId} agentName={hostsOf.agentName} canAdopt={!isSuperadmin && user?.role !== 'business_owner'}
          onClose={() => setHostsOf(null)} />
      )}
      {newScan && (
        <NewScanModal agents={agents} networks={networks ?? []} initial={newScan}
          onClose={() => { setNewScan(null); if (searchParams.has('scan')) setSearchParams({}, { replace: true }) }} onSubmit={startScan} />
      )}
    </div>
  )
}
