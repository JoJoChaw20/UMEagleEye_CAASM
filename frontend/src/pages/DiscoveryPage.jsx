import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { Plus, RefreshCw, Network, Radio, ScanLine, ChevronRight, Wifi, AlertTriangle } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'
import { Tabs, Toast, useToast, Spinner, Pager, ago } from '../components/common/PageParts'
import HostsPanel from '../components/discovery/HostsPanel'
import NewScanModal from '../components/discovery/NewScanModal'
import ScanCompare from '../components/discovery/ScanCompare'
import { KIND_LABEL, KIND_HINT } from '../components/discovery/discoveryMeta'

// Asset Discovery: the networks the agents have been on (and whether each has been
// fully scanned), the history of every scan, and an active-vs-passive comparison.
// Server: GET /scans/networks, GET /scans (paged), GET /scans/:id/hosts.

const PAGE_SIZE = 25
const QUIET_MINUTES = 15       // passive records arrive about every 5 min while an agent is on the network

const STATUS_CLS = {
  pending:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  running:   'bg-blue-500/20 text-blue-400 border-blue-500/30',
  completed: 'bg-green-500/20 text-green-400 border-green-500/30',
  failed:    'bg-red-500/20 text-red-400 border-red-500/30',
  cancelled: 'bg-dark-600/40 text-dark-400 border-dark-500/30',
}
function StatusBadge({ status }) {
  return <span className={`text-xs px-2 py-0.5 rounded-full border font-medium capitalize ${STATUS_CLS[status] ?? STATUS_CLS.cancelled}`}>{status}</span>
}

function NetworkCard({ n, agentName, canScan, onScan, onHosts, onHistory }) {
  const listening = n.last_heard_at && (Date.now() - new Date(n.last_heard_at).getTime()) < QUIET_MINUTES * 60000
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
        <span className={`inline-flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full border ${listening
          ? 'border-green-500/30 bg-green-500/10 text-green-400' : 'border-dark-600/50 text-dark-400'}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${listening ? 'bg-green-400 animate-pulse' : 'bg-dark-500'}`} />
          {listening ? 'Agent listening now' : n.last_heard_at ? `Last heard ${ago(n.last_heard_at)}` : 'Not heard passively'}
        </span>
      </div>

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

export default function DiscoveryPage() {
  const { user } = useAuth()
  const isSuperadmin = user?.role === 'superadmin'
  const canScan = ['tenant_superadmin', 'tenant_admin'].includes(user?.role)
  const { toast, show: showToast } = useToast()
  const [tab, setTab] = useState('networks')
  const [tenantFilter, setTenantFilter] = useState('')
  const [agents, setAgents] = useState([])
  const [networks, setNetworks] = useState(null)
  const [networkDays, setNetworkDays] = useState(30)
  const [scans, setScans] = useState(null)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [kind, setKind] = useState('')
  const [status, setStatus] = useState('')
  const [networkFilter, setNetworkFilter] = useState('')
  const [loading, setLoading] = useState(false)
  const [hostsOf, setHostsOf] = useState(null)        // { scanId, agentName }
  const [newScan, setNewScan] = useState(null)        // null | { subnet?, agentId? }

  const tParams = useMemo(() => (tenantFilter ? { tenant_id: tenantFilter } : {}), [tenantFilter])

  const loadNetworks = useCallback(async () => {
    const [agentsRes, netRes] = await Promise.all([
      client.get('/agents'),
      client.get('/scans/networks', { params: tParams }),
    ])
    setAgents((agentsRes.data.agents || []).filter((a) => a.status !== 'retired' && (!tenantFilter || a.tenant_id === tenantFilter)))
    setNetworks(netRes.data.networks || [])
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
  const clearFilters = () => { setKind(''); setStatus(''); setNetworkFilter(''); setPage(1) }
  const hasFilters = kind || status || networkFilter
  const neverScanned = (networks ?? []).filter((n) => !n.last_full_scan).length

  return (
    <div className="space-y-6">
      <Toast toast={toast} />

      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Asset Discovery</h1>
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
        { id: 'compare', label: 'Compare' },
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
            {networks.map((n) => (
              <NetworkCard key={n.subnet} n={n} agentName={agentName} canScan={canScan}
                onScan={() => setNewScan({ subnet: n.subnet, agentId: agents.find((a) => a.agent_id === n.latest_agent_id && a.status === 'online')?.agent_id })}
                onHosts={() => setHostsOf({ scanId: n.last_heard_scan_id, agentName: agentName(n.latest_agent_id) })}
                onHistory={() => showHistory(n.subnet)} />
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
                          <td className="font-mono text-xs text-accent-cyan">{s.kind === 'passive' ? '—' : s.subnet}</td>
                          <td className="font-mono text-xs text-dark-300">{s.network ?? <span className="text-dark-500">unknown</span>}</td>
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

      {tab === 'compare' && <ScanCompare />}

      {hostsOf && (
        <HostsPanel scanId={hostsOf.scanId} agentName={hostsOf.agentName} canAdopt={!isSuperadmin && user?.role !== 'business_owner'}
          onClose={() => setHostsOf(null)} />
      )}
      {newScan && (
        <NewScanModal agents={agents} networks={networks ?? []} initial={newScan}
          onClose={() => setNewScan(null)} onSubmit={startScan} />
      )}
    </div>
  )
}
