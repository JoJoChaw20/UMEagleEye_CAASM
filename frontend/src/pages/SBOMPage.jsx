import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Package, Shield, Search, ChevronDown, ChevronUp,
  RefreshCw, FileCode2, Database, Cpu, CheckCircle2, Trash2,
  Clock3, AlertCircle, AlertTriangle, XCircle, Download,
} from 'lucide-react'
import {
  BarChart, Bar, Cell, ResponsiveContainer, XAxis, YAxis, Tooltip, CartesianGrid,
} from 'recharts'
import { Link } from 'react-router-dom'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'
import SbomRunNote, { sbomRunProblems } from '../components/common/SbomRunNote'
import PackageSearch from '../components/common/PackageSearch'

// ── Package-manager icon/label map ────────────────────────────
const PM_META = {
  pip:    { icon: '🐍', label: 'pip (Python)',  color: '#3b82f6' },
  npm:    { icon: '📦', label: 'npm (Node)',    color: '#f59e0b' },
  maven:  { icon: '☕', label: 'Maven (Java)',  color: '#ef4444' },
  apk:    { icon: '🐧', label: 'apk (Alpine)',  color: '#10b981' },
  deb:    { icon: '📋', label: 'deb (Debian)',  color: '#8b5cf6' },
  rpm:    { icon: '🎩', label: 'rpm (RHEL)',    color: '#ec4899' },
  go:     { icon: '🐹', label: 'go (Golang)',   color: '#06b6d4' },
  system: { icon: '⚙️', label: 'System',        color: '#6b7280' },
}
const pmColor  = (pm) => PM_META[pm]?.color  ?? '#6b7280'
const pmIcon   = (pm) => PM_META[pm]?.icon   ?? '📦'
const pmLabel  = (pm) => PM_META[pm]?.label  ?? pm

const formatElapsed = (seconds) => {
  const value = Math.max(0, seconds || 0)
  const minutes = Math.floor(value / 60)
  const remainder = value % 60
  return minutes > 0 ? `${minutes}m ${remainder}s` : `${remainder}s`
}

export default function SBOMPage() {
  const { user } = useAuth()
  // SBOMs come from the EagleEye agent installed on each computer (daily, or on request
  // here). A scan always runs on the asset's own agent; the folders are the agent's setting.
  const canScan = ['tenant_superadmin', 'tenant_admin'].includes(user?.role)
  const canDeleteSbom = ['tenant_superadmin', 'tenant_admin'].includes(user?.role)

  // ── State ────────────────────────────────────────────────────
  const [sboms,       setSboms]       = useState([])
  const [stats,       setStats]       = useState(null)
  const [total,       setTotal]       = useState(0)
  const [page,        setPage]        = useState(1)
  const [loading,     setLoading]     = useState(true)
  const [tenantFilter, setTenantFilter] = useState('')

  // Expanded SBOM → dependency panel
  const [expandedId,  setExpandedId]  = useState(null)
  const [deps,        setDeps]        = useState([])
  const [depsLoading, setDepsLoading] = useState(false)
  const [depSearch,   setDepSearch]   = useState('')
  const [depsTotal,   setDepsTotal]   = useState({ all: 0, matching: 0 })  // server counts (the list is capped)
  const [depPms,      setDepPms]      = useState([])   // [{ package_manager, count }] of the whole SBOM
  const [pmFilter,    setPmFilter]    = useState('')

  // Per-asset SBOM scan trigger
  const [scanning,    setScanning]    = useState({})
  const [cancelling,  setCancelling]  = useState({})
  const [clock,       setClock]       = useState(Date.now())
  const scanPolls = useRef({})
  const completionTimers = useRef({})

  useEffect(() => () => {
    Object.values(scanPolls.current).forEach(clearInterval)
    Object.values(completionTimers.current).forEach(clearTimeout)
  }, [])

  useEffect(() => {
    if (Object.keys(scanning).length === 0) return undefined
    const timer = setInterval(() => setClock(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [scanning])

  // Superadmin: delete all SBOMs for an asset
  const deleteSbomsByAsset = async (assetId) => {
    if (!confirm(`Delete all SBOM records for asset ${assetId.slice(0, 8)}…? This cannot be undone.`)) return
    try {
      await client.delete(`/sboms/by-asset/${assetId}`)
      loadData()
    } catch {
      alert('Failed to delete SBOM records.')
    }
  }

  const PAGE_SIZE = 15
  const DEP_LIMIT = 1000   // the API's maximum per request

  // ── Data fetching ────────────────────────────────────────────
  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const tParam = tenantFilter ? { tenant_id: tenantFilter } : {}
      const [sbomsRes, statsRes] = await Promise.all([
        client.get('/sboms', { params: { page, page_size: PAGE_SIZE, ...tParam } }),
        client.get('/sboms/stats/summary', { params: tParam }),
      ])
      setSboms(sbomsRes.data.items || [])
      setTotal(sbomsRes.data.total || 0)
      setStats(statsRes.data)
    } catch (err) {
      console.error('SBOM load error:', err)
    } finally {
      setLoading(false)
    }
  }, [page, tenantFilter])

  useEffect(() => { loadData() }, [loadData])

  const removeScanAfterDelay = useCallback((assetId) => {
    clearTimeout(completionTimers.current[assetId])
    completionTimers.current[assetId] = setTimeout(() => {
      setScanning(current => {
        const next = { ...current }
        delete next[assetId]
        return next
      })
      delete completionTimers.current[assetId]
    }, 12000)
  }, [])

  const pollScanStatus = useCallback(async (assetId) => {
    try {
      const response = await client.get(`/assets/${assetId}/sbom-scan-status`)
      const data = response.data
      const scanInfo = {
        status: data.status,
        scanId: data.scan_id,
        startedAt: data.started_at,
        completedAt: data.completed_at,
        failureReason: data.failure_reason,
        mode: data.mode,       // full | quick (agents 2.2.6+)
      }

      if (data.status === 'pending' || data.status === 'running') {
        setScanning(current => ({ ...current, [assetId]: { ...current[assetId], ...scanInfo } }))
        return false
      }

      clearInterval(scanPolls.current[assetId])
      delete scanPolls.current[assetId]

      if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
        setScanning(current => ({ ...current, [assetId]: scanInfo }))
        removeScanAfterDelay(assetId)
        if (data.status === 'completed') await loadData()
      } else {
        setScanning(current => {
          const next = { ...current }
          delete next[assetId]
          return next
        })
      }
      return true
    } catch (err) {
      console.error('SBOM status polling error:', err)
      return false
    }
  }, [loadData, removeScanAfterDelay])

  const startScanPolling = useCallback((assetId) => {
    clearInterval(scanPolls.current[assetId])
    void pollScanStatus(assetId)
    scanPolls.current[assetId] = setInterval(() => {
      void pollScanStatus(assetId)
    }, 5000)
  }, [pollScanStatus])

  // Recover queued/running scans after refresh or tenant navigation.
  useEffect(() => {
    if (!canScan) return undefined
    let cancelled = false

    Object.values(scanPolls.current).forEach(clearInterval)
    scanPolls.current = {}

    const recoverActiveScans = async () => {
      try {
        const params = tenantFilter ? { tenant_id: tenantFilter } : {}
        const response = await client.get('/sboms/scans/active', { params })
        if (cancelled) return
        const recovered = {}
        for (const item of response.data.items || []) {
          if (!item.asset_id) continue
          recovered[item.asset_id] = {
            status: item.status,
            scanId: item.scan_id,
            startedAt: item.started_at,
          }
        }
        setScanning(recovered)
        Object.keys(recovered).forEach(startScanPolling)
      } catch (err) {
        console.error('Failed to recover active SBOM scans:', err)
      }
    }

    void recoverActiveScans()
    return () => { cancelled = true }
  }, [canScan, tenantFilter, startScanPolling])

  // ── Dependency expansion ─────────────────────────────────────
  const toggleDeps = async (sbomId) => {
    if (expandedId === sbomId) {
      setExpandedId(null)
      setDeps([])
      setDepSearch('')
      setPmFilter('')
      return
    }
    setExpandedId(sbomId)
    setDepsLoading(true)
    setDepSearch('')
    setPmFilter('')
    try {
      const res = await client.get(`/sboms/${sbomId}/dependencies`, { params: { limit: DEP_LIMIT } })
      setDeps(res.data.items || [])
      setDepsTotal({ all: res.data.total ?? 0, matching: res.data.total ?? 0 })
      setDepPms(res.data.package_managers || [])
    } catch (err) {
      console.error('Deps load error:', err)
    } finally {
      setDepsLoading(false)
    }
  }

  // A computer can have thousands of packages but the list loads at most DEP_LIMIT, so
  // the search box and the package-manager filter run on the server (all packages).
  // A response that arrives after a newer request was made is ignored.
  const depRequest = useRef(0)
  useEffect(() => {
    if (!expandedId) return undefined
    const id = ++depRequest.current
    const t = setTimeout(async () => {
      try {
        const res = await client.get(`/sboms/${expandedId}/dependencies`, {
          params: { limit: DEP_LIMIT, ...(depSearch ? { search: depSearch } : {}), ...(pmFilter ? { package_manager: pmFilter } : {}) },
        })
        if (id !== depRequest.current) return
        setDeps(res.data.items || [])
        setDepsTotal(cur => ({ ...cur, matching: res.data.total ?? 0 }))
      } catch (err) {
        console.error('Deps search error:', err)
      }
    }, depSearch ? 300 : 0)
    return () => clearTimeout(t)
  }, [depSearch, pmFilter]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Per-asset SBOM scan ──────────────────────────────────────
  const triggerScan = async (assetId) => {
    setScanning(s => ({
      ...s,
      [assetId]: { status: 'pending', startedAt: new Date().toISOString() },
    }))
    try {
      const response = await client.post(`/assets/${assetId}/scan-sbom`)
      setScanning(s => ({
        ...s,
        [assetId]: {
          status: 'pending',
          scanId: response.data.scan_id,
          startedAt: new Date().toISOString(),
          message: response.data.message,
        },
      }))
      startScanPolling(assetId)
    } catch (err) {
      setScanning(s => {
        const next = { ...s }
        delete next[assetId]
        return next
      })
      alert(err?.response?.data?.detail || '❌ Failed to queue SBOM scan.')
    }
  }

  const downloadSbom = async (sbom) => {
    try {
      const res = await client.get(`/sboms/${sbom.sbom_id}/download`, { responseType: 'blob' })
      const url = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = url
      a.download = `sbom-${sbom.asset_id}.cdx.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      alert('Failed to download the SBOM file.')
    }
  }

  const cancelScan = async (assetId, scanId) => {
    if (!scanId || !confirm('Cancel this SBOM scan? Its results will be discarded when they arrive.')) return
    setCancelling(current => ({ ...current, [scanId]: true }))
    try {
      await client.post(`/scans/${scanId}/cancel`)
      await pollScanStatus(assetId)
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to cancel the SBOM scan.')
    } finally {
      setCancelling(current => {
        const next = { ...current }
        delete next[scanId]
        return next
      })
    }
  }

  // ── Derived chart + filter data ──────────────────────────────
  const pmChartData = stats
    ? Object.entries(stats.by_package_manager || {})
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([pm, count]) => ({ name: pm, count, fill: pmColor(pm) }))
    : []

  // The server already applied the search and the package-manager filter.
  const filteredDeps = deps

  const totalPages = Math.ceil(total / PAGE_SIZE)

  // ── Render ───────────────────────────────────────────────────
  return (
    <div className="space-y-6">

      {/* ── Page header ── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Package className="w-6 h-6 text-eagle-400" />
            Software Bill of Materials
          </h1>
          <p className="text-dark-400 text-sm mt-1">
            Package lists (CycloneDX) built by the EagleEye agent on each computer with Syft, checked for CVEs with Grype
          </p>
        </div>
        <div className="flex items-center gap-2">
          <TenantSelector value={tenantFilter} onChange={(id) => { setTenantFilter(id); setPage(1) }} />
          <button
            onClick={loadData}
            className="btn-secondary flex items-center gap-2 text-sm"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* ── Live SBOM scan progress ── */}
      {Object.keys(scanning).length > 0 && (
        <div className="glass-card p-5 border border-eagle-500/20">
          <div className="flex items-center justify-between gap-3 mb-4">
            <div>
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <RefreshCw className="w-4 h-4 text-eagle-400" />
                Live SBOM Scan Progress
              </h2>
              <p className="text-xs text-dark-400 mt-1">Updates automatically every 5 seconds</p>
            </div>
            <span className="flex items-center gap-1.5 text-xs text-accent-green">
              <span className="w-2 h-2 rounded-full bg-accent-green animate-pulse" /> Live
            </span>
          </div>

          <div className="space-y-3">
            {Object.entries(scanning).map(([assetId, scan]) => {
              const status = scan.status || 'pending'
              const isPending = status === 'pending'
              const isRunning = status === 'running'
              const isCompleted = status === 'completed'
              const isFailed = status === 'failed'
              const started = Date.parse(scan.startedAt || '')
              const finished = Date.parse(scan.completedAt || '')
              const elapsedUntil = (isCompleted || isFailed) && Number.isFinite(finished) ? finished : clock
              const elapsed = Number.isFinite(started)
                ? Math.max(0, Math.floor((elapsedUntil - started) / 1000))
                : 0
              const stage = isPending
                ? (scan.message || 'Queued — waiting for the EagleEye agent on this device')
                : isRunning
                  ? 'The agent is listing packages (Syft) and checking them for CVEs (Grype)'
                  : isCompleted
                    ? 'SBOM generated and stored successfully'
                    : isFailed
                      ? (scan.failureReason || 'The scan failed without a reported reason')
                      : 'Scan was cancelled'

              return (
                <div key={assetId} className="rounded-xl bg-dark-800/60 border border-dark-700/70 p-4">
                  <div className="flex items-start justify-between gap-4 mb-3">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-dark-100 break-all">Asset {assetId}</p>
                      <p className={`text-xs mt-1 ${isFailed ? 'text-red-400' : isCompleted ? 'text-accent-green' : 'text-dark-400'}`}>
                        {stage}
                      </p>
                    </div>
                    <div className="shrink-0 flex items-center gap-2">
                      <span className={`px-2.5 py-1 rounded-full border text-xs font-medium ${
                        isPending ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                          : isRunning ? 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                            : isCompleted ? 'bg-green-500/10 text-accent-green border-green-500/30'
                              : 'bg-red-500/10 text-red-400 border-red-500/30'
                      }`}>
                        {status.charAt(0).toUpperCase() + status.slice(1)}
                      </span>
                      {(isPending || isRunning) && scan.scanId && (
                        <button
                          type="button"
                          onClick={() => cancelScan(assetId, scan.scanId)}
                          disabled={Boolean(cancelling[scan.scanId])}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-red-500/40 text-xs font-medium text-red-400 hover:bg-red-500/10 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <XCircle className="w-3.5 h-3.5" />
                          {cancelling[scan.scanId] ? 'Cancelling…' : 'Cancel'}
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="h-2.5 bg-dark-700 rounded-full overflow-hidden mb-3">
                    {isRunning ? (
                      <div className="sbom-progress-indeterminate h-full w-1/3 rounded-full bg-gradient-to-r from-eagle-500 to-accent-cyan" />
                    ) : (
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          isPending ? 'bg-yellow-500' : isCompleted ? 'bg-accent-green' : 'bg-red-500'
                        }`}
                        style={{ width: isPending ? '12%' : '100%' }}
                      />
                    )}
                  </div>

                  <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-dark-500">
                    <span className="flex items-center gap-1.5">
                      <Clock3 className="w-3.5 h-3.5" />
                      {isCompleted || isFailed ? 'Total' : 'Elapsed'}: {formatElapsed(elapsed)}
                    </span>
                    {scan.scanId && <span className="font-mono">Scan {scan.scanId.slice(0, 8)}…</span>}
                    {isFailed && <AlertCircle className="w-3.5 h-3.5 text-red-400" />}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ── Stats cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-dark-400 text-xs">Total SBOMs</span>
            <FileCode2 className="w-4 h-4 text-eagle-400" />
          </div>
          <p className="text-3xl font-bold text-white">{stats?.total_sboms ?? 0}</p>
          <p className="text-xs text-dark-500 mt-1">scans completed</p>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-dark-400 text-xs">Total Packages</span>
            <Package className="w-4 h-4 text-eagle-400" />
          </div>
          <p className="text-3xl font-bold text-eagle-400">{stats?.total_dependencies ?? 0}</p>
          <p className="text-xs text-dark-500 mt-1">across all assets</p>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-dark-400 text-xs">Assets Scanned</span>
            <Cpu className="w-4 h-4 text-accent-cyan" />
          </div>
          <p className="text-3xl font-bold text-accent-cyan">{stats?.assets_scanned ?? 0}</p>
          <p className="text-xs text-dark-500 mt-1">unique assets</p>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-dark-400 text-xs">Last Scan</span>
            <CheckCircle2 className="w-4 h-4 text-accent-green" />
          </div>
          <p className="text-sm font-semibold text-accent-green mt-1">
            {stats?.latest_scan
              ? new Date(stats.latest_scan).toLocaleDateString()
              : '—'}
          </p>
          <p className="text-xs text-dark-500 mt-1">
            {stats?.latest_scan
              ? new Date(stats.latest_scan).toLocaleTimeString()
              : 'no scans yet'}
          </p>
        </div>
      </div>

      {/* ── Package manager chart ── */}
      {pmChartData.length > 0 && (
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-dark-200 mb-4 flex items-center gap-2">
            <Database className="w-4 h-4 text-eagle-400" />
            Package Manager Distribution
          </h3>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Bar chart */}
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={pmChartData} margin={{ left: 0, bottom: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2028" />
                <XAxis
                  dataKey="name"
                  tick={{ fill: '#7b7f87', fontSize: 11 }}
                  angle={-30}
                  textAnchor="end"
                  height={60}
                />
                <YAxis tick={{ fill: '#7b7f87', fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: 'rgb(var(--dark-700))', border: '1px solid rgb(var(--dark-500))', borderRadius: '8px', color: 'rgb(var(--dark-100))', boxShadow: '0 8px 24px rgba(0,0,0,0.3)' }}
                  formatter={(v, name) => [v, 'packages']}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {pmChartData.map((e, i) => <Cell key={i} fill={e.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>

            {/* Legend / breakdown */}
            <div className="space-y-2 my-auto">
              {pmChartData.map(({ name, count }) => (
                <div key={name} className="flex items-center gap-3">
                  <span className="text-base w-6 text-center">{pmIcon(name)}</span>
                  <span className="text-sm text-dark-300 w-32">{pmLabel(name)}</span>
                  <div className="flex-1 h-2 bg-dark-700 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${(count / (pmChartData[0]?.count || 1)) * 100}%`,
                        background: pmColor(name),
                      }}
                    />
                  </div>
                  <span className="text-sm font-mono text-dark-400 w-10 text-right">{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <PackageSearch tenantId={tenantFilter} />

      {/* ── SBOM table ── */}
      <div className="glass-card overflow-hidden">
        <div className="p-4 border-b border-dark-700/50">
          <h3 className="text-sm font-semibold text-dark-200">SBOM Records</h3>
          <p className="text-xs text-dark-500 mt-0.5">
            Click any row to expand its dependency list
          </p>
        </div>

        {loading ? (
          <div className="flex justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : sboms.length === 0 ? (
          <div className="text-center py-20 text-dark-400">
            <Package className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium mb-2">No SBOMs generated yet</p>
            <p className="text-sm max-w-lg mx-auto">
              The EagleEye agent builds one for its computer once a day. To run one now, open the
              computer in <strong className="text-eagle-400">Assets</strong> and press <strong>Run SBOM scan</strong>.
            </p>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Format</th>
                <th>Components</th>
                <th>Tool</th>
                <th>File</th>
                <th>Generated</th>
                {canScan && <th>Re-scan</th>}
                {canDeleteSbom && <th>Delete</th>}
                <th className="w-8" />
              </tr>
            </thead>
            <tbody>
              {sboms.map(sbom => (
                <>
                  {/* ── Main SBOM row ── */}
                  <tr
                    key={sbom.sbom_id}
                    className="cursor-pointer hover:bg-dark-700/30 transition-colors"
                    onClick={() => toggleDeps(sbom.sbom_id)}
                  >
                    <td onClick={e => e.stopPropagation()}>
                      <Link to={`/inventory/${sbom.asset_id}`} className="hover:underline" title={sbom.asset_id}>
                        <span className="text-sm text-accent-cyan font-medium">{sbom.asset_hostname || sbom.asset_ip || sbom.asset_id}</span>
                        {sbom.asset_hostname && sbom.asset_ip && <span className="block font-mono text-xs text-dark-500">{sbom.asset_ip}</span>}
                      </Link>
                    </td>
                    <td>
                      <span className="text-xs px-2 py-0.5 rounded bg-eagle-600/20 text-eagle-300 border border-eagle-500/30 uppercase tracking-wide">
                        {sbom.format}
                      </span>
                      <span className="text-dark-500 text-xs ml-1.5">v{sbom.format_version}</span>
                    </td>
                    <td>
                      <span className="text-lg font-bold text-eagle-400">
                        {sbom.component_count ?? '—'}
                      </span>
                      {sbomRunProblems(sbom.run) > 0 && (
                        <span title={`${sbomRunProblems(sbom.run)} folder(s) not listed in the last run; expand the row for details`}>
                          <AlertTriangle className="inline w-4 h-4 ml-1.5 text-amber-400 align-text-bottom" />
                        </span>
                      )}
                    </td>
                    <td className="text-dark-300 text-xs">{sbom.generated_by || sbom.tool_used}</td>
                    <td onClick={e => e.stopPropagation()}>
                      <button
                        onClick={() => downloadSbom(sbom)}
                        className="flex items-center gap-1 text-xs text-eagle-400 hover:underline"
                        title={sbom.scope?.length ? `Scanned: ${sbom.scope.join(', ')}` : 'Download the CycloneDX file'}
                      >
                        <Download className="w-3.5 h-3.5" /> Download
                      </button>
                    </td>
                    <td className="text-dark-400 text-xs">
                      {new Date(sbom.generated_at).toLocaleString()}
                    </td>
                    {canScan && (
                      <td onClick={e => e.stopPropagation()}>
                        <button
                          onClick={() => triggerScan(sbom.asset_id)}
                          disabled={['pending', 'running'].includes(scanning[sbom.asset_id]?.status)}
                          className="p-1.5 hover:bg-eagle-500/10 rounded text-eagle-400 transition-colors disabled:opacity-40"
                          title={['pending', 'running'].includes(scanning[sbom.asset_id]?.status)
                            ? ({ quick: 'A daily SBOM is running (only the folders that changed); it usually finishes within a few minutes',
                                 full: 'A full SBOM is already running; its result will appear here when it finishes' }[scanning[sbom.asset_id].mode]
                               ?? `SBOM scan ${scanning[sbom.asset_id].status}`)
                            : 'Re-trigger SBOM scan for this asset'}
                        >
                          {['pending', 'running'].includes(scanning[sbom.asset_id]?.status)
                            ? <RefreshCw className="w-4 h-4 animate-spin" />
                            : <Shield className="w-4 h-4" />}
                        </button>
                      </td>
                    )}
                    {canDeleteSbom && (
                      <td onClick={e => e.stopPropagation()}>
                        <button
                          onClick={() => deleteSbomsByAsset(sbom.asset_id)}
                          className="p-1.5 hover:bg-red-500/10 rounded text-dark-400 hover:text-red-400 transition-colors"
                          title="Delete SBOM records for this asset"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    )}
                    <td>
                      {expandedId === sbom.sbom_id
                        ? <ChevronUp className="w-4 h-4 text-dark-400" />
                        : <ChevronDown className="w-4 h-4 text-dark-400" />}
                    </td>
                  </tr>

                  {/* ── Expanded dependency panel ── */}
                  {expandedId === sbom.sbom_id && (
                    <tr key={`${sbom.sbom_id}-deps`}>
                      <td
                        colSpan={(canScan ? 8 : 7) + (canDeleteSbom ? 1 : 0)}
                        className="p-0 bg-dark-900/60"
                      >
                        <div className="border-t border-dark-700/50 p-4 w-0 min-w-full">
                          {depsLoading ? (
                            <div className="flex justify-center py-6">
                              <div className="w-6 h-6 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
                            </div>
                          ) : (
                            <>
                              <SbomRunNote run={sbom.run} />
                              {/* Dependency filter bar */}
                              <div className="flex items-center gap-3 mb-3 flex-wrap">
                                <h4 className="text-sm font-semibold text-dark-200">
                                  {depsTotal.all} dependencies
                                </h4>

                                {/* Search */}
                                <div className="relative">
                                  <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-dark-400" />
                                  <input
                                    type="text"
                                    placeholder="Filter packages…"
                                    value={depSearch}
                                    onChange={e => setDepSearch(e.target.value)}
                                    onClick={e => e.stopPropagation()}
                                    className="input-field text-xs pl-7 py-1 w-48"
                                  />
                                </div>

                                {/* Package-manager filter: every manager in this SBOM, always shown */}
                                {depPms.length > 0 && (
                                  <select
                                    value={pmFilter}
                                    onChange={e => setPmFilter(e.target.value)}
                                    onClick={e => e.stopPropagation()}
                                    className="input-field text-xs py-1 w-48"
                                  >
                                    <option value="">All package managers ({depsTotal.all})</option>
                                    {depPms.map(({ package_manager: pm, count }) => (
                                      <option key={pm} value={pm}>
                                        {pmIcon(pm)} {pmLabel(pm)} ({count})
                                      </option>
                                    ))}
                                  </select>
                                )}

                                <span className="text-xs text-dark-500 ml-auto whitespace-nowrap">
                                  showing {filteredDeps.length} of {depsTotal.matching}
                                  {depsTotal.matching > deps.length && ` (first ${DEP_LIMIT}; type to search all)`}
                                </span>
                              </div>

                              {/* Dependency table */}
                              <div className="max-h-72 overflow-y-auto rounded border border-dark-700/50">
                                <table className="w-full text-xs table-fixed">
                                  <colgroup>
                                    <col className="w-[32%]" /><col className="w-[16%]" /><col className="w-[11%]" />
                                    <col className="w-[13%]" /><col className="w-[28%]" />
                                  </colgroup>
                                  <thead className="sticky top-0 z-10 bg-dark-800 shadow-[0_1px_0_rgb(var(--dark-700))]">
                                    <tr className="text-dark-400 border-b border-dark-700">
                                      <th className="text-left py-2 px-3 font-medium">Package</th>
                                      <th className="text-left py-2 px-3 font-medium">Version</th>
                                      <th className="text-left py-2 px-3 font-medium">Manager</th>
                                      <th className="text-left py-2 px-3 font-medium">License</th>
                                      <th className="text-left py-2 px-3 font-medium">PURL</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {filteredDeps.length === 0 ? (
                                      <tr>
                                        <td colSpan="5" className="text-center py-6 text-dark-500">
                                          No matching packages
                                        </td>
                                      </tr>
                                    ) : filteredDeps.map(dep => (
                                      <tr
                                        key={dep.dependency_id}
                                        className="border-b border-dark-700/30 hover:bg-dark-700/20"
                                      >
                                        <td className="py-1.5 px-3 font-medium text-dark-100 truncate" title={dep.name}>
                                          {dep.name}
                                        </td>
                                        <td className="py-1.5 px-3 font-mono text-dark-400 truncate" title={dep.version || ''}>
                                          {dep.version || '—'}
                                        </td>
                                        <td className="py-1.5 px-3">
                                          <span
                                            className="flex items-center gap-1"
                                            style={{ color: pmColor(dep.package_manager || 'system') }}
                                          >
                                            <span>{pmIcon(dep.package_manager || 'system')}</span>
                                            <span>{dep.package_manager || 'system'}</span>
                                          </span>
                                        </td>
                                        <td className="py-1.5 px-3 text-dark-500 truncate" title={Array.isArray(dep.licenses) ? dep.licenses.join(', ') : ''}>
                                          {Array.isArray(dep.licenses) && dep.licenses.length > 0
                                            ? dep.licenses.join(', ')
                                            : '—'}
                                        </td>
                                        <td className="py-1.5 px-3 font-mono text-dark-600 truncate" title={dep.purl || ''}>
                                          {dep.purl || '—'}
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* ── Pagination ── */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="btn-secondary text-sm py-1 px-3 disabled:opacity-30"
          >
            Previous
          </button>
          <span className="text-dark-400 text-sm">
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="btn-secondary text-sm py-1 px-3 disabled:opacity-30"
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}
