import { useState, useEffect, useCallback } from 'react'
import { Server, Search, Shield, Bookmark, GitBranch, Target, Building2, CheckCircle, RefreshCw } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import AssetGraph from '../components/common/AssetGraph'
import BlastRadiusModal from '../components/common/BlastRadiusModal'

const PAGE_SIZE = 25

export default function AssetsPage() {
  const { user } = useAuth()
  const [assets, setAssets] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [deviceTypeFilter, setDeviceTypeFilter] = useState('')
  const [tenantFilter, setTenantFilter] = useState('')
  const [tenants, setTenants] = useState([])
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('inventory') // 'inventory' | 'graph'
  const [blastRadiusAssetId, setBlastRadiusAssetId] = useState(null)
  const [graphBlastId, setGraphBlastId] = useState(null)
  const [rescoring, setRescoring] = useState(false)

  // Fetch tenant list for superadmin filter
  useEffect(() => {
    if (user?.role === 'superadmin') {
      client.get('/tenants')
        .then(res => setTenants(res.data.tenants || []))
        .catch(() => {})
    }
  }, [user?.role])

  const loadAssets = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, page_size: PAGE_SIZE }
      if (search) params.search = search
      if (deviceTypeFilter) params.device_type = deviceTypeFilter
      if (tenantFilter) params.tenant_id = tenantFilter
      const res = await client.get('/assets', { params })
      setAssets(res.data.items || [])
      setTotal(res.data.total || 0)
    } catch (err) { console.error(err) }
    finally { setLoading(false) }
  }, [page, search, deviceTypeFilter, tenantFilter])

  useEffect(() => { loadAssets() }, [loadAssets])

  const promoteToMyAssets = async (asset) => {
    try {
      await client.post('/assets', {
        ip_address: asset.ipAddress,
        hostname: asset.hostname || undefined,
        mac_address: asset.macAddress || undefined,
        device_type: asset.deviceType,
        os_info: asset.osInfo || undefined,
        is_internet_facing: asset.isInternetFacing,
        source: 'manual',
        tenant_id: asset.tenantId || undefined,
      })
      loadAssets()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to accept asset')
    }
  }

  const triggerSbomScan = async (assetId) => {
    const target = prompt(
      "Enter Syft scan target (leave blank to scan the agent machine's filesystem):\n" +
      "  • Blank / dir:C:\\Program Files  — agent machine (Windows default)\n" +
      "  • dir:/home             — agent machine (Linux default)\n" +
      "  • image:nginx:alpine    — Docker image on agent machine",
      ""
    );
    if (target === null) return;  // user pressed Cancel
    try {
      await client.post(`/assets/${assetId}/scan-sbom`, { target: target || undefined })
      alert('SBOM Scan queued. Check Alerts page in a few minutes.')
    } catch (err) {
      console.error(err)
      alert('Failed to trigger SBOM scan.')
    }
  }

  const triggerSetBaseline = async (assetId) => {
    if (!confirm('Set current state as Golden Image baseline? This will overwrite any existing baseline.')) return
    try {
      await client.post(`/assets/${assetId}/baseline`, { confirm: true })
      alert('Baseline set successfully.')
      loadAssets()
    } catch (err) {
      console.error(err)
      alert('Failed to set baseline.')
    }
  }

  const rescoreAssets = async () => {
    if (!confirm('Recalculate criticality scores for all assets using the risk formula?')) return
    setRescoring(true)
    try {
      const res = await client.post('/assets/rescore')
      alert(`Rescored ${res.data.updated} asset(s) successfully.`)
      loadAssets()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to rescore assets.')
    } finally {
      setRescoring(false)
    }
  }

  const handleGraphAssetSelect = (assetId) => {
    setGraphBlastId(prev => prev === assetId ? null : assetId)
  }

  const SOURCE_META = {
    manual:       { label: 'My Assets', cls: 'bg-green-500/20 text-green-400 border-green-500/30' },
    scan_active:  { label: 'Active scan', cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
    scan_passive: { label: 'Passive scan', cls: 'bg-dark-600/40 text-dark-400 border-dark-500/30' },
  }

  const DEVICE_TYPE_META = {
    server:      { icon: '🖥️', label: 'Server' },
    workstation: { icon: '💻', label: 'Workstation' },
    network:     { icon: '🌐', label: 'Network' },
    iot:         { icon: '📡', label: 'IoT' },
    unknown:     { icon: '❓', label: 'Unknown' },
  }
  const getCriticalityMeta = (score) => {
    const s = Number(score)
    if (s >= 9) return { label: 'Critical', cls: 'bg-red-500/20 text-red-400 border-red-500/30' }
    if (s >= 7) return { label: 'High', cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30' }
    if (s >= 4) return { label: 'Medium', cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' }
    return { label: 'Low', cls: 'bg-green-500/20 text-green-400 border-green-500/30' }
  }

  const totalPages = Math.ceil(total / PAGE_SIZE)
  const activeTenantName = tenants.find(t => t.tenant_id === tenantFilter)?.name

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Asset Inventory</h1>
          <p className="text-dark-400 text-sm mt-1">
            {total} assets discovered
            {activeTenantName && <span className="ml-2 text-eagle-400">· {activeTenantName}</span>}
          </p>
        </div>
        <button
          onClick={rescoreAssets}
          disabled={rescoring}
          className="btn-secondary flex items-center gap-2 text-sm"
          title="Recalculate criticality scores for all assets"
        >
          <RefreshCw className={`w-4 h-4 ${rescoring ? 'animate-spin' : ''}`} />
          {rescoring ? 'Rescoring…' : 'Rescore Criticality'}
        </button>
      </div>

      {/* Tab Toggle + shared Tenant Filter */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-1 p-1 bg-dark-800/60 rounded-xl w-fit border border-dark-700/50" id="asset-view-toggle">
          <button
            onClick={() => setActiveTab('inventory')}
            className={`tab-toggle ${activeTab === 'inventory' ? 'active' : ''}`}
            id="tab-inventory"
          >
            <Server className="w-4 h-4" />
            Inventory
          </button>
          <button
            onClick={() => setActiveTab('graph')}
            className={`tab-toggle ${activeTab === 'graph' ? 'active' : ''}`}
            id="tab-graph"
          >
            <GitBranch className="w-4 h-4" />
            Relationship Graph
          </button>
        </div>

        {/* Tenant filter — superadmin only, shared between both tabs */}
        {user?.role === 'superadmin' && tenants.length > 0 && (
          <div className="relative">
            <Building2 className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400 pointer-events-none" />
            <select
              value={tenantFilter}
              onChange={(e) => { setTenantFilter(e.target.value); setPage(1) }}
              className="input-field pl-9 pr-8 text-sm appearance-none min-w-[180px]"
            >
              <option value="">All Tenants</option>
              {tenants.map((t) => (
                <option key={t.tenant_id} value={t.tenant_id}>{t.name}</option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Inventory View */}
      {activeTab === 'inventory' && (
        <>
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
              <input type="text" placeholder="Search by hostname or IP..." value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1) }}
                className="input-field pl-10 text-sm" id="asset-search" />
            </div>
            <select
              value={deviceTypeFilter}
              onChange={e => { setDeviceTypeFilter(e.target.value); setPage(1) }}
              className="input-field text-sm py-1.5 w-44"
            >
              <option value="">All Types</option>
              <option value="server">Server</option>
              <option value="workstation">Workstation</option>
              <option value="network">Network</option>
              <option value="iot">IoT</option>
              <option value="unknown">Unknown</option>
            </select>
            <button
              onClick={() => { setSearch(''); setDeviceTypeFilter(''); setPage(1) }}
              className="text-xs text-dark-400 hover:text-dark-200 underline underline-offset-2"
            >
              Clear filters
            </button>
            <span className="text-dark-400 text-sm ml-auto">{total} assets</span>
          </div>

          <div className="glass-card overflow-hidden">
            {loading ? (
              <div className="flex items-center justify-center py-20">
                <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
              </div>
            ) : assets.length > 0 ? (
              <table className="data-table">
                <thead><tr><th>Type</th><th>Hostname / IP</th><th>Source</th><th>Vendor</th><th className="criticality-col">Criticality</th><th>Baseline</th><th>Last Scanned</th><th>Actions</th></tr></thead>
                <tbody>
                  {assets.map((a) => {
                    const srcMeta = SOURCE_META[a.source] ?? SOURCE_META.scan_passive
                    const isManual = a.source === 'manual'
                    const deviceMeta = DEVICE_TYPE_META[a.deviceType] ?? DEVICE_TYPE_META.unknown
                    const { label: critLabel, cls: critCls } = getCriticalityMeta(a.criticalityScore)
                    return (
                      <tr key={a.assetId}>
                        <td>
                          <span className="flex items-center gap-1.5 whitespace-nowrap">
                            <span className="text-base leading-none">{deviceMeta.icon}</span>
                            <span className="text-xs text-dark-300">{deviceMeta.label}</span>
                          </span>
                        </td>
                        <td>
                          <div className="font-medium text-white">{a.hostname || '—'}</div>
                          <div className="font-mono text-xs text-accent-cyan">{a.ipAddress}</div>
                        </td>
                        <td className="whitespace-nowrap">
                          <span style={{ whiteSpace: 'nowrap' }} className={`text-xs px-2 py-0.5 rounded-full border font-medium ${srcMeta.cls}`}>
                            {srcMeta.label}
                          </span>
                        </td>
                        <td className="text-dark-300 text-sm">{a.hardwareVendor || '—'}</td>
                        <td className="criticality-col">
                          <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${critCls}`}>
                            {a.criticalityScore}/10 <span className="opacity-70">{critLabel}</span>
                          </span>
                        </td>
                        <td>{a.baselineState ? <span className="badge-resolved">Set</span> : <span className="text-dark-500 text-xs">No</span>}</td>
                        <td className="text-dark-400 text-xs">{a.lastScanned ? new Date(a.lastScanned).toLocaleString() : '—'}</td>
                        <td>
                          <div className="flex items-center gap-1">
                            {!isManual && (
                              <button
                                onClick={() => promoteToMyAssets(a)}
                                className="p-1.5 hover:bg-green-500/10 rounded text-dark-400 hover:text-green-400 transition-colors"
                                title="Accept to My Assets"
                              >
                                <CheckCircle className="w-4 h-4" />
                              </button>
                            )}
                            <button
                              onClick={() => triggerSbomScan(a.assetId)}
                              className="p-1.5 hover:bg-eagle-500/10 rounded text-eagle-400 transition-colors"
                              title="Scan SBOM"
                            >
                              <Shield className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => triggerSetBaseline(a.assetId)}
                              className={`p-1.5 rounded transition-colors ${a.baselineState ? 'text-eagle-500 hover:bg-eagle-500/10' : 'text-dark-400 hover:bg-dark-500/20'}`}
                              title="Set Baseline"
                            >
                              <Bookmark className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => setBlastRadiusAssetId(a.assetId)}
                              className="p-1.5 hover:bg-red-500/10 rounded text-dark-400 hover:text-red-400 transition-colors"
                              title="Blast Radius"
                            >
                              <Target className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            ) : (
              <div className="text-center py-20 text-dark-400">
                <Server className="w-16 h-16 mx-auto mb-4 opacity-20" />
                <p>No assets found. Run a scan or adjust your filters.</p>
              </div>
            )}
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="btn-secondary text-sm py-1 px-3 disabled:opacity-30"
              >
                Previous
              </button>
              <span className="text-dark-400 text-sm">Page {page} of {totalPages}</span>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="btn-secondary text-sm py-1 px-3 disabled:opacity-30"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}

      {/* Graph View */}
      {activeTab === 'graph' && (
        <div className="glass-card p-5">
          <AssetGraph
            onSelectAsset={handleGraphAssetSelect}
            blastRadiusId={graphBlastId}
            tenantFilter={tenantFilter}
          />
        </div>
      )}

      {/* Blast Radius Modal */}
      {blastRadiusAssetId && (
        <BlastRadiusModal
          assetId={blastRadiusAssetId}
          onClose={() => setBlastRadiusAssetId(null)}
        />
      )}
    </div>
  )
}
