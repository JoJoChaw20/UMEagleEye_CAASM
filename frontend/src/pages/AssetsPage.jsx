import { useState, useEffect, useCallback, Fragment } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Server, Search, Shield, CheckCircle, MinusCircle, Trash2, RefreshCw, Layers, Filter, X } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import DuplicatesPanel from '../components/common/DuplicatesPanel'
import TenantSelector from '../components/common/TenantSelector'
import { AddressCellInfo, AddressTimelineRow } from '../components/common/AssetAddressInfo'
import { formatSeen } from '../utils/time'
import { isLocallyAdministeredMac } from '../utils/mac'
import { RISKY_PORTS } from '../components/common/alertMeta'

const PAGE_SIZE = 25

// Exact filters that other pages link to (dashboard panels, alert drawer)
const LINK_FILTER_KEYS = ['asset_id', 'gap', 'port', 'internet_facing']
const GAP_LABELS = {
  new_7d:       'New devices this week',
  unidentified: 'Unidentified devices (no type, vendor or hostname)',
  stale:        'Not seen by a scan in 7 days',
  no_sbom:      'Servers & PCs without an SBOM',
}

function readLinkFilter(sp) {
  const params = {}
  for (const k of LINK_FILTER_KEYS) { const v = sp.get(k); if (v) params[k] = v }
  if (!Object.keys(params).length) return null
  const parts = []
  if (params.asset_id) parts.push(sp.get('label') ? `Asset ${sp.get('label')}` : 'One asset')
  if (params.gap) parts.push(GAP_LABELS[params.gap] ?? params.gap)
  if (params.port) parts.push(`${RISKY_PORTS[params.port] ? `${RISKY_PORTS[params.port]} ` : ''}port ${params.port} open`)
  if (params.internet_facing) parts.push('Internet-facing')
  return { params, label: parts.join(' · ') }
}

export default function AssetsPage() {
  const { user } = useAuth()
  const isSuperadmin = user?.role === 'superadmin'
  const isBusinessOwner = user?.role === 'business_owner'
  const canManageAssets = !isSuperadmin && !isBusinessOwner
  const canDelete = user?.role === 'tenant_superadmin'
  const [assets, setAssets] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [searchParams, setSearchParams] = useSearchParams()
  const [search, setSearch] = useState(() => searchParams.get('q') ?? '')
  const [deviceTypeFilter, setDeviceTypeFilter] = useState(() => searchParams.get('device_type') ?? '')
  const [sourceFilter, setSourceFilter] = useState(() => searchParams.get('source') ?? '')
  const [membershipFilter, setMembershipFilter] = useState(() => searchParams.get('in_my_assets') ?? '')  // '', 'true', 'false'
  const [linkFilter, setLinkFilter] = useState(() => readLinkFilter(searchParams))
  const [tenantFilter, setTenantFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [rescoring, setRescoring] = useState(false)
  const [sbomScans, setSbomScans] = useState({})
  const [showDuplicates, setShowDuplicates] = useState(false)
  const [dupCount, setDupCount] = useState(0)
  const [expandedId, setExpandedId] = useState(null)   // asset whose address timeline is open
  const toggleTimeline = (id) => setExpandedId((cur) => (cur === id ? null : id))

  const loadAssets = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, page_size: PAGE_SIZE }
      if (search) params.search = search
      if (deviceTypeFilter) params.device_type = deviceTypeFilter
      if (sourceFilter) params.source = sourceFilter
      if (membershipFilter) params.in_my_assets = membershipFilter
      if (tenantFilter) params.tenant_id = tenantFilter
      Object.assign(params, linkFilter?.params)
      const res = await client.get('/assets', { params })
      setAssets(res.data.items || [])
      setTotal(res.data.total || 0)
    } catch (err) { console.error(err) }
    finally { setLoading(false) }
  }, [page, search, deviceTypeFilter, sourceFilter, membershipFilter, tenantFilter, linkFilter])

  // Follow in-app links that change the query while this page is open
  useEffect(() => {
    const next = readLinkFilter(searchParams)
    setLinkFilter(prev => JSON.stringify(prev) === JSON.stringify(next) ? prev : next)
    setSearch(searchParams.get('q') ?? '')
    setDeviceTypeFilter(searchParams.get('device_type') ?? '')
    setSourceFilter(searchParams.get('source') ?? '')
    setMembershipFilter(searchParams.get('in_my_assets') ?? '')
    setPage(1)
  }, [searchParams])

  const clearLinkFilter = () => { setLinkFilter(null); setSearchParams({}, { replace: true }); setPage(1) }

  const loadDupCount = useCallback(async () => {
    try {
      const params = tenantFilter ? { tenant_id: tenantFilter } : {}
      const res = await client.get('/assets/duplicates', { params })
      setDupCount(res.data.count || 0)
    } catch { setDupCount(0) }
  }, [tenantFilter])

  useEffect(() => { loadAssets() }, [loadAssets])
  useEffect(() => { if (!isBusinessOwner) loadDupCount() }, [loadDupCount, isBusinessOwner])

  const promoteToMyAssets = async (asset) => {
    try {
      // Adopt into My Assets — flip the flag only, never re-POST (which would reset
      // `source`, the last-observation method).
      await client.patch(`/assets/${asset.assetId}`, { in_my_assets: true })
      loadAssets()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to add asset to My Assets')
    }
  }

  const removeFromMyAssets = async (asset) => {
    if (!confirm(
      'Remove this asset from My Assets?\n\n' +
      '• It stays in All Assets with its history, owner and criticality.\n' +
      '• It will be hidden from the relationship graph.\n' +
      '• You can add it back at any time.'
    )) return
    try {
      await client.patch(`/assets/${asset.assetId}`, { in_my_assets: false })
      loadAssets()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to remove asset from My Assets')
    }
  }

  const deletePermanently = async (asset) => {
    if (!confirm(
      `Delete ${asset.hostname || asset.ipAddress} permanently?\n\n` +
      'This permanently deletes the asset and its events, SBOMs, dependencies and ' +
      'relationships. This cannot be undone.'
    )) return
    try {
      await client.delete(`/assets/${asset.assetId}`)
      loadAssets()
      loadDupCount()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to delete asset')
    }
  }

  const triggerSbomScan = async (assetId) => {
    const target = prompt(
      "Enter Syft scan target (leave blank to scan the agent machine's filesystem):\n" +
      "  • Blank                  — agent's default scan directory\n" +
      "  • dir:/home             — agent machine (Linux default)\n" +
      "  • image:nginx:alpine    — Docker image on agent machine",
      ""
    )
    if (target === null) return
    try {
      const res = await client.post(`/assets/${assetId}/scan-sbom`, { target: target || undefined })
      const scanId = res.data.scan_id
      setSbomScans(prev => ({ ...prev, [assetId]: { status: 'pending', scanId } }))
      const poll = setInterval(async () => {
        try {
          const r = await client.get(`/assets/${assetId}/sbom-scan-status`)
          const s = r.data.status
          setSbomScans(prev => ({ ...prev, [assetId]: { status: s, scanId: r.data.scan_id } }))
          if (s === 'completed' || s === 'failed' || s === 'none') {
            clearInterval(poll)
            if (s === 'completed') loadAssets()
            if (s === 'failed') {
              alert(`SBOM scan failed: ${r.data.failure_reason || 'No failure reason was reported by the agent.'}`)
            }
          }
        } catch { clearInterval(poll) }
      }, 5000)
    } catch (err) {
      console.error(err)
      alert(err?.response?.data?.detail || 'Failed to trigger SBOM scan.')
    }
  }

  const rescoreAssets = async () => {
    if (!confirm('Recalculate criticality scores for all assets using the risk formula?')) return
    setRescoring(true)
    try {
      const res = await client.post('/assets/rescore')
      alert(res.data.message)
      loadAssets()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to rescore assets.')
    } finally {
      setRescoring(false)
    }
  }

  // source = the LAST observation method only (My Assets membership is a separate
  // green badge driven by a.inMyAssets).
  const SOURCE_META = {
    manual:       { label: 'Manual',       cls: 'bg-dark-600/40 text-dark-300 border-dark-500/30' },
    scan_active:  { label: 'Active scan',  cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
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
    if (s >= 7) return { label: 'High',     cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30' }
    if (s >= 4) return { label: 'Medium',   cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' }
    return              { label: 'Low',      cls: 'bg-green-500/20 text-green-400 border-green-500/30' }
  }

  const totalPages = Math.ceil(total / PAGE_SIZE)
  const colCount = canManageAssets ? 7 : 6   // columns in the table (for the timeline colSpan)

  // Human-readable summary of the active filters, for the empty state.
  const activeFilterBits = []
  if (deviceTypeFilter) activeFilterBits.push(`type ${DEVICE_TYPE_META[deviceTypeFilter]?.label ?? deviceTypeFilter}`)
  if (sourceFilter) activeFilterBits.push(`source ${SOURCE_META[sourceFilter]?.label ?? sourceFilter}`)
  if (membershipFilter === 'true') activeFilterBits.push('in My Assets')
  else if (membershipFilter === 'false') activeFilterBits.push('not in My Assets')
  const filterSummary = activeFilterBits.join(', ')

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Asset Inventory</h1>
          <p className="text-dark-400 text-sm mt-1">{total} assets discovered</p>
        </div>
        <div className="flex items-center gap-2">
          {!isBusinessOwner && (
            <button
              onClick={() => setShowDuplicates(true)}
              className="btn-secondary flex items-center gap-2 text-sm relative"
              title="Review and merge duplicate assets"
            >
              <Layers className="w-4 h-4" />
              Duplicates
              {dupCount > 0 && (
                <span className="ml-0.5 text-xs px-1.5 py-0.5 rounded-full bg-yellow-500/20 text-yellow-400 border border-yellow-500/40">
                  {dupCount}
                </span>
              )}
            </button>
          )}
          {!isSuperadmin && !isBusinessOwner && (
            <button
              onClick={rescoreAssets}
              disabled={rescoring}
              className="btn-secondary flex items-center gap-2 text-sm"
              title="Recalculate criticality scores for all assets"
            >
              <RefreshCw className={`w-4 h-4 ${rescoring ? 'animate-spin' : ''}`} />
              {rescoring ? 'Rescoring…' : 'Rescore Criticality'}
            </button>
          )}
        </div>
      </div>

      {linkFilter && (
        <div className="glass-card px-4 py-2.5 flex items-center gap-2 text-sm border-eagle-500/40">
          <Filter className="w-4 h-4 text-eagle-400" />
          <span className="text-dark-400">Showing</span>
          <span className="text-dark-100 font-medium">{linkFilter.label}</span>
          <button onClick={clearLinkFilter} className="ml-auto inline-flex items-center gap-1 text-xs text-dark-400 hover:text-dark-100">
            <X className="w-3.5 h-3.5" /> Show all assets
          </button>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <TenantSelector value={tenantFilter} onChange={(id) => { setTenantFilter(id); setPage(1) }} />
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
          <input
            type="text"
            placeholder="Search hostname, vendor, IP or MAC"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1) }}
            className="input-field pl-10 text-sm"
            id="asset-search"
          />
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
        <select
          value={sourceFilter}
          onChange={e => { setSourceFilter(e.target.value); setPage(1) }}
          className="input-field text-sm py-1.5 w-40"
        >
          <option value="">All Sources</option>
          <option value="scan_active">Active scan</option>
          <option value="scan_passive">Passive scan</option>
          <option value="manual">Manual</option>
        </select>
        <select
          value={membershipFilter}
          onChange={e => { setMembershipFilter(e.target.value); setPage(1) }}
          className="input-field text-sm py-1.5 w-44"
        >
          <option value="">All assets</option>
          <option value="true">In My Assets</option>
          <option value="false">Not in My Assets</option>
        </select>
        <button
          onClick={() => { setSearch(''); setDeviceTypeFilter(''); setSourceFilter(''); setMembershipFilter(''); clearLinkFilter() }}
          className="text-xs text-dark-400 hover:text-dark-200 underline underline-offset-2"
        >
          Clear filters
        </button>
        <span className="text-dark-400 text-sm ml-auto">{total} assets</span>
      </div>

      {/* Table */}
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : assets.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Hostname / IP</th>
                <th>Source</th>
                <th>Vendor</th>
                <th className="criticality-col">Criticality</th>
                <th>First / Last seen</th>
                {canManageAssets && <th>Actions</th>}
              </tr>
            </thead>
            <tbody>
              {assets.map((a) => {
                const srcMeta    = SOURCE_META[a.source] ?? SOURCE_META.scan_passive
                const deviceMeta = DEVICE_TYPE_META[a.deviceType] ?? DEVICE_TYPE_META.unknown
                const { label: critLabel, cls: critCls } = getCriticalityMeta(a.criticalityScore)
                return (
                  <Fragment key={a.assetId}>
                  <tr>
                    <td>
                      <span className="flex items-center gap-1.5 whitespace-nowrap">
                        <span className="text-base leading-none">{deviceMeta.icon}</span>
                        <span className="text-xs text-dark-300">{deviceMeta.label}</span>
                      </span>
                    </td>
                    <td>
                      <div className="font-medium text-white">{a.hostname || '—'}</div>
                      <div className="font-mono text-xs text-accent-cyan">{a.ipAddress}</div>
                      <AddressCellInfo asset={a} searchTerm={search} expanded={expandedId === a.assetId} onToggle={() => toggleTimeline(a.assetId)} />
                    </td>
                    <td className="whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${srcMeta.cls}`}>
                          {srcMeta.label}
                        </span>
                        {a.inMyAssets && (
                          <span className="text-xs px-2 py-0.5 rounded-full border font-medium bg-green-500/20 text-green-400 border-green-500/30">
                            My Assets
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="text-dark-300 text-sm">
                      {a.hardwareVendor
                        ? a.hardwareVendor
                        : isLocallyAdministeredMac(a.macAddress)
                          ? <span className="text-dark-400 italic">Private (randomized) MAC</span>
                          : '—'}
                      {a.macAddress && (
                        <div className="font-mono text-[11px] text-dark-400 mt-0.5 lowercase">{a.macAddress}</div>
                      )}
                    </td>
                    <td className="criticality-col">
                      <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${critCls}`}>
                        {a.criticalityScore}/10 <span className="opacity-70">{critLabel}</span>
                      </span>
                    </td>
                    <td className="text-xs">
                      {(() => {
                        const first = formatSeen(a.createdAt)
                        const last = formatSeen(a.lastScanned, { nullText: 'Never scanned' })
                        return (
                          <div className="space-y-0.5 whitespace-nowrap">
                            <div className="text-dark-400"><span className="text-dark-500">First</span> <span title={first.title || ''}>{first.text}</span></div>
                            <div className={last.stale ? 'text-amber-400' : 'text-dark-400'}><span className="text-dark-500">Last</span> <span title={last.title || ''}>{last.text}</span></div>
                          </div>
                        )
                      })()}
                    </td>
                    {canManageAssets && <td>
                      <div className="flex items-center gap-1">
                        {!a.inMyAssets && (
                          <button
                            onClick={() => promoteToMyAssets(a)}
                            className="p-1.5 hover:bg-green-500/10 rounded text-dark-400 hover:text-green-400 transition-colors"
                            title="Add to My Assets"
                          >
                            <CheckCircle className="w-4 h-4" />
                          </button>
                        )}
                        {a.inMyAssets && (
                          <button
                            onClick={() => removeFromMyAssets(a)}
                            className="p-1.5 hover:bg-amber-500/10 rounded text-dark-400 hover:text-amber-400 transition-colors"
                            title="Remove from My Assets"
                          >
                            <MinusCircle className="w-4 h-4" />
                          </button>
                        )}
                        {!isSuperadmin && !isBusinessOwner && (
                          <button
                            onClick={() => triggerSbomScan(a.assetId)}
                            className="p-1.5 hover:bg-eagle-500/10 rounded text-eagle-400 transition-colors flex items-center gap-1"
                            title="Scan SBOM"
                            disabled={['pending', 'running'].includes(sbomScans[a.assetId]?.status)}
                          >
                            <Shield className={`w-4 h-4 ${sbomScans[a.assetId]?.status === 'running' ? 'animate-pulse text-blue-400' : sbomScans[a.assetId]?.status === 'pending' ? 'text-yellow-400' : ''}`} />
                            {sbomScans[a.assetId]?.status === 'running' && <span className="text-xs text-blue-400">Running</span>}
                            {sbomScans[a.assetId]?.status === 'pending' && <span className="text-xs text-yellow-400">Queued</span>}
                          </button>
                        )}
                        {canDelete && (
                          <button
                            onClick={() => deletePermanently(a)}
                            className="p-1.5 hover:bg-red-500/10 rounded text-dark-400 hover:text-red-400 transition-colors"
                            title="Delete permanently"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </td>}
                  </tr>
                  {expandedId === a.assetId && (
                    <AddressTimelineRow asset={a} colSpan={colCount} searchTerm={search} tenantId={tenantFilter || undefined} />
                  )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <Server className="w-16 h-16 mx-auto mb-4 opacity-20" />
            {search ? (
              <p>No assets match “{search}”{filterSummary ? ` with ${filterSummary}` : ''}. Searched hostname, vendor, and current <span className="whitespace-nowrap">&amp; historical</span> IPs/MACs.</p>
            ) : filterSummary ? (
              <p>No assets match the current filters ({filterSummary}).</p>
            ) : (
              <p>No assets found. Run a scan or adjust your filters.</p>
            )}
          </div>
        )}
      </div>

      {/* Pagination */}
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

      {showDuplicates && (
        <DuplicatesPanel
          tenantId={tenantFilter}
          canMerge={user?.role === 'tenant_superadmin'}
          onClose={() => setShowDuplicates(false)}
          onMerged={() => { loadAssets(); loadDupCount() }}
        />
      )}
    </div>
  )
}
