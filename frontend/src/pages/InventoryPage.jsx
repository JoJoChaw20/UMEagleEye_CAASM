import { useState, useEffect, useCallback, useMemo, Fragment } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import {
  Server, Search, Plus, Upload, Zap, Filter, X, Pencil, RefreshCw,
  Bookmark, MinusCircle, CheckCircle, Trash2, Link2,
} from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'
import AssetGraph from '../components/common/AssetGraph'
import CriticalityBadge from '../components/common/CriticalityBadge'
import { AddressCellInfo, AddressTimelineRow } from '../components/common/AssetAddressInfo'
import { AddAssetModal, EditAssetModal, ImportModal } from '../components/assets/AssetModals'
import { DEVICE_TYPE_META, SOURCE_META, SCOPES, assetName, buildMatchIndex } from '../components/assets/assetMeta'
import AdoptMatchModal from '../components/assets/AdoptMatchModal'
import { RISKY_PORTS } from '../components/common/alertMeta'
import { formatSeen } from '../utils/time'
import { isLocallyAdministeredMac } from '../utils/mac'

const PAGE_SIZE = 25

// Exact filters that other pages link to (dashboard panels, alert drawer). A link
// with no `scope` searches both scopes, so its count matches the card it came from.
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

function readScope(sp) {
  const s = sp.get('scope')
  if (s === 'mine' || s === 'discovered') return s
  return readLinkFilter(sp) ? 'any' : 'mine'
}

// ── Main page ─────────────────────────────────────────────────────
export default function InventoryPage() {
  const { user } = useAuth()
  const navigate = useNavigate()
  const isSuperadmin = user?.role === 'superadmin'
  const isBusinessOwner = user?.role === 'business_owner'
  const isReadOnly = isSuperadmin || isBusinessOwner
  const canDelete = user?.role === 'tenant_superadmin'

  const [searchParams, setSearchParams] = useSearchParams()
  const [scope, setScope] = useState(() => readScope(searchParams))
  const [linkFilter, setLinkFilter] = useState(() => readLinkFilter(searchParams))
  const [activeTab, setActiveTab] = useState('inventory') // 'inventory' | 'graph'
  const [search, setSearch] = useState(() => searchParams.get('q') ?? '')
  const [deviceTypeFilter, setDeviceTypeFilter] = useState(() => searchParams.get('device_type') ?? '')
  const [sourceFilter, setSourceFilter] = useState(() => searchParams.get('source') ?? '')
  const [tenantFilter, setTenantFilter] = useState('')
  const [page, setPage] = useState(1)

  const [assets, setAssets] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [scopeCounts, setScopeCounts] = useState({ mine: null, discovered: null })
  const [dupGroups, setDupGroups] = useState([])

  const [expandedId, setExpandedId] = useState(null)
  const [showAdd, setShowAdd] = useState(false)
  const [showImport, setShowImport] = useState(false)
  const [editingAsset, setEditingAsset] = useState(null)
  const [adoptTarget, setAdoptTarget] = useState(null)   // { asset, matches, reasons }
  const [rescoring, setRescoring] = useState(false)
  const [rescoringId, setRescoringId] = useState(null)
  const [graphBlastId, setGraphBlastId] = useState(null)

  // Follow in-app links that change the query while this page is open.
  useEffect(() => {
    const next = readLinkFilter(searchParams)
    setLinkFilter((prev) => (JSON.stringify(prev) === JSON.stringify(next) ? prev : next))
    setScope(readScope(searchParams))
    setSearch(searchParams.get('q') ?? '')
    setDeviceTypeFilter(searchParams.get('device_type') ?? '')
    setSourceFilter(searchParams.get('source') ?? '')
    setPage(1)
  }, [searchParams])

  useEffect(() => {
    if (!notice) return
    const t = setTimeout(() => setNotice(null), 6000)
    return () => clearTimeout(t)
  }, [notice])

  const changeScope = (next) => {
    setActiveTab('inventory')
    // Switching scope drops link filters but keeps the search term.
    const params = next === 'mine' ? {} : { scope: next }
    if (search) params.q = search
    setSearchParams(params, { replace: true })
  }

  const clearLinkFilter = () => setSearchParams(scope === 'discovered' ? { scope } : {}, { replace: true })

  const loadAssets = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = { page, limit: PAGE_SIZE }
      if (scope !== 'any') params.in_my_assets = SCOPES[scope].inMyAssets
      if (search) params.search = search
      if (deviceTypeFilter) params.device_type = deviceTypeFilter
      if (sourceFilter) params.source = sourceFilter
      if (tenantFilter) params.tenant_id = tenantFilter
      Object.assign(params, linkFilter?.params)
      const res = await client.get('/assets', { params })
      setAssets(res.data.items || [])
      setTotal(res.data.total || 0)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load assets')
    } finally {
      setLoading(false)
    }
  }, [page, scope, search, deviceTypeFilter, sourceFilter, tenantFilter, linkFilter])

  // Unfiltered totals for the scope tabs (limit=1: only the count is used).
  const loadScopeCounts = useCallback(async () => {
    const base = { page: 1, limit: 1, ...(tenantFilter ? { tenant_id: tenantFilter } : {}) }
    try {
      const [mine, disc] = await Promise.all([
        client.get('/assets', { params: { ...base, in_my_assets: 'true' } }),
        client.get('/assets', { params: { ...base, in_my_assets: 'false' } }),
      ])
      setScopeCounts({ mine: mine.data.total ?? 0, discovered: disc.data.total ?? 0 })
    } catch { /* counts are cosmetic */ }
  }, [tenantFilter])

  const loadDuplicates = useCallback(async () => {
    if (isBusinessOwner) return
    try {
      const res = await client.get('/assets/duplicates', { params: tenantFilter ? { tenant_id: tenantFilter } : {} })
      setDupGroups(res.data.groups || [])
    } catch { setDupGroups([]) }
  }, [tenantFilter, isBusinessOwner])

  useEffect(() => { loadAssets() }, [loadAssets])
  useEffect(() => { loadScopeCounts() }, [loadScopeCounts])
  useEffect(() => { loadDuplicates() }, [loadDuplicates])

  const refreshAll = async () => { await Promise.all([loadAssets(), loadScopeCounts(), loadDuplicates()]) }

  const matchIndex = useMemo(() => buildMatchIndex(dupGroups), [dupGroups])
  // Matches that matter for adoption: other group members already in My Assets.
  const myAssetMatches = (assetId) => (matchIndex.get(assetId)?.others || []).filter((o) => o.inMyAssets)

  // ── Actions ──
  const setMembership = async (asset, inMyAssets) => {
    await client.patch(`/assets/${asset.assetId}`, { in_my_assets: inMyAssets })
    setNotice({
      text: inMyAssets ? `${assetName(asset)} added to My Assets.` : `${assetName(asset)} moved to Discovered.`,
    })
    await refreshAll()
  }

  const handleAdopt = async (asset) => {
    const matches = myAssetMatches(asset.assetId)
    if (matches.length > 0) {
      setAdoptTarget({ asset, matches, reasons: matchIndex.get(asset.assetId)?.reasons || [] })
      return
    }
    try { await setMembership(asset, true) } catch (err) { alert(err?.response?.data?.detail || 'Failed to add asset to My Assets') }
  }

  const handleRemove = async (asset) => {
    if (!confirm(
      `Move ${assetName(asset)} to Discovered?\n\n` +
      '• It keeps its history, owner and criticality.\n' +
      '• It will be hidden from the relationship graph.\n' +
      '• You can adopt it again at any time.'
    )) return
    try { await setMembership(asset, false) } catch (err) { alert(err?.response?.data?.detail || 'Failed to remove asset from My Assets') }
  }

  const handleDelete = async (asset) => {
    if (!confirm(
      `Delete ${assetName(asset)} permanently?\n\n` +
      'This permanently deletes the asset and its events, SBOMs, dependencies and relationships. This cannot be undone.'
    )) return
    try {
      await client.delete(`/assets/${asset.assetId}`)
      setNotice({ text: `${assetName(asset)} deleted.` })
      await refreshAll()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to delete asset')
    }
  }

  const handleAddAsset = async (form) => {
    await client.post('/assets', tenantFilter ? { ...form, tenant_id: tenantFilter } : form)
    await refreshAll()
  }

  const handleEditSave = async (patch) => {
    await client.patch(`/assets/${editingAsset.assetId}`, patch)
    await loadAssets()
  }

  const handleBaseline = async (asset) => {
    if (!confirm('Set the baseline to this asset\'s current state?\n\nThis replaces the current baseline (ports, packages, hostname, MAC, exposure and device type).')) return
    try {
      await client.post(`/assets/${asset.assetId}/baseline`, { confirm: true })
      setNotice({ text: `Baseline set for ${assetName(asset)}.` })
      await loadAssets()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to set baseline')
    }
  }

  const handleRescoreOne = async (asset) => {
    setRescoringId(asset.assetId)
    try {
      const res = await client.post(`/assets/${asset.assetId}/rescore`)
      const { changed, previous, current } = res.data
      setNotice({ text: changed ? `${assetName(asset)}: criticality ${previous}/10 → ${current}/10.` : `${assetName(asset)}: criticality already up to date.` })
      if (changed) await loadAssets()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Rescore failed')
    } finally {
      setRescoringId(null)
    }
  }

  const handleRescoreAll = async () => {
    setRescoring(true)
    try {
      const qs = new URLSearchParams({ scope: scope === 'discovered' ? 'discovered' : 'my_assets' })
      if (tenantFilter) qs.set('tenant_id', tenantFilter)
      const res = await client.post(`/assets/rescore?${qs.toString()}`)
      setNotice({ text: res.data.message })
      await loadAssets()
    } catch (err) {
      alert(err?.response?.data?.detail || 'Rescore failed')
    } finally {
      setRescoring(false)
    }
  }

  const clearFilters = () => {
    setSearch(''); setDeviceTypeFilter(''); setSourceFilter(''); setPage(1)
    if (linkFilter) clearLinkFilter()
  }

  // ── Derived ──
  const totalPages = Math.ceil(total / PAGE_SIZE)
  const showActions = !isReadOnly
  const colCount = showActions ? 8 : 7
  const matchedDiscoveredCount = useMemo(() => {
    let n = 0
    for (const g of dupGroups) {
      if (!g.assets.some((a) => a.inMyAssets)) continue
      n += g.assets.filter((a) => !a.inMyAssets).length
    }
    return n
  }, [dupGroups])

  const activeFilterBits = []
  if (deviceTypeFilter) activeFilterBits.push(`type ${DEVICE_TYPE_META[deviceTypeFilter]?.label ?? deviceTypeFilter}`)
  if (sourceFilter) activeFilterBits.push(`source ${SOURCE_META[sourceFilter]?.label ?? sourceFilter}`)
  const filterSummary = activeFilterBits.join(', ')
  const hasFilters = !!(search || deviceTypeFilter || sourceFilter)

  const subtitle = activeTab === 'graph'
    ? 'Relationships between the assets you manage'
    : scope === 'mine' ? 'Assets you manage and track'
      : scope === 'discovered' ? 'Found by scans and not yet adopted. Review them and adopt the ones you manage.'
        : 'Linked results from both My Assets and Discovered'

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white">Asset Inventory</h1>
          <p className="text-dark-400 text-sm mt-1">{subtitle}</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {scope !== 'any' && activeTab === 'inventory' && !isReadOnly && (
            <button
              onClick={handleRescoreAll}
              disabled={rescoring}
              title={`Re-score criticality for all assets in ${SCOPES[scope].label}`}
              className="btn-secondary flex items-center gap-2 text-sm"
            >
              {rescoring
                ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                : <Zap className="w-4 h-4 text-yellow-400" />}
              Rescore All
            </button>
          )}
          {scope === 'mine' && activeTab === 'inventory' && !isReadOnly && (
            <>
              <button onClick={() => setShowImport(true)} className="btn-secondary flex items-center gap-2 text-sm">
                <Upload className="w-4 h-4" /> Import CSV
              </button>
              <button onClick={() => setShowAdd(true)} className="btn-primary flex items-center gap-2 text-sm">
                <Plus className="w-4 h-4" /> Add Asset
              </button>
            </>
          )}
        </div>
      </div>

      {/* Scope + view toggles */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-1 p-1 bg-dark-800/60 rounded-xl w-fit border border-dark-700/50" role="tablist" aria-label="Asset scope">
          {['mine', 'discovered'].map((s) => (
            <button
              key={s}
              role="tab"
              aria-selected={scope === s}
              onClick={() => changeScope(s)}
              className={`tab-toggle ${scope === s ? 'active' : ''}`}
            >
              {SCOPES[s].label}
              {scopeCounts[s] != null && <span className="text-xs text-dark-400 ml-0.5">{scopeCounts[s]}</span>}
            </button>
          ))}
        </div>
        {scope === 'mine' && (
          <div className="flex items-center gap-1 p-1 bg-dark-800/60 rounded-xl w-fit border border-dark-700/50">
            <button onClick={() => setActiveTab('inventory')} className={`tab-toggle ${activeTab === 'inventory' ? 'active' : ''}`}>
              List
            </button>
            <button onClick={() => setActiveTab('graph')} className={`tab-toggle ${activeTab === 'graph' ? 'active' : ''}`}>
              Relationship Graph
            </button>
          </div>
        )}
      </div>

      {notice && (
        <div className="glass-card px-4 py-2.5 flex items-center gap-2 text-sm border-green-500/30" role="status">
          <CheckCircle className="w-4 h-4 text-green-400" />
          <span className="text-dark-100">{notice.text}</span>
          <button onClick={() => setNotice(null)} aria-label="Dismiss" className="ml-auto text-dark-400 hover:text-dark-100"><X className="w-3.5 h-3.5" /></button>
        </div>
      )}

      {scope === 'discovered' && matchedDiscoveredCount > 0 && activeTab === 'inventory' && (
        <div className="glass-card px-4 py-2.5 flex items-center gap-2 text-sm border-yellow-500/30">
          <Link2 className="w-4 h-4 text-yellow-400" />
          <span className="text-dark-200">
            {matchedDiscoveredCount} discovered {matchedDiscoveredCount === 1 ? 'asset looks' : 'assets look'} like {matchedDiscoveredCount === 1 ? 'one' : 'ones'} already in My Assets.
            Open {matchedDiscoveredCount === 1 ? 'it' : 'one'} to review the match.
          </span>
        </div>
      )}

      {linkFilter && (
        <div className="glass-card px-4 py-2.5 flex items-center gap-2 text-sm border-eagle-500/40">
          <Filter className="w-4 h-4 text-eagle-400" />
          <span className="text-dark-400">Showing</span>
          <span className="text-dark-100 font-medium">{linkFilter.label}</span>
          {scope === 'any' && <span className="text-dark-400">in My Assets and Discovered</span>}
          <button onClick={clearLinkFilter} className="ml-auto inline-flex items-center gap-1 text-xs text-dark-400 hover:text-dark-100">
            <X className="w-3.5 h-3.5" /> Clear
          </button>
        </div>
      )}

      {/* Graph */}
      {activeTab === 'graph' && scope === 'mine' && (
        <div className="glass-card p-5">
          <AssetGraph
            onSelectAsset={(id) => setGraphBlastId((prev) => (prev === id ? null : id))}
            blastRadiusId={graphBlastId}
            tenantFilter={tenantFilter}
          />
        </div>
      )}

      {activeTab === 'inventory' && (
        <>
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
                aria-label="Search assets"
              />
            </div>
            <select value={deviceTypeFilter} onChange={(e) => { setDeviceTypeFilter(e.target.value); setPage(1) }} className="input-field text-sm py-1.5 w-44" aria-label="Device type">
              <option value="">All Types</option>
              {Object.entries(DEVICE_TYPE_META).map(([k, m]) => <option key={k} value={k}>{m.label}</option>)}
            </select>
            <select value={sourceFilter} onChange={(e) => { setSourceFilter(e.target.value); setPage(1) }} className="input-field text-sm py-1.5 w-40" aria-label="Source">
              <option value="">All Sources</option>
              <option value="scan_active">Active scan</option>
              <option value="scan_passive">Passive scan</option>
              <option value="manual">Manual</option>
              <option value="agent">Agent</option>
            </select>
            {(hasFilters || linkFilter) && (
              <button onClick={clearFilters} className="text-xs text-dark-400 hover:text-dark-200 underline underline-offset-2">Clear filters</button>
            )}
            <span className="text-dark-400 text-sm ml-auto">{total} assets</span>
          </div>

          {error && (
            <div className="glass-card p-4 border border-red-500/30">
              <p className="text-red-400 text-sm">{error}</p>
              <button onClick={loadAssets} className="btn-secondary text-sm mt-2">Retry</button>
            </div>
          )}

          {/* Table */}
          <div className="glass-card overflow-visible">
            {loading ? (
              <div className="flex items-center justify-center py-20">
                <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
              </div>
            ) : assets.length > 0 ? (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Asset</th>
                    <th>Owner</th>
                    <th>Vendor</th>
                    <th className="criticality-col">Criticality</th>
                    <th>Source</th>
                    <th>First / Last seen</th>
                    {showActions && <th>Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {assets.map((a) => {
                    const deviceMeta = DEVICE_TYPE_META[a.deviceType] ?? DEVICE_TYPE_META.unknown
                    const srcMeta = SOURCE_META[a.source] ?? SOURCE_META.scan_passive
                    const matches = a.inMyAssets ? [] : myAssetMatches(a.assetId)
                    const first = formatSeen(a.createdAt)
                    const last = formatSeen(a.lastScanned, { nullText: 'Never scanned' })
                    const stop = (fn) => (e) => { e.stopPropagation(); fn() }
                    return (
                      <Fragment key={a.assetId}>
                        <tr onClick={() => navigate(`/inventory/${a.assetId}`)} className="cursor-pointer">
                          <td>
                            <span className="flex items-center gap-1.5 whitespace-nowrap">
                              <span className="text-base leading-none">{deviceMeta.icon}</span>
                              <span className="text-xs text-dark-300">{deviceMeta.label}</span>
                            </span>
                          </td>
                          <td>
                            <Link to={`/inventory/${a.assetId}`} onClick={(e) => e.stopPropagation()} className="font-medium text-white hover:text-eagle-400">
                              {a.hostname || '—'}
                            </Link>
                            <div className="font-mono text-xs text-accent-cyan">{a.ipAddress}</div>
                            <div className="flex items-center gap-1.5 flex-wrap mt-0.5">
                              {a.isInternetFacing && (
                                <span className="text-[11px] px-1.5 py-0.5 rounded border bg-yellow-500/10 text-yellow-400 border-yellow-500/30">Internet-facing</span>
                              )}
                              {scope === 'any' && a.inMyAssets && (
                                <span className="text-[11px] px-1.5 py-0.5 rounded border bg-green-500/20 text-green-400 border-green-500/30">My Assets</span>
                              )}
                              {matches.length > 0 && (
                                <span
                                  className="text-[11px] px-1.5 py-0.5 rounded border bg-yellow-500/10 text-yellow-300 border-yellow-500/30"
                                  title={`Matches ${matches.map(assetName).join(', ')}`}
                                >
                                  Matches {matches.length === 1 ? assetName(matches[0]) : `${matches.length} of My Assets`}
                                </span>
                              )}
                            </div>
                            <div onClick={(e) => e.stopPropagation()}>
                              <AddressCellInfo asset={a} searchTerm={search} expanded={expandedId === a.assetId} onToggle={() => setExpandedId((cur) => (cur === a.assetId ? null : a.assetId))} />
                            </div>
                          </td>
                          <td className="text-sm text-dark-200">{a.owner || <span className="text-dark-500">—</span>}</td>
                          <td className="text-dark-300 text-sm">
                            {a.hardwareVendor
                              ? a.hardwareVendor
                              : isLocallyAdministeredMac(a.macAddress)
                                ? <span className="text-dark-400 italic">Private (randomized) MAC</span>
                                : '—'}
                            {a.macAddress && <div className="font-mono text-[11px] text-dark-400 mt-0.5 lowercase">{a.macAddress}</div>}
                          </td>
                          <td className="criticality-col" onClick={(e) => e.stopPropagation()}>
                            <CriticalityBadge score={a.criticalityScore} assetId={a.assetId} footer="computed" />
                          </td>
                          <td className="whitespace-nowrap">
                            <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${srcMeta.cls}`}>{srcMeta.label}</span>
                          </td>
                          <td className="text-xs">
                            <div className="space-y-0.5 whitespace-nowrap">
                              <div className="text-dark-400"><span className="text-dark-500">First</span> <span title={first.title || ''}>{first.text}</span></div>
                              <div className={last.stale ? 'text-amber-400' : 'text-dark-400'}><span className="text-dark-500">Last</span> <span title={last.title || ''}>{last.text}</span></div>
                            </div>
                          </td>
                          {showActions && (
                            <td>
                              <div className="flex items-center gap-1">
                                {!isReadOnly && a.inMyAssets && (
                                  <>
                                    <button onClick={stop(() => setEditingAsset(a))} className="p-1.5 hover:bg-eagle-500/10 rounded text-dark-400 hover:text-eagle-400 transition-colors" title="Edit asset" aria-label="Edit asset">
                                      <Pencil className="w-4 h-4" />
                                    </button>
                                    <button onClick={stop(() => handleRescoreOne(a))} disabled={rescoringId === a.assetId} className="p-1.5 hover:bg-eagle-500/10 rounded text-dark-400 hover:text-eagle-400 transition-colors" title="Rescore this asset's criticality" aria-label="Rescore this asset's criticality">
                                      <RefreshCw className={`w-4 h-4 ${rescoringId === a.assetId ? 'animate-spin' : ''}`} />
                                    </button>
                                    <button onClick={stop(() => handleBaseline(a))} className={`p-1.5 rounded transition-colors ${a.baselineState ? 'text-eagle-400 hover:bg-eagle-500/10' : 'text-dark-400 hover:bg-dark-700'}`} title="Set baseline to the asset's current state" aria-label="Set baseline to the asset's current state">
                                      <Bookmark className="w-4 h-4" />
                                    </button>
                                    <button onClick={stop(() => handleRemove(a))} className="p-1.5 hover:bg-amber-500/10 rounded text-dark-400 hover:text-amber-400 transition-colors" title="Move to Discovered" aria-label="Move to Discovered">
                                      <MinusCircle className="w-4 h-4" />
                                    </button>
                                  </>
                                )}
                                {!isReadOnly && !a.inMyAssets && (
                                  <button onClick={stop(() => handleAdopt(a))} className="px-2 py-1 hover:bg-green-500/10 rounded text-green-400 transition-colors flex items-center gap-1 text-xs font-medium" title="Adopt into My Assets" aria-label="Adopt into My Assets">
                                    <CheckCircle className="w-4 h-4" /> Adopt
                                  </button>
                                )}
                                {canDelete && !a.inMyAssets && (
                                  <button onClick={stop(() => handleDelete(a))} className="p-1.5 hover:bg-red-500/10 rounded text-dark-400 hover:text-red-400 transition-colors" title="Delete permanently" aria-label="Delete permanently">
                                    <Trash2 className="w-4 h-4" />
                                  </button>
                                )}
                              </div>
                            </td>
                          )}
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
                  <p>No assets match “{search}”{filterSummary ? ` with ${filterSummary}` : ''}. Searched hostname, vendor, and current &amp; historical IPs/MACs.</p>
                ) : filterSummary || linkFilter ? (
                  <p>No assets match the current filters.</p>
                ) : scope === 'mine' ? (
                  <>
                    <p className="text-lg font-medium mb-2">No assets in My Assets yet</p>
                    <p className="text-sm mb-4">Add assets by hand, import a CSV, or adopt them from Discovered.</p>
                    <div className="flex items-center justify-center gap-2">
                      {!isReadOnly && (
                        <button onClick={() => setShowAdd(true)} className="btn-primary text-sm flex items-center gap-2"><Plus className="w-4 h-4" /> Add Asset</button>
                      )}
                      <button onClick={() => changeScope('discovered')} className="btn-secondary text-sm">Go to Discovered</button>
                    </div>
                  </>
                ) : (
                  <p>Nothing waiting for review. New devices found by scans appear here.</p>
                )}
              </div>
            )}
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2">
              <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} className="btn-secondary text-sm py-1 px-3 disabled:opacity-30">Previous</button>
              <span className="text-dark-400 text-sm">Page {page} of {totalPages}</span>
              <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages} className="btn-secondary text-sm py-1 px-3 disabled:opacity-30">Next</button>
            </div>
          )}
        </>
      )}

      {showAdd && <AddAssetModal onClose={() => setShowAdd(false)} onSave={handleAddAsset} />}
      {showImport && <ImportModal onClose={() => setShowImport(false)} onImport={refreshAll} tenantId={tenantFilter || undefined} />}
      {editingAsset && <EditAssetModal asset={editingAsset} onClose={() => setEditingAsset(null)} onSave={handleEditSave} />}
      {adoptTarget && (
        <AdoptMatchModal
          asset={adoptTarget.asset}
          matches={adoptTarget.matches}
          reasons={adoptTarget.reasons}
          onClose={() => setAdoptTarget(null)}
          reviewLabel="Review on asset page"
          onReviewDuplicates={() => navigate(`/inventory/${adoptTarget.asset.assetId}`)}
          onAdopt={async () => {
            try { await setMembership(adoptTarget.asset, true); setAdoptTarget(null) } catch (err) { alert(err?.response?.data?.detail || 'Failed to add asset to My Assets') }
          }}
        />
      )}
    </div>
  )
}
