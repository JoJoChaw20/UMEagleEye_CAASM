import { useState, useEffect, useCallback } from 'react'
import {
  Globe, RefreshCw, Shield, Search, X, AlertTriangle,
  CheckCircle2, Clock, ExternalLink, Info, Filter,
} from 'lucide-react'

// ── Inline toast hook ─────────────────────────────────────────
function useToast() {
  const [toast, setToast] = useState(null)
  const show = (msg, type = 'success') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 4000)
  }
  return { toast, show }
}
import {
  BarChart, Bar, Cell, ResponsiveContainer, XAxis, YAxis, Tooltip, CartesianGrid,
} from 'recharts'
import client from '../api/client'

// ── Constants ─────────────────────────────────────────────────
const MITRE_TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

const TACTIC_COLORS = [
  '#ff5252','#ff6e40','#ff9800','#ffc400','#ffea00','#c6ff00',
  '#69f0ae','#00e5ff','#448aff','#7c4dff','#e040fb','#ff4081',
  '#ff5252','#ff6e40',
]

const TYPE_ICONS = { ip: '🌐', domain: '🔗', url: '📎', hash: '🔐', email: '📧' }

const PAGE_SIZE = 15

// ── Confidence bar ────────────────────────────────────────────
function ConfBar({ score }) {
  const pct = ((score ?? 0) * 100).toFixed(0)
  const color = score >= 0.8 ? '#ff5252' : score >= 0.6 ? '#ff9800' : '#ffc400'
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-14 h-1.5 bg-dark-700 rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="text-xs text-dark-400">{pct}%</span>
    </div>
  )
}

export default function ThreatIntelPage() {
  const [indicators, setIndicators] = useState([])
  const [matrix,     setMatrix]     = useState({})
  const [stats,      setStats]      = useState(null)
  const [loading,    setLoading]    = useState(true)
  const [ingesting,  setIngesting]  = useState(false)
  const { toast, show: showToast }  = useToast()
  const [tab,        setTab]        = useState('indicators') // indicators | matrix | lookup

  // IoC Feed filters + server-side pagination
  const [sourceFilter, setSourceFilter] = useState('')
  const [typeFilter,   setTypeFilter]   = useState('')
  const [page,         setPage]         = useState(1)
  const [total,        setTotal]        = useState(0)

  // IOC Lookup
  const [lookupValue,   setLookupValue]   = useState('')
  const [lookupResult,  setLookupResult]  = useState(null)
  const [lookupLoading, setLookupLoading] = useState(false)
  const [lookupError,   setLookupError]   = useState('')

  // Load matrix + stats once (not filter-dependent)
  const loadStaticData = useCallback(async () => {
    try {
      const [matrixRes, statsRes] = await Promise.all([
        client.get('/cti/matrix'),
        client.get('/cti/stats'),
      ])
      setMatrix(matrixRes.data.matrix || {})
      setStats(statsRes.data)
    } catch (err) { console.error(err) }
  }, [])

  // Load indicators with server-side filters + pagination
  const loadIndicators = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, limit: PAGE_SIZE }
      if (sourceFilter) params.source = sourceFilter
      if (typeFilter)   params.indicator_type = typeFilter
      const res = await client.get('/cti/indicators', { params })
      setIndicators(res.data.items || [])
      setTotal(res.data.total || 0)
    } catch (err) { console.error(err) }
    finally { setLoading(false) }
  }, [page, sourceFilter, typeFilter])

  useEffect(() => { loadStaticData() }, [loadStaticData])
  useEffect(() => { loadIndicators() }, [loadIndicators])

  const triggerIngestion = async () => {
    setIngesting(true)
    try {
      const res = await client.post('/cti/ingest')
      const data = res.data
      if (data?.queued === false) {
        showToast('Ingestion already running — try again in a few minutes.', 'info')
        setIngesting(false)
      } else {
        showToast('Feed ingestion queued! Refreshing in ~15 seconds…', 'success')
        setTimeout(() => { loadStaticData(); loadIndicators(); setIngesting(false) }, 15000)
      }
    } catch (err) {
      const msg = err?.response?.data?.detail ?? 'Failed to queue ingestion'
      showToast(msg, 'error')
      setIngesting(false)
    }
  }

  const doLookup = async () => {
    if (!lookupValue.trim()) return
    setLookupLoading(true)
    setLookupResult(null)
    setLookupError('')
    try {
      const res = await client.get('/cti/lookup', { params: { value: lookupValue.trim() } })
      setLookupResult(res.data)
    } catch (err) {
      setLookupError(err.response?.data?.detail || 'Lookup failed.')
    } finally {
      setLookupLoading(false)
    }
  }

  // ── Derived values ────────────────────────────────────────────
  // Source/type dropdown options from stats (full-table, no limit)
  const uniqueSources = Object.keys(stats?.by_source ?? {})
  const uniqueTypes   = Object.keys(stats?.by_type   ?? {})

  // Pagination driven by server-returned total
  const totalPages = Math.ceil(total / PAGE_SIZE)

  const clearFilters = () => { setSourceFilter(''); setTypeFilter(''); setPage(1) }

  // Chart data
  const matrixChartData = MITRE_TACTICS.map((tactic, i) => ({
    tactic: tactic.split(' ').slice(0, 2).join(' '),
    count: (matrix[tactic] || []).reduce((s, t) => s + t.count, 0),
    fill: TACTIC_COLORS[i],
  })).filter(d => d.count > 0)

  // ── Render ───────────────────────────────────────────────────
  return (
    <div className="space-y-6">

      {/* ── Toast ── */}
      {toast && (
        <div className={`fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-3 rounded-lg shadow-lg text-sm font-medium
          ${toast.type === 'success' ? 'bg-green-900/90 text-green-200 border border-green-700'
          : toast.type === 'info'    ? 'bg-blue-900/90  text-blue-200  border border-blue-700'
          :                            'bg-red-900/90   text-red-200   border border-red-700'}`}>
          {toast.type === 'success' ? <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
          : toast.type === 'info'   ? <Info         className="w-4 h-4 flex-shrink-0" />
          :                           <AlertTriangle className="w-4 h-4 flex-shrink-0" />}
          {toast.msg}
        </div>
      )}

      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Intelligence</h1>
          <p className="text-dark-400 text-sm mt-1">
            {stats?.total_indicators ?? 0} indicators ·{' '}
            {Object.keys(stats?.by_source ?? {}).length} sources
          </p>
        </div>
        <button
          onClick={triggerIngestion}
          disabled={ingesting}
          className="btn-primary flex items-center gap-2"
        >
          {ingesting
            ? <RefreshCw className="w-4 h-4 animate-spin" />
            : <Globe className="w-4 h-4" />}
          {ingesting ? 'Ingesting…' : 'Ingest Feeds'}
        </button>
      </div>

      {/* ── Source & type stat cards ── */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Object.entries(stats.by_source || {}).map(([source, count]) => (
            <div key={source} className="stat-card">
              <p className="text-dark-400 text-xs mb-1 truncate">{source}</p>
              <p className="text-2xl font-bold text-white">{count}</p>
            </div>
          ))}
          {Object.entries(stats.by_type || {}).map(([type, count]) => (
            <div key={type} className="stat-card">
              <p className="text-dark-400 text-xs mb-1">
                {TYPE_ICONS[type] || '❓'} {type}
              </p>
              <p className="text-2xl font-bold text-white">{count}</p>
            </div>
          ))}
        </div>
      )}

      {/* ── Tabs ── */}
      <div className="flex gap-1 bg-dark-800 rounded-lg p-1 w-fit">
        {[
          { id: 'indicators', label: 'IoC Feed' },
          { id: 'matrix',     label: 'MITRE ATT&CK' },
          { id: 'lookup',     label: '🔍 IOC Lookup' },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              tab === t.id
                ? 'bg-eagle-600 text-white'
                : 'text-dark-400 hover:text-dark-100 hover:bg-dark-700/40'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Loading spinner ── */}
      {loading ? (
        <div className="flex justify-center py-20">
          <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
        </div>
      ) : tab === 'indicators' ? (

        // ── IoC Feed tab ─────────────────────────────────────────
        <>
          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <select
              value={sourceFilter}
              onChange={e => { setSourceFilter(e.target.value); setPage(1) }}
              className="input-field text-sm py-1.5 w-48"
            >
              <option value="">All Sources</option>
              {uniqueSources.map(s => <option key={s} value={s}>{s}</option>)}
            </select>

            <select
              value={typeFilter}
              onChange={e => { setTypeFilter(e.target.value); setPage(1) }}
              className="input-field text-sm py-1.5 w-36"
            >
              <option value="">All Types</option>
              {uniqueTypes.map(t => (
                <option key={t} value={t}>{TYPE_ICONS[t] || '❓'} {t}</option>
              ))}
            </select>

            <button
              onClick={clearFilters}
              className="text-xs text-dark-400 hover:text-dark-200 underline underline-offset-2"
            >
              Clear filters
            </button>

            <span className="text-dark-400 text-sm ml-auto">
              {total} indicators
            </span>
          </div>

          <div className="glass-card overflow-hidden">
            {indicators.length > 0 ? (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Value</th>
                    <th>Source</th>
                    <th>Confidence</th>
                    <th>ATT&CK Tactic</th>
                    <th>Technique</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {indicators.map(ind => (
                    <tr key={ind.indicator_id}>
                      <td>
                        {TYPE_ICONS[ind.indicator_type] || '❓'}{' '}
                        <span className="text-xs text-dark-400">{ind.indicator_type}</span>
                      </td>
                      <td className="font-mono text-xs text-accent-cyan max-w-xs truncate">
                        {ind.value}
                      </td>
                      <td className="text-dark-300 text-xs">{ind.source}</td>
                      <td><ConfBar score={ind.confidence_score} /></td>
                      <td className="text-dark-300 text-xs">{ind.attack_tactic || '—'}</td>
                      <td className="font-mono text-xs text-accent-purple">{ind.attack_technique || '—'}</td>
                      <td className="text-dark-400 text-xs">
                        {new Date(ind.last_seen).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="text-center py-20 text-dark-400">
                <Globe className="w-16 h-16 mx-auto mb-4 opacity-20" />
                <p>No threat indicators yet. Click <strong>Ingest Feeds</strong> to pull from OTX &amp; ThreatFox.</p>
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
        </>

      ) : tab === 'matrix' ? (

        // ── MITRE ATT&CK tab ─────────────────────────────────────
        (() => {
          const maxCount = Math.max(
            ...MITRE_TACTICS.flatMap(t => (matrix[t] || []).map(x => x.count)), 1
          )
          const toRgba = (hex, alpha) => {
            const r = parseInt(hex.slice(1, 3), 16)
            const g = parseInt(hex.slice(3, 5), 16)
            const b = parseInt(hex.slice(5, 7), 16)
            return `rgba(${r},${g},${b},${alpha.toFixed(2)})`
          }
          return (
            <div className="space-y-4">
              {/* Bar chart summary */}
              {matrixChartData.length > 0 && (
                <div className="glass-card p-5">
                  <h3 className="text-sm font-semibold text-dark-200 mb-4">
                    Technique Coverage by Tactic
                  </h3>
                  <ResponsiveContainer width="100%" height={260}>
                    <BarChart data={matrixChartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e2028" />
                      <XAxis dataKey="tactic" tick={{ fill: '#7b7f87', fontSize: 10 }} angle={-30} textAnchor="end" height={80} />
                      <YAxis tick={{ fill: '#7b7f87', fontSize: 11 }} />
                      <Tooltip contentStyle={{ background: 'rgb(var(--dark-700))', border: '1px solid rgb(var(--dark-500))', borderRadius: '8px', color: 'rgb(var(--dark-100))' }} />
                      <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                        {matrixChartData.map((e, i) => <Cell key={i} fill={e.fill} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}

              {/* 2-D Heatmap */}
              <div className="glass-card p-5">
                <div className="flex items-center justify-between mb-1">
                  <h3 className="text-sm font-semibold text-dark-200">MITRE ATT&CK Heatmap</h3>
                  <div className="flex items-center gap-2 text-[10px] text-dark-500">
                    <span>Low</span>
                    <div className="flex gap-0.5">
                      {[0.15, 0.35, 0.55, 0.75, 0.95].map(a => (
                        <span key={a} className="w-4 h-3 rounded-sm inline-block" style={{ background: toRgba('#3393ff', a) }} />
                      ))}
                    </div>
                    <span>High</span>
                  </div>
                </div>
                <p className="text-[10px] text-dark-600 mb-4">Cell colour = indicator count intensity · hover for details</p>

                <div className="overflow-x-auto">
                  <div className="flex gap-1 min-w-max pb-2">
                    {MITRE_TACTICS.map((tactic, ti) => {
                      const techniques = matrix[tactic] || []
                      const color = TACTIC_COLORS[ti]
                      return (
                        <div key={tactic} className="flex flex-col gap-0.5 w-[88px]">
                          {/* Tactic column header */}
                          <div
                            className="text-center py-1.5 px-1 rounded text-[9px] font-bold leading-tight h-10 flex items-center justify-center"
                            style={{ background: toRgba(color, 0.18), color, border: `1px solid ${toRgba(color, 0.4)}` }}
                          >
                            {tactic}
                          </div>

                          {/* Technique cells */}
                          {techniques.length > 0
                            ? techniques.map(t => {
                                const intensity = t.count / maxCount
                                const bg = toRgba(color, intensity * 0.72 + 0.14)
                                const textColor = intensity > 0.55 ? '#fff' : color
                                return (
                                  <div
                                    key={t.technique_id}
                                    title={`${t.technique_id} — ${t.count} indicator${t.count !== 1 ? 's' : ''}`}
                                    className="text-center py-1 px-0.5 rounded text-[10px] font-mono leading-tight cursor-default transition-transform hover:scale-105 hover:z-10"
                                    style={{ background: bg, color: textColor, border: `1px solid ${toRgba(color, 0.3)}` }}
                                  >
                                    {t.technique_id}
                                    <span className="ml-0.5 text-[8px] opacity-80">({t.count})</span>
                                  </div>
                                )
                              })
                            : (
                              <div className="text-center py-1.5 rounded text-[10px] text-dark-700 border border-dark-800/40">
                                —
                              </div>
                            )}
                        </div>
                      )
                    })}
                  </div>
                </div>
              </div>
            </div>
          )
        })()

      ) : (

        // ── IOC Lookup tab ───────────────────────────────────────
        <div className="glass-card p-6 space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-dark-200 mb-1">IOC Lookup</h3>
            <p className="text-xs text-dark-500">
              Check an IP address, domain, URL, or file hash against the threat intelligence database.
            </p>
          </div>

          {/* Lookup input */}
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
              <input
                type="text"
                placeholder="e.g. 185.220.101.5 · malware.example.com · abc123hash…"
                value={lookupValue}
                onChange={e => { setLookupValue(e.target.value); setLookupResult(null); setLookupError('') }}
                onKeyDown={e => e.key === 'Enter' && doLookup()}
                className="input-field w-full pl-10"
              />
            </div>
            <button
              onClick={doLookup}
              disabled={lookupLoading || !lookupValue.trim()}
              className="btn-primary flex items-center gap-2 disabled:opacity-50"
            >
              {lookupLoading
                ? <RefreshCw className="w-4 h-4 animate-spin" />
                : <Search className="w-4 h-4" />}
              Lookup
            </button>
            {(lookupResult || lookupError) && (
              <button
                onClick={() => { setLookupResult(null); setLookupError(''); setLookupValue('') }}
                className="p-2 text-dark-400 hover:text-dark-200 transition-colors"
                title="Clear"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* Error */}
          {lookupError && (
            <div className="flex items-center gap-2 text-sm text-red-500 bg-red-500/10 border border-red-500/40 rounded-lg p-3">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              {lookupError}
            </div>
          )}

          {/* Lookup result */}
          {lookupResult && (
            <div className="space-y-4">
              {/* Verdict banner */}
              <div className={`flex items-center gap-3 p-4 rounded-lg border ${
                lookupResult.found
                  ? 'bg-red-500/10 border-red-500/40 text-red-500'
                  : 'bg-green-500/10 border-green-500/40 text-green-600'
              }`}>
                {lookupResult.found
                  ? <AlertTriangle className="w-5 h-5 flex-shrink-0 text-red-500" />
                  : <CheckCircle2  className="w-5 h-5 flex-shrink-0 text-green-500" />}
                <div>
                  <p className="font-semibold text-sm">
                    {lookupResult.found
                      ? '⚠️ KNOWN THREAT INDICATOR — found in threat intelligence database'
                      : '✅ Not found in threat intelligence database'}
                  </p>
                  {!lookupResult.found && (
                    <p className="text-xs opacity-70 mt-0.5">
                      This does not mean the indicator is safe — it may not yet be tracked.
                    </p>
                  )}
                </div>
              </div>

              {/* Indicator details */}
              {lookupResult.found && lookupResult.indicator && (
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                  {[
                    { label: 'Source',           value: lookupResult.indicator.source },
                    { label: 'Type',             value: `${TYPE_ICONS[lookupResult.indicator.indicator_type] || '❓'} ${lookupResult.indicator.indicator_type}` },
                    { label: 'Confidence',       value: `${((lookupResult.indicator.confidence_score ?? 0) * 100).toFixed(0)}%` },
                    { label: 'ATT&CK Tactic',    value: lookupResult.indicator.attack_tactic || '—' },
                    { label: 'ATT&CK Technique', value: lookupResult.indicator.attack_technique || '—' },
                    { label: 'First Seen',       value: new Date(lookupResult.indicator.first_seen).toLocaleString() },
                    { label: 'Last Seen',        value: new Date(lookupResult.indicator.last_seen).toLocaleString() },
                  ].map(({ label, value }) => (
                    <div key={label} className="bg-dark-800/60 rounded-lg p-3">
                      <p className="text-xs text-dark-400 mb-0.5">{label}</p>
                      <p className="text-sm font-medium text-dark-100">{value}</p>
                    </div>
                  ))}
                </div>
              )}

              {/* Internal asset match */}
              {lookupResult.matched_internal_asset ? (
                <div className="bg-red-500/10 border border-red-500/40 rounded-lg p-4">
                  <p className="text-sm font-semibold text-red-500 mb-2 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" />
                    ⚡ Matched Internal Asset — Immediate Triage Required
                  </p>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                    {[
                      { label: 'Hostname',       value: lookupResult.matched_internal_asset.hostname || '—' },
                      { label: 'IP Address',     value: lookupResult.matched_internal_asset.ip_address },
                      { label: 'Criticality',    value: `${lookupResult.matched_internal_asset.criticality_score}/10` },
                      { label: 'Internet Facing',value: lookupResult.matched_internal_asset.is_internet_facing ? '⚠️ Yes' : 'No' },
                    ].map(({ label, value }) => (
                      <div key={label}>
                        <p className="text-dark-400">{label}</p>
                        <p className="text-dark-100 font-medium">{value}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="bg-dark-800/40 border border-dark-700/40 rounded-lg p-3 text-xs text-dark-400">
                  <CheckCircle2 className="w-4 h-4 inline mr-1.5 text-green-500" />
                  No internal assets matched this indicator.
                </div>
              )}
            </div>
          )}

          {/* Quick reference */}
          {!lookupResult && !lookupError && (
            <div className="text-xs text-dark-500 space-y-1 border-t border-dark-700/40 pt-4">
              <p className="font-medium text-dark-400">Example lookups:</p>
              {[
                '185.220.101.5  — Known Tor exit node / C2',
                'malware.example.com  — Suspicious domain',
                'CVE-2021-44228  — Log4Shell CVE (cross-referenced in CTI feed)',
              ].map(ex => (
                <p key={ex} className="font-mono">{ex}</p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
