import { useState, useEffect, useCallback } from 'react'
import { Globe, RefreshCw, Search, X, Crosshair, Server, BookOpen, Database, CheckCircle2, AlertTriangle } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TiEventsPanel from '../components/threatintel/TiEventsPanel'
import AttackMatrixPanel from '../components/threatintel/AttackMatrixPanel'
import MatchesPanel from '../components/threatintel/MatchesPanel'
import IndicatorPanel, { TypeLabel, TYPE_META } from '../components/threatintel/IndicatorPanel'
import { Tabs, StatTile, Toast, useToast, Spinner, Pager, ago } from '../components/common/PageParts'

// Threat Intelligence: does any of it touch our assets? Matches first, then our own
// threat-intel events, the global feeds (OTX, ThreatFox, CISA KEV) and the ATT&CK view.

const PAGE_SIZE = 20
const STALE_HOURS = 36       // the feeds load nightly: older than this means a run was missed

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

// One line per feed: count, when it last loaded, and a warning when it failed or is old.
function FeedHealth({ stats, ingesting, onIngest }) {
  const feeds = stats?.feeds ?? []
  const hoursOld = (ts) => (ts ? (Date.now() - new Date(ts).getTime()) / 3600000 : Infinity)
  return (
    <div className="glass-card px-4 py-3 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs">
      <span className="text-dark-400 font-medium">Feeds</span>
      {feeds.length === 0 && <span className="text-dark-400">No feed data loaded yet.</span>}
      {feeds.map((f) => {
        const failed = f.ok === false
        const stale = !failed && f.last_ok_at && hoursOld(f.last_ok_at) > STALE_HOURS
        return (
          <span key={f.source} className="inline-flex items-center gap-1.5 text-dark-300"
            title={failed ? 'The last run could not load this feed' : f.last_ok_at ? `Loaded ${new Date(f.last_ok_at).toLocaleString()}` : 'Not loaded since feed health was recorded'}>
            {failed || stale
              ? <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              : <CheckCircle2 className={`w-3.5 h-3.5 ${f.last_ok_at ? 'text-accent-green' : 'text-dark-500'}`} />}
            <span className="text-dark-100">{f.source}</span>
            <span>{f.count.toLocaleString()}</span>
            <span className={failed || stale ? 'text-amber-400' : 'text-dark-500'}>
              {failed ? `failed${f.last_ok_at ? `, last loaded ${ago(f.last_ok_at)}` : ''}` : `updated ${ago(f.last_ok_at, 'unknown')}`}
            </span>
          </span>
        )
      })}
      <span className="ml-auto flex items-center gap-3 text-dark-500">
        {stats?.next_ingest_at && <span>Next update {new Date(stats.next_ingest_at).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' })}</span>}
        {stats?.can_ingest && (
          <button onClick={onIngest} disabled={ingesting} className="btn-secondary text-xs py-1 px-2.5 inline-flex items-center gap-1.5 disabled:opacity-60"
            title="Load all feeds now, for every tenant (platform superadmin)">
            <RefreshCw className={`w-3.5 h-3.5 ${ingesting ? 'animate-spin' : ''}`} />
            {ingesting ? 'Updating…' : 'Update feeds now'}
          </button>
        )}
      </span>
    </div>
  )
}

export default function ThreatIntelPage() {
  const { user } = useAuth()
  const { toast, show: showToast } = useToast()
  const [stats, setStats] = useState(null)
  const [tab, setTab] = useState(null)              // set once the stats say whether there are matches
  const [ingesting, setIngesting] = useState(false)
  const [lookupInput, setLookupInput] = useState('')
  const [panelValue, setPanelValue] = useState(null)

  // Indicators tab
  const [indicators, setIndicators] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [q, setQ] = useState('')
  const [qDebounced, setQDebounced] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [matchedOnly, setMatchedOnly] = useState(false)
  const [attackFilter, setAttackFilter] = useState(null)   // from the ATT&CK tab: { family } | { technique }, with a label

  const loadStats = useCallback(async () => {
    try {
      const res = await client.get('/cti/stats')
      setStats(res.data)
      setTab((cur) => cur ?? (res.data?.matches?.open > 0 ? 'matches' : 'events'))
    } catch {
      setTab((cur) => cur ?? 'events')
    }
  }, [])
  useEffect(() => { loadStats() }, [loadStats])

  useEffect(() => {
    const t = setTimeout(() => { setQDebounced(q.trim()); setPage(1) }, 300)
    return () => clearTimeout(t)
  }, [q])

  const loadIndicators = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, limit: PAGE_SIZE }
      if (qDebounced) params.q = qDebounced
      if (typeFilter) params.indicator_type = typeFilter
      if (sourceFilter) params.source = sourceFilter
      if (matchedOnly) params.matched = 'true'
      if (attackFilter?.family) params.family = attackFilter.family
      if (attackFilter?.technique) params.technique = attackFilter.technique
      const res = await client.get('/cti/indicators', { params })
      setIndicators(res.data.items || [])
      setTotal(res.data.total || 0)
    } catch (err) {
      showToast(err?.response?.data?.detail || 'Failed to load indicators', 'error')
    } finally {
      setLoading(false)
    }
  }, [page, qDebounced, typeFilter, sourceFilter, matchedOnly, attackFilter, showToast])
  useEffect(() => { if (tab === 'indicators') loadIndicators() }, [tab, loadIndicators])

  const ingest = async () => {
    setIngesting(true)
    try {
      const res = await client.post('/cti/ingest')
      if (res.data?.queued === false) {
        showToast('An update is already running or ran in the last hour.', 'info')
        setIngesting(false)
      } else {
        showToast('Feed update queued. Refreshing in about 15 seconds…', 'success')
        setTimeout(() => { loadStats(); if (tab === 'indicators') loadIndicators(); setIngesting(false) }, 15000)
      }
    } catch (err) {
      showToast(err?.response?.data?.detail ?? 'Failed to queue the feed update', 'error')
      setIngesting(false)
    }
  }

  const lookup = (e) => {
    e?.preventDefault()
    const v = lookupInput.trim()
    if (v) setPanelValue(v)
  }

  const showAttackIndicators = (f) => {
    setAttackFilter(f); setSourceFilter(''); setTypeFilter(''); setQ(''); setMatchedOnly(false); setPage(1); setTab('indicators')
  }
  const clearFilters = () => { setQ(''); setTypeFilter(''); setSourceFilter(''); setMatchedOnly(false); setAttackFilter(null); setPage(1) }
  const hasFilters = q || typeFilter || sourceFilter || matchedOnly || attackFilter

  const m = stats?.matches
  const types = Object.entries(stats?.by_type ?? {})
  const sources = (stats?.feeds ?? []).map((f) => f.source)

  return (
    <div className="space-y-6">
      <Toast toast={toast} />

      {/* Header + lookup */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Intelligence</h1>
          <p className="text-dark-400 text-sm mt-1 max-w-2xl">Which of your assets threat intelligence names, your own threat-intel events, and the feeds behind them.</p>
        </div>
        <form onSubmit={lookup} className="flex gap-2 w-full sm:w-auto" role="search">
          <div className="relative flex-1 sm:w-80">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
            <input type="text" value={lookupInput} onChange={(e) => setLookupInput(e.target.value)}
              placeholder="Look up an IP, domain, hash or CVE…" aria-label="Look up a value in threat intelligence"
              className="input-field w-full pl-10 text-sm" />
          </div>
          <button type="submit" disabled={!lookupInput.trim()} className="btn-primary text-sm disabled:opacity-50">Look up</button>
        </form>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatTile label="Matches on our assets" icon={Crosshair}
          value={m ? m.open : '—'} tone={m?.open > 0 ? 'danger' : 'good'}
          sub={m ? (m.open > 0 ? `${m.high} critical or high` : 'nothing matched') : ' '}
          onClick={() => setTab('matches')} />
        <StatTile label="Assets affected" icon={Server}
          value={m ? m.assets : '—'} tone={m?.assets > 0 ? 'warning' : 'muted'}
          sub="with an open match" onClick={() => setTab('matches')} />
        <StatTile label="Threat-intel events" icon={BookOpen}
          value={stats?.ti_events?.total ?? '—'} sub={stats ? `${stats.ti_events.published} published` : ' '}
          onClick={() => setTab('events')} />
        <StatTile label="Feed indicators" icon={Database}
          value={stats ? stats.total_indicators.toLocaleString() : '—'}
          sub={stats ? `+${stats.recent_7d.toLocaleString()} in the last 7 days` : ' '}
          onClick={() => { clearFilters(); setTab('indicators') }} />
      </div>

      <FeedHealth stats={stats} ingesting={ingesting} onIngest={ingest} />

      {tab && (
        <Tabs label="Threat intelligence views" active={tab} onChange={setTab} tabs={[
          { id: 'matches', label: 'Matches', count: m?.open },
          { id: 'events', label: 'Events', count: stats?.ti_events?.total },
          { id: 'indicators', label: 'Indicators' },
          { id: 'matrix', label: 'MITRE ATT&CK' },
        ]} />
      )}

      {!tab ? <Spinner /> : tab === 'matches' ? (
        <MatchesPanel onLookup={setPanelValue} showToast={showToast} />
      ) : tab === 'events' ? (
        <TiEventsPanel user={user} showToast={showToast} />
      ) : tab === 'matrix' ? (
        <AttackMatrixPanel onShowIndicators={showAttackIndicators} />
      ) : (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-dark-400" />
              <input type="text" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search values…"
                aria-label="Search indicator values" className="input-field text-sm py-1.5 pl-8 w-56" />
            </div>
            <div className="flex items-center gap-1 flex-wrap" role="group" aria-label="Indicator type">
              <button onClick={() => { setTypeFilter(''); setPage(1) }}
                className={`text-xs px-2.5 py-1 rounded-full border ${!typeFilter ? 'bg-eagle-600/20 text-eagle-300 border-eagle-500/40' : 'border-dark-600 text-dark-400 hover:text-dark-200'}`}>
                All
              </button>
              {types.map(([t, n]) => {
                const Icon = TYPE_META[t]?.icon ?? Globe
                return (
                  <button key={t} onClick={() => { setTypeFilter(t); setPage(1) }} aria-pressed={typeFilter === t}
                    className={`text-xs px-2.5 py-1 rounded-full border inline-flex items-center gap-1 ${typeFilter === t ? 'bg-eagle-600/20 text-eagle-300 border-eagle-500/40' : 'border-dark-600 text-dark-400 hover:text-dark-200'}`}>
                    <Icon className="w-3 h-3" />{TYPE_META[t]?.label ?? t}<span className="text-dark-500">{n.toLocaleString()}</span>
                  </button>
                )
              })}
            </div>
            <select value={sourceFilter} onChange={(e) => { setSourceFilter(e.target.value); setPage(1) }} className="input-field text-sm py-1.5 w-44" aria-label="Feed">
              <option value="">All feeds</option>
              {sources.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <label className="inline-flex items-center gap-2 text-xs text-dark-300 cursor-pointer">
              <input type="checkbox" checked={matchedOnly} onChange={(e) => { setMatchedOnly(e.target.checked); setPage(1) }} className="accent-eagle-500" />
              Matching our assets only
            </label>
            {attackFilter && (
              <span className="flex items-center gap-1 text-xs bg-eagle-600/20 text-eagle-400 border border-eagle-600/40 rounded px-2 py-1">
                ATT&CK {attackFilter.family ? 'family' : 'technique'}: {attackFilter.label}
                <button onClick={() => { setAttackFilter(null); setPage(1) }} title="Remove filter"><X className="w-3 h-3" /></button>
              </span>
            )}
            {hasFilters && <button onClick={clearFilters} className="text-xs text-dark-400 hover:text-dark-200 underline underline-offset-2">Clear</button>}
            <span className="text-dark-400 text-sm ml-auto">{total.toLocaleString()} indicators</span>
          </div>

          <div className="glass-card overflow-hidden">
            {loading ? <Spinner className="py-20" /> : indicators.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr><th>Type</th><th>Value</th><th>Feed</th><th>Confidence</th><th>Malware family</th><th>ATT&CK</th><th>Last seen</th></tr>
                  </thead>
                  <tbody>
                    {indicators.map((ind) => (
                      <tr key={ind.indicator_id} className="cursor-pointer hover:bg-dark-700/30" onClick={() => setPanelValue(ind.value)}
                        tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') setPanelValue(ind.value) }}>
                        <td><TypeLabel type={ind.indicator_type} /></td>
                        <td className="font-mono text-xs text-accent-cyan max-w-xs truncate" title={ind.value}>{ind.value}</td>
                        <td className="text-dark-300 text-xs">{ind.source}</td>
                        <td><ConfBar score={ind.confidence_score} /></td>
                        <td className="text-dark-300 text-xs max-w-[10rem] truncate" title={ind.malware_family || ''}>{ind.malware_family || '—'}</td>
                        <td className="text-xs">
                          {ind.technique_count > 0 ? (
                            <span className="text-accent-purple" title={ind.attack_software ? `${ind.attack_software_name} (${ind.attack_software}) in MITRE ATT&CK` : 'Techniques named by the feed'}>
                              {ind.attack_software ? <span className="font-mono">{ind.attack_software}</span> : 'Named'} · {ind.technique_count} techniques
                            </span>
                          ) : <span className="text-dark-500">—</span>}
                        </td>
                        <td className="text-dark-400 text-xs whitespace-nowrap">{new Date(ind.last_seen).toLocaleDateString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-center py-16 text-dark-400 px-4">
                <Globe className="w-14 h-14 mx-auto mb-4 opacity-20" />
                <p className="font-medium text-dark-200">{hasFilters ? 'No indicators match these filters' : 'No feed indicators yet'}</p>
                {!hasFilters && <p className="text-sm mt-1">The feeds load every night.</p>}
              </div>
            )}
          </div>
          <Pager page={page} totalPages={Math.ceil(total / PAGE_SIZE)} onChange={setPage} />
        </div>
      )}

      {panelValue && <IndicatorPanel value={panelValue} onClose={() => setPanelValue(null)} />}
    </div>
  )
}
