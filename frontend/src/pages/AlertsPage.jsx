import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import {
  Bell, Shield, AlertTriangle, TrendingUp, Zap, Filter, RefreshCw, CheckCircle2,
  Server, ExternalLink, Search, X, Globe, Clock, User, ChevronLeft, ChevronRight,
  Timer, Lightbulb, History, Link2, Crosshair,
} from 'lucide-react'
import {
  BarChart, Bar, ResponsiveContainer, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from 'recharts'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'
import {
  SEVERITY_COLORS, EVENT_TYPE_LABELS, DRIFT_TYPES, alertLabel, renderDetail, playbook,
  StatusBadge, SevBadge, timeAgo, CHART_TOOLTIP_STYLE, RISKY_PORTS, CONCERNS, riskReasons,
} from '../components/common/alertMeta'
import {
  ConcernCard, AgingHeatmap, ReasonChips, PriorityTier, DueLabel, fmtNum,
} from '../components/common/triageViz'

const PAGE_SIZE = 20
const LAST_VISIT_KEY = 'alerts_last_visit'
const DRIFT_CSV = [...DRIFT_TYPES].join(',')

// Saved views — each is a work queue with its own filter + sort. Concern views
// are picked from the cards at the top; the rest are tabs.
const VIEWS = [
  { id: 'open',      label: 'All open',                   params: { status: 'open' } },
  { id: 'mine',      label: 'My queue',                   params: { status: 'open', assigned_to: 'me' } },
  { id: 'overdue',   label: 'Past SLA',                   params: { status: 'open', overdue: 'true' } },
  { id: 'exposed',   label: 'Critical on internet-facing', params: { status: 'open', severity: 'critical,high', internet_facing: 'true' } },
  { id: 'drift',     label: 'Drift to review',            params: { status: 'open', event_type: DRIFT_CSV } },
  { id: 'cve',       label: 'All CVEs',                   params: { status: 'open', event_type: 'cve_detected' } },
  { id: 'closed',    label: 'Closed (audit)',             params: { status: 'closed' }, sort: 'time' },
  ...CONCERNS.map(c => ({ id: c.id, label: c.title, params: { status: 'open', concern: c.id }, concern: true })),
]
// Older links (bookmarks, other pages) used these ids
const LEGACY_VIEWS = { ports: 'exposed_services', devices: 'new_devices', threat: 'threat_intel' }
const resolveView = (id) => VIEWS.find(v => v.id === (LEGACY_VIEWS[id] ?? id))?.id ?? 'open'
const AGE_LABELS = { lt1d: 'open < 1 day', d1_3: 'open 1–3 days', d3_7: 'open 3–7 days', d7_30: 'open 7–30 days', gt30: 'open > 30 days' }

const CLOSE_STATUSES = new Set(['resolved', 'false_positive', 'accepted_risk'])
const ACTION_LABELS = {
  in_progress:    'Start work',
  resolved:       'Resolve',
  false_positive: 'Mark false positive',
  accepted_risk:  'Accept risk',
  open:           'Reopen',
}

function useToast() {
  const [toast, setToast] = useState(null)
  const show = (msg, type = 'success') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3500)
  }
  return { toast, show }
}

function readLastVisit() {
  try { return localStorage.getItem(LAST_VISIT_KEY) } catch { return null }
}
function writeLastVisit(v) {
  try { localStorage.setItem(LAST_VISIT_KEY, v) } catch { /* private mode */ }
}

export default function AlertsPage() {
  const { user } = useAuth()
  const isSuperadmin    = user?.role === 'superadmin'
  const isBusinessOwner = user?.role === 'business_owner'
  const canManage       = !isSuperadmin && !isBusinessOwner
  const [searchParams, setSearchParams] = useSearchParams()

  const [view,         setView]         = useState(() => resolveView(searchParams.get('view')))
  const [search,       setSearch]       = useState(searchParams.get('q') ?? '')
  const [debounced,    setDebounced]    = useState(search)
  const [severity,     setSeverity]     = useState(() => searchParams.get('severity') ?? '')
  const [age,          setAge]          = useState('')
  const [typeFilter,   setTypeFilter]   = useState('')
  const [deviceType,   setDeviceType]   = useState('')
  const [onlyExposed,  setOnlyExposed]  = useState(false)
  const [onlyNew,      setOnlyNew]      = useState(false)
  const [sort,         setSort]         = useState('priority')
  const [tenantFilter, setTenantFilter] = useState('')
  const [page,         setPage]         = useState(1)

  const [events,    setEvents]    = useState([])
  const [total,     setTotal]     = useState(0)
  const [stats,     setStats]     = useState(null)
  const [loading,   setLoading]   = useState(true)
  const [selected,  setSelected]  = useState(new Set())
  const [assignees, setAssignees] = useState([])
  const [detailId,  setDetailId]  = useState(searchParams.get('event'))
  const [action,    setAction]    = useState(null)   // { ids, status }
  const { toast, show: showToast } = useToast()

  // "New since my last visit" is relative to the previous visit, captured once
  const lastVisit = useRef(readLastVisit())
  useEffect(() => { writeLastVisit(new Date().toISOString()) }, [])

  useEffect(() => {
    const t = setTimeout(() => setDebounced(search.trim()), 300)
    return () => clearTimeout(t)
  }, [search])

  const activeView = VIEWS.find(v => v.id === view) ?? VIEWS[0]

  const queryParams = useMemo(() => {
    const p = { page, page_size: PAGE_SIZE, sort: activeView.sort ?? sort, ...activeView.params }
    if (severity) p.severity = severity
    if (age) p.age = age
    if (typeFilter && !activeView.params.event_type && !activeView.params.concern) p.event_type = typeFilter
    if (deviceType) p.device_type = deviceType
    if (onlyExposed) p.internet_facing = 'true'
    if (onlyNew && lastVisit.current) p.since = lastVisit.current
    if (debounced) p.q = debounced
    if (tenantFilter) p.tenant_id = tenantFilter
    return p
  }, [page, sort, activeView, severity, age, typeFilter, deviceType, onlyExposed, onlyNew, debounced, tenantFilter])

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const tParam = tenantFilter ? { tenant_id: tenantFilter } : {}
      const [eventsRes, statsRes] = await Promise.all([
        client.get('/events', { params: queryParams }),
        client.get('/events/stats/summary', { params: tParam }),
      ])
      setEvents(eventsRes.data.items || [])
      setTotal(eventsRes.data.total || 0)
      setStats(statsRes.data)
      setSelected(new Set())
    } catch (err) {
      console.error('Alerts load error:', err)
    } finally {
      setLoading(false)
    }
  }, [queryParams, tenantFilter])

  useEffect(() => { loadData() }, [loadData])

  useEffect(() => {
    if (!canManage) return
    client.get('/events/assignees', { params: tenantFilter ? { tenant_id: tenantFilter } : {} })
      .then(r => setAssignees(r.data.items || []))
      .catch(() => setAssignees([]))
  }, [canManage, tenantFilter])

  // Keep view / search / open drawer in the URL so a link reproduces the queue
  useEffect(() => {
    const next = {}
    if (view !== 'open') next.view = view
    if (debounced) next.q = debounced
    if (detailId) next.event = detailId
    setSearchParams(next, { replace: true })
  }, [view, debounced, detailId, setSearchParams])

  const resetPage = (fn) => (v) => { fn(v); setPage(1) }

  // ── Actions ──────────────────────────────────────────────────
  const runUpdate = async (ids, body) => {
    try {
      if (ids.length === 1) await client.patch(`/events/${ids[0]}`, body)
      else await client.post('/events/bulk', { event_ids: ids, ...body })
      showToast(ids.length === 1 ? 'Alert updated.' : `${ids.length} alerts updated.`)
      await loadData()
      return true
    } catch (err) {
      showToast(err.response?.data?.detail || 'Update failed.', 'error')
      return false
    }
  }

  const requestStatus = (ids, status) => {
    // Closing needs a reason on record; starting/reopening does not
    if (CLOSE_STATUSES.has(status)) setAction({ ids, status })
    else runUpdate(ids, { status })
  }

  const assign = (ids, assignedTo) => runUpdate(ids, { assigned_to: assignedTo || null })

  const triggerAdvisory = async (ids) => {
    try {
      await Promise.all(ids.map(id => client.post(`/events/${id}/advisory`)))
      showToast(`AI advisory queued for ${ids.length} alert${ids.length === 1 ? '' : 's'} — check Advisories shortly.`)
    } catch {
      showToast('Failed to queue advisory generation.', 'error')
    }
  }

  const triggerDriftAudit = async () => {
    try {
      await client.post('/scans/drift-audit')
      showToast('Drift audit triggered.')
      setTimeout(loadData, 2000)
    } catch {
      showToast('Failed to trigger drift audit.', 'error')
    }
  }

  const trendData = stats?.daily_trend || []
  const pickView = (id) => { setView(id); setPage(1) }
  const pickCell = (sev, bucket) => { setView('open'); setSeverity(sev); setAge(bucket); setPage(1) }

  const totalPages = Math.ceil(total / PAGE_SIZE)
  const allOnPageSelected = events.length > 0 && events.every(e => selected.has(e.event_id))
  const toggleAll = () => setSelected(allOnPageSelected ? new Set() : new Set(events.map(e => e.event_id)))
  const toggleOne = (id) => setSelected(s => {
    const n = new Set(s)
    n.has(id) ? n.delete(id) : n.add(id)
    return n
  })

  const filtersActive = severity || age || typeFilter || deviceType || onlyExposed || onlyNew || search
  const clearFilters = () => {
    setSeverity(''); setAge(''); setTypeFilter(''); setDeviceType(''); setOnlyExposed(false); setOnlyNew(false); setSearch(''); setPage(1)
  }

  return (
    <div className="space-y-6">
      {toast && (
        <div className={`fixed top-4 right-4 z-[60] flex items-center gap-2 px-4 py-3 rounded-lg shadow-lg text-sm font-medium
          ${toast.type === 'success'
            ? 'bg-green-900/90 text-green-200 border border-green-700'
            : 'bg-red-900/90 text-red-200 border border-red-700'}`}>
          {toast.type === 'success' ? <CheckCircle2 className="w-4 h-4 flex-shrink-0" /> : <AlertTriangle className="w-4 h-4 flex-shrink-0" />}
          {toast.msg}
        </div>
      )}

      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-dark-50">Alerts</h1>
          <p className="text-dark-400 text-sm mt-1">
            Start with the categories at the top, then work the queue from P1 down
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <TenantSelector value={tenantFilter} onChange={resetPage(setTenantFilter)} />
          {canManage && (
            <button onClick={triggerDriftAudit} className="btn-secondary flex items-center gap-2 text-sm">
              <RefreshCw className="w-4 h-4" />
              Run Drift Audit
            </button>
          )}
        </div>
      </div>

      {/* ── Start here: concern categories ── */}
      <section>
        <div className="flex items-baseline gap-3 flex-wrap mb-3">
          <h2 className="text-base font-semibold text-dark-100">Start here</h2>
          <span className="text-xs text-dark-500">
            {stats ? <>{fmtNum(stats.open_total)} open alerts in total. These categories are the ones attackers use first. Click one to filter the queue.</> : 'Loading…'}
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4">
          {CONCERNS.map(meta => (
            <ConcernCard key={meta.id} meta={meta} loading={!stats} count={stats?.concerns?.[meta.id] ?? 0}
              active={view === meta.id} onOpen={() => pickView(view === meta.id ? 'open' : meta.id)} />
          ))}
        </div>
      </section>

      {/* ── Backlog shape ── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="glass-card p-5 xl:col-span-2">
          <h3 className="text-base font-semibold text-dark-100 flex items-center gap-2">
            <Timer className="w-4 h-4 text-eagle-400" /> How long has open work been waiting?
          </h3>
          <p className="text-xs text-dark-500 mt-1 mb-4">
            Rows are severity, columns are time since first detection. Old critical and high alerts are the SLA breaches.
            {stats?.sla_breaches > 0 && <> <button onClick={() => pickView('overdue')} className="text-red-400 hover:underline">{fmtNum(stats.sla_breaches)} past SLA →</button></>}
          </p>
          <AgingHeatmap aging={stats?.aging} onCell={pickCell} />
        </div>

        <div className="glass-card p-5 flex flex-col">
          <h3 className="text-base font-semibold text-dark-100 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-eagle-400" /> Is the team keeping up?
          </h3>
          {(() => {
            const net = stats ? (stats.new_7d ?? 0) - (stats.resolved_7d ?? 0) : null
            const mttr = stats?.mttr_hours
            return (
              <>
                <div className="flex items-baseline gap-2 mt-3">
                  <span className={`text-4xl font-bold ${net > 0 ? 'text-orange-400' : 'text-emerald-400'}`}>
                    {net == null ? '—' : `${net > 0 ? '+' : ''}${fmtNum(net)}`}
                  </span>
                  <span className="text-sm text-dark-300">{net == null ? '' : net > 0 ? 'backlog grew in 7 days' : net < 0 ? 'backlog shrank in 7 days' : 'backlog unchanged'}</span>
                </div>
                <p className="text-xs text-dark-500 mt-1">
                  {stats ? <>{fmtNum(stats.new_7d)} new · {fmtNum(stats.resolved_7d)} closed · {fmtNum(stats.by_status?.in_progress)} in progress
                    {mttr != null && <> · fixes take {mttr < 48 ? `${mttr}h` : `${Math.round(mttr / 24)}d`} on average</>}</> : ''}
                </p>
                <div className="mt-4 flex-1 min-h-[160px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={trendData} barGap={2} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                      <CartesianGrid vertical={false} stroke="rgb(var(--dark-700))" />
                      <XAxis dataKey="date" tick={{ fill: 'rgb(var(--dark-400))', fontSize: 11 }} axisLine={false} tickLine={false} />
                      <YAxis allowDecimals={false} tick={{ fill: 'rgb(var(--dark-400))', fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={CHART_TOOLTIP_STYLE} cursor={{ fill: 'rgb(var(--dark-700) / 0.3)' }} />
                      <Legend wrapperStyle={{ fontSize: 11 }} iconType="square" iconSize={9} />
                      <Bar name="New" dataKey="new" fill="#ff9800" radius={[4, 4, 0, 0]} maxBarSize={14} />
                      <Bar name="Closed" dataKey="resolved" fill="#00e676" radius={[4, 4, 0, 0]} maxBarSize={14} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </>
            )
          })()}
        </div>
      </div>

      {/* ── Saved views ── */}
      <div className="flex gap-1 overflow-x-auto border-b border-dark-700 -mb-2">
        {VIEWS.filter(v => !v.concern && (canManage || v.id !== 'mine')).map(v => (
          <button key={v.id} onClick={() => { setView(v.id); setPage(1) }}
            className={`px-3 py-2 text-sm whitespace-nowrap border-b-2 transition-colors ${view === v.id
              ? 'border-eagle-500 text-eagle-400 font-medium'
              : 'border-transparent text-dark-400 hover:text-dark-200'}`}>
            {v.label}
            {v.id === 'overdue' && (stats?.sla_breaches ?? 0) > 0 && (
              <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-300">{fmtNum(stats.sla_breaches)}</span>
            )}
          </button>
        ))}
        {activeView.concern && (
          <span className="px-3 py-2 text-sm whitespace-nowrap border-b-2 border-eagle-500 text-eagle-400 font-medium inline-flex items-center gap-1.5">
            {activeView.label}
            <button onClick={() => pickView('open')} aria-label="Back to all open" className="text-dark-400 hover:text-dark-100"><X className="w-3.5 h-3.5" /></button>
          </span>
        )}
      </div>

      {/* ── Filters ── */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-dark-400" />
          <input value={search} onChange={e => { setSearch(e.target.value); setPage(1) }}
            placeholder="Host, IP, CVE or package…" className="input-field text-sm py-1.5 pl-9 w-64" />
        </div>
        <select value={severity} onChange={e => resetPage(setSeverity)(e.target.value)} className="input-field text-sm py-1.5 w-36">
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        {age && (
          <span className="inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded-full border border-eagle-500/40 text-eagle-300 bg-eagle-500/10">
            {AGE_LABELS[age]}
            <button onClick={() => resetPage(setAge)('')} aria-label="Remove age filter"><X className="w-3 h-3" /></button>
          </span>
        )}
        {!activeView.params.event_type && !activeView.params.concern && (
          <select value={typeFilter} onChange={e => resetPage(setTypeFilter)(e.target.value)} className="input-field text-sm py-1.5 w-44">
            <option value="">All types</option>
            {Object.entries(EVENT_TYPE_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        )}
        <select value={deviceType} onChange={e => resetPage(setDeviceType)(e.target.value)} className="input-field text-sm py-1.5 w-36">
          <option value="">All devices</option>
          <option value="server">Server</option>
          <option value="workstation">Workstation</option>
          <option value="network">Network</option>
          <option value="iot">IoT</option>
          <option value="unknown">Unknown</option>
        </select>
        <label className="flex items-center gap-1.5 text-sm text-dark-300 cursor-pointer">
          <input type="checkbox" checked={onlyExposed} onChange={e => resetPage(setOnlyExposed)(e.target.checked)} />
          <Globe className="w-3.5 h-3.5" /> Internet-facing
        </label>
        {lastVisit.current && (
          <label className="flex items-center gap-1.5 text-sm text-dark-300 cursor-pointer" title={`Since ${new Date(lastVisit.current).toLocaleString()}`}>
            <input type="checkbox" checked={onlyNew} onChange={e => resetPage(setOnlyNew)(e.target.checked)} />
            New since last visit
          </label>
        )}
        {filtersActive && (
          <button onClick={clearFilters} className="text-xs text-dark-400 hover:text-dark-200 underline underline-offset-2">Clear</button>
        )}
        <div className="ml-auto flex items-center gap-3">
          {!activeView.sort && (
            <select value={sort} onChange={e => resetPage(setSort)(e.target.value)} className="input-field text-sm py-1.5 w-40">
              <option value="priority">Sort: priority</option>
              <option value="time">Sort: last seen</option>
            </select>
          )}
          <span className="text-dark-400 text-sm">{total} alert{total === 1 ? '' : 's'}</span>
        </div>
      </div>

      {/* ── Bulk action bar ── */}
      {canManage && selected.size > 0 && (
        <div className="glass-card px-4 py-2.5 flex items-center gap-2 flex-wrap border-eagle-500/40">
          <span className="text-sm text-dark-200 font-medium mr-2">{selected.size} selected</span>
          <AssignSelect assignees={assignees} value="" onChange={(v) => assign([...selected], v)} placeholder="Assign to…" />
          {['in_progress', 'resolved', 'false_positive', 'accepted_risk'].map(s => (
            <button key={s} onClick={() => requestStatus([...selected], s)} className="btn-secondary text-xs py-1.5 px-3">
              {ACTION_LABELS[s]}
            </button>
          ))}
          <button onClick={() => triggerAdvisory([...selected])} className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1">
            <Zap className="w-3.5 h-3.5" /> Advisory
          </button>
          <button onClick={() => setSelected(new Set())} className="ml-auto text-xs text-dark-400 hover:text-dark-200">Clear selection</button>
        </div>
      )}

      {/* ── Queue ── */}
      <div className="glass-card overflow-x-auto">
        {loading ? (
          <div className="flex justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : events.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                {canManage && <th className="w-8"><input type="checkbox" checked={allOnPageSelected} onChange={toggleAll} aria-label="Select all" /></th>}
                <th title="P1 urgent → P4 low. Score = risk × internet exposure × asset criticality (+ threat intel)">Priority</th>
                <th>Alert &amp; why it matters</th>
                <th>Evidence</th>
                <th>Asset</th>
                <th>CVSS / EPSS</th>
                <th>Seen / due</th>
                <th>Status</th>
                <th>Owner</th>
              </tr>
            </thead>
            <tbody>
              {events.map(e => (
                <tr key={e.event_id} onClick={() => setDetailId(e.event_id)}
                  className={`cursor-pointer ${detailId === e.event_id ? 'bg-eagle-500/5' : ''}`}>
                  {canManage && (
                    <td onClick={ev => ev.stopPropagation()} style={{ boxShadow: `inset 3px 0 0 ${SEVERITY_COLORS[e.severity]}` }}>
                      <input type="checkbox" checked={selected.has(e.event_id)} onChange={() => toggleOne(e.event_id)} aria-label="Select alert" />
                    </td>
                  )}
                  <td style={canManage ? undefined : { boxShadow: `inset 3px 0 0 ${SEVERITY_COLORS[e.severity]}` }}>
                    <div className="flex flex-col items-start gap-1">
                      <PriorityTier score={e.priority_score} />
                      <SevBadge sev={e.severity} />
                    </div>
                  </td>
                  <td className="text-dark-200 text-xs min-w-[300px]">
                    <div className="flex items-center gap-1.5 text-sm text-dark-100 font-medium">
                      {(e.event_type === 'cti_match' || e.details?.has_cti_match) && <Crosshair className="w-3.5 h-3.5 text-accent-red" title="Threat-intel match" />}
                      {alertLabel(e)}
                    </div>
                    <div className="mt-1"><ReasonChips reasons={riskReasons(e)} max={4} /></div>
                    {e.has_advisory && <span className="text-[10px] text-accent-green">● advisory ready</span>}
                  </td>
                  <td className="font-mono text-xs text-accent-cyan max-w-[220px] truncate">
                    {e.details?.cve_id ? (
                      <a href={`https://nvd.nist.gov/vuln/detail/${e.details.cve_id}`} target="_blank" rel="noreferrer"
                        onClick={ev => ev.stopPropagation()} className="hover:text-eagle-300 inline-flex items-center gap-1" title="View on NVD">
                        {e.details.cve_id}<ExternalLink className="w-3 h-3 opacity-60" />
                      </a>
                    ) : renderDetail(e)}
                    {e.details?.package_name && (
                      <p className="text-dark-400 font-sans">{e.details.package_name}{e.details.package_version ? ` ${e.details.package_version}` : ''}</p>
                    )}
                  </td>
                  <td>
                    <div className="flex items-start gap-1.5">
                      <Server className="w-3.5 h-3.5 text-dark-400 flex-shrink-0 mt-0.5" />
                      <div className="min-w-0">
                        <div className="flex items-center gap-1">
                          <span className="text-sm text-dark-200 truncate max-w-[140px]">{e.asset_hostname || e.asset_ip || e.asset_id?.slice(0, 8)}</span>
                          {e.asset_internet_facing && <Globe className="w-3.5 h-3.5 text-accent-amber flex-shrink-0" title="Internet-facing" />}
                        </div>
                        <p className="font-mono text-[11px] text-dark-500">
                          {e.asset_hostname ? e.asset_ip : ''} {e.asset_device_type && <span className="capitalize font-sans">· {e.asset_device_type}</span>}
                          {e.asset_criticality != null && <span className={`font-sans ${e.asset_criticality >= 8 ? 'text-accent-red' : ''}`}> · crit {e.asset_criticality}</span>}
                        </p>
                      </div>
                    </div>
                  </td>
                  <td className="font-mono text-xs whitespace-nowrap">
                    {e.details?.cvss_base_score != null
                      ? <span style={{ color: e.details.cvss_base_score >= 9 ? '#ff5252' : e.details.cvss_base_score >= 7 ? '#ff9800' : e.details.cvss_base_score >= 4 ? '#ffc400' : '#00e676' }}>{e.details.cvss_base_score}</span>
                      : '—'}
                    <span className="text-dark-500"> / </span>
                    {e.details?.epss_score != null ? `${(e.details.epss_score * 100).toFixed(1)}%` : '—'}
                  </td>
                  <td className="text-xs text-dark-400 whitespace-nowrap">
                    <div title={`First seen ${new Date(e.first_seen).toLocaleString()}`}>{timeAgo(e.last_seen)}</div>
                    {e.occurrences > 1 && <div className="text-dark-500">×{e.occurrences} · since {timeAgo(e.first_seen)}</div>}
                    {(e.status === 'open' || e.status === 'in_progress') && <div className="mt-0.5"><DueLabel e={e} /></div>}
                  </td>
                  <td><StatusBadge status={e.status} /></td>
                  <td className="text-xs text-dark-300 whitespace-nowrap">
                    {e.assignee_name ? <span className="inline-flex items-center gap-1"><User className="w-3 h-3" />{e.assignee_name}</span> : <span className="text-dark-500">Unassigned</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <CheckCircle2 className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium mb-2">{view === 'closed' ? 'No closed alerts yet' : 'Queue is clear'}</p>
            <p className="text-sm">
              {filtersActive ? 'No alerts match these filters.' : 'Nothing needs attention in this view. Run scans, SBOMs or a drift audit to detect new issues.'}
            </p>
          </div>
        )}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="btn-secondary text-sm py-1 px-3 disabled:opacity-30">Previous</button>
          <span className="text-dark-400 text-sm">Page {page} of {totalPages}</span>
          <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages} className="btn-secondary text-sm py-1 px-3 disabled:opacity-30">Next</button>
        </div>
      )}

      {detailId && (
        <AlertDrawer
          eventId={detailId}
          canManage={canManage}
          assignees={assignees}
          onClose={() => setDetailId(null)}
          onStatus={(status) => requestStatus([detailId], status)}
          onAssign={(v) => assign([detailId], v)}
          onAdvisory={() => triggerAdvisory([detailId])}
          onNavigate={(dir) => {
            const i = events.findIndex(e => e.event_id === detailId)
            const next = events[i + dir]
            if (next) setDetailId(next.event_id)
          }}
          reloadKey={events}
        />
      )}

      {action && (
        <CloseDialog
          count={action.ids.length}
          status={action.status}
          onCancel={() => setAction(null)}
          onConfirm={async (note) => {
            const ok = await runUpdate(action.ids, { status: action.status, note })
            if (ok) setAction(null)
          }}
        />
      )}
    </div>
  )
}

// ── Small pieces ───────────────────────────────────────────────
function AssignSelect({ assignees, value, onChange, placeholder = 'Unassigned' }) {
  return (
    <select value={value ?? ''} onChange={e => onChange(e.target.value)} onClick={e => e.stopPropagation()}
      className="input-field text-xs py-1.5 px-2 w-40">
      <option value="">{placeholder}</option>
      {assignees.map(a => <option key={a.user_id} value={a.user_id}>{a.username}</option>)}
    </select>
  )
}

function CloseDialog({ count, status, onCancel, onConfirm }) {
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const hints = {
    resolved:       'What was done? e.g. "Upgraded openssl to 3.0.14, verified with rescan"',
    false_positive: 'Why is the detection wrong? e.g. "Port 8080 is the scanner\'s own proxy"',
    accepted_risk:  'Who approved it and why? e.g. "RDP required for vendor support, approved by IT lead, firewall-restricted"',
  }
  return (
    <div role="dialog" aria-modal="true" className="fixed inset-0 z-[55] bg-black/60 flex items-center justify-center p-4" onClick={onCancel}>
      <div className="glass-card p-5 w-full max-w-md bg-dark-800" onClick={e => e.stopPropagation()}>
        <h3 className="text-white font-semibold mb-1">{ACTION_LABELS[status]}{count > 1 ? ` — ${count} alerts` : ''}</h3>
        <p className="text-xs text-dark-400 mb-3">
          {status === 'accepted_risk'
            ? 'The current state becomes the approved baseline for drift alerts. This is recorded in the audit log.'
            : 'A note is required and is recorded in the audit log.'}
        </p>
        <textarea value={note} onChange={e => setNote(e.target.value)} rows={4} autoFocus
          placeholder={hints[status]} className="input-field w-full text-sm" />
        <div className="flex justify-end gap-2 mt-4">
          <button onClick={onCancel} className="btn-secondary text-sm py-1.5">Cancel</button>
          <button disabled={note.trim().length < 3 || busy}
            onClick={async () => { setBusy(true); await onConfirm(note.trim()); setBusy(false) }}
            className="btn-primary text-sm py-1.5 disabled:opacity-40">
            {busy ? 'Saving…' : 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Detail drawer: everything needed to decide, without leaving the queue ──
function AlertDrawer({ eventId, canManage, assignees, onClose, onStatus, onAssign, onAdvisory, onNavigate, reloadKey }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    setError(null)
    client.get(`/events/${eventId}`)
      .then(r => { if (!cancelled) setData(r.data) })
      .catch(() => { if (!cancelled) setError('Could not load this alert.') })
    return () => { cancelled = true }
  }, [eventId, reloadKey])

  useEffect(() => {
    const onKey = (e) => {
      // Don't hijack typing in the note dialog or filters
      if (e.target.closest?.('input, textarea, select, [role="dialog"]')) return
      if (e.key === 'Escape') onClose()
      if (e.key === 'j' || e.key === 'ArrowDown') onNavigate(1)
      if (e.key === 'k' || e.key === 'ArrowUp') onNavigate(-1)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose, onNavigate])

  const e = data && data.event_id === eventId ? data : null
  const guide = e ? playbook({ ...e, asset_internet_facing: e.asset?.is_internet_facing }) : null
  const isOpen = e && (e.status === 'open' || e.status === 'in_progress')
  const d = e?.details ?? {}

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <aside className="relative w-full max-w-xl h-full overflow-y-auto bg-dark-900 border-l border-dark-700 shadow-2xl"
        onClick={ev => ev.stopPropagation()}>
        <div className="sticky top-0 z-10 bg-dark-900/95 backdrop-blur border-b border-dark-700 px-5 py-3 flex items-center gap-2">
          <button onClick={() => onNavigate(-1)} className="p-1 rounded hover:bg-dark-700 text-dark-400" title="Previous (k)"><ChevronLeft className="w-4 h-4" /></button>
          <button onClick={() => onNavigate(1)} className="p-1 rounded hover:bg-dark-700 text-dark-400" title="Next (j)"><ChevronRight className="w-4 h-4" /></button>
          <span className="text-xs text-dark-500 ml-1">j / k to move · Esc to close</span>
          <button onClick={onClose} className="ml-auto p-1 rounded hover:bg-dark-700 text-dark-400" aria-label="Close"><X className="w-5 h-5" /></button>
        </div>

        {error && <p className="p-5 text-accent-red text-sm">{error}</p>}
        {!e && !error && (
          <div className="flex justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        )}

        {e && (
          <div className="p-5 space-y-5">
            {/* Title */}
            <div>
              <div className="flex items-center gap-2 flex-wrap mb-2">
                <SevBadge sev={e.severity} />
                <StatusBadge status={e.status} />
                {e.asset?.is_internet_facing && (
                  <span className="text-xs px-2 py-0.5 rounded-full border border-amber-500/30 bg-amber-500/10 text-amber-400 inline-flex items-center gap-1">
                    <Globe className="w-3 h-3" />internet-facing{e.asset.internet_facing_confirmed ? '' : ' (inferred)'}
                  </span>
                )}
              </div>
              <h2 className="text-lg font-semibold text-white">{alertLabel(e)} — <span className="font-mono text-accent-cyan">{renderDetail(e)}</span></h2>
              <p className="text-xs text-dark-400 mt-1">
                First seen {new Date(e.first_seen).toLocaleString()} · last seen {timeAgo(e.last_seen)}
                {e.occurrences > 1 ? ` · detected ${e.occurrences}×` : ''}
              </p>
            </div>

            {/* Next step */}
            {guide && (
              <div className="rounded-lg border border-eagle-500/30 bg-eagle-500/5 p-3">
                <div className="flex items-center gap-2 text-sm font-semibold text-eagle-300 mb-1">
                  <Lightbulb className="w-4 h-4" /> Next step
                  <span className="ml-auto text-[11px] font-mono px-1.5 py-0.5 rounded bg-dark-800 text-dark-200">{guide.urgency}</span>
                </div>
                <p className="text-sm text-dark-200">{guide.text}</p>
              </div>
            )}

            {/* Actions */}
            {canManage && (
              <div className="flex items-center gap-2 flex-wrap">
                <AssignSelect assignees={assignees} value={e.assigned_to} onChange={onAssign} />
                {isOpen ? (
                  <>
                    {e.status === 'open' && <button onClick={() => onStatus('in_progress')} className="btn-secondary text-xs py-1.5 px-3">Start work</button>}
                    <button onClick={() => onStatus('resolved')} className="btn-primary text-xs py-1.5 px-3">Resolve</button>
                    <button onClick={() => onStatus('false_positive')} className="btn-secondary text-xs py-1.5 px-3">False positive</button>
                    <button onClick={() => onStatus('accepted_risk')} className="btn-secondary text-xs py-1.5 px-3">
                      {DRIFT_TYPES.has(e.event_type) ? 'Accept change' : 'Accept risk'}
                    </button>
                  </>
                ) : (
                  <button onClick={() => onStatus('open')} className="btn-secondary text-xs py-1.5 px-3">Reopen</button>
                )}
              </div>
            )}
            {e.resolution_note && (
              <p className="text-xs text-dark-300 bg-dark-800 rounded p-2"><span className="text-dark-500">Note: </span>{e.resolution_note}</p>
            )}

            {/* Evidence */}
            <Section icon={Shield} title="Evidence">
              <KV rows={[
                d.cve_id && ['CVE', <a href={`https://nvd.nist.gov/vuln/detail/${d.cve_id}`} target="_blank" rel="noreferrer" className="text-accent-cyan hover:underline">{d.cve_id}</a>],
                d.package_name && ['Package', `${d.package_name} ${d.package_version ?? ''}`],
                Array.isArray(d.fix_versions) && d.fix_versions.length > 0 && ['Fixed in', d.fix_versions.join(', ')],
                d.cvss_base_score != null && ['CVSS', d.cvss_base_score],
                d.epss_score != null && ['EPSS', `${(d.epss_score * 100).toFixed(1)}% chance of exploitation in 30 days`],
                e.composite_risk_score != null && ['Risk score', e.composite_risk_score],
                d.port != null && ['Port', `${d.port}/${d.protocol ?? 'tcp'}${RISKY_PORTS[d.port] ? ` — ${RISKY_PORTS[d.port]}` : ''}`],
                d.port != null && serviceOn(e.asset, d.port) && ['Service', serviceOn(e.asset, d.port)],
                d.from != null && ['Before', String(d.from)],
                d.to != null && ['After', String(d.to)],
                d.mac && ['MAC', d.mac],
                d.source && ['Detected by', d.source.replace('_', ' ')],
              ]} />
              {d.description && <p className="text-xs text-dark-400 mt-2 leading-relaxed">{d.description}</p>}
            </Section>

            {/* Asset */}
            {e.asset && (
              <Section icon={Server} title="Asset">
                <KV rows={[
                  ['Host', `${e.asset.hostname ?? '—'} (${e.asset.ip_address})`],
                  ['Type', <span className="capitalize">{e.asset.device_type}</span>],
                  ['Criticality', `${e.asset.criticality_score} / 10`],
                  e.asset.owner && ['Owner', e.asset.owner],
                  (e.asset.os_name || e.asset.os_version) && ['OS', `${e.asset.os_name ?? ''} ${e.asset.os_version ?? ''}`],
                  (e.asset.mac_address || e.asset.hardware_vendor) && ['Hardware', `${e.asset.hardware_vendor ?? 'Unknown vendor'} ${e.asset.mac_address ? `· ${e.asset.mac_address}` : ''}`],
                  e.asset.snmp_sysdescr && ['SNMP', `${String(e.asset.snmp_sysdescr).slice(0, 120)}${e.asset.snmp_interfaces ? ` · ${e.asset.snmp_interfaces} interfaces` : ''}`],
                  ['Open ports', e.asset.ports.length ? (
                    <span className="font-mono">{e.asset.ports.map(p => (
                      <span key={p} className={RISKY_PORTS[p] ? 'text-accent-amber' : ''}>{p}{RISKY_PORTS[p] ? `(${RISKY_PORTS[p]})` : ''} </span>
                    ))}</span>) : '—'],
                  ['Last scanned', e.asset.last_scanned ? `${timeAgo(e.asset.last_scanned)} (${e.asset.source?.replace('scan_', '')})` : 'never'],
                ]} />
              </Section>
            )}

            {/* Blast radius */}
            <Section icon={Link2} title={`Related assets (${e.related_assets.length})`}>
              {e.related_assets.length === 0
                ? <p className="text-xs text-dark-500">No mapped relationships. Check the topology view if this host is shared infrastructure.</p>
                : <ul className="space-y-1">{e.related_assets.map((r, i) => (
                    <li key={i} className="text-xs text-dark-300 flex items-center gap-2">
                      <span className="text-dark-500 w-16">{r.direction === 'outbound' ? '→' : '←'} {r.relationship.replace(/_/g, ' ')}</span>
                      <span>{r.hostname ?? r.ip}</span><span className="text-dark-500 capitalize">{r.device_type}</span>
                    </li>
                  ))}</ul>}
            </Section>

            {/* Threat intel */}
            {e.cti_indicators.length > 0 && (
              <Section icon={Crosshair} title="Threat intelligence">
                <ul className="space-y-1.5">{e.cti_indicators.map((i, n) => (
                  <li key={n} className="text-xs text-dark-300">
                    <span className="font-mono text-accent-red">{i.value}</span> <span className="text-dark-500">({i.type}, {i.source})</span>
                    {(i.tactic || i.technique) && <div className="text-dark-400">ATT&CK: {[i.tactic, i.technique].filter(Boolean).join(' / ')}</div>}
                  </li>
                ))}</ul>
              </Section>
            )}

            {/* Advisory */}
            <Section icon={Zap} title="AI advisory">
              {e.advisory ? (
                <div className="space-y-2">
                  <p className="text-sm text-dark-200">{e.advisory.summary}</p>
                  <p className="text-xs text-dark-300 whitespace-pre-line">{e.advisory.recommended_action}</p>
                  <Link to="/advisories" className="text-xs text-eagle-400 hover:underline">Open in Advisories →</Link>
                </div>
              ) : canManage ? (
                <button onClick={onAdvisory} className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1"><Zap className="w-3.5 h-3.5" /> Generate advisory</button>
              ) : <p className="text-xs text-dark-500">No advisory yet.</p>}
            </Section>

            {/* Audit trail */}
            {e.history.length > 0 && (
              <Section icon={History} title="Activity">
                <ul className="space-y-1.5">{e.history.map((h, i) => (
                  <li key={i} className="text-xs text-dark-400">
                    <span className="text-dark-200">{h.by ?? 'system'}</span> changed {h.previous?.status} → <span className="text-dark-200">{h.next?.status}</span>
                    {h.next?.note && <span className="text-dark-300"> — “{h.next.note}”</span>}
                    <span className="text-dark-500"> · {timeAgo(h.at)}</span>
                  </li>
                ))}</ul>
              </Section>
            )}
          </div>
        )}
      </aside>
    </div>
  )
}

function serviceOn(asset, port) {
  const s = asset?.services?.find(x => Number(x.port) === Number(port))
  if (!s) return null
  return [s.service, s.product, s.version].filter(Boolean).join(' ') || null
}

function Section({ icon: Icon, title, children }) {
  return (
    <section>
      <h3 className="text-xs uppercase tracking-wide text-dark-400 font-semibold flex items-center gap-1.5 mb-2">
        <Icon className="w-3.5 h-3.5" />{title}
      </h3>
      {children}
    </section>
  )
}

function KV({ rows }) {
  return (
    <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1 text-xs">
      {rows.filter(Boolean).map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-dark-500">{k}</dt>
          <dd className="text-dark-200 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  )
}
