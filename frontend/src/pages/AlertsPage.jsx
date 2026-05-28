import { useState, useEffect, useCallback } from 'react'
import {
  Bell, Shield, AlertTriangle, TrendingUp, Zap, Filter,
  RefreshCw, Activity, CheckCircle2, Server, ExternalLink,
} from 'lucide-react'
import {
  PieChart, Pie, Cell, AreaChart, Area, BarChart, Bar,
  ResponsiveContainer, XAxis, YAxis, CartesianGrid, Tooltip,
} from 'recharts'
import client from '../api/client'

// ── Colour maps ───────────────────────────────────────────────
const SEVERITY_COLORS = {
  critical: '#ff5252',
  high:     '#ff9800',
  medium:   '#ffc400',
  low:      '#00e676',
}

const EVENT_TYPE_LABELS = {
  cve_detected:    'CVE Detected',
  cti_match:       'Threat Intel Match',
  port_opened:     'Port Opened',
  port_closed:     'Port Closed',
  version_downgrade: 'Version Downgrade',
  version_upgrade: 'Version Upgrade',
  config_change:   'Config Change',
  new_package:     'New Package',
  removed_package: 'Removed Package',
  new_device:      'New Device',
}

// ── Severity badge ────────────────────────────────────────────
function SevBadge({ sev }) {
  const cls = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high:     'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low:      'bg-green-500/20 text-green-400 border-green-500/30',
  }[sev] ?? 'bg-dark-700 text-dark-300 border-dark-600'
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-semibold uppercase tracking-wide ${cls}`}>
      {sev}
    </span>
  )
}

// ── Toast-style feedback (simple inline) ──────────────────────
function useToast() {
  const [toast, setToast] = useState(null)
  const show = (msg, type = 'success') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3500)
  }
  return { toast, show }
}

export default function AlertsPage() {
  const [events,          setEvents]          = useState([])
  const [stats,           setStats]           = useState(null)
  const [loading,         setLoading]         = useState(true)
  const [total,           setTotal]           = useState(0)
  const [page,            setPage]            = useState(1)
  const [severityFilter,  setSeverityFilter]  = useState('')
  const [typeFilter,      setTypeFilter]      = useState('')
  const [advisoryLoading, setAdvisoryLoading] = useState({}) // eventId → bool
  const { toast, show: showToast } = useToast()

  const PAGE_SIZE = 15

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, page_size: PAGE_SIZE }
      if (severityFilter) params.severity = severityFilter
      if (typeFilter) params.event_type = typeFilter

      const [eventsRes, statsRes] = await Promise.all([
        client.get('/events', { params }),
        client.get('/events/stats/summary'),
      ])

      setEvents(eventsRes.data.items || [])
      setTotal(eventsRes.data.total || 0)
      setStats(statsRes.data)
    } catch (err) {
      console.error('Alerts load error:', err)
    } finally {
      setLoading(false)
    }
  }, [page, severityFilter, typeFilter])

  useEffect(() => { loadData() }, [loadData])

  // ── Actions ──────────────────────────────────────────────────
  const triggerAdvisory = async (eventId) => {
    setAdvisoryLoading(s => ({ ...s, [eventId]: true }))
    try {
      await client.post(`/events/${eventId}/advisory`)
      showToast('AI Advisory generation queued — check Advisories page shortly.', 'success')
    } catch {
      showToast('Failed to trigger advisory generation.', 'error')
    } finally {
      setAdvisoryLoading(s => ({ ...s, [eventId]: false }))
    }
  }

  const triggerDriftAudit = async () => {
    try {
      await client.post('/scans/drift-audit')
      showToast('Drift audit triggered.', 'success')
      setTimeout(loadData, 2000)
    } catch {
      showToast('Failed to trigger drift audit.', 'error')
    }
  }

  // ── Chart data ───────────────────────────────────────────────
  const severityData = stats ? [
    { name: 'Critical', value: stats.by_severity?.critical || 0, color: SEVERITY_COLORS.critical },
    { name: 'High',     value: stats.by_severity?.high     || 0, color: SEVERITY_COLORS.high },
    { name: 'Medium',   value: stats.by_severity?.medium   || 0, color: SEVERITY_COLORS.medium },
    { name: 'Low',      value: stats.by_severity?.low      || 0, color: SEVERITY_COLORS.low },
  ] : []

  const trendData = stats?.daily_trend || []

  const typeData = stats
    ? Object.entries(stats.by_type || {}).map(([key, value]) => ({
        name: EVENT_TYPE_LABELS[key] || key.replace(/_/g, ' '),
        count: value,
      }))
    : []

  const totalPages = Math.ceil(total / PAGE_SIZE)

  // ── Render ───────────────────────────────────────────────────
  return (
    <div className="space-y-6">

      {/* ── Toast ── */}
      {toast && (
        <div className={`fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-3 rounded-lg shadow-lg text-sm font-medium transition-all
          ${toast.type === 'success'
            ? 'bg-green-900/90 text-green-200 border border-green-700'
            : 'bg-red-900/90 text-red-200 border border-red-700'}`}>
          {toast.type === 'success'
            ? <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
            : <AlertTriangle className="w-4 h-4 flex-shrink-0" />}
          {toast.msg}
        </div>
      )}

      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Alerts</h1>
          <p className="text-dark-400 text-sm mt-1">
            Unified view of CVE detections, drift events, and CTI matches
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={triggerDriftAudit}
            className="btn-secondary flex items-center gap-2 text-sm"
          >
            <RefreshCw className="w-4 h-4" />
            Run Drift Audit
          </button>
        </div>
      </div>

      {/* ── Summary cards ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="flex items-center justify-between mb-3">
            <span className="text-dark-400 text-sm">Total Alerts</span>
            <div className="w-8 h-8 rounded-lg bg-eagle-500/20 flex items-center justify-center">
              <Bell className="w-4 h-4 text-eagle-400" />
            </div>
          </div>
          <p className="text-3xl font-bold text-white">{stats?.total_alerts ?? 0}</p>
          <p className="text-xs text-dark-400 mt-1">all security events</p>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between mb-3">
            <span className="text-dark-400 text-sm">Critical</span>
            <div className="w-8 h-8 rounded-lg bg-accent-red/20 flex items-center justify-center">
              <AlertTriangle className="w-4 h-4 text-accent-red" />
            </div>
          </div>
          <p className="text-3xl font-bold text-accent-red">{stats?.by_severity?.critical ?? 0}</p>
          <p className="text-xs text-dark-400 mt-1">requires immediate action</p>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between mb-3">
            <span className="text-dark-400 text-sm">Resolution Rate</span>
            <div className="w-8 h-8 rounded-lg bg-accent-green/20 flex items-center justify-center">
              <Shield className="w-4 h-4 text-accent-green" />
            </div>
          </div>
          <p className="text-3xl font-bold text-accent-green">{stats?.resolution_rate ?? 100}%</p>
          <p className="text-xs text-dark-400 mt-1">advisories resolved</p>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between mb-3">
            <span className="text-dark-400 text-sm">Avg Risk Score</span>
            <div className="w-8 h-8 rounded-lg bg-accent-amber/20 flex items-center justify-center">
              <Activity className="w-4 h-4 text-accent-amber" />
            </div>
          </div>
          <p className="text-3xl font-bold text-accent-amber">{stats?.avg_risk_score ?? 0}</p>
          <p className="text-xs text-dark-400 mt-1">EPSS-weighted composite</p>
        </div>
      </div>

      {/* ── Charts ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Severity donut */}
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-dark-200 flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-accent-red" />
            Severity Breakdown
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={severityData.filter(d => d.value > 0)}
                cx="50%" cy="50%"
                innerRadius={50} outerRadius={75}
                paddingAngle={4}
                dataKey="value"
              >
                {severityData.filter(d => d.value > 0).map((entry, idx) => (
                  <Cell key={idx} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: 'rgb(var(--dark-700))', border: '1px solid rgb(var(--dark-500))', borderRadius: '8px', color: 'rgb(var(--dark-100))', boxShadow: '0 8px 24px rgba(0,0,0,0.3)' }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-wrap justify-center gap-3 mt-2">
            {severityData.map(s => (
              <div key={s.name} className="flex items-center gap-1.5 text-xs text-dark-300">
                <span className="w-2.5 h-2.5 rounded-full" style={{ background: s.color }} />
                {s.name}: {s.value}
              </div>
            ))}
          </div>
        </div>

        {/* Trend area chart */}
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-dark-200 flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-eagle-400" />
            Alerts Over Time (7d)
          </h3>
          <ResponsiveContainer width="100%" height={230}>
            <AreaChart data={trendData}>
              <defs>
                <linearGradient id="alertGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#3393ff" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3393ff" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2028" />
              <XAxis dataKey="date" tick={{ fill: '#7b7f87', fontSize: 11 }} axisLine={{ stroke: '#1e2028' }} />
              <YAxis tick={{ fill: '#7b7f87', fontSize: 11 }} axisLine={{ stroke: '#1e2028' }} />
              <Tooltip contentStyle={{ background: 'rgb(var(--dark-700))', border: '1px solid rgb(var(--dark-500))', borderRadius: '8px', color: 'rgb(var(--dark-100))', boxShadow: '0 8px 24px rgba(0,0,0,0.3)' }} />
              <Area type="monotone" dataKey="count" stroke="#3393ff" fill="url(#alertGradient)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Alert type bar chart */}
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-dark-200 flex items-center gap-2 mb-4">
            <Filter className="w-4 h-4 text-accent-cyan" />
            Alert Types
          </h3>
          <ResponsiveContainer width="100%" height={230}>
            <BarChart data={typeData} layout="vertical" margin={{ left: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2028" />
              <XAxis type="number" tick={{ fill: '#7b7f87', fontSize: 11 }} axisLine={{ stroke: '#1e2028' }} />
              <YAxis dataKey="name" type="category" tick={{ fill: '#7b7f87', fontSize: 10 }} axisLine={{ stroke: '#1e2028' }} width={110} />
              <Tooltip contentStyle={{ background: 'rgb(var(--dark-700))', border: '1px solid rgb(var(--dark-500))', borderRadius: '8px', color: 'rgb(var(--dark-100))', boxShadow: '0 8px 24px rgba(0,0,0,0.3)' }} />
              <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Filters ── */}
      <div className="flex items-center gap-3 flex-wrap">
        <select
          value={severityFilter}
          onChange={e => { setSeverityFilter(e.target.value); setPage(1) }}
          className="input-field text-sm py-1.5 w-40"
          id="severity-filter"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <select
          value={typeFilter}
          onChange={e => { setTypeFilter(e.target.value); setPage(1) }}
          className="input-field text-sm py-1.5 w-48"
          id="type-filter"
        >
          <option value="">All Types</option>
          {Object.entries(EVENT_TYPE_LABELS).map(([v, l]) => (
            <option key={v} value={v}>{l}</option>
          ))}
        </select>

        <button
          onClick={() => { setSeverityFilter(''); setTypeFilter(''); setPage(1) }}
          className="text-xs text-dark-400 hover:text-dark-200 underline underline-offset-2"
        >
          Clear filters
        </button>

        <span className="text-dark-400 text-sm ml-auto">{total} total alerts</span>
      </div>

      {/* ── Events table ── */}
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : events.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Type</th>
                <th>Detail</th>
                <th>Asset</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>Risk Score</th>
                <th>Time</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {events.map(e => (
                <tr key={e.event_id}>
                  <td><SevBadge sev={e.severity} /></td>

                  <td className="text-dark-300 text-xs">
                    {EVENT_TYPE_LABELS[e.event_type] || e.event_type}
                  </td>

                  <td className="font-mono text-sm text-accent-cyan max-w-xs">
                    {e.details?.cve_id
                      ? <a
                          href={`https://nvd.nist.gov/vuln/detail/${e.details.cve_id}`}
                          target="_blank"
                          rel="noreferrer"
                          onClick={ev => ev.stopPropagation()}
                          className="hover:text-eagle-300 flex items-center gap-1 group"
                          title="View on NVD"
                        >
                          {e.details.cve_id}
                          <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-70 transition-opacity" />
                        </a>
                      : e.details?.indicator_value
                        || e.details?.changed_attribute
                        || '—'}
                  </td>

                  {/* Asset: prefer hostname, fall back to IP, then UUID */}
                  <td>
                    <div className="flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5 text-dark-400 flex-shrink-0" />
                      <div>
                        {e.asset_hostname
                          ? <span className="text-sm text-dark-200">{e.asset_hostname}</span>
                          : e.asset_ip
                            ? <span className="font-mono text-xs text-accent-cyan">{e.asset_ip}</span>
                            : <span className="font-mono text-xs text-dark-500">
                                {e.asset_id?.slice(0, 8)}…
                              </span>}
                        {e.asset_hostname && e.asset_ip && (
                          <p className="font-mono text-xs text-dark-500">{e.asset_ip}</p>
                        )}
                        {/* Package info below asset */}
                        {e.details?.package_name && (
                          <p className="text-xs text-dark-400 mt-0.5">
                            {e.details.package_name}
                            {e.details.package_version && ` ${e.details.package_version}`}
                          </p>
                        )}
                      </div>
                    </div>
                  </td>

                  <td className="font-mono text-sm">
                    {e.details?.cvss_base_score != null
                      ? <span style={{ color: e.details.cvss_base_score >= 9 ? '#ff5252' : e.details.cvss_base_score >= 7 ? '#ff9800' : e.details.cvss_base_score >= 4 ? '#ffc400' : '#00e676' }}>
                          {e.details.cvss_base_score}
                        </span>
                      : '—'}
                  </td>

                  <td className="font-mono text-sm">
                    {e.details?.epss_score != null
                      ? `${(e.details.epss_score * 100).toFixed(1)}%`
                      : '—'}
                  </td>

                  <td className="font-mono text-sm font-semibold">
                    <span style={{
                      color: (e.composite_risk_score ?? 0) >= 50 ? '#ff5252'
                           : (e.composite_risk_score ?? 0) >= 25 ? '#ffc400'
                           : '#00e676',
                    }}>
                      {e.composite_risk_score ?? '—'}
                    </span>
                  </td>

                  <td className="text-dark-400 text-xs whitespace-nowrap">
                    {new Date(e.timestamp).toLocaleString()}
                  </td>

                  <td>
                    <button
                      onClick={() => triggerAdvisory(e.event_id)}
                      disabled={advisoryLoading[e.event_id]}
                      className="p-1.5 hover:bg-eagle-500/10 rounded text-eagle-400 transition-colors disabled:opacity-40"
                      title="Generate AI Advisory"
                    >
                      {advisoryLoading[e.event_id]
                        ? <RefreshCw className="w-4 h-4 animate-spin" />
                        : <Zap className="w-4 h-4" />}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <Bell className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium mb-2">No alerts detected</p>
            <p className="text-sm">
              Generate SBOMs or run drift audits to start detecting security events.
            </p>
          </div>
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
    </div>
  )
}
