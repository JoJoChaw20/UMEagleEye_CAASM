import { useState, useEffect } from 'react'
import { Bell, Shield, AlertTriangle, TrendingUp, Zap, Filter, RefreshCw, Activity } from 'lucide-react'
import { PieChart, Pie, Cell, AreaChart, Area, BarChart, Bar, ResponsiveContainer, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts'
import client from '../api/client'

const SEVERITY_COLORS = {
  critical: '#ff5252',
  high: '#ff9800',
  medium: '#ffc400',
  low: '#00e676',
}

const EVENT_TYPE_LABELS = {
  cve_detected: 'CVE Detected',
  cti_match: 'Threat Intel Match',
  port_opened: 'Port Opened',
  port_closed: 'Port Closed',
  version_downgrade: 'Version Downgrade',
  version_upgrade: 'Version Upgrade',
  config_change: 'Config Change',
  new_package: 'New Package',
  removed_package: 'Removed Package',
  new_device: 'New Device',
}

export default function AlertsPage() {
  const [events, setEvents] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [severityFilter, setSeverityFilter] = useState('')
  const [typeFilter, setTypeFilter] = useState('')

  useEffect(() => { loadData() }, [page, severityFilter, typeFilter])

  const loadData = async () => {
    setLoading(true)
    try {
      const params = { page, page_size: 15 }
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
  }

  const triggerAdvisory = async (eventId) => {
    try {
      await client.post(`/events/${eventId}/advisory`)
      alert('AI Advisory generation queued. Check Advisories page in a moment.')
    } catch (err) {
      console.error(err)
      alert('Failed to trigger advisory generation.')
    }
  }

  const triggerDriftAudit = async () => {
    try {
      await client.post('/scans/drift-audit')
      alert('Drift audit triggered.')
      setTimeout(loadData, 2000)
    } catch { alert('Failed to trigger drift audit.') }
  }

  // Chart data
  const severityData = stats ? [
    { name: 'Critical', value: stats.by_severity?.critical || 0, color: SEVERITY_COLORS.critical },
    { name: 'High', value: stats.by_severity?.high || 0, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: stats.by_severity?.medium || 0, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: stats.by_severity?.low || 0, color: SEVERITY_COLORS.low },
  ] : []

  const trendData = stats?.daily_trend || []

  const typeData = stats ? Object.entries(stats.by_type || {}).map(([key, value]) => ({
    name: key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
    count: value,
  })) : []

  const totalPages = Math.ceil(total / 15)

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Alerts</h1>
          <p className="text-dark-400 text-sm mt-1">Unified view of all security events, vulnerabilities, and drift alerts</p>
        </div>
        <div className="flex gap-2">
          <button onClick={triggerDriftAudit} className="btn-secondary flex items-center gap-2 text-sm">
            <RefreshCw className="w-4 h-4" />
            Run Drift Audit
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="flex items-center justify-between mb-3">
            <span className="text-dark-400 text-sm">Total Alerts</span>
            <div className="w-8 h-8 rounded-lg bg-eagle-500/20 flex items-center justify-center">
              <Bell className="w-4 h-4 text-eagle-400" />
            </div>
          </div>
          <p className="text-3xl font-bold text-white">{stats?.total_alerts ?? 0}</p>
          <p className="text-xs text-dark-400 mt-1">all events</p>
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

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Severity breakdown */}
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-dark-200 flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-accent-red" />
            Severity Breakdown
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={severityData.filter(d => d.value > 0)}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={75}
                paddingAngle={4}
                dataKey="value"
              >
                {severityData.filter(d => d.value > 0).map((entry, idx) => (
                  <Cell key={idx} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#1e2028', border: '1px solid #3e4047', borderRadius: '8px', color: '#e2e3e5' }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-wrap justify-center gap-3 mt-2">
            {severityData.map((s) => (
              <div key={s.name} className="flex items-center gap-1.5 text-xs text-dark-300">
                <span className="w-2.5 h-2.5 rounded-full" style={{ background: s.color }} />
                {s.name}: {s.value}
              </div>
            ))}
          </div>
        </div>

        {/* Alerts over time */}
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-dark-200 flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-eagle-400" />
            Alerts Over Time
          </h3>
          <ResponsiveContainer width="100%" height={230}>
            <AreaChart data={trendData}>
              <defs>
                <linearGradient id="alertGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3393ff" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3393ff" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2028" />
              <XAxis dataKey="date" tick={{ fill: '#7b7f87', fontSize: 11 }} axisLine={{ stroke: '#1e2028' }} />
              <YAxis tick={{ fill: '#7b7f87', fontSize: 11 }} axisLine={{ stroke: '#1e2028' }} />
              <Tooltip
                contentStyle={{ background: '#1e2028', border: '1px solid #3e4047', borderRadius: '8px', color: '#e2e3e5' }}
              />
              <Area type="monotone" dataKey="count" stroke="#3393ff" fill="url(#alertGradient)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Alert types */}
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
              <Tooltip
                contentStyle={{ background: '#1e2028', border: '1px solid #3e4047', borderRadius: '8px', color: '#e2e3e5' }}
              />
              <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <select
          value={severityFilter}
          onChange={(e) => { setSeverityFilter(e.target.value); setPage(1) }}
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
          onChange={(e) => { setTypeFilter(e.target.value); setPage(1) }}
          className="input-field text-sm py-1.5 w-48"
          id="type-filter"
        >
          <option value="">All Types</option>
          <option value="cve_detected">CVE Detected</option>
          <option value="cti_match">CTI Match</option>
          <option value="port_opened">Port Opened</option>
          <option value="port_closed">Port Closed</option>
          <option value="version_downgrade">Version Downgrade</option>
          <option value="config_change">Config Change</option>
          <option value="new_package">New Package</option>
          <option value="new_device">New Device</option>
        </select>

        <span className="text-dark-400 text-sm ml-auto">{total} total alerts</span>
      </div>

      {/* Events table */}
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
                <th>Package / Asset</th>
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
                  <td><span className={`badge-${e.severity}`}>{e.severity}</span></td>
                  <td className="text-dark-300 text-xs">{EVENT_TYPE_LABELS[e.event_type] || e.event_type}</td>
                  <td className="font-mono text-sm text-accent-cyan">
                    {e.details?.cve_id || e.details?.indicator_value || e.details?.changed_attribute || '—'}
                  </td>
                  <td className="text-dark-300 text-sm">
                    {e.details?.package_name
                      ? `${e.details.package_name} ${e.details.package_version || ''}`
                      : e.asset_id?.slice(0, 8) + '...'}
                  </td>
                  <td className="font-mono text-sm">{e.details?.cvss_base_score ?? '—'}</td>
                  <td className="font-mono text-sm">
                    {e.details?.epss_score != null
                      ? `${(e.details.epss_score * 100).toFixed(1)}%`
                      : '—'}
                  </td>
                  <td className="font-mono text-sm font-semibold">
                    <span style={{
                      color: (e.composite_risk_score ?? 0) >= 50 ? '#ff5252'
                        : (e.composite_risk_score ?? 0) >= 25 ? '#ffc400'
                        : '#00e676'
                    }}>
                      {e.composite_risk_score ?? '—'}
                    </span>
                  </td>
                  <td className="text-dark-400 text-xs">{new Date(e.timestamp).toLocaleString()}</td>
                  <td>
                    <button
                      onClick={() => triggerAdvisory(e.event_id)}
                      className="p-1.5 hover:bg-eagle-500/10 rounded text-eagle-400 transition-colors"
                      title="Generate AI Advisory"
                    >
                      <Zap className="w-4 h-4" />
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
            <p className="text-sm">Generate SBOMs or run drift audits to start detecting security events.</p>
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
    </div>
  )
}
