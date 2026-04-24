import { useState, useEffect } from 'react'
import { Shield, Server, AlertTriangle, Activity, TrendingUp, Bug } from 'lucide-react'
import { AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, ResponsiveContainer, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts'
import client from '../api/client'

const SEVERITY_COLORS = {
  critical: '#ff5252',
  high: '#ff9800',
  medium: '#ffc400',
  low: '#00e676',
}

export default function DashboardPage() {
  const [posture, setPosture] = useState(null)
  const [history, setHistory] = useState([])
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadDashboardData()
  }, [])

  const loadDashboardData = async () => {
    try {
      const [postureRes, historyRes, eventsRes] = await Promise.all([
        client.get('/posture/current'),
        client.get('/posture/history?limit=30'),
        client.get('/events?page_size=10'),
      ])
      setPosture(postureRes.data)
      setHistory(historyRes.data.items || [])
      setEvents(eventsRes.data.items || [])
    } catch (err) {
      console.error('Dashboard load error:', err)
    } finally {
      setLoading(false)
    }
  }

  const score = posture?.overall_score ?? 100
  const scoreColor = score >= 80 ? '#00e676' : score >= 50 ? '#ffc400' : '#ff5252'

  // Mock data for charts when no data is available
  const trendData = history.length > 0 ? history.map((h, i) => ({
    day: `Day ${i + 1}`,
    score: h.overall_score,
    assets: h.total_assets,
  })) : Array.from({ length: 14 }, (_, i) => ({
    day: `Day ${i + 1}`,
    score: Math.floor(70 + Math.random() * 25),
    assets: Math.floor(10 + Math.random() * 40),
  }))

  const severityData = [
    { name: 'Critical', value: events.filter(e => e.severity === 'critical').length || 2, color: SEVERITY_COLORS.critical },
    { name: 'High', value: events.filter(e => e.severity === 'high').length || 5, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: events.filter(e => e.severity === 'medium').length || 8, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: events.filter(e => e.severity === 'low').length || 12, color: SEVERITY_COLORS.low },
  ]

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Posture Dashboard</h1>
          <p className="text-dark-400 text-sm mt-1">Real-time attack surface overview</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-accent-green animate-pulse" />
          <span className="text-xs text-dark-400">Live Monitoring Active</span>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="flex items-center justify-between mb-3">
            <span className="text-dark-400 text-sm">Posture Score</span>
            <div className="w-8 h-8 rounded-lg bg-eagle-500/20 flex items-center justify-center">
              <Shield className="w-4 h-4 text-eagle-400" />
            </div>
          </div>
          <p className="text-3xl font-bold" style={{ color: scoreColor }}>{score}</p>
          <p className="text-xs text-dark-400 mt-1">out of 100</p>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between mb-3">
            <span className="text-dark-400 text-sm">Total Assets</span>
            <div className="w-8 h-8 rounded-lg bg-accent-cyan/20 flex items-center justify-center">
              <Server className="w-4 h-4 text-accent-cyan" />
            </div>
          </div>
          <p className="text-3xl font-bold text-white">{posture?.total_assets ?? 0}</p>
          <p className="text-xs text-dark-400 mt-1">discovered devices</p>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between mb-3">
            <span className="text-dark-400 text-sm">Active Alerts</span>
            <div className="w-8 h-8 rounded-lg bg-accent-red/20 flex items-center justify-center">
              <AlertTriangle className="w-4 h-4 text-accent-red" />
            </div>
          </div>
          <p className="text-3xl font-bold text-accent-red">{posture?.open_critical_events ?? 0}</p>
          <p className="text-xs text-dark-400 mt-1">unresolved critical/high</p>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between mb-3">
            <span className="text-dark-400 text-sm">Critical Assets</span>
            <div className="w-8 h-8 rounded-lg bg-accent-amber/20 flex items-center justify-center">
              <Activity className="w-4 h-4 text-accent-amber" />
            </div>
          </div>
          <p className="text-3xl font-bold text-accent-amber">{posture?.total_critical_assets ?? 0}</p>
          <p className="text-xs text-dark-400 mt-1">criticality ≥ 8</p>
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Posture trend */}
        <div className="glass-card p-5 lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-dark-200 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-eagle-400" />
              Posture Score Trend
            </h3>
            <span className="text-xs text-dark-400">Last 14 days</span>
          </div>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={trendData}>
              <defs>
                <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3393ff" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3393ff" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2028" />
              <XAxis dataKey="day" tick={{ fill: '#7b7f87', fontSize: 11 }} axisLine={{ stroke: '#1e2028' }} />
              <YAxis domain={[0, 100]} tick={{ fill: '#7b7f87', fontSize: 11 }} axisLine={{ stroke: '#1e2028' }} />
              <Tooltip
                contentStyle={{ background: '#1e2028', border: '1px solid #3e4047', borderRadius: '8px', color: '#e2e3e5' }}
              />
              <Area type="monotone" dataKey="score" stroke="#3393ff" fill="url(#scoreGradient)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Threat distribution */}
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-dark-200 flex items-center gap-2 mb-4">
            <Bug className="w-4 h-4 text-accent-red" />
            Threat Distribution
          </h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={85}
                paddingAngle={4}
                dataKey="value"
              >
                {severityData.map((entry, idx) => (
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
      </div>

      {/* Recent events */}
      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-dark-200 mb-4">Recent Security Events</h3>
        {events.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Severity</th>
                <th>Asset</th>
                <th>Risk Score</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {events.slice(0, 8).map((event) => (
                <tr key={event.event_id}>
                  <td className="font-mono text-xs">{event.event_type}</td>
                  <td>
                    <span className={`badge-${event.severity}`}>{event.severity}</span>
                  </td>
                  <td className="text-dark-300 text-xs">{event.asset_id?.slice(0, 8)}...</td>
                  <td className="font-mono">{event.composite_risk_score ?? '—'}</td>
                  <td className="text-dark-400 text-xs">{new Date(event.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-12 text-dark-400">
            <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p>No events yet. Run your first scan to populate data.</p>
          </div>
        )}
      </div>
    </div>
  )
}
