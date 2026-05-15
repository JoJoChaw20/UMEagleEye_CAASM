import { useState, useEffect } from 'react'
import { Globe, RefreshCw, Shield } from 'lucide-react'
import { BarChart, Bar, Cell, ResponsiveContainer, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts'
import client from '../api/client'

const MITRE_TACTICS = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control",
  "Exfiltration", "Impact"
]

const TACTIC_COLORS = [
  '#ff5252', '#ff6e40', '#ff9800', '#ffc400', '#ffea00', '#c6ff00',
  '#69f0ae', '#00e5ff', '#448aff', '#7c4dff', '#e040fb', '#ff4081',
  '#ff5252', '#ff6e40'
]

export default function ThreatIntelPage() {
  const [indicators, setIndicators] = useState([])
  const [matrix, setMatrix] = useState({})
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [ingesting, setIngesting] = useState(false)
  const [tab, setTab] = useState('indicators') // indicators | matrix

  useEffect(() => { loadData() }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      const [indRes, matrixRes, statsRes] = await Promise.all([
        client.get('/cti/indicators', { params: { limit: 100 } }),
        client.get('/cti/matrix'),
        client.get('/cti/stats'),
      ])
      setIndicators(indRes.data.items || [])
      setMatrix(matrixRes.data.matrix || {})
      setStats(statsRes.data)
    } catch (err) { console.error(err) }
    finally { setLoading(false) }
  }

  const triggerIngestion = async () => {
    setIngesting(true)
    try {
      await client.post('/cti/ingest')
      setTimeout(() => { loadData(); setIngesting(false) }, 10000)
    } catch { setIngesting(false) }
  }

  // Build chart data from matrix
  const matrixChartData = MITRE_TACTICS.map((tactic, i) => ({
    tactic: tactic.split(' ').slice(0, 2).join(' '),
    count: (matrix[tactic] || []).reduce((sum, t) => sum + t.count, 0),
    fill: TACTIC_COLORS[i],
  })).filter(d => d.count > 0)

  const typeIcons = { ip: '🌐', domain: '🔗', url: '📎', hash: '🔐', email: '📧' }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Intelligence</h1>
          <p className="text-dark-400 text-sm mt-1">
            {stats?.total_indicators || 0} indicators from {Object.keys(stats?.by_source || {}).length} sources
          </p>
        </div>
        <button onClick={triggerIngestion} disabled={ingesting} className="btn-primary flex items-center gap-2">
          {ingesting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />}
          {ingesting ? 'Ingesting...' : 'Ingest Feeds'}
        </button>
      </div>

      {/* Source stats cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Object.entries(stats.by_source || {}).map(([source, count]) => (
            <div key={source} className="stat-card">
              <p className="text-dark-400 text-xs mb-1">{source}</p>
              <p className="text-2xl font-bold text-white">{count}</p>
            </div>
          ))}
          {Object.entries(stats.by_type || {}).map(([type, count]) => (
            <div key={type} className="stat-card">
              <p className="text-dark-400 text-xs mb-1">{typeIcons[type] || '❓'} {type}</p>
              <p className="text-2xl font-bold text-white">{count}</p>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 bg-dark-800 rounded-lg p-1 w-fit">
        {['indicators', 'matrix'].map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              tab === t ? 'bg-eagle-600 text-white' : 'text-dark-400 hover:text-white'
            }`}>
            {t === 'indicators' ? 'IoC Feed' : 'MITRE ATT&CK'}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-20"><div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" /></div>
      ) : tab === 'indicators' ? (
        <div className="glass-card overflow-hidden">
          {indicators.length > 0 ? (
            <table className="data-table">
              <thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Confidence</th><th>ATT&CK Tactic</th><th>Technique</th><th>Last Seen</th></tr></thead>
              <tbody>
                {indicators.map(ind => (
                  <tr key={ind.indicator_id}>
                    <td>{typeIcons[ind.indicator_type] || '❓'} <span className="text-xs">{ind.indicator_type}</span></td>
                    <td className="font-mono text-xs text-accent-cyan max-w-xs truncate">{ind.value}</td>
                    <td className="text-dark-300 text-xs">{ind.source}</td>
                    <td>
                      <div className="flex items-center gap-1.5">
                        <div className="w-12 h-1.5 bg-dark-700 rounded-full overflow-hidden">
                          <div className="h-full rounded-full bg-eagle-500" style={{ width: `${(ind.confidence_score || 0) * 100}%` }} />
                        </div>
                        <span className="text-xs text-dark-400">{((ind.confidence_score || 0) * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="text-dark-300 text-xs">{ind.attack_tactic || '—'}</td>
                    <td className="font-mono text-xs text-accent-purple">{ind.attack_technique || '—'}</td>
                    <td className="text-dark-400 text-xs">{new Date(ind.last_seen).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="text-center py-20 text-dark-400">
              <Globe className="w-16 h-16 mx-auto mb-4 opacity-20" />
              <p>No threat indicators yet. Click "Ingest Feeds" to pull from OTX & ThreatFox.</p>
            </div>
          )}
        </div>
      ) : (
        /* MITRE ATT&CK Matrix View */
        <div className="space-y-4">
          {matrixChartData.length > 0 && (
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-dark-200 mb-4">Technique Coverage by Tactic</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={matrixChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2028" />
                  <XAxis dataKey="tactic" tick={{ fill: '#7b7f87', fontSize: 10 }} angle={-30} textAnchor="end" height={80} />
                  <YAxis tick={{ fill: '#7b7f87', fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: '#1e2028', border: '1px solid #3e4047', borderRadius: '8px', color: '#e2e3e5' }} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {matrixChartData.map((entry, idx) => (
                      <Cell key={idx} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          <div className="glass-card p-5">
            <h3 className="text-sm font-semibold text-dark-200 mb-4">ATT&CK Tactic Matrix</h3>
            <div className="grid grid-cols-7 gap-2">
              {MITRE_TACTICS.map((tactic, i) => {
                const techniques = matrix[tactic] || []
                return (
                  <div key={tactic} className="text-center">
                    <div className="text-[9px] font-semibold text-dark-300 mb-1 h-8 flex items-center justify-center">{tactic}</div>
                    {techniques.length > 0 ? techniques.map(t => (
                      <div key={t.technique_id} className="mb-1 px-1 py-1 rounded text-[10px] font-mono" style={{ background: TACTIC_COLORS[i] + '30', color: TACTIC_COLORS[i], border: `1px solid ${TACTIC_COLORS[i]}40` }}>
                        {t.technique_id} ({t.count})
                      </div>
                    )) : (
                      <div className="text-[10px] text-dark-600 py-1">—</div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
