import { useState, useEffect, useCallback, useRef } from 'react'
import { Search, Plus, RefreshCw, X, ChevronRight, Wifi, Server, Globe } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

// ── Status badge ──────────────────────────────────────────────────
function StatusBadge({ status }) {
  const map = {
    pending: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    running: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    completed: 'bg-green-500/20 text-green-400 border-green-500/30',
    failed: 'bg-red-500/20 text-red-400 border-red-500/30',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium capitalize ${map[status] || 'bg-dark-600/40 text-dark-400 border-dark-500/30'}`}>
      {status}
    </span>
  )
}

// ── Relative time helper ──────────────────────────────────────────
function relativeTime(ts) {
  if (!ts) return '—'
  const diff = Date.now() - new Date(ts).getTime()
  const min = Math.floor(diff / 60000)
  if (min < 1) return 'just now'
  if (min < 60) return `${min}m ago`
  const h = Math.floor(min / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

// ── New Scan Modal ────────────────────────────────────────────────
function NewScanModal({ onClose, onSubmit, agents }) {
  const [subnet, setSubnet] = useState(import.meta.env.VITE_SCAN_DEFAULT_SUBNET || '192.168.1.0/24')
  const [agentId, setAgentId] = useState('')
  const [scanType, setScanType] = useState('active')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      await onSubmit({ subnet, agent_id: agentId || undefined, scan_type: scanType })
      onClose()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to start scan')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="glass-card w-full max-w-md p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">New Scan</h2>
          <button onClick={onClose} className="text-dark-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs text-dark-400 mb-1">Target Subnet</label>
            <input
              type="text"
              value={subnet}
              onChange={(e) => setSubnet(e.target.value)}
              placeholder="192.168.1.0/24"
              className="input-field w-full text-sm"
              required
            />
          </div>

          <div>
            <label className="block text-xs text-dark-400 mb-1">Agent</label>
            <select value={agentId} onChange={(e) => setAgentId(e.target.value)} className="input-field w-full text-sm">
              <option value="">Auto-select</option>
              {agents.map((a) => (
                <option key={a.agent_id} value={a.agent_id}>{a.name} ({a.status})</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs text-dark-400 mb-2">Scan Type</label>
            <div className="flex gap-3">
              {['active', 'passive'].map((t) => (
                <label key={t} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    name="scanType"
                    value={t}
                    checked={scanType === t}
                    onChange={() => setScanType(t)}
                    className="accent-eagle-500"
                  />
                  <span className="text-sm text-dark-300 capitalize">{t}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="btn-secondary flex-1 text-sm">Cancel</button>
            <button type="submit" disabled={submitting} className="btn-primary flex-1 text-sm flex items-center justify-center gap-2">
              {submitting ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Wifi className="w-4 h-4" />}
              Start Scan
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Discovered hosts side panel ────────────────────────────────────
function HostsPanel({ scan, onClose, onAddAsset }) {
  const hosts = scan?.raw_results || []
  const [adding, setAdding] = useState({})

  const handleAdd = async (host) => {
    setAdding(prev => ({ ...prev, [host.ip]: true }))
    try {
      await onAddAsset(host)
    } finally {
      setAdding(prev => ({ ...prev, [host.ip]: false }))
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-end bg-black/40 backdrop-blur-sm">
      <div className="glass-card w-full sm:w-[480px] h-full sm:h-auto sm:max-h-[85vh] flex flex-col overflow-hidden sm:rounded-2xl sm:mr-4 sm:mb-4">
        <div className="flex items-center justify-between p-4 border-b border-dark-700/50">
          <div>
            <h3 className="font-semibold text-white">Discovered Hosts</h3>
            <p className="text-xs text-dark-400 mt-0.5">{scan.subnet} — {hosts.length} hosts</p>
          </div>
          <button onClick={onClose} className="text-dark-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {hosts.length === 0 ? (
            <p className="text-dark-400 text-sm text-center py-8">No hosts in results</p>
          ) : (
            hosts.map((host, i) => (
              <div key={i} className="bg-dark-800/60 rounded-xl p-3 border border-dark-700/40">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="font-mono text-sm text-accent-cyan">{host.ip || host.ip_address}</p>
                    {host.hostname && <p className="text-xs text-dark-300 mt-0.5">{host.hostname}</p>}
                    {host.mac && <p className="text-xs text-dark-500 font-mono mt-0.5">{host.mac}</p>}
                    {host.os && <p className="text-xs text-dark-400 mt-1">{host.os}</p>}
                    {host.ports && host.ports.length > 0 && (
                      <p className="text-xs text-dark-500 mt-1 truncate">
                        Ports: {Array.isArray(host.ports) ? host.ports.join(', ') : host.ports}
                      </p>
                    )}
                  </div>
                  <button
                    onClick={() => handleAdd(host)}
                    disabled={adding[host.ip || host.ip_address]}
                    className="btn-secondary text-xs py-1 px-2 flex-shrink-0 flex items-center gap-1"
                  >
                    {adding[host.ip || host.ip_address]
                      ? <div className="w-3 h-3 border border-white/30 border-t-white rounded-full animate-spin" />
                      : <Plus className="w-3 h-3" />
                    }
                    Add
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────
export default function DiscoveryPage() {
  const { user } = useAuth()
  const [scans, setScans] = useState([])
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)
  const [showNew, setShowNew] = useState(false)
  const [selectedScan, setSelectedScan] = useState(null)
  const [error, setError] = useState(null)
  const intervalRef = useRef(null)

  const loadData = useCallback(async () => {
    try {
      const [scansRes, agentsRes] = await Promise.all([
        client.get('/scans'),
        client.get('/agents'),
      ])
      setScans(scansRes.data.scans || scansRes.data.items || [])
      setAgents(agentsRes.data.agents || [])
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load data')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadData()
  }, [loadData])

  // Auto-refresh every 10s if any scan is pending/running
  useEffect(() => {
    const hasActive = scans.some(s => s.status === 'pending' || s.status === 'running')
    if (hasActive) {
      intervalRef.current = setInterval(loadData, 10000)
    } else {
      clearInterval(intervalRef.current)
    }
    return () => clearInterval(intervalRef.current)
  }, [scans, loadData])

  const handleStartScan = async ({ subnet, agent_id, scan_type }) => {
    await client.post('/scans/active', { subnet, agent_id, scan_type })
    await loadData()
  }

  const handleAddAsset = async (host) => {
    try {
      await client.post('/assets', {
        ip_address: host.ip || host.ip_address,
        hostname: host.hostname,
        mac_address: host.mac,
      })
      alert(`Asset ${host.ip || host.ip_address} added to inventory.`)
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to add asset')
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Asset Discovery</h1>
          <p className="text-dark-400 text-sm mt-1">Trigger network scans and review discovered hosts</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            disabled={loading}
            className="btn-secondary flex items-center gap-2 text-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowNew(true)}
            className="btn-primary flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            New Scan
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="glass-card p-4 border border-red-500/30">
          <p className="text-red-400 text-sm">{error}</p>
          <button onClick={loadData} className="btn-secondary text-sm mt-2">Retry</button>
        </div>
      )}

      {/* Scans table */}
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : scans.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Agent</th>
                <th>Subnet</th>
                <th>Type</th>
                <th>Status</th>
                <th>Hosts Found</th>
                <th>Started</th>
                <th>Completed</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr
                  key={scan.scan_id}
                  className={scan.status === 'completed' ? 'cursor-pointer hover:bg-dark-700/30' : ''}
                  onClick={() => scan.status === 'completed' && setSelectedScan(scan)}
                >
                  <td className="font-mono text-xs text-dark-400">{scan.scan_id?.slice(0, 12)}...</td>
                  <td className="text-dark-300 text-sm">{scan.agent_id?.slice(0, 8) || '—'}</td>
                  <td className="font-mono text-sm text-accent-cyan">{scan.subnet || '—'}</td>
                  <td className="text-xs text-dark-300 capitalize">{scan.scan_type || 'active'}</td>
                  <td><StatusBadge status={scan.status} /></td>
                  <td className="font-medium text-white">{scan.hosts_discovered ?? 0}</td>
                  <td className="text-dark-400 text-xs">{relativeTime(scan.started_at)}</td>
                  <td className="text-dark-400 text-xs">{relativeTime(scan.completed_at)}</td>
                  <td>
                    {scan.status === 'completed' && (
                      <ChevronRight className="w-4 h-4 text-dark-400" />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <Globe className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium mb-2">No scans yet</p>
            <p className="text-sm mb-4">Run your first scan to discover network assets.</p>
            <button onClick={() => setShowNew(true)} className="btn-primary">
              <Plus className="w-4 h-4 mr-2" />
              Start First Scan
            </button>
          </div>
        )}
      </div>

      {/* Modals */}
      {showNew && (
        <NewScanModal
          onClose={() => setShowNew(false)}
          onSubmit={handleStartScan}
          agents={agents}
        />
      )}

      {selectedScan && (
        <HostsPanel
          scan={selectedScan}
          onClose={() => setSelectedScan(null)}
          onAddAsset={handleAddAsset}
        />
      )}
    </div>
  )
}
