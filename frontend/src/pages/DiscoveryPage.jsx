import { useState, useEffect, useCallback, useRef } from 'react'
import { Search, Plus, RefreshCw, X, Wifi, Globe, CheckCircle2, Download } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

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
                <option key={a.agentId} value={a.agentId}>{a.name} ({a.status})</option>
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

export default function DiscoveryPage() {
  const { user } = useAuth()
  const [scans, setScans] = useState([])
  const [agents, setAgents] = useState([])
  const [importedIps, setImportedIps] = useState(new Set())
  const [loading, setLoading] = useState(true)
  const [importing, setImporting] = useState({})
  const [search, setSearch] = useState('')
  const [showNew, setShowNew] = useState(false)
  const [error, setError] = useState(null)
  const intervalRef = useRef(null)

  const canImport = ['ops_lead', 'superadmin'].includes(user?.role)

  const loadData = useCallback(async () => {
    try {
      const [scansRes, agentsRes, importedRes] = await Promise.all([
        client.get('/scans'),
        client.get('/agents'),
        client.get('/assets', { params: { source: 'discovered', limit: 200 } }),
      ])
      setScans(scansRes.data.scans || scansRes.data.items || [])
      setAgents(agentsRes.data.agents || [])
      const ips = new Set((importedRes.data.items || []).map(a => a.ipAddress))
      setImportedIps(ips)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load data')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadData() }, [loadData])

  useEffect(() => {
    const hasActive = scans.some(s => s.status === 'pending' || s.status === 'running')
    if (hasActive) {
      intervalRef.current = setInterval(loadData, 10000)
    } else {
      clearInterval(intervalRef.current)
    }
    return () => clearInterval(intervalRef.current)
  }, [scans, loadData])

  // Flatten all hosts from completed scans, deduplicate by IP (keep most recent)
  const hosts = (() => {
    const allHosts = scans
      .filter(s => s.status === 'completed' && s.rawResults?.length > 0)
      .flatMap(s => (s.rawResults || []).map(h => ({ ...h, scanId: s.scanId, subnet: s.subnet, scannedAt: s.completedAt })))
    const seen = new Map()
    for (const h of allHosts) {
      const ip = h.ip || h.ip_address
      if (!ip) continue
      if (!seen.has(ip) || new Date(h.scannedAt) > new Date(seen.get(ip).scannedAt)) {
        seen.set(ip, h)
      }
    }
    return Array.from(seen.values())
  })()

  const filtered = search
    ? hosts.filter(h => {
        const ip = h.ip || h.ip_address || ''
        const hn = h.hostname || ''
        return ip.includes(search) || hn.toLowerCase().includes(search.toLowerCase())
      })
    : hosts

  const handleStartScan = async ({ subnet, agent_id, scan_type }) => {
    await client.post('/scans/active', { subnet, agent_id, scan_type })
    await loadData()
  }

  const handleImport = async (host) => {
    const ip = host.ip || host.ip_address
    setImporting(prev => ({ ...prev, [ip]: true }))
    try {
      await client.post('/assets', {
        ip_address: ip,
        hostname: host.hostname || undefined,
        mac_address: host.mac || undefined,
        source: 'discovered',
      })
      setImportedIps(prev => new Set([...prev, ip]))
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to import asset')
    } finally {
      setImporting(prev => ({ ...prev, [ip]: false }))
    }
  }

  const completedScans = scans.filter(s => s.status === 'completed')
  const activeScans = scans.filter(s => s.status === 'pending' || s.status === 'running')

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Discovery</h1>
          <p className="text-dark-400 text-sm mt-1">All hosts discovered by network scans</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={loadData} disabled={loading} className="btn-secondary flex items-center gap-2 text-sm">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button onClick={() => setShowNew(true)} className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" />
            New Scan
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Discovered Hosts', value: hosts.length, color: 'text-accent-cyan' },
          { label: 'Imported to Assets', value: importedIps.size, color: 'text-green-400' },
          { label: 'Completed Scans', value: completedScans.length, color: 'text-eagle-400' },
          { label: 'Active Scans', value: activeScans.length, color: 'text-yellow-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="glass-card p-4">
            <p className={`text-2xl font-bold ${color}`}>{value}</p>
            <p className="text-xs text-dark-400 mt-1">{label}</p>
          </div>
        ))}
      </div>

      {/* Active scans notice */}
      {activeScans.length > 0 && (
        <div className="glass-card p-4 border border-blue-500/30 flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-blue-400 animate-pulse flex-shrink-0" />
          <p className="text-sm text-blue-300">
            {activeScans.length} scan{activeScans.length > 1 ? 's' : ''} in progress — auto-refreshing every 10s
          </p>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="glass-card p-4 border border-red-500/30">
          <p className="text-red-400 text-sm">{error}</p>
          <button onClick={loadData} className="btn-secondary text-sm mt-2">Retry</button>
        </div>
      )}

      {/* Search */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
        <input
          type="text"
          placeholder="Search by IP or hostname..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="input-field w-full pl-10 text-sm"
        />
      </div>

      {/* Hosts table */}
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : filtered.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>MAC</th>
                <th>OS</th>
                <th>Open Ports</th>
                <th>Subnet</th>
                <th>Scanned</th>
                <th>Status</th>
                {canImport && <th></th>}
              </tr>
            </thead>
            <tbody>
              {filtered.map((host, i) => {
                const ip = host.ip || host.ip_address
                const isImported = importedIps.has(ip)
                return (
                  <tr key={`${ip}-${i}`}>
                    <td className="font-mono text-sm text-accent-cyan">{ip}</td>
                    <td className="text-dark-300 text-sm">{host.hostname || '—'}</td>
                    <td className="font-mono text-xs text-dark-400">{host.mac || '—'}</td>
                    <td className="text-xs text-dark-300">{host.os || '—'}</td>
                    <td className="text-xs text-dark-500 max-w-[160px] truncate" title={Array.isArray(host.ports) ? host.ports.join(', ') : host.ports}>
                      {host.ports?.length > 0
                        ? (Array.isArray(host.ports) ? host.ports.slice(0, 5).join(', ') : host.ports)
                        : '—'
                      }
                    </td>
                    <td className="font-mono text-xs text-dark-400">{host.subnet || '—'}</td>
                    <td className="text-dark-400 text-xs">{relativeTime(host.scannedAt)}</td>
                    <td>
                      {isImported
                        ? <span className="flex items-center gap-1 text-xs text-green-400 font-medium"><CheckCircle2 className="w-3.5 h-3.5" />Imported</span>
                        : <span className="text-xs text-dark-500">Not imported</span>
                      }
                    </td>
                    {canImport && (
                      <td>
                        {!isImported && (
                          <button
                            onClick={() => handleImport(host)}
                            disabled={importing[ip]}
                            className="btn-secondary text-xs py-1 px-3 flex items-center gap-1"
                          >
                            {importing[ip]
                              ? <div className="w-3 h-3 border border-white/30 border-t-white rounded-full animate-spin" />
                              : <Download className="w-3 h-3" />
                            }
                            Import
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-20 text-dark-400">
            <Globe className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium mb-2">
              {hosts.length > 0 && search ? 'No hosts match your search' : 'No discovered hosts yet'}
            </p>
            <p className="text-sm mb-4">
              {hosts.length > 0 && search
                ? 'Try a different search term.'
                : 'Run a network scan to discover hosts on your network.'}
            </p>
            {!search && (
              <button onClick={() => setShowNew(true)} className="btn-primary">
                <Plus className="w-4 h-4 mr-2" />
                Start First Scan
              </button>
            )}
          </div>
        )}
      </div>

      {/* Scan history */}
      {scans.length > 0 && (
        <div className="glass-card overflow-hidden">
          <div className="p-4 border-b border-dark-700/50">
            <h2 className="text-sm font-semibold text-dark-200">Scan History</h2>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Subnet</th>
                <th>Type</th>
                <th>Status</th>
                <th>Hosts Found</th>
                <th>Started</th>
                <th>Completed</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.scanId}>
                  <td className="font-mono text-xs text-dark-400">{scan.scanId?.slice(0, 12)}…</td>
                  <td className="font-mono text-sm text-accent-cyan">{scan.subnet || '—'}</td>
                  <td className="text-xs text-dark-300 capitalize">{scan.scanType || 'active'}</td>
                  <td><StatusBadge status={scan.status} /></td>
                  <td className="font-medium text-white">{scan.hostsDiscovered ?? 0}</td>
                  <td className="text-dark-400 text-xs">{relativeTime(scan.startedAt)}</td>
                  <td className="text-dark-400 text-xs">{relativeTime(scan.completedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showNew && (
        <NewScanModal
          onClose={() => setShowNew(false)}
          onSubmit={handleStartScan}
          agents={agents}
        />
      )}
    </div>
  )
}
