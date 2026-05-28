import { useState, useEffect, useCallback, useRef } from 'react'
import { Plus, RefreshCw, X, ChevronRight, Wifi, Globe } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

// ── Status badge ──────────────────────────────────────────────────
function StatusBadge({ status }) {
  const map = {
    pending:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    running:   'bg-blue-500/20 text-blue-400 border-blue-500/30',
    completed: 'bg-green-500/20 text-green-400 border-green-500/30',
    failed:    'bg-red-500/20 text-red-400 border-red-500/30',
    cancelled: 'bg-dark-600/40 text-dark-400 border-dark-500/30',
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

// ── OS label helper ───────────────────────────────────────────────
function formatOs(os) {
  if (!os) return null
  if (typeof os === 'string') return os
  if (typeof os === 'object') {
    const name = os.name || ''
    const acc = os.accuracy ? ` (${os.accuracy}%)` : ''
    return name ? name + acc : null
  }
  return null
}

// ── Port display helper ───────────────────────────────────────────
function formatPorts(ports) {
  if (!ports || ports.length === 0) return null
  const list = Array.isArray(ports)
    ? ports.slice(0, 8).map(p => typeof p === 'object' ? `${p.port}/${p.protocol || 'tcp'}` : String(p))
    : [String(ports)]
  const extra = Array.isArray(ports) && ports.length > 8 ? ` +${ports.length - 8} more` : ''
  return list.join('  ') + extra
}

// ── New Scan Modal ────────────────────────────────────────────────
// Validates a single IPv4 address (e.g. 192.168.0.1)
function isValidIpv4(ip) {
  return /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/.test(ip)
}

// Validates a subnet: either a plain IPv4 or an IPv4 CIDR (e.g. 192.168.1.0/24)
function validateSubnet(value) {
  const trimmed = value.trim()
  if (!trimmed) return 'Target subnet is required'
  const [ip, prefix] = trimmed.split('/')
  if (!isValidIpv4(ip)) return 'Invalid IP address format (e.g. 192.168.1.0 or 192.168.1.0/24)'
  if (prefix !== undefined) {
    const num = Number(prefix)
    if (!Number.isInteger(num) || num < 0 || num > 32)
      return 'CIDR prefix must be between 0 and 32 (e.g. /24)'
  }
  return null // valid
}

function NewScanModal({ onClose, onSubmit, agents, tenants, userTenantId }) {
  const [subnet, setSubnet] = useState(import.meta.env.VITE_SCAN_DEFAULT_SUBNET || '192.168.1.0/24')
  const [agentId, setAgentId] = useState('')
  const [scanType, setScanType] = useState('active')
  const [tenantId, setTenantId] = useState(userTenantId || (tenants.length === 1 ? tenants[0].tenant_id : ''))
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)
  const [subnetError, setSubnetError] = useState(null)

  const handleSubnetChange = (e) => {
    const val = e.target.value
    setSubnet(val)
    setSubnetError(validateSubnet(val))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)

    // Resolve agent: use selected or auto-pick first online
    let effectiveAgentId = agentId
    if (!effectiveAgentId) {
      const onlineAgent = agents.find(a => a.status === 'online')
      if (!onlineAgent) {
        setError('No online agents available. Please ensure an agent is running before scanning.')
        setSubmitting(false)
        return
      }
      effectiveAgentId = onlineAgent.agent_id
    }

    try {
      const finalSubnet = scanType === 'passive' ? 'arp-discovery' : subnet
      await onSubmit({ subnet: finalSubnet, agent_id: effectiveAgentId, scan_type: scanType, tenant_id: tenantId || undefined })
      onClose()
    } catch (err) {
      const data = err?.response?.data
      // Extract the most useful message: detail → first Zod issue → raw message → fallback
      const reason =
        data?.detail ||
        data?.error?.issues?.[0]?.message ||
        err?.message ||
        'Failed to start scan. Please check your input and try again.'
      setError(reason)
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
          {scanType === 'active' && (
            <div>
              <label className="block text-xs text-dark-400 mb-1">Target Subnet</label>
              <input
                type="text"
                value={subnet}
                onChange={handleSubnetChange}
                placeholder="192.168.1.0/24"
                className={`input-field w-full text-sm ${subnetError ? 'border-red-500/60 focus:border-red-500' : ''}`}
                required
              />
              {subnetError && (
                <p className="text-xs text-red-400 mt-1 flex items-center gap-1">
                  <span>⚠</span> {subnetError}
                </p>
              )}
            </div>
          )}

          <div>
            <label className="block text-xs text-dark-400 mb-1">
              Tenant <span className="text-dark-500">(auto-detected from agent)</span>
            </label>
            <select value={tenantId} onChange={(e) => setTenantId(e.target.value)} className="input-field w-full text-sm">
              <option value="">— Auto from agent —</option>
              {tenants.map((t) => (
                <option key={t.tenant_id} value={t.tenant_id}>{t.name}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs text-dark-400 mb-1">Agent</label>
            <select value={agentId} onChange={(e) => setAgentId(e.target.value)} className="input-field w-full text-sm">
              <option value="">Auto-select (first online)</option>
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
            <button
              type="submit"
              disabled={submitting || (scanType === 'active' && !!subnetError)}
              className="btn-primary flex-1 text-sm flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
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
function HostsPanel({ scan, onClose, onAddAsset, inventoriedIps, myAssetIps }) {
  const hosts = scan?.rawResults || scan?.raw_results || []
  const [adding, setAdding] = useState({})
  const [accepted, setAccepted] = useState(new Set())

  const handleAdd = async (host) => {
    const ip = host.ip || host.ip_address
    setAdding(prev => ({ ...prev, [ip]: true }))
    try {
      await onAddAsset(host)
      setAccepted(prev => new Set([...prev, ip]))
    } catch {
      // error shown by onAddAsset
    } finally {
      setAdding(prev => ({ ...prev, [ip]: false }))
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-end bg-black/40 backdrop-blur-sm">
      <div className="glass-card w-full sm:w-[500px] h-full sm:h-auto sm:max-h-[88vh] flex flex-col overflow-hidden sm:rounded-2xl sm:mr-4 sm:mb-4">
        <div className="flex items-center justify-between p-4 border-b border-dark-700/50">
          <div>
            <h3 className="font-semibold text-white">Discovered Hosts</h3>
            <p className="text-xs text-dark-400 mt-0.5">
              {scan.subnet || '—'} · {hosts.length} host{hosts.length !== 1 ? 's' : ''} · <span className="capitalize">{scan.scanType || 'active'}</span> scan
            </p>
          </div>
          <button onClick={onClose} className="text-dark-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-4 py-3 border-b border-dark-700/30 bg-dark-800/50 space-y-3">
          <div className="flex items-start gap-2 p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <span className="text-base leading-none">💡</span>
            <p className="text-xs leading-relaxed">
              <span className="font-semibold block mb-0.5">Selective Inventory Recommended</span>
              Avoid adding every discovered host blindly. Only <strong>Accept</strong> devices that are relevant to your organization (e.g., servers, company workstations, infrastructure). Ignore personal phones, smart TVs, or guest devices.
            </p>
          </div>
          <p className="text-xs text-dark-400 px-1">
            Click <span className="text-white font-medium">Accept</span> to track an asset, or <span className="text-white font-medium">Update</span> to refresh an already-inventoried asset with new scan data.
          </p>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-2.5">
          {hosts.length === 0 ? (
            <p className="text-dark-400 text-sm text-center py-8">No hosts in results</p>
          ) : (
            hosts.map((host, i) => {
              const ip = host.ip || host.ip_address
              const isAccepted = accepted.has(ip)
              const isInMyAssets = myAssetIps?.has(ip)
              const isKnown = inventoriedIps.has(ip) && !isInMyAssets
              const isAdding = !!adding[ip]
              const osLabel = formatOs(host.os)
              const portsLabel = formatPorts(host.ports)

              return (
                <div
                  key={i}
                  className={`rounded-xl p-3 border transition-colors ${
                    isAccepted || isInMyAssets
                      ? 'bg-green-500/5 border-green-500/20'
                      : isKnown
                        ? 'bg-blue-500/5 border-blue-500/20'
                        : 'bg-dark-800/60 border-dark-700/40'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1 space-y-0.5">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-sm text-accent-cyan">{ip}</span>
                        {(isAccepted || isInMyAssets) && (
                          <span className="text-xs px-1.5 py-0.5 bg-green-500/20 text-green-400 border border-green-500/30 rounded-full">
                            In My Assets
                          </span>
                        )}
                        {!isAccepted && !isInMyAssets && isKnown && (
                          <span className="text-xs px-1.5 py-0.5 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded-full">
                            Auto-discovered
                          </span>
                        )}
                      </div>
                      {host.hostname && (
                        <p className="text-xs text-dark-300">{host.hostname}</p>
                      )}
                      {host.mac && (
                        <p className="text-xs text-dark-500 font-mono">{host.mac}</p>
                      )}
                      {osLabel && (
                        <p className="text-xs text-dark-400">
                          <span className="text-dark-500">OS:</span> {osLabel}
                        </p>
                      )}
                      {portsLabel && (
                        <p className="text-xs text-dark-500">
                          <span>Ports:</span>{' '}
                          <span className="font-mono text-dark-400">{portsLabel}</span>
                        </p>
                      )}

                      {host.description && (
                        <div className="pt-1.5 mt-1.5 border-t border-dark-700/50">
                          <p className="text-xs text-dark-300">
                            <span className="text-accent-cyan/80 font-medium">AI Analysis:</span> {host.description}
                          </p>
                          {host.suggestion && (
                            <p className={`text-xs mt-0.5 ${host.suggestion.toLowerCase().includes('accept') ? 'text-green-400' : host.suggestion.toLowerCase().includes('ignore') ? 'text-yellow-500' : 'text-blue-400'}`}>
                              <span className="font-medium">Recommendation:</span> {host.suggestion}
                            </p>
                          )}
                        </div>
                      )}
                    </div>

                    {!isAccepted && !isInMyAssets && (
                      <button
                        onClick={() => handleAdd(host)}
                        disabled={isAdding}
                        className={`text-xs py-1.5 px-3 flex-shrink-0 flex items-center gap-1.5 ${isKnown ? 'btn-secondary' : 'btn-primary'}`}
                      >
                        {isAdding
                          ? <div className="w-3 h-3 border border-white/30 border-t-white rounded-full animate-spin" />
                          : isKnown
                            ? <RefreshCw className="w-3 h-3" />
                            : <Plus className="w-3 h-3" />
                        }
                        {isKnown ? 'Accept' : 'Accept'}
                      </button>
                    )}
                  </div>
                </div>
              )
            })
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
  const [tenants, setTenants] = useState([])
  const [loading, setLoading] = useState(true)
  const [showNew, setShowNew] = useState(false)
  const [selectedScan, setSelectedScan] = useState(null)
  const [error, setError] = useState(null)
  const [inventoriedIps, setInventoriedIps] = useState(new Set())   // all known assets
  const [myAssetIps, setMyAssetIps] = useState(new Set())           // manually accepted only
  const intervalRef = useRef(null)

  const loadData = useCallback(async () => {
    try {
      const [scansRes, agentsRes, allAssetsRes, myAssetsRes, tenantsRes] = await Promise.all([
        client.get('/scans'),
        client.get('/agents'),
        client.get('/assets', { params: { limit: 200 } }),
        client.get('/assets', { params: { source: 'manual', limit: 200 } }),
        client.get('/tenants').catch(() => ({ data: { tenants: [] } })),
      ])
      setScans(scansRes.data.scans || scansRes.data.items || [])
      setAgents(agentsRes.data.agents || [])
      setTenants(tenantsRes.data.tenants || [])
      setInventoriedIps(new Set((allAssetsRes.data.items || []).map(a => a.ipAddress)))
      setMyAssetIps(new Set((myAssetsRes.data.items || []).map(a => a.ipAddress)))
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load data')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadData()
  }, [loadData])

  // Auto-refresh every 10s while any scan is pending/running
  useEffect(() => {
    const hasActive = scans.some(s => s.status === 'pending' || s.status === 'running')
    if (hasActive) {
      intervalRef.current = setInterval(loadData, 10000)
    } else {
      clearInterval(intervalRef.current)
    }
    return () => clearInterval(intervalRef.current)
  }, [scans, loadData])

  const handleStartScan = async ({ subnet, agent_id, scan_type, tenant_id }) => {
    await client.post('/scans/active', { subnet, agent_id, scan_type, tenant_id })
    await loadData()
  }

  const handleAddAsset = async (host) => {
    const ip = host.ip || host.ip_address
    const portNums = (host.ports || []).map(p =>
      typeof p === 'object' ? Number(p.port) : parseInt(p)
    ).filter(Boolean)
    let deviceType = 'unknown'
    if (portNums.some(p => [3389, 445, 137, 138].includes(p))) deviceType = 'workstation'
    else if (portNums.some(p => [22, 80, 443, 3306, 5432, 6379, 27017, 8080, 8443].includes(p))) deviceType = 'server'

    // Build os_info — preserve OS object AND include ports so the backend
    // criticality formula uses the same port risk that was shown on the discovery panel.
    const osInfo = host.os && typeof host.os === 'object'
      ? { ...host.os }
      : (host.os ? { name: String(host.os) } : {})

    // Normalise ports to "port/protocol" strings that computeCriticality can parse
    if (host.ports && host.ports.length > 0) {
      osInfo.ports = host.ports.map(p =>
        typeof p === 'object' ? `${p.port}/${p.protocol || 'tcp'}` : String(p)
      )
    }

    if (host.description) osInfo.ai_description = host.description
    if (host.suggestion) osInfo.ai_suggestion = host.suggestion

    try {
      await client.post('/assets', {
        ip_address: ip,
        hostname: host.hostname || undefined,
        mac_address: host.mac || undefined,
        device_type: deviceType,
        os_info: Object.keys(osInfo).length > 0 ? osInfo : undefined,
        tenant_id: selectedScan?.tenantId || undefined,
      })
      setInventoriedIps(prev => new Set([...prev, ip]))
      setMyAssetIps(prev => new Set([...prev, ip]))
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to add asset')
      throw err
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
                <th>Target</th>
                <th>Type</th>
                <th>Status</th>
                <th>Hosts Found</th>
                <th>Started</th>
                <th>Completed</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const agentName = agents.find(a => a.agent_id === scan.agentId)?.name || scan.agentId?.slice(0, 8) || '—'
                const subnetLabel = scan.subnet === 'arp-discovery' ? 'ARP Passive' : (scan.subnet || '—')
                const isClickable = scan.status === 'completed' && Array.isArray(scan.rawResults) && scan.rawResults.length > 0
                return (
                  <tr
                    key={scan.scanId}
                    className={isClickable ? 'cursor-pointer hover:bg-dark-700/30' : ''}
                    onClick={() => isClickable && setSelectedScan(scan)}
                  >
                    <td className="font-mono text-xs text-dark-400">{scan.scanId?.slice(0, 12)}...</td>
                    <td className="text-dark-300 text-sm">{agentName}</td>
                    <td className={`font-mono text-sm ${scan.subnet === 'arp-discovery' ? 'text-dark-400 italic' : 'text-accent-cyan'}`}>{subnetLabel}</td>
                    <td className="text-xs text-dark-300 capitalize">{scan.scanType || 'active'}</td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td className="font-medium text-white">{scan.hostsDiscovered ?? 0}</td>
                    <td className="text-dark-400 text-xs">{relativeTime(scan.startedAt)}</td>
                    <td className="text-dark-400 text-xs">{relativeTime(scan.completedAt)}</td>
                    <td>
                      {isClickable && (
                        <ChevronRight className="w-4 h-4 text-dark-400" />
                      )}
                    </td>
                  </tr>
                )
              })}
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
          tenants={tenants}
          userTenantId={user?.tenantId}
        />
      )}

      {selectedScan && (
        <HostsPanel
          scan={selectedScan}
          onClose={() => setSelectedScan(null)}
          onAddAsset={handleAddAsset}
          inventoriedIps={inventoriedIps}
          myAssetIps={myAssetIps}
        />
      )}
    </div>
  )
}
