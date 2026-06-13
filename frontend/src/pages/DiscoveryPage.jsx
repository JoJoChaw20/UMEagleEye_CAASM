import { useState, useEffect, useCallback, useRef } from 'react'
import { Plus, RefreshCw, X, ChevronRight, Wifi, Globe, GitCompare } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'

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
function HostsPanel({ scan, onClose, onAddAsset, inventoriedIps, myAssetIps, readOnly }) {
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
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-end bg-black/60 backdrop-blur-sm">
      <div className="w-full sm:w-[500px] h-full sm:h-auto sm:max-h-[88vh] flex flex-col overflow-hidden sm:rounded-2xl sm:mr-4 sm:mb-4 bg-dark-900 border border-dark-700 shadow-2xl">
        <div className="flex items-center justify-between p-4 border-b border-dark-700">
          <div>
            <h3 className="font-semibold text-dark-100">Discovered Hosts</h3>
            <p className="text-xs text-dark-400 mt-0.5">
              {scan.subnet || '—'} · {hosts.length} host{hosts.length !== 1 ? 's' : ''} · <span className="capitalize">{scan.scanType || 'active'}</span> scan
            </p>
          </div>
          <button onClick={onClose} className="text-dark-400 hover:text-dark-100 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-4 py-3 border-b border-dark-700 bg-dark-850 space-y-3">
          <div className="flex items-start gap-2 p-3 rounded-lg bg-blue-500/15 border border-blue-500/30 text-blue-500">
            <span className="text-base leading-none">💡</span>
            <p className="text-xs leading-relaxed">
              <span className="font-semibold block mb-0.5">Selective Inventory Recommended</span>
              Avoid adding every discovered host blindly. Only <strong>Accept</strong> devices that are relevant to your organization (e.g., servers, company workstations, infrastructure). Ignore personal phones, smart TVs, or guest devices.
            </p>
          </div>
          <p className="text-xs text-dark-400 px-1">
            Click <span className="text-dark-100 font-medium">Accept</span> to track an asset, or <span className="text-dark-100 font-medium">Update</span> to refresh an already-inventoried asset with new scan data.
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
                      ? 'bg-green-500/10 border-green-500/30'
                      : isKnown
                        ? 'bg-blue-500/10 border-blue-500/30'
                        : 'bg-dark-850 border-dark-700'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1 space-y-0.5">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-sm text-accent-cyan">{ip}</span>
                        {(isAccepted || isInMyAssets) && (
                          <span className="text-xs px-1.5 py-0.5 bg-green-500/20 text-green-500 border border-green-500/40 rounded-full">
                            In My Assets
                          </span>
                        )}
                        {!isAccepted && !isInMyAssets && isKnown && (
                          <span className="text-xs px-1.5 py-0.5 bg-blue-500/20 text-blue-500 border border-blue-500/40 rounded-full">
                            Auto-discovered
                          </span>
                        )}
                      </div>
                      {host.hostname && (
                        <p className="text-xs text-dark-200">{host.hostname}</p>
                      )}
                      {host.mac && (
                        <p className="text-xs text-dark-300 font-mono">{host.mac}</p>
                      )}
                      {osLabel && (
                        <p className="text-xs text-dark-300">
                          <span className="text-dark-400">OS:</span> {osLabel}
                        </p>
                      )}
                      {portsLabel && (
                        <p className="text-xs text-dark-400">
                          <span>Ports:</span>{' '}
                          <span className="font-mono text-dark-300">{portsLabel}</span>
                        </p>
                      )}

                      {host.description && (
                        <div className="pt-1.5 mt-1.5 border-t border-dark-700">
                          <p className="text-xs text-dark-200">
                            <span className="text-accent-cyan font-medium">AI Analysis:</span> {host.description}
                          </p>
                          {host.suggestion && (
                            <p className={`text-xs mt-0.5 ${host.suggestion.toLowerCase().includes('accept') ? 'text-green-500' : host.suggestion.toLowerCase().includes('ignore') ? 'text-amber-500' : 'text-blue-500'}`}>
                              <span className="font-medium">Recommendation:</span> {host.suggestion}
                            </p>
                          )}
                        </div>
                      )}
                    </div>

                    {!readOnly && !isAccepted && !isInMyAssets && (
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

// ── Scan Compare Panel ────────────────────────────────────────────
function ScanComparePanel({ onClose }) {
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [expanded, setExpanded] = useState(null)

  useEffect(() => {
    client.get('/scans/compare')
      .then(r => setData(r.data))
      .catch(e => setError(e?.response?.data?.detail || 'Failed to load comparison'))
      .finally(() => setLoading(false))
  }, [])

  const richBar = (score, max = 4) => (
    <div className="flex gap-0.5">
      {Array.from({ length: max }).map((_, i) => (
        <div key={i} className={`h-1.5 w-4 rounded-sm ${i < score ? 'bg-eagle-500' : 'bg-dark-700'}`} />
      ))}
    </div>
  )

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/70 backdrop-blur-sm p-4 pt-10 overflow-y-auto">
      <div className="w-full max-w-5xl p-6 space-y-5 mb-10 bg-dark-900 border border-dark-700 rounded-2xl shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-dark-100">Active vs Passive Scan Comparison</h2>
            <p className="text-xs text-dark-400 mt-0.5">Assets discovered by both scan methods — side-by-side data comparison</p>
          </div>
          <button onClick={onClose} className="text-dark-400 hover:text-dark-100 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {loading && (
          <div className="flex items-center justify-center py-16">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        )}

        {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}

        {data && (
          <>
            {/* Summary stats */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { label: 'Both Scans',   value: data.total_overlap,     color: 'text-eagle-500' },
                { label: 'Active Total', value: data.total_active_ips,  color: 'text-blue-500'  },
                { label: 'Passive Total',value: data.total_passive_ips, color: 'text-cyan-500'  },
                { label: 'Active Only',  value: data.active_only_count, color: 'text-amber-500' },
              ].map(s => (
                <div key={s.label} className="bg-dark-850 rounded-xl border border-dark-700 p-3 text-center">
                  <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
                  <p className="text-xs text-dark-300 mt-0.5">{s.label}</p>
                </div>
              ))}
            </div>

            {/* Legend */}
            <div className="flex flex-wrap gap-4 text-xs text-dark-300 border border-dark-700 rounded-lg p-3 bg-dark-850">
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" /> Active scan data</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-cyan-500 inline-block" /> Passive scan data</span>
              <span className="flex items-center gap-1.5"><span className="text-green-500 font-bold">✓</span> Match between scans</span>
              <span className="flex items-center gap-1.5"><span className="text-amber-500 font-bold">≠</span> Mismatch between scans</span>
              <span className="flex items-center gap-1.5"><span className="text-dark-400">—</span> Not captured</span>
            </div>

            {data.overlap.length === 0 ? (
              <div className="text-center py-10 text-dark-400">
                <p className="text-sm">No assets found in both active and passive scan results yet.</p>
                <p className="text-xs mt-1">Run at least one active and one passive scan targeting the same subnet.</p>
              </div>
            ) : (
              <div className="space-y-2">
                {/* Column headers */}
                <div className="grid grid-cols-12 gap-2 text-[10px] text-dark-400 uppercase tracking-wide px-3">
                  <div className="col-span-2">IP Address</div>
                  <div className="col-span-2">Hostname</div>
                  <div className="col-span-2">MAC Address</div>
                  <div className="col-span-2">Open Ports (Active)</div>
                  <div className="col-span-2">OS (Active)</div>
                  <div className="col-span-1 text-center">Active Rich.</div>
                  <div className="col-span-1 text-center">Passive Rich.</div>
                </div>

                {data.overlap.map((row) => {
                  const isExpanded = expanded === row.ip
                  const osName = row.active.os
                    ? (row.active.os.name || row.active.os.fingerbank_device || row.active.os.dhcp_device_hint || null)
                    : null
                  const portStr = row.delta.ports_found > 0
                    ? row.active.ports.slice(0, 4).map(p => `${p.port}/${p.protocol}`).join('  ') +
                      (row.active.ports.length > 4 ? ` +${row.active.ports.length - 4}` : '')
                    : null

                  return (
                    <div key={row.ip} className="rounded-xl border border-dark-700 overflow-hidden bg-dark-850">
                      {/* Row */}
                      <button
                        className="w-full grid grid-cols-12 gap-2 items-center px-3 py-2.5 hover:bg-dark-700/40 transition-colors text-left"
                        onClick={() => setExpanded(isExpanded ? null : row.ip)}
                      >
                        {/* IP */}
                        <div className="col-span-2 font-mono text-sm text-accent-cyan">{row.ip}</div>

                        {/* Hostname */}
                        <div className="col-span-2 text-xs space-y-0.5">
                          {row.active.hostname
                            ? <p className="text-blue-500">{row.active.hostname}</p>
                            : <p className="text-dark-400">—</p>}
                          {row.passive.hostname
                            ? <p className={`${row.delta.hostname_match ? 'text-green-500' : 'text-amber-500'}`}>
                                {row.delta.hostname_match ? '✓ ' : '≠ '}{row.passive.hostname}
                              </p>
                            : <p className="text-dark-400">— passive</p>}
                        </div>

                        {/* MAC */}
                        <div className="col-span-2 text-xs space-y-0.5 font-mono">
                          {row.active.mac
                            ? <p className="text-blue-500">{row.active.mac}</p>
                            : <p className="text-dark-400">—</p>}
                          {row.passive.mac
                            ? <p className={`${row.delta.mac_match ? 'text-green-500' : 'text-amber-500'}`}>
                                {row.delta.mac_match ? '✓ ' : '≠ '}{row.passive.mac}
                              </p>
                            : <p className="text-dark-400">— passive</p>}
                        </div>

                        {/* Ports */}
                        <div className="col-span-2 text-xs font-mono">
                          {portStr
                            ? <span className="text-blue-500">{portStr}</span>
                            : <span className="text-dark-400">none detected</span>}
                          <span className="block text-dark-400 text-[10px]">— passive</span>
                        </div>

                        {/* OS */}
                        <div className="col-span-2 text-xs">
                          {osName
                            ? <span className="text-blue-500">{String(osName).slice(0, 30)}</span>
                            : <span className="text-dark-400">not identified</span>}
                          <span className="block text-dark-400 text-[10px]">— passive</span>
                        </div>

                        {/* Active richness */}
                        <div className="col-span-1 flex justify-center">{richBar(row.delta.active_richness)}</div>

                        {/* Passive richness */}
                        <div className="col-span-1 flex justify-center">{richBar(row.delta.passive_richness)}</div>
                      </button>

                      {/* Expanded detail */}
                      {isExpanded && (
                        <div className="grid grid-cols-2 gap-4 px-4 py-4 border-t border-dark-700 bg-dark-900 text-xs">
                          {/* Active detail */}
                          <div className="space-y-2">
                            <p className="text-blue-500 font-semibold uppercase tracking-wide text-[10px]">Active Scan Detail</p>
                            <div className="space-y-1 text-dark-200">
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Scan ID</span><span className="font-mono text-[10px] truncate">{row.active.scan_id}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Subnet</span><span>{row.active.subnet || '—'}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Scanned</span><span>{new Date(row.active.scanned_at).toLocaleString()}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Hostname</span><span>{row.active.hostname || '—'}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">MAC</span><span className="font-mono">{row.active.mac || '—'}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">OS</span><span>{osName ? String(osName) : '—'}</span></div>
                              {row.active.ports.length > 0 && (
                                <div>
                                  <span className="text-dark-400">Ports</span>
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {row.active.ports.map((p, i) => (
                                      <span key={i} className="bg-blue-500/15 text-blue-500 border border-blue-500/40 px-1.5 py-0.5 rounded font-mono text-[10px]">
                                        {p.port}/{p.protocol}{p.service ? ` (${p.service})` : ''}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {row.active.description && (
                                <div className="flex gap-2 pt-1 border-t border-dark-700">
                                  <span className="text-dark-400 w-20 shrink-0">AI Analysis</span>
                                  <span className="text-dark-200">{row.active.description}</span>
                                </div>
                              )}
                            </div>
                          </div>

                          {/* Passive detail */}
                          <div className="space-y-2">
                            <p className="text-cyan-500 font-semibold uppercase tracking-wide text-[10px]">Passive Scan Detail</p>
                            <div className="space-y-1 text-dark-200">
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Scan ID</span><span className="font-mono text-[10px] truncate">{row.passive.scan_id}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Source</span><span>{row.passive.subnet || 'ARP Discovery'}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Seen at</span><span>{new Date(row.passive.scanned_at).toLocaleString()}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Hostname</span><span>{row.passive.hostname || '—'}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">MAC</span><span className="font-mono">{row.passive.mac || '—'}</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">Ports</span><span className="text-dark-400 italic">not available (ARP only)</span></div>
                              <div className="flex gap-2"><span className="text-dark-400 w-20 shrink-0">OS</span><span className="text-dark-400 italic">not available (ARP only)</span></div>
                              {row.passive.description && (
                                <div className="flex gap-2 pt-1 border-t border-dark-700">
                                  <span className="text-dark-400 w-20 shrink-0">AI Analysis</span>
                                  <span className="text-dark-200">{row.passive.description}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

const SCAN_PAGE_SIZE = 15

// ── Main page ─────────────────────────────────────────────────────
export default function DiscoveryPage() {
  const { user } = useAuth()
  const isSuperadmin = user?.role === 'superadmin'
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
  const [statusFilter, setStatusFilter] = useState('')
  const [scanTypeFilter, setScanTypeFilter] = useState('')
  const [scanPage, setScanPage] = useState(1)
  const [showCompare, setShowCompare] = useState(false)
  const [tenantFilter, setTenantFilter] = useState('')

  const loadData = useCallback(async () => {
    try {
      const scanParams = tenantFilter ? { tenant_id: tenantFilter } : {}
      const [scansRes, agentsRes, allAssetsRes, myAssetsRes, tenantsRes] = await Promise.all([
        client.get('/scans', { params: scanParams }),
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
  }, [tenantFilter])

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

  const filteredScans = scans.filter(s => {
    if (statusFilter && s.status !== statusFilter) return false
    if (scanTypeFilter && (s.scanType || 'active') !== scanTypeFilter) return false
    return true
  })
  const scanTotalPages = Math.ceil(filteredScans.length / SCAN_PAGE_SIZE)
  const pagedScans = filteredScans.slice((scanPage - 1) * SCAN_PAGE_SIZE, scanPage * SCAN_PAGE_SIZE)

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
          {!isSuperadmin && (
            <button
              onClick={() => setShowCompare(true)}
              className="btn-secondary flex items-center gap-2 text-sm"
            >
              <GitCompare className="w-4 h-4" />
              Compare Scans
            </button>
          )}
          {!isSuperadmin && (
            <button
              onClick={() => setShowNew(true)}
              className="btn-primary flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              New Scan
            </button>
          )}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="glass-card p-4 border border-red-500/30">
          <p className="text-red-400 text-sm">{error}</p>
          <button onClick={loadData} className="btn-secondary text-sm mt-2">Retry</button>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <TenantSelector value={tenantFilter} onChange={(id) => { setTenantFilter(id); setScanPage(1) }} />
        <select
          value={statusFilter}
          onChange={e => { setStatusFilter(e.target.value); setScanPage(1) }}
          className="input-field text-sm py-1.5 w-40"
        >
          <option value="">All Statuses</option>
          <option value="pending">Pending</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
        </select>
        <select
          value={scanTypeFilter}
          onChange={e => { setScanTypeFilter(e.target.value); setScanPage(1) }}
          className="input-field text-sm py-1.5 w-36"
        >
          <option value="">All Types</option>
          <option value="active">Active</option>
          <option value="passive">Passive</option>
        </select>
        <button
          onClick={() => { setStatusFilter(''); setScanTypeFilter(''); setScanPage(1) }}
          className="text-xs text-dark-400 hover:text-dark-200 underline underline-offset-2"
        >
          Clear filters
        </button>
        <span className="text-dark-400 text-sm ml-auto">{filteredScans.length} scans</span>
      </div>

      {/* Scans table */}
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : filteredScans.length > 0 ? (
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
              {pagedScans.map((scan) => {
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
            <p className="text-lg font-medium mb-2">
              {statusFilter || scanTypeFilter ? 'No scans match your filters.' : 'No scans yet'}
            </p>
            {!statusFilter && !scanTypeFilter && (
              <>
                <p className="text-sm mb-4">Run your first scan to discover network assets.</p>
                <button onClick={() => setShowNew(true)} className="btn-primary">
                  <Plus className="w-4 h-4 mr-2" />
                  Start First Scan
                </button>
              </>
            )}
          </div>
        )}
      </div>

      {/* Pagination */}
      {scanTotalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={() => setScanPage(p => Math.max(1, p - 1))}
            disabled={scanPage === 1}
            className="btn-secondary text-sm py-1 px-3 disabled:opacity-30"
          >
            Previous
          </button>
          <span className="text-dark-400 text-sm">Page {scanPage} of {scanTotalPages}</span>
          <button
            onClick={() => setScanPage(p => Math.min(scanTotalPages, p + 1))}
            disabled={scanPage === scanTotalPages}
            className="btn-secondary text-sm py-1 px-3 disabled:opacity-30"
          >
            Next
          </button>
        </div>
      )}

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
          readOnly={isSuperadmin}
          inventoriedIps={inventoriedIps}
          myAssetIps={myAssetIps}
        />
      )}

      {showCompare && (
        <ScanComparePanel onClose={() => setShowCompare(false)} />
      )}
    </div>
  )
}
