import { useState, useEffect, useCallback } from 'react'
import { Plus, Trash2, Settings, Copy, Check, X, RefreshCw, Radio, AlertCircle, Waypoints, Network } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'

// ── Helpers ───────────────────────────────────────────────────────
function relativeTime(ts) {
  if (!ts) return 'Never'
  const diff = Date.now() - new Date(ts).getTime()
  const sec = Math.floor(diff / 1000)
  if (sec < 60) return `${sec}s ago`
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min}m ago`
  const h = Math.floor(min / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

// ── Status badge ──────────────────────────────────────────────────
function StatusBadge({ status }) {
  const map = {
    online:   'bg-green-500/20 text-green-400 border-green-500/30',
    degraded: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    offline:  'bg-red-500/20 text-red-400 border-red-500/30',
  }
  const dot = { online: 'bg-green-400', degraded: 'bg-yellow-400', offline: 'bg-red-400' }
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium flex items-center gap-1.5 w-fit ${map[status] ?? 'bg-dark-600/40 text-dark-400 border-dark-500/30'}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dot[status] ?? 'bg-dark-500'} ${status === 'online' ? 'animate-pulse' : ''}`} />
      {status}
    </span>
  )
}

// ── Copy button ───────────────────────────────────────────────────
function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000) }}
      className="p-1.5 hover:bg-eagle-500/10 rounded text-dark-400 hover:text-eagle-400 transition-colors"
    >
      {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
    </button>
  )
}

// ── Modals ────────────────────────────────────────────────────────
function ApiKeyModal({ agentName, apiKey, onClose }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="glass-card w-full max-w-lg p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Agent Registered — {agentName}</h2>
          <button onClick={onClose} className="text-dark-400 hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="flex items-start gap-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-xl">
          <AlertCircle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-yellow-300">This API key is shown <strong>only once</strong>. Copy it now — it cannot be retrieved after closing.</p>
        </div>
        <div>
          <p className="text-xs text-dark-400 mb-1">API Key</p>
          <div className="flex items-center gap-2 bg-dark-800/80 border border-dark-600/50 rounded-lg p-3">
            <code className="text-xs font-mono text-accent-cyan flex-1 break-all">{apiKey}</code>
            <CopyButton text={apiKey} />
          </div>
        </div>
        <div className="bg-dark-800/60 border border-dark-700/40 rounded-xl p-4">
          <p className="text-xs text-dark-400 mb-2 font-medium">Run the EagleEye agent:</p>
          <code className="text-xs font-mono text-dark-300">./eagleeye-agent --api-key {apiKey}</code>
        </div>
        <button onClick={onClose} className="btn-primary w-full">I have saved the API key</button>
      </div>
    </div>
  )
}

const DEFAULT_AGENT_CONFIG = JSON.stringify({
  subnet:       "192.168.1.0/24",
  location:     "Main Office – Server Room A",
  description:  "Primary LAN scanner",
  scan_options: {
    ports:    "22,80,443,3389,8080,8443,3306,5432",
    timing:   "T4",
    version_detection: true,
  },
  notify_on_offline: true,
  tags: ["production", "internal"],
}, null, 2)

function RegisterModal({ onClose, onSubmit }) {
  const [name, setName] = useState('')
  const [configText, setConfigText] = useState(DEFAULT_AGENT_CONFIG)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    let config
    try { config = JSON.parse(configText) } catch { setError('Config must be valid JSON'); return }
    setSubmitting(true)
    try { await onSubmit({ name, config }) }
    catch (err) { setError(err?.response?.data?.detail || 'Failed to register agent') }
    finally { setSubmitting(false) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="glass-card w-full max-w-md p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Register Agent</h2>
          <button onClick={onClose} className="text-dark-400 hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs text-dark-400 mb-1">Agent Name *</label>
            <input type="text" value={name} onChange={e => setName(e.target.value)} placeholder="branch-office-agent-01" className="input-field w-full text-sm" required />
          </div>
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs text-dark-400">Config (JSON)</label>
              <span className="text-[10px] text-dark-500">Edit to match your network</span>
            </div>
            <textarea value={configText} onChange={e => setConfigText(e.target.value)} rows={14} className="input-field w-full text-xs font-mono resize-y" />
          </div>
          <div className="flex gap-3">
            <button type="button" onClick={onClose} className="btn-secondary flex-1 text-sm">Cancel</button>
            <button type="submit" disabled={submitting} className="btn-primary flex-1 text-sm flex items-center justify-center gap-2">
              {submitting ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Plus className="w-4 h-4" />}
              Register
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Config view/edit modal ────────────────────────────────────────
function ConfigModal({ agent, onClose, onSave, readOnly }) {
  const [configText, setConfigText] = useState(JSON.stringify(agent.config || {}, null, 2))
  const [nameText, setNameText] = useState(agent.name)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const handleSave = async () => {
    setError(null)
    let config
    try { config = JSON.parse(configText) } catch { setError('Config must be valid JSON'); return }
    setSaving(true)
    try {
      await onSave(agent.agent_id, { name: nameText, config })
      onClose()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to save config')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="glass-card w-full max-w-lg p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">
            {readOnly ? 'View' : 'Edit'} Config — {agent.name}
          </h2>
          <button onClick={onClose} className="text-dark-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {readOnly && (
          <p className="text-xs text-dark-400 bg-dark-800/60 border border-dark-700/40 rounded-lg px-3 py-2">
            View-only — you do not have permission to edit agent configuration.
          </p>
        )}

        {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}
        <div>
          <label className="block text-xs text-dark-400 mb-1">Name</label>
          <input
            type="text"
            value={nameText}
            onChange={(e) => setNameText(e.target.value)}
            disabled={readOnly}
            className="input-field w-full text-sm disabled:opacity-50"
          />
        </div>
        <div>
          <label className="block text-xs text-dark-400 mb-1">Config JSON</label>
          <textarea
            value={configText}
            onChange={(e) => setConfigText(e.target.value)}
            rows={10}
            disabled={readOnly}
            className="input-field w-full text-sm font-mono resize-none disabled:opacity-50"
          />
        </div>
        <div className="flex gap-3">
          <button type="button" onClick={onClose} className="btn-secondary flex-1 text-sm">
            {readOnly ? 'Close' : 'Cancel'}
          </button>
          {!readOnly && (
            <button onClick={handleSave} disabled={saving} className="btn-primary flex-1 text-sm flex items-center justify-center gap-2">
              {saving ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Check className="w-4 h-4" />}
              Save Config
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Register bridge modal ─────────────────────────────────────────
function RegisterBridgeModal({ onClose, onSubmit }) {
  const [name, setName] = useState('')
  const [mode, setMode] = useState('relay')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const modeOptions = [
    {
      value: 'relay',
      label: 'Relay',
      description: 'Immediately forward all agent requests (requires stable internet)',
    },
    {
      value: 'buffer',
      label: 'Buffer',
      description: 'Queue scan results in SQLite and flush when online (for unstable links)',
    },
  ]

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await onSubmit({ name, mode })
      onClose()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to register bridge')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="glass-card w-full max-w-md p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Register Bridge</h2>
          <button onClick={onClose} className="text-dark-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs text-dark-400 mb-1">Bridge Name *</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="branch-bridge-01"
              className="input-field w-full text-sm"
              required
            />
          </div>

          <div>
            <label className="block text-xs text-dark-400 mb-1">Mode</label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value)}
              className="input-field w-full text-sm"
            >
              {modeOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
            <p className="text-xs text-dark-500 mt-1">
              {modeOptions.find((o) => o.value === mode)?.description}
            </p>
          </div>

          <div className="flex gap-3">
            <button type="button" onClick={onClose} className="btn-secondary flex-1 text-sm">Cancel</button>
            <button type="submit" disabled={submitting} className="btn-primary flex-1 text-sm flex items-center justify-center gap-2">
              {submitting ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Plus className="w-4 h-4" />}
              Register
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Bridge API Key display modal (shown once on registration) ─────
function BridgeApiKeyModal({ bridgeName, apiKey, bridgeId, onClose }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="glass-card w-full max-w-lg p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Bridge Registered</h2>
          <button onClick={onClose} className="text-dark-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex items-start gap-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-xl">
          <AlertCircle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-yellow-300">
            This API key is shown <strong>only once</strong>. Copy it now and store it securely.
            It cannot be retrieved after closing this dialog.
          </p>
        </div>

        <div>
          <p className="text-xs text-dark-400 mb-2">Bridge: <span className="text-white">{bridgeName}</span></p>
          <p className="text-xs text-dark-400 mb-1">API Key</p>
          <div className="flex items-center gap-2 bg-dark-800/80 border border-dark-600/50 rounded-lg p-3">
            <code className="text-xs font-mono text-accent-cyan flex-1 break-all">{apiKey}</code>
            <CopyButton text={apiKey} />
          </div>
        </div>

        <div className="bg-dark-800/60 border border-dark-700/40 rounded-xl p-4 space-y-2">
          <p className="text-xs text-dark-400 mb-1 font-medium">Setup instructions</p>
          <ol className="text-xs text-dark-300 space-y-1.5 list-decimal list-inside">
            <li>Copy <code className="font-mono text-accent-cyan">bridge.py</code> and <code className="font-mono text-accent-cyan">bridge.env.example</code> to your bridge server</li>
            <li>
              Rename <code className="font-mono text-accent-cyan">bridge.env.example</code> → <code className="font-mono text-accent-cyan">bridge.env</code> and fill in:
              <div className="mt-1 ml-4 font-mono text-dark-400 space-y-0.5">
                <div>BRIDGE_ID=<span className="text-accent-cyan">{bridgeId}</span></div>
                <div>BRIDGE_API_KEY=<span className="text-accent-cyan">{apiKey}</span></div>
                <div>WORKER_URL=https://umeagleeye-api.syntaxch404.workers.dev/api/v1</div>
              </div>
            </li>
            <li>Run: <code className="font-mono text-accent-cyan">python bridge.py</code></li>
            <li>Point isolated agents to: <code className="font-mono text-accent-cyan">http://&lt;bridge-ip&gt;:8080/api/v1</code></li>
          </ol>
        </div>

        <button onClick={onClose} className="btn-primary w-full">
          I have saved the API key
        </button>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────
export default function AgentsPage() {
  const { user } = useAuth()
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showRegister, setShowRegister] = useState(false)
  const [newApiKey, setNewApiKey] = useState(null)
  const [configAgent, setConfigAgent] = useState(null)

  // Bridge state
  const [bridges, setBridges] = useState([])
  const [bridgesLoading, setBridgesLoading] = useState(true)
  const [showRegisterBridge, setShowRegisterBridge] = useState(false)
  const [newBridgeKey, setNewBridgeKey] = useState(null)

  const isReadOnly = ['mssp_analyst', 'business_owner'].includes(user?.role)
  const canManage = ['ops_lead', 'superadmin'].includes(user?.role)

  const loadAgents = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await client.get('/agents')
      setAgents(res.data.agents || [])
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load agents')
    } finally {
      setLoading(false)
    }
  }, [])

  const loadBridges = useCallback(async () => {
    setBridgesLoading(true)
    try {
      const res = await client.get('/bridges')
      setBridges(res.data.bridges || [])
    } catch {
      // silently ignore bridge load errors
    } finally {
      setBridgesLoading(false)
    }
  }, [])

  useEffect(() => {
    loadAgents()
    loadBridges()
  }, [loadAgents, loadBridges])

  const handleRegister = async ({ name, config }) => {
    const res = await client.post('/agents', { name, config })
    setNewApiKey({ name: res.data.name, apiKey: res.data.api_key })
    await loadAgents()
  }

  const handleSaveConfig = async (agentId, updates) => {
    await client.patch(`/agents/${agentId}`, updates)
    setAgents(prev => prev.map(a => a.agent_id === agentId ? { ...a, ...updates } : a))
  }

  const handleDelete = async (agentId, name) => {
    if (!confirm(`Delete agent "${name}"? This cannot be undone.`)) return
    try {
      await client.delete(`/agents/${agentId}`)
      setAgents(prev => prev.filter(a => a.agent_id !== agentId))
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to delete agent')
    }
  }

  const handleRegisterBridge = async ({ name, mode }) => {
    const res = await client.post('/bridges', { name, mode })
    setNewBridgeKey({ name: res.data.name, apiKey: res.data.api_key, bridgeId: res.data.bridge_id })
    await loadBridges()
  }

  const handleDeleteBridge = async (bridgeId, name) => {
    if (!confirm(`Delete bridge "${name}"? This cannot be undone.`)) return
    try {
      await client.delete(`/bridges/${bridgeId}`)
      setBridges(prev => prev.filter(b => b.bridge_id !== bridgeId))
    } catch (err) {
      alert(err?.response?.data?.detail || 'Failed to delete bridge')
    }
  }

  return (
    <div className="space-y-6">
      {/* ── Page header ──────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Agents</h1>
          <p className="text-dark-400 text-sm mt-1">Manage scanning agents and network bridges</p>
        </div>
        <button onClick={() => { loadAgents(); loadBridges() }} disabled={loading} className="btn-secondary flex items-center gap-2 text-sm">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="glass-card p-4 border border-red-500/30">
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      )}

      {/* ── Agents section ───────────────────────────────────────── */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">Scanning Agents</h2>
            <p className="text-dark-400 text-xs mt-0.5">{agents.length} agent{agents.length !== 1 ? 's' : ''} registered — run nmap scans and report results</p>
          </div>
          {canManage && (
            <button onClick={() => setShowRegister(true)} className="btn-primary flex items-center gap-2 text-sm">
              <Plus className="w-4 h-4" /> Register Agent
            </button>
          )}
        </div>

        <div className="glass-card overflow-hidden">
          {loading ? (
            <div className="flex items-center justify-center py-20">
              <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
            </div>
          ) : agents.length > 0 ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Agent Name</th>
                  <th>Connection</th>
                  <th>Status</th>
                  <th>Last Heartbeat</th>
                  <th>Gateway IP</th>
                  <th>Version</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a) => {
                  const bridge = a.bridge_id ? bridges.find((b) => b.bridge_id === a.bridge_id) : null
                  return (
                    <tr key={a.agent_id}>
                      <td>
                        <div>
                          <p className="font-medium text-white">{a.name}</p>
                          <div className="flex items-center gap-1">
                            <p className="text-xs text-dark-500 font-mono">{a.agent_id?.slice(0, 12)}...</p>
                            <CopyButton text={a.agent_id} />
                          </div>
                        </div>
                      </td>
                      <td>
                        {a.bridge_id ? (
                          <span className="bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded text-xs flex items-center gap-1 w-fit">
                            <Network className="w-3 h-3" />
                            {bridge ? bridge.name : 'via bridge'}
                          </span>
                        ) : (
                          <span className="bg-dark-700/60 text-dark-400 border border-dark-600/30 px-2 py-0.5 rounded text-xs">
                            Direct
                          </span>
                        )}
                      </td>
                      <td><StatusBadge status={a.status} /></td>
                      <td className="text-dark-400 text-sm">{relativeTime(a.last_heartbeat)}</td>
                      <td className="font-mono text-sm text-accent-cyan">{a.gateway_ip || '—'}</td>
                      <td className="text-dark-400 text-sm">{a.version || '—'}</td>
                      <td>
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => setConfigAgent(a)}
                            className="p-1.5 hover:bg-dark-700 rounded text-dark-400 hover:text-white transition-colors"
                            title={isReadOnly ? 'View Config' : 'Edit Config'}
                          >
                            <Settings className="w-4 h-4" />
                          </button>
                          {canManage && (
                            <button
                              onClick={() => handleDelete(a.agent_id, a.name)}
                              className="p-1.5 hover:bg-red-500/10 rounded text-dark-400 hover:text-red-400 transition-colors"
                              title="Delete Agent"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          ) : (
            <div className="text-center py-20 text-dark-400">
              <Radio className="w-16 h-16 mx-auto mb-4 opacity-20" />
              <p className="text-lg font-medium mb-2">No agents registered</p>
              <p className="text-sm mb-1">Register your first EagleEye agent to start scanning.</p>
              <p className="text-sm text-dark-500 mb-4">Run: <code className="font-mono text-accent-cyan">./eagleeye-agent --api-key &lt;key&gt;</code></p>
              {canManage && (
                <button onClick={() => setShowRegister(true)} className="btn-primary">
                  <Plus className="w-4 h-4 mr-2" /> Register Agent
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ── Bridges section ──────────────────────────────────────── */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">Bridges</h2>
            <p className="text-dark-400 text-xs mt-0.5">Optional relay for agents in isolated networks with no internet access</p>
          </div>
          {canManage && (
            <button onClick={() => setShowRegisterBridge(true)} className="btn-secondary flex items-center gap-2 text-sm">
              <Plus className="w-4 h-4" />
              Register Bridge
            </button>
          )}
        </div>

        <div className="glass-card overflow-hidden">
          {bridgesLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
            </div>
          ) : bridges.length > 0 ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Bridge Name</th>
                  <th>Mode</th>
                  <th>Status</th>
                  <th>Last Heartbeat</th>
                  <th>Bridge IP</th>
                  <th>Agents Behind</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {bridges.map((b) => (
                  <tr key={b.bridge_id}>
                    <td>
                      <div>
                        <p className="font-medium text-white">{b.name}</p>
                        <div className="flex items-center gap-1">
                          <p className="text-xs text-dark-500 font-mono">{b.bridge_id?.slice(0, 12)}...</p>
                          <CopyButton text={b.bridge_id} />
                        </div>
                      </div>
                    </td>
                    <td>
                      <span className={`text-xs px-2 py-0.5 rounded border font-medium ${
                        b.mode === 'relay'
                          ? 'bg-blue-500/20 text-blue-400 border-blue-500/30'
                          : 'bg-purple-500/20 text-purple-400 border-purple-500/30'
                      }`}>
                        {b.mode}
                      </span>
                    </td>
                    <td><StatusBadge status={b.status} /></td>
                    <td className="text-dark-400 text-sm">{relativeTime(b.last_heartbeat)}</td>
                    <td className="font-mono text-sm text-accent-cyan">{b.bridge_ip || '—'}</td>
                    <td className="text-dark-400 text-sm">{b.agent_count ?? 0}</td>
                    <td>
                      {canManage && (
                        <button
                          onClick={() => handleDeleteBridge(b.bridge_id, b.name)}
                          className="p-1.5 hover:bg-red-500/10 rounded text-dark-400 hover:text-red-400 transition-colors"
                          title="Delete Bridge"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="text-center py-12 text-dark-400">
              <Waypoints className="w-12 h-12 mx-auto mb-3 opacity-20" />
              <p className="text-base font-medium mb-1">No bridges registered</p>
              <p className="text-sm text-dark-500">Only needed if your agent machine has no internet access.</p>
              {canManage && (
                <button onClick={() => setShowRegisterBridge(true)} className="btn-secondary mt-4">
                  <Plus className="w-4 h-4 mr-2" />
                  Register Bridge
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {showRegister && (
        <RegisterModal
          onClose={() => setShowRegister(false)}
          onSubmit={async (data) => { await handleRegister(data); setShowRegister(false) }}
        />
      )}
      {newApiKey && (
        <ApiKeyModal agentName={newApiKey.name} apiKey={newApiKey.apiKey} onClose={() => setNewApiKey(null)} />
      )}
      {configAgent && (
        <ConfigModal
          agent={configAgent}
          onClose={() => setConfigAgent(null)}
          onSave={handleSaveConfig}
          readOnly={!canManage}
        />
      )}

      {showRegisterBridge && (
        <RegisterBridgeModal onClose={() => setShowRegisterBridge(false)} onSubmit={handleRegisterBridge} />
      )}

      {newBridgeKey && (
        <BridgeApiKeyModal
          bridgeName={newBridgeKey.name}
          apiKey={newBridgeKey.apiKey}
          bridgeId={newBridgeKey.bridgeId}
          onClose={() => setNewBridgeKey(null)}
        />
      )}
    </div>
  )
}
