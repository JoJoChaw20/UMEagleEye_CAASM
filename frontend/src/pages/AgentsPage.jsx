import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  Plus, Trash2, Copy, Check, X, RefreshCw, Radio, AlertCircle, KeyRound, Pencil, ChevronDown, ChevronRight, Monitor,
} from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'
import { formatSeen } from '../utils/time'
import { agentApiUrl, makeConnectionCode } from '../utils/connectionCode'

// Agents: one EagleEye Agent per computer. It scans the computer's network and reports
// the computer's own inventory and security settings. The 1.x agents (eagleeye_agent.py)
// are retired: their keys are revoked and they are listed apart, with their history.

const INSTALLER_NAME = 'EagleEyeAgent-Setup-2.0.2.exe'

// ── Small parts ───────────────────────────────────────────────────
const STATUS_META = {
  online:   { label: 'Online',   cls: 'bg-green-500/20 text-green-400 border-green-500/30',   dot: 'bg-green-400 animate-pulse' },
  degraded: { label: 'Late',     cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', dot: 'bg-yellow-400' },
  offline:  { label: 'Offline',  cls: 'bg-red-500/20 text-red-400 border-red-500/30',          dot: 'bg-red-400' },
  retired:  { label: 'Retired',  cls: 'bg-dark-600/40 text-dark-400 border-dark-500/30',       dot: 'bg-dark-500' },
}

function StatusBadge({ status }) {
  const m = STATUS_META[status] ?? STATUS_META.offline
  return (
    <span
      className={`text-xs px-2 py-0.5 rounded-full border font-medium inline-flex items-center gap-1.5 ${m.cls}`}
      title={status === 'degraded' ? 'No heartbeat for 2 to 10 minutes' : undefined}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${m.dot}`} />
      {m.label}
    </span>
  )
}

function CopyButton({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1800) } catch { /* select by hand */ }
  }
  return (
    <button type="button" onClick={copy} className="p-1.5 hover:bg-eagle-500/10 rounded text-dark-400 hover:text-eagle-400 transition-colors flex-shrink-0" title={label} aria-label={label}>
      {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
    </button>
  )
}

function Seen({ value, nullText }) {
  const s = formatSeen(value, { nullText })
  return <span title={s.title || ''} className={s.stale ? 'text-amber-400' : 'text-dark-300'}>{s.text}</span>
}

function Modal({ title, onClose, children, wide = false }) {
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 overflow-y-auto" role="dialog" aria-modal="true" aria-label={title}>
      <div className={`glass-card w-full ${wide ? 'max-w-xl' : 'max-w-md'} p-6 space-y-4 my-auto`}>
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          <button onClick={onClose} className="text-dark-400 hover:text-white" aria-label="Close"><X className="w-5 h-5" /></button>
        </div>
        {children}
      </div>
    </div>
  )
}

function ValueRow({ label, value, mono = true }) {
  return (
    <div>
      <p className="text-xs text-dark-400 mb-1">{label}</p>
      <div className="flex items-center gap-2 bg-dark-800/80 border border-dark-600/50 rounded-lg px-3 py-2">
        <code className={`text-xs ${mono ? 'font-mono' : ''} text-dark-100 flex-1 break-all`}>{value}</code>
        <CopyButton text={value} label={`Copy ${label}`} />
      </div>
    </div>
  )
}

// ── Register ──────────────────────────────────────────────────────
function RegisterModal({ onClose, onSubmit }) {
  const [name, setName] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const submit = async (e) => {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try { await onSubmit(name.trim()) }
    catch (err) { setError(err?.response?.data?.detail || 'Could not register the agent') }
    finally { setSubmitting(false) }
  }

  return (
    <Modal title="Register an agent" onClose={onClose}>
      <p className="text-sm text-dark-300">Register one agent for each computer. You get a connection code to paste into the agent on that computer.</p>
      {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label htmlFor="agent-name" className="block text-xs text-dark-400 mb-1">Name</label>
          <input id="agent-name" type="text" value={name} onChange={(e) => setName(e.target.value)} maxLength={100}
            placeholder="e.g. Finance laptop 03 or Server room PC" className="input-field w-full text-sm" required autoFocus />
          <p className="text-[11px] text-dark-500 mt-1">A name you will recognise. The computer's own name appears beside it once the agent reports.</p>
        </div>
        <div className="flex gap-3">
          <button type="button" onClick={onClose} className="btn-secondary flex-1 text-sm">Cancel</button>
          <button type="submit" disabled={submitting || !name.trim()} className="btn-primary flex-1 text-sm flex items-center justify-center gap-2">
            {submitting ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Plus className="w-4 h-4" />}
            Register
          </button>
        </div>
      </form>
    </Modal>
  )
}

// ── Connection details (after Register or Rotate key) ─────────────
function ConnectionModal({ agentName, agentId, apiKey, rotated, onClose }) {
  const apiUrl = agentApiUrl(client.defaults.baseURL)
  const code = makeConnectionCode({ apiUrl, agentId, apiKey })
  const [showValues, setShowValues] = useState(false)
  return (
    <Modal title={rotated ? `New key for ${agentName}` : `${agentName} is registered`} onClose={onClose} wide>
      <div className="flex items-start gap-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-xl">
        <AlertCircle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
        <p className="text-xs text-yellow-200">
          The API key inside this code is shown <strong>only now</strong>. Copy the code before closing.
          {rotated && ' The old key has stopped working: the agent disconnects until the new code is pasted.'}
        </p>
      </div>

      <ValueRow label="Connection code" value={code} />

      <div className="rounded-xl bg-dark-800/60 border border-dark-700/40 p-4 space-y-2 text-sm text-dark-200">
        <p className="text-xs font-medium text-dark-400 uppercase tracking-wider">On that computer</p>
        <ol className="list-decimal pl-5 space-y-1">
          {!rotated && <li>Install the agent with <code className="font-mono text-xs">{INSTALLER_NAME}</code>.</li>}
          <li>Open <strong>Settings</strong> in the agent, paste the code into <strong>Connection code</strong> and choose <strong>Use code</strong>.</li>
          <li>Choose <strong>Test connection</strong>, then <strong>Save</strong>.</li>
        </ol>
        <p className="text-xs text-dark-400">Send the code over a private channel: anyone with it can report as this agent.</p>
      </div>

      <button type="button" onClick={() => setShowValues((v) => !v)} className="text-xs text-eagle-400 hover:underline inline-flex items-center gap-1">
        {showValues ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
        Show the three values separately (for agents older than 2.0.2 or the command line)
      </button>
      {showValues && (
        <div className="space-y-3">
          <ValueRow label="API URL" value={apiUrl} />
          <ValueRow label="Agent ID" value={agentId} />
          <ValueRow label="API key" value={apiKey} />
        </div>
      )}

      <button onClick={onClose} className="btn-primary w-full">I have copied the code</button>
    </Modal>
  )
}

// ── Rename ────────────────────────────────────────────────────────
function RenameModal({ agent, onClose, onSave }) {
  const [name, setName] = useState(agent.name)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const submit = async (e) => {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try { await onSave(agent, name.trim()); onClose() }
    catch (err) { setError(err?.response?.data?.detail || 'Could not rename the agent') }
    finally { setSaving(false) }
  }
  return (
    <Modal title="Rename agent" onClose={onClose}>
      {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label htmlFor="rename-agent" className="block text-xs text-dark-400 mb-1">Name</label>
          <input id="rename-agent" type="text" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} className="input-field w-full text-sm" required autoFocus />
        </div>
        <div className="flex gap-3">
          <button type="button" onClick={onClose} className="btn-secondary flex-1 text-sm">Cancel</button>
          <button type="submit" disabled={saving || !name.trim() || name.trim() === agent.name} className="btn-primary flex-1 text-sm">Save</button>
        </div>
      </form>
    </Modal>
  )
}

// ── One agent row ─────────────────────────────────────────────────
function AgentRow({ a, canManage, showTenant, tenantName, onRename, onRotate, onDelete, busy }) {
  const retired = a.status === 'retired'
  return (
    <tr className={retired ? 'opacity-70' : ''}>
      <td>
        <p className="font-medium text-white">{a.name}</p>
        <div className="flex items-center gap-1 mt-0.5">
          <p className="text-[11px] text-dark-500 font-mono truncate max-w-[16rem]" title={a.agent_id}>{a.agent_id}</p>
          <CopyButton text={a.agent_id} label="Copy agent ID" />
        </div>
      </td>
      <td><StatusBadge status={a.status} /></td>
      <td>
        {a.host ? (
          <Link to={`/inventory/${a.host.asset_id}`} className="group inline-flex items-start gap-2">
            <Monitor className="w-4 h-4 mt-0.5 text-dark-400 group-hover:text-eagle-400" />
            <span>
              <span className="block text-sm text-dark-100 group-hover:text-eagle-400">{a.host.hostname || a.host.ip_address}</span>
              <span className="block text-[11px] font-mono text-dark-400">{a.host.ip_address}</span>
            </span>
          </Link>
        ) : (
          <span className="text-xs text-dark-500" title="Shown after the agent's first inventory report">
            {retired ? '—' : (a.local_ip ? <span className="font-mono">{a.local_ip}</span> : 'Not reported yet')}
          </span>
        )}
      </td>
      <td className="text-sm"><Seen value={a.last_heartbeat} nullText="Never" /></td>
      <td className="text-sm">{a.host ? <Seen value={a.host.inventory_collected_at} nullText="—" /> : <span className="text-dark-500">—</span>}</td>
      <td className="text-sm whitespace-nowrap">
        {a.version
          ? <span className={a.legacy ? 'text-dark-400' : 'text-dark-200'}>{a.version}{a.legacy && <span className="text-dark-500"> · old agent</span>}</span>
          : <span className="text-dark-500">—</span>}
      </td>
      {showTenant && <td className="text-sm text-dark-300">{tenantName ?? <span className="text-dark-500">—</span>}</td>}
      {canManage && (
        <td>
          <div className="flex items-center gap-1">
            {!retired && (
              <>
                <button onClick={() => onRename(a)} className="p-1.5 hover:bg-dark-700 rounded text-dark-400 hover:text-white transition-colors" title="Rename" aria-label={`Rename ${a.name}`}>
                  <Pencil className="w-4 h-4" />
                </button>
                <button onClick={() => onRotate(a)} disabled={busy === a.agent_id} className="p-1.5 hover:bg-eagle-500/10 rounded text-dark-400 hover:text-eagle-400 transition-colors" title="New connection code (rotate the API key)" aria-label={`Rotate the key of ${a.name}`}>
                  <KeyRound className="w-4 h-4" />
                </button>
              </>
            )}
            <button onClick={() => onDelete(a)} disabled={busy === a.agent_id} className="p-1.5 hover:bg-red-500/10 rounded text-dark-400 hover:text-red-400 transition-colors" title="Delete" aria-label={`Delete ${a.name}`}>
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        </td>
      )}
    </tr>
  )
}

// ── Main page ─────────────────────────────────────────────────────
export default function AgentsPage() {
  const { user } = useAuth()
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [busy, setBusy] = useState(null)
  const [showRegister, setShowRegister] = useState(false)
  const [connection, setConnection] = useState(null)     // { agentName, agentId, apiKey, rotated }
  const [renaming, setRenaming] = useState(null)
  const [showRetired, setShowRetired] = useState(false)
  const [tenants, setTenants] = useState([])
  const [tenantFilter, setTenantFilter] = useState('')

  const isSuperadmin = user?.role === 'superadmin'
  const canManage = ['tenant_superadmin', 'tenant_admin'].includes(user?.role)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await client.get('/agents')
      setAgents(res.data.agents || [])
    } catch (err) {
      setError(err?.response?.data?.detail || 'Could not load the agents')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    if (isSuperadmin) client.get('/tenants').then((r) => setTenants(r.data.tenants || [])).catch(() => {})
  }, [load, isSuperadmin])

  useEffect(() => {
    if (!notice) return undefined
    const t = setTimeout(() => setNotice(null), 6000)
    return () => clearTimeout(t)
  }, [notice])

  const register = async (name) => {
    const res = await client.post('/agents', { name })
    setShowRegister(false)
    setConnection({ agentName: res.data.name, agentId: res.data.agent_id, apiKey: res.data.api_key, rotated: false })
    await load()
  }

  const rename = async (agent, name) => {
    await client.patch(`/agents/${agent.agent_id}`, { name })
    setAgents((prev) => prev.map((a) => (a.agent_id === agent.agent_id ? { ...a, name } : a)))
  }

  const rotate = async (agent) => {
    if (!confirm(`Issue a new connection code for "${agent.name}"?\n\nThe current key stops working at once, so the agent disconnects until the new code is pasted into it.`)) return
    setBusy(agent.agent_id)
    try {
      const res = await client.post(`/agents/${agent.agent_id}/rotate-key`)
      setConnection({ agentName: res.data.name, agentId: res.data.agent_id, apiKey: res.data.api_key, rotated: true })
    } catch (err) {
      alert(err?.response?.data?.detail || 'Could not rotate the key')
    } finally {
      setBusy(null)
    }
  }

  const remove = async (agent) => {
    if (!confirm(
      `Delete agent "${agent.name}"?\n\n` +
      'This also deletes every Discovery record the agent produced. The assets it found stay. This cannot be undone.' +
      (agent.status === 'retired' ? '' : '\n\nTo stop it reporting but keep its history, uninstall the agent on its computer instead.'),
    )) return
    setBusy(agent.agent_id)
    try {
      await client.delete(`/agents/${agent.agent_id}`)
      setAgents((prev) => prev.filter((a) => a.agent_id !== agent.agent_id))
      setNotice(`${agent.name} deleted.`)
    } catch (err) {
      alert(err?.response?.data?.detail || 'Could not delete the agent')
    } finally {
      setBusy(null)
    }
  }

  const scoped = tenantFilter ? agents.filter((a) => a.tenant_id === tenantFilter) : agents
  const active = useMemo(() => scoped.filter((a) => a.status !== 'retired')
    .sort((x, y) => x.name.localeCompare(y.name)), [scoped])
  const retired = useMemo(() => scoped.filter((a) => a.status === 'retired'), [scoped])
  const counts = useMemo(() => ({
    online: active.filter((a) => a.status === 'online').length,
    late: active.filter((a) => a.status === 'degraded').length,
    offline: active.filter((a) => a.status === 'offline').length,
  }), [active])
  const tenantName = (id) => tenants.find((t) => t.tenant_id === id)?.name

  const head = (
    <thead>
      <tr>
        <th>Agent</th>
        <th>Status</th>
        <th>Computer</th>
        <th>Last heartbeat</th>
        <th>Last inventory</th>
        <th>Version</th>
        {isSuperadmin && <th>Tenant</th>}
        {canManage && <th>Actions</th>}
      </tr>
    </thead>
  )
  const row = (a) => (
    <AgentRow key={a.agent_id} a={a} canManage={canManage} showTenant={isSuperadmin} tenantName={tenantName(a.tenant_id)}
      onRename={setRenaming} onRotate={rotate} onDelete={remove} busy={busy} />
  )

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Agents</h1>
          <p className="text-dark-400 text-sm mt-1 max-w-2xl">
            One EagleEye Agent per computer. It scans that computer's network and reports the computer's security settings.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <TenantSelector value={tenantFilter} onChange={setTenantFilter} />
          <button onClick={load} disabled={loading} className="btn-secondary flex items-center gap-2 text-sm">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
          {canManage && (
            <button onClick={() => setShowRegister(true)} className="btn-primary flex items-center gap-2 text-sm">
              <Plus className="w-4 h-4" /> Register agent
            </button>
          )}
        </div>
      </div>

      {error && <div className="glass-card p-4 border border-red-500/30"><p className="text-red-400 text-sm">{error}</p></div>}
      {notice && <div className="glass-card px-4 py-3 text-sm text-dark-200 border border-green-500/30">{notice}</div>}

      {!loading && active.length > 0 && (
        <div className="flex flex-wrap gap-2 text-sm" aria-label="Agent status summary">
          <span className="px-3 py-1 rounded-full border border-green-500/30 bg-green-500/10 text-green-400">{counts.online} online</span>
          {counts.late > 0 && <span className="px-3 py-1 rounded-full border border-yellow-500/30 bg-yellow-500/10 text-yellow-400">{counts.late} late</span>}
          <span className={`px-3 py-1 rounded-full border ${counts.offline ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-dark-600/40 text-dark-400'}`}>{counts.offline} offline</span>
        </div>
      )}

      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
          </div>
        ) : active.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="data-table">{head}<tbody>{active.map(row)}</tbody></table>
          </div>
        ) : (
          <div className="text-center py-16 text-dark-400 px-4">
            <Radio className="w-14 h-14 mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium mb-2 text-dark-200">No agents yet</p>
            <p className="text-sm max-w-md mx-auto">Register an agent, install EagleEye Agent on the computer, and paste the connection code you get into its Settings.</p>
            {canManage && (
              <button onClick={() => setShowRegister(true)} className="btn-primary mt-4 inline-flex items-center gap-2">
                <Plus className="w-4 h-4" /> Register agent
              </button>
            )}
          </div>
        )}
      </div>

      {retired.length > 0 && (
        <div className="glass-card overflow-hidden">
          <button onClick={() => setShowRetired((v) => !v)} className="w-full flex items-center gap-2 px-4 py-3 text-sm text-dark-200 hover:bg-dark-800/40" aria-expanded={showRetired}>
            {showRetired ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
            Retired agents ({retired.length})
            <span className="text-xs text-dark-400">old 1.x agents that can no longer connect; their Discovery history is kept</span>
          </button>
          {showRetired && (
            <div className="overflow-x-auto border-t border-dark-700/50">
              <table className="data-table">{head}<tbody>{retired.map(row)}</tbody></table>
            </div>
          )}
        </div>
      )}

      {showRegister && <RegisterModal onClose={() => setShowRegister(false)} onSubmit={register} />}
      {connection && <ConnectionModal {...connection} onClose={() => setConnection(null)} />}
      {renaming && <RenameModal agent={renaming} onClose={() => setRenaming(null)} onSave={rename} />}
    </div>
  )
}
