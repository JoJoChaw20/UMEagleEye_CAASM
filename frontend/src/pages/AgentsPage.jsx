import { useState, useEffect, useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Plus, X, RefreshCw, Radio, AlertCircle, ChevronDown, ChevronRight, Monitor, Download,
} from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'
import ScanPolicyCard from '../components/common/ScanPolicyCard'
import AgentPanel from '../components/agents/AgentPanel'
import AgentDefaultsCard from '../components/agents/AgentDefaultsCard'
import InstallTab, { DownloadButton, useDownloads } from '../components/agents/InstallTab'
import { ROLES } from '../components/agents/policy'
import { CopyButton, MobileBadge, NetworkBadge, Seen, StatusBadge } from '../components/agents/parts'
import { agentApiUrl, makeConnectionCode } from '../utils/connectionCode'

// Agents, in three tabs: the agents (a row opens its panel: settings and actions), Install
// (downloads and guides per OS, connection code for one computer, install codes for many) and Defaults (the
// tenant's default settings). Settings are set only here (2.6); the agent's app shows them.
// The 1.x agents (eagleeye_agent.py) are retired: listed apart, with their history.

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
function ConnectionModal({ agentName, agentId, apiKey, rotated, installer, onClose }) {   // installer: the Windows download
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
          {!rotated && (
            <li>
              Install the agent with{' '}
              <code className="font-mono text-xs">{installer?.filename ?? 'EagleEyeAgent-Setup-<version>.exe'}</code>
              {installer && (
                <span className="ml-2 align-middle">
                  <DownloadButton pkg={installer} package="windows" className="btn-secondary !py-1 !px-2" label="Download" details={false} />
                </span>
              )}
              . It needs administrator rights on that computer.
            </li>
          )}
          <li>Open <strong>Connection</strong> in the agent, paste the code into <strong>Connection code</strong> and choose <strong>Use code</strong>.</li>
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
// The roles an agent has (read from its settings), and whether it applied the latest change.
function Roles({ a }) {
  if (!a.roles) return <span className="text-dark-500">—</span>
  const on = ROLES.filter((r) => a.roles[r.key])
  return (
    <div className="flex flex-wrap items-center gap-1">
      {on.map((r) => (
        <span key={r.key} title={r.help} className="px-2 py-0.5 rounded-full text-[11px] border border-eagle-500/30 bg-eagle-500/10 text-eagle-300">{r.label}</span>
      ))}
      {on.length === 0 && <span className="text-xs text-dark-500">None</span>}
      {a.policy?.in_sync === false && (
        <span className="text-[11px] text-yellow-400" title="The agent applies the latest settings at its next heartbeat">applying…</span>
      )}
    </div>
  )
}

// What the agent looks after: its computer, or (a network agent) the routers and switches.
function Where({ a }) {
  if (a.kind === 'network') return <span className="text-[11px] text-dark-500">routers and switches{a.host ? ` · from ${a.host.hostname || a.host.ip_address}` : ''}</span>
  if (a.host) {
    return (
      <span className="text-[11px] text-dark-400 inline-flex items-center gap-1">
        <Monitor className="w-3 h-3" /> {a.host.hostname || a.host.ip_address}
        {a.networks?.length > 0 && <span className="font-mono text-dark-500"> · {a.networks.join(', ')}</span>}
      </span>
    )
  }
  return <span className="text-[11px] text-dark-500">{a.local_ip ? <span className="font-mono">{a.local_ip}</span> : a.status === 'retired' ? '' : 'Not reported yet'}</span>
}

function AgentRow({ a, showTenant, tenantName, onOpen }) {
  const retired = a.status === 'retired'
  return (
    <tr
      className={`cursor-pointer hover:bg-dark-800/50 ${retired ? 'opacity-70' : ''}`} tabIndex={0}
      onClick={() => onOpen(a)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen(a) } }}
      aria-label={`Open ${a.name}`}
    >
      <td>
        <p className="font-medium text-dark-50 flex items-center gap-1.5 flex-wrap">
          {a.name}
          {a.kind === 'network' && <NetworkBadge />}
          {a.kind === 'mobile' && <MobileBadge />}
        </p>
        <Where a={a} />
      </td>
      <td>
        <div className="flex flex-col items-start gap-0.5">
          <StatusBadge status={a.status} />
          {!retired && <span className="text-[11px]"><Seen value={a.last_heartbeat} nullText="never seen" /></span>}
        </div>
      </td>
      <td>{retired ? <span className="text-dark-500">—</span> : <Roles a={a} />}</td>
      <td className="text-sm whitespace-nowrap">
        {a.version
          ? <span className={a.legacy ? 'text-dark-400' : 'text-dark-200'}>{a.version}{a.legacy && <span className="text-dark-500"> · old</span>}</span>
          : <span className="text-dark-500">—</span>}
      </td>
      {showTenant && <td className="text-sm text-dark-300">{tenantName ?? <span className="text-dark-500">—</span>}</td>}
      <td className="w-8 text-dark-500"><ChevronRight className="w-4 h-4" /></td>
    </tr>
  )
}

// ── Main page ─────────────────────────────────────────────────────
const TABS = [
  { key: 'agents', label: 'Agents' },
  { key: 'install', label: 'Install' },
  { key: 'defaults', label: 'Defaults' },
]

export default function AgentsPage() {
  const { user } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [busy, setBusy] = useState(null)
  const [showRegister, setShowRegister] = useState(false)
  const [connection, setConnection] = useState(null)     // { agentName, agentId, apiKey, rotated }
  const [renaming, setRenaming] = useState(null)
  const [openId, setOpenId] = useState(null)             // the agent whose panel is open
  const [showRetired, setShowRetired] = useState(false)
  const [tenants, setTenants] = useState([])
  const [tenantFilter, setTenantFilter] = useState(() => searchParams.get('tenant_id') ?? '')

  const tab = TABS.some((t) => t.key === searchParams.get('tab')) ? searchParams.get('tab') : 'agents'
  const setParam = (key, value) => {
    const next = new URLSearchParams(searchParams)
    if (value) next.set(key, value)
    else next.delete(key)
    setSearchParams(next, { replace: true })
  }

  const isSuperadmin = user?.role === 'superadmin'
  const canManage = ['tenant_superadmin', 'tenant_admin'].includes(user?.role)
  const downloads = useDownloads()

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
    setTenantFilter(searchParams.get('tenant_id') ?? '')
  }, [searchParams])

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

  const runNow = async (agent) => {
    setBusy(agent.agent_id)
    try {
      const res = await client.post(`/network/run/${agent.agent_id}`)
      setNotice(res.data.status === 'already waiting'
        ? `${agent.name} already has a crawl waiting.`
        : `${agent.name} reads the network at its next heartbeat (within a minute); the result appears on the Discovery page.`)
    } catch (err) {
      alert(err?.response?.data?.detail || 'Could not start the crawl')
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
      setOpenId(null)
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
  const opened = agents.find((a) => a.agent_id === openId)
  const listed = showRetired ? retired : active
  const policyTenant = isSuperadmin ? tenantFilter : user?.tenantId

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="page-title">Agents</h1>
          <p className="text-dark-400 text-sm mt-1 max-w-2xl">
            An EagleEye Agent on each computer reports it and scans its network; network agents read the routers and switches.
            Their settings are set here.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <TenantSelector value={tenantFilter} onChange={(tenantId) => { setTenantFilter(tenantId); setParam('tenant_id', tenantId) }} />
          <button onClick={load} disabled={loading} className="btn-secondary flex items-center gap-2 text-sm">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      <div className="flex gap-1 border-b border-dark-700/60" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.key} role="tab" aria-selected={tab === t.key} onClick={() => setParam('tab', t.key === 'agents' ? '' : t.key)}
            className={`px-4 py-2 text-sm -mb-px border-b-2 transition-colors ${tab === t.key
              ? 'border-eagle-500 text-dark-50' : 'border-transparent text-dark-400 hover:text-dark-200'}`}
          >
            {t.label}
            {t.key === 'agents' && !loading && <span className="ml-1.5 text-xs text-dark-500">{active.length}</span>}
          </button>
        ))}
      </div>

      {error && <div className="glass-card p-4 border border-red-500/30"><p className="text-red-400 text-sm">{error}</p></div>}
      {notice && <div className="glass-card px-4 py-3 text-sm text-dark-200 border border-green-500/30">{notice}</div>}

      {tab === 'agents' && (
        <>
          {!loading && (active.length > 0 || retired.length > 0) && (
            <div className="flex flex-wrap items-center gap-2 text-sm" aria-label="Agent status summary">
              <span className="px-3 py-1 rounded-full border border-green-500/30 bg-green-500/10 text-green-400">{counts.online} online</span>
              {counts.late > 0 && <span className="px-3 py-1 rounded-full border border-yellow-500/30 bg-yellow-500/10 text-yellow-400">{counts.late} late</span>}
              <span className={`px-3 py-1 rounded-full border ${counts.offline ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-dark-600/40 text-dark-400'}`}>{counts.offline} offline</span>
              {retired.length > 0 && (
                <button type="button" onClick={() => setShowRetired((v) => !v)} aria-pressed={showRetired}
                  title="Old 1.x agents that can no longer connect; their Discovery history is kept"
                  className={`ml-auto px-3 py-1 rounded-full border text-xs ${showRetired ? 'border-eagle-500/40 text-eagle-300' : 'border-dark-600/40 text-dark-400 hover:text-dark-200'}`}>
                  {showRetired ? 'Show current agents' : `Show retired (${retired.length})`}
                </button>
              )}
            </div>
          )}

          <div className="glass-card overflow-hidden">
            {loading ? (
              <div className="flex items-center justify-center py-20">
                <div className="w-8 h-8 border-4 border-eagle-500/30 border-t-eagle-500 rounded-full animate-spin" />
              </div>
            ) : listed.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Agent</th>
                      <th>Status</th>
                      <th>Roles</th>
                      <th>Version</th>
                      {isSuperadmin && <th>Tenant</th>}
                      <th aria-label="Open" />
                    </tr>
                  </thead>
                  <tbody>
                    {listed.map((a) => (
                      <AgentRow key={a.agent_id} a={a} showTenant={isSuperadmin} tenantName={tenantName(a.tenant_id)} onOpen={(x) => setOpenId(x.agent_id)} />
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-center py-16 text-dark-400 px-4">
                <Radio className="w-14 h-14 mx-auto mb-4 opacity-20" />
                <p className="text-lg font-medium mb-2 text-dark-200">No agents yet</p>
                <p className="text-sm max-w-md mx-auto">Install EagleEye Agent on a computer and connect it with a connection code, or use an install code for many computers.</p>
                <button onClick={() => setParam('tab', 'install')} className="btn-primary mt-4 inline-flex items-center gap-2">
                  <Download className="w-4 h-4" /> Install agents
                </button>
              </div>
            )}
          </div>
        </>
      )}

      {tab === 'install' && (
        <InstallTab downloads={downloads} canManage={canManage} isSuperadmin={isSuperadmin} onRegister={() => setShowRegister(true)} />
      )}

      {tab === 'defaults' && (
        <div className="space-y-6">
          <AgentDefaultsCard tenantId={policyTenant} onSaved={load} />
          {/* Platform superadmin: the policy of the tenant picked in the filter */}
          <ScanPolicyCard tenantId={policyTenant} canEdit={isSuperadmin || user?.role === 'tenant_superadmin'} />
        </div>
      )}

      {opened && (
        <AgentPanel
          agent={opened} tenantName={isSuperadmin ? tenantName(opened.tenant_id) : null} canManage={canManage}
          busy={busy === opened.agent_id} onClose={() => setOpenId(null)} onSaved={load}
          onRename={setRenaming} onRotate={rotate} onDelete={remove} onRunNow={runNow}
        />
      )}
      {showRegister && <RegisterModal onClose={() => setShowRegister(false)} onSubmit={register} />}
      {connection && <ConnectionModal {...connection} installer={downloads?.windows} onClose={() => setConnection(null)} />}
      {renaming && <RenameModal agent={renaming} onClose={() => setRenaming(null)} onSave={rename} />}
    </div>
  )
}
