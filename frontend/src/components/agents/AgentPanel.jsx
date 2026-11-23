// One agent, in a panel beside the Agents list: what it is, what to do with it, and its
// settings (GET/PATCH /agents/:id/policy). The agent applies a settings change at its next
// heartbeat (within a minute), between jobs; its app only shows them.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, KeyRound, Monitor, Pencil, Play, RefreshCw, Trash2, X } from 'lucide-react'
import client from '../../api/client'
import { GROUPS, PolicyInput, ROLES, SOURCE_LABEL, helpOf, invalid, labelOf, metaOf, same, show } from './policy'
import { useAuth } from '../../context/AuthContext'
import { requiresTitle } from '../../utils/actions'
import { CopyButton, NetworkBadge, Seen, StatusBadge } from './parts'
import AgentUpdate from './AgentUpdate'

export default function AgentPanel({ agent, tenantName, busy, onClose, onSaved, onRename, onRotate, onDelete, onRunNow }) {
  const { can } = useAuth()
  const retired = agent.status === 'retired'
  const network = agent.kind === 'network'
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-dark-950/50" onClick={onClose}>
      <aside
        className="h-full w-full max-w-xl bg-dark-900 border-l border-dark-700/60 shadow-2xl overflow-y-auto"
        role="dialog" aria-modal="true" aria-label={agent.name} onClick={(e) => e.stopPropagation()}
      >
        <div className="sticky top-0 z-10 bg-dark-900/95 backdrop-blur border-b border-dark-700/60 px-6 py-4 flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="text-lg font-semibold text-dark-50 truncate">{agent.name}</h2>
            <div className="flex items-center gap-2 mt-1 flex-wrap">
              <StatusBadge status={agent.status} />
              {network && <NetworkBadge />}
              {agent.version && <span className="text-xs text-dark-400">{agent.version}{agent.legacy && ' · old agent'}</span>}
            </div>
          </div>
          <button onClick={onClose} className="text-dark-400 hover:text-dark-50" aria-label="Close"><X className="w-5 h-5" /></button>
        </div>

        <div className="px-6 py-5 space-y-6">
          <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-2 text-sm">
            <dt className="text-dark-400">{network ? 'Runs on' : 'Computer'}</dt>
            <dd>
              {agent.host ? (
                <Link to={`/inventory/${agent.host.asset_id}`} className="inline-flex items-center gap-1.5 text-dark-100 hover:text-eagle-400">
                  <Monitor className="w-4 h-4 text-dark-400" />
                  {agent.host.hostname || agent.host.ip_address}
                  <span className="font-mono text-xs text-dark-400">{agent.host.ip_address}</span>
                </Link>
              ) : agent.local_ip ? <span className="font-mono text-dark-200">{agent.local_ip}</span>
                : <span className="text-dark-500">{retired ? '—' : 'Not reported yet'}</span>}
            </dd>
            {!network && agent.networks?.length > 0 && (
              <>
                <dt className="text-dark-400" title="New scan sends scans of these networks to this agent">Networks</dt>
                <dd className="font-mono text-xs text-dark-200 pt-0.5">{agent.networks.join(', ')}</dd>
              </>
            )}
            <dt className="text-dark-400">Last heartbeat</dt>
            <dd><Seen value={agent.last_heartbeat} nullText="Never" /></dd>
            {!network && (
              <>
                <dt className="text-dark-400">Last inventory</dt>
                <dd>{agent.host ? <Seen value={agent.host.inventory_collected_at} nullText="—" /> : <span className="text-dark-500">—</span>}</dd>
              </>
            )}
            {tenantName && (<><dt className="text-dark-400">Tenant</dt><dd className="text-dark-200">{tenantName}</dd></>)}
            <dt className="text-dark-400">Agent ID</dt>
            <dd className="flex items-center gap-1 min-w-0">
              <span className="font-mono text-xs text-dark-300 truncate" title={agent.agent_id}>{agent.agent_id}</span>
              <CopyButton text={agent.agent_id} label="Copy agent ID" />
            </dd>
          </dl>

          {!retired && <AgentUpdate agent={agent} onUpdated={onSaved} />}

          {(can('network.map.run') || can('agent.rename') || can('agent.key.rotate') || can('agent.remove')) && (
            <div className="flex flex-wrap gap-2">
              {!retired && network && can('network.map.run') && (
                <button onClick={() => onRunNow(agent)} disabled={busy} className="btn-secondary text-sm inline-flex items-center gap-1.5" title="Read the network at the agent's next heartbeat">
                  <Play className="w-4 h-4" /> Run now
                </button>
              )}
              {!retired && (
                <>
                  {can('agent.rename') && (
                    <button onClick={() => onRename(agent)} className="btn-secondary text-sm inline-flex items-center gap-1.5">
                      <Pencil className="w-4 h-4" /> Rename
                    </button>
                  )}
                  {can('agent.key.rotate') && <button onClick={() => onRotate(agent)} disabled={busy} className="btn-secondary text-sm inline-flex items-center gap-1.5" title="Rotate the API key: the agent disconnects until the new code is pasted">
                    <KeyRound className="w-4 h-4" /> New connection code
                  </button>}
                </>
              )}
              {can('agent.remove') && <button onClick={() => onDelete(agent)} disabled={busy} className="btn-secondary text-sm inline-flex items-center gap-1.5 hover:!text-red-400 hover:!border-red-500/40">
                <Trash2 className="w-4 h-4" /> Delete
              </button>}
            </div>
          )}

          {retired
            ? <p className="text-sm text-dark-400">An old 1.x agent: it can no longer connect. Its Discovery history is kept until you delete it.</p>
            : <AgentSettings agent={agent} onSaved={onSaved} />}
        </div>
      </aside>
    </div>
  )
}

function AgentSettings({ agent, onSaved }) {
  const { can, catalog } = useAuth()
  const canAssignRoles = can('agent.roles.assign')
  const canSightings = can('agent.sightings.enable')
  const [policy, setPolicy] = useState(null)
  const [draft, setDraft] = useState({})            // setting -> override (null = default)
  const [advanced, setAdvanced] = useState(false)
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [rev, setRev] = useState(0)                 // remounts the inputs when the draft is reset

  const take = (data) => {
    setPolicy(data)
    setDraft(Object.fromEntries(data.settings.map((s) => [s.key, s.override])))
    setRev((r) => r + 1)
  }
  const load = useCallback(async () => {
    setError(null)
    try { take((await client.get(`/agents/${agent.agent_id}/policy`)).data) } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load the settings of this agent')
    }
  }, [agent.agent_id])
  useEffect(() => { load() }, [load])

  const byKey = useMemo(() => Object.fromEntries((policy?.settings ?? []).map((s) => [s.key, s])), [policy])
  const changed = (policy?.settings ?? []).filter((s) => !same(draft[s.key], s.override))
  const problems = (policy?.settings ?? []).filter((s) => invalid(s.spec, draft[s.key]))
  const roles = ROLES.filter((r) => r.key in (policy?.roles ?? {}))   // a network agent has only Collector
  const canEdit = !!policy?.can_edit
  // A setting that switches a role needs "Assign agent roles"; sightings needs its own action.
  const roleKeys = new Set(Object.values(policy?.role_settings ?? {}).flat())
  const lockOf = (key) => (key === 'sightings' && !canSightings ? 'agent.sightings.enable'
    : roleKeys.has(key) && !canAssignRoles ? 'agent.roles.assign' : null)

  // A setting with the draft: this agent's value, else what it inherits (tenant or built-in default).
  const valueOf = (s) => draft[s.key] ?? s.inherited
  const roleOn = (role) => (policy.role_settings[role] ?? []).filter((k) => byKey[k]).some((k) => valueOf(byKey[k]) === true)
  const setRole = (role, on) => setDraft((d) => ({
    ...d, ...Object.fromEntries((policy.role_settings[role] ?? []).filter((k) => byKey[k]).map((k) => [k, on])),
  }))

  const save = async () => {
    setSaving(true); setError(null)
    try {
      const settings = Object.fromEntries(changed.map((s) => [s.key, draft[s.key] ?? null]))
      take((await client.patch(`/agents/${agent.agent_id}/policy`, { settings })).data)
      setSaved(true); setTimeout(() => setSaved(false), 4000)
      onSaved?.()
    } catch (err) {
      setError(err?.response?.data?.detail
        || (err?.response ? `Failed to save the settings (HTTP ${err.response.status})`
          : 'Failed to save the settings: the server did not answer (network, or the browser blocked the request)'))
    } finally { setSaving(false) }
  }

  const fallback = (s) => `${s.tenant_default !== null ? 'Tenant default' : 'Default'}: ${show(metaOf(s.key), s.spec, s.inherited)}`
  const inSync = policy && policy.applied_version !== null ? policy.applied_version === policy.version : null
  const hasAdvanced = GROUPS.some((g) => g.settings.some((m) => m.advanced && byKey[m.key]))

  if (error && !policy) return <ErrorBox text={error} />
  if (!policy) return <div className="flex justify-center py-10"><RefreshCw className="w-6 h-6 animate-spin text-dark-400" /></div>

  return (
    <section className="space-y-5" aria-label="Settings">
      <div>
        <h3 className="text-sm font-semibold text-dark-50">Settings</h3>
        <p className="text-xs text-dark-400 mt-0.5">
          {canEdit ? 'Leave a setting at its default to follow the tenant default (Defaults tab).' : requiresTitle('agent.configure', catalog)}
          {inSync === false && ' The agent applies the latest change at its next heartbeat.'}
          {policy.applied_version === null && ' This agent is older than 2.4.0 and does not apply these; the server still refuses jobs they rule out.'}
        </p>
      </div>
      {error && <ErrorBox text={error} />}
      {policy.capabilities?.lan_adapter && (
        <p className="text-xs text-dark-400">
          Network adapter: <span className="font-mono text-dark-200">{policy.capabilities.lan_adapter}</span>, pinned on the computer
          (EAGLEEYE_PASSIVE_INTERFACE). Passive listening, the agent's address and its network follow it, not the adapter to the internet.
        </p>
      )}
      {/* 2.6+ agents say whether their service finds Syft and Grype (older ones do not say) */}
      {byKey.sbom?.value === true && policy.capabilities?.sbom_tools === false && (
        <div className="flex items-start gap-2 text-sm text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <span>SBOM is on, but the agent cannot find Syft and Grype on its computer, so it skips the SBOM and CVE check.
            Install them where the agent service can see them (its window's Setup page says where), or turn SBOM off here.</span>
        </div>
      )}
      {/* Agents that report capabilities but not `sightings` are older than threat sightings */}
      {byKey.sightings?.value === true && policy.capabilities && policy.capabilities.sightings !== true && (
        <div className="flex items-start gap-2 text-sm text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <span>Threat sightings is on, but this agent is older than the feature and does not check its computer's traffic.
            Update the agent from the Agents page installer.</span>
        </div>
      )}
      {byKey.sightings?.value === true && policy.capabilities?.sightings === true && policy.capabilities?.admin === false && (
        <div className="flex items-start gap-2 text-sm text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <span>The agent does not run as Administrator/root, so it cannot read DNS answers; it still checks the computer's connections.</span>
        </div>
      )}
      {/* OpenSCAP runs on Linux only; an agent older than the setting does not report `openscap` */}
      {byKey.openscap?.value === true && policy.capabilities && policy.capabilities.openscap !== true && (
        <div className="flex items-start gap-2 text-sm text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <span>{policy.capabilities.openscap === false
            ? 'OpenSCAP is on, but it runs on Linux only: this agent ignores it. Its security baseline covers the same ground.'
            : 'OpenSCAP is on, but this agent is older than the setting. Update it from the Agents page.'}</span>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        {roles.map((r) => {
          const on = roleOn(r.key)
          return (
            <button
              key={r.key} type="button" role="switch" aria-checked={on} title={canAssignRoles ? r.help : requiresTitle('agent.roles.assign', catalog)} disabled={!canEdit || !canAssignRoles || saving}
              onClick={() => setRole(r.key, !on)}
              className={`px-3 py-1.5 rounded-full text-xs border transition-colors disabled:cursor-default ${on
                ? 'border-eagle-500/40 bg-eagle-500/15 text-eagle-300' : 'border-dark-600/60 text-dark-400 hover:text-dark-200'}`}
            >
              {r.label}: {on ? 'On' : 'Off'}
            </button>
          )
        })}
      </div>

      {GROUPS.map((g) => {
        const items = g.settings.filter((m) => byKey[m.key] && (advanced || !m.advanced))
        if (!items.length) return null
        return (
          <div key={g.title} className="space-y-3">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-dark-400">{g.title}</h4>
            {items.map((m) => {
              const s = byKey[m.key]
              const problem = invalid(s.spec, draft[s.key])
              return (
                <div key={m.key} className="space-y-1">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <label htmlFor={`policy-${m.key}`} className="text-sm text-dark-50">{labelOf(m, agent.kind)}</label>
                      {helpOf(m, agent.kind) && <p className="text-xs text-dark-400">{helpOf(m, agent.kind)}</p>}
                    </div>
                    <span title={lockOf(m.key) ? requiresTitle(lockOf(m.key), catalog) : undefined}>
                      <PolicyInput key={`${m.key}-${rev}`} meta={m} spec={s.spec} value={draft[s.key] ?? null} disabled={!canEdit || !!lockOf(m.key) || saving}
                        fallback={fallback(s)} onChange={(v) => setDraft((d) => ({ ...d, [s.key]: v }))} />
                    </span>
                  </div>
                  {/* the input shows the value and where it comes from; after a change, what it was */}
                  {!same(draft[s.key], s.override) && (
                    <p className="text-[11px] text-yellow-400/80">Now {show(m, s.spec, s.value)} ({SOURCE_LABEL[s.source]}), until saved</p>
                  )}
                  {problem && <p className="text-[11px] text-red-400">Must be {problem}</p>}
                </div>
              )
            })}
          </div>
        )
      })}

      {hasAdvanced && (
        <button type="button" onClick={() => setAdvanced((v) => !v)} className="text-xs text-eagle-400 hover:underline">
          {advanced ? 'Hide advanced settings' : 'Show advanced settings (intervals, hops)'}
        </button>
      )}

      {canEdit && (
        <div className="sticky bottom-0 -mx-6 px-6 py-3 bg-dark-900/95 backdrop-blur border-t border-dark-700/60 flex items-center justify-end gap-3">
          {saved && <span className="text-xs text-green-400">Saved. The agent applies it within a minute.</span>}
          {changed.length > 0 && (
            <button type="button" onClick={() => take(policy)}
              disabled={saving} className="btn-secondary text-sm">Undo</button>
          )}
          <button type="button" onClick={save} disabled={saving || changed.length === 0 || problems.length > 0} className="btn-primary text-sm">
            {saving ? 'Saving…' : changed.length ? `Save ${changed.length} change${changed.length > 1 ? 's' : ''}` : 'No changes'}
          </button>
        </div>
      )}
    </section>
  )
}

function ErrorBox({ text }) {
  return (
    <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
      <AlertTriangle className="w-4 h-4 flex-shrink-0" /> {text}
    </div>
  )
}
