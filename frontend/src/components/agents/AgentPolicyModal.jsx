// One agent's settings (GET/PATCH /agents/:id/policy): its roles, then each setting with
// where its value comes from. The agent applies a change at its next heartbeat (within
// a minute), between jobs; its app then shows those settings as set by the admin.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, RefreshCw, X } from 'lucide-react'
import client from '../../api/client'
import { GROUPS, PolicyInput, ROLES, SOURCE_LABEL, invalid, show } from './policy'

export default function AgentPolicyModal({ agent, onClose, onSaved }) {
  const [policy, setPolicy] = useState(null)
  const [draft, setDraft] = useState({})            // setting -> override (null = default)
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    setError(null)
    try {
      const { data } = await client.get(`/agents/${agent.agent_id}/policy`)
      setPolicy(data)
      setDraft(Object.fromEntries(data.settings.map((s) => [s.key, s.override])))
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load the settings of this agent')
    }
  }, [agent.agent_id])
  useEffect(() => { load() }, [load])
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const byKey = useMemo(() => Object.fromEntries((policy?.settings ?? []).map((s) => [s.key, s])), [policy])
  const changed = useMemo(() => (policy?.settings ?? []).filter((s) => (draft[s.key] ?? null) !== (s.override ?? null)), [policy, draft])
  const problems = (policy?.settings ?? []).map((s) => [s, invalid(s.spec, draft[s.key])]).filter(([, p]) => p)
  const canEdit = !!policy?.can_edit

  // What a setting would be with the draft: this agent's value, else what it inherits
  // (the tenant default, the agent's own, or what every agent does: from the server).
  const valueOf = (s) => draft[s.key] ?? s.inherited
  const roleOn = (role) => {
    const keys = policy?.role_settings?.[role] ?? []
    const values = keys.map((k) => byKey[k] && valueOf(byKey[k]))
    return values.some((v) => v === null || v === undefined) ? null : values.some((v) => v === true)
  }
  const setRole = (role, on) => setDraft((d) => ({ ...d, ...Object.fromEntries((policy.role_settings[role] ?? []).map((k) => [k, on])) }))

  const save = async () => {
    setSaving(true); setError(null)
    try {
      const settings = Object.fromEntries(changed.map((s) => [s.key, draft[s.key] ?? null]))
      const { data } = await client.patch(`/agents/${agent.agent_id}/policy`, { settings })
      setPolicy(data)
      setDraft(Object.fromEntries(data.settings.map((s) => [s.key, s.override])))
      onSaved?.()
    } catch (err) {
      setError(err?.response?.data?.detail
        || (err?.response ? `Failed to save the settings (HTTP ${err.response.status})`
          : 'Failed to save the settings: the server did not answer (network, or the browser blocked the request)'))
    } finally { setSaving(false) }
  }

  const fallback = (s) => {
    if (s.inherited === null || s.inherited === undefined) return "Agent's own setting"
    const where = s.tenant_default !== null && s.tenant_default !== undefined ? 'Tenant default'
      : s.local !== null && s.local !== undefined ? "Agent's own" : 'Default'
    return `${where}: ${show(metaOf(s.key), s.spec, s.inherited)}`
  }
  const inSync = policy && policy.applied_version !== null ? policy.applied_version === policy.version : null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-dark-950/70 p-4 overflow-y-auto" role="dialog" aria-modal="true" aria-label={`Settings of ${agent.name}`}>
      <div className="glass-card w-full max-w-2xl p-6 space-y-5 my-auto">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-dark-50">Settings of {agent.name}</h2>
            <p className="text-xs text-dark-400 mt-0.5">
              {canEdit ? 'Leave a setting at its default to follow the tenant default, or the agent\'s own setting when the tenant sets none.'
                : 'Only a tenant superadmin or admin can change these.'}
              {inSync === false && ' The agent has not applied the latest change yet (it does at its next heartbeat).'}
              {policy && policy.applied_version === null && ' This agent is older than 2.4.0: it only follows "May start its own scans"; the server still refuses jobs it rules out.'}
            </p>
          </div>
          <button onClick={onClose} className="text-dark-400 hover:text-dark-50" aria-label="Close"><X className="w-5 h-5" /></button>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" /> {error}
          </div>
        )}
        {!policy && !error && <div className="flex justify-center py-10"><RefreshCw className="w-6 h-6 animate-spin text-dark-400" /></div>}

        {policy && (
          <>
            <div className="grid sm:grid-cols-3 gap-3">
              {ROLES.map((r) => {
                const on = roleOn(r.key)
                return (
                  <div key={r.key} className="rounded-lg border border-dark-700/60 p-3 space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-medium text-dark-50">{r.label}</span>
                      <span className={`text-xs ${on ? 'text-accent-green' : on === false ? 'text-dark-400' : 'text-dark-500'}`}>
                        {on === null ? 'Unknown' : on ? 'On' : 'Off'}
                      </span>
                    </div>
                    <p className="text-[11px] text-dark-400">{r.help}</p>
                    {canEdit && (
                      <div className="flex gap-2">
                        <button type="button" className="btn-secondary text-xs px-2 py-1" onClick={() => setRole(r.key, true)}>Turn on</button>
                        <button type="button" className="btn-secondary text-xs px-2 py-1" onClick={() => setRole(r.key, false)}>Turn off</button>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>

            {GROUPS.map((g) => (
              <div key={g.title} className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-dark-400">{g.title}</h3>
                {g.settings.filter((m) => byKey[m.key]).map((m) => {
                  const s = byKey[m.key]
                  const problem = invalid(s.spec, draft[s.key])
                  return (
                    <div key={m.key} className="flex items-start justify-between gap-4 py-1">
                      <div className="min-w-0">
                        <label htmlFor={`policy-${m.key}`} className="text-sm text-dark-50">{m.label}</label>
                        {m.help && <p className="text-xs text-dark-400">{m.help}</p>}
                        <p className="text-[11px] text-dark-500">
                          Now: {show(m, s.spec, s.value)} · {SOURCE_LABEL[s.source]}
                        </p>
                        {problem && <p className="text-[11px] text-red-400">Must be {problem}</p>}
                      </div>
                      <PolicyInput meta={m} spec={s.spec} value={draft[s.key] ?? null} disabled={!canEdit || saving}
                        fallback={fallback(s)} onChange={(v) => setDraft((d) => ({ ...d, [s.key]: v }))} />
                    </div>
                  )
                })}
              </div>
            ))}

            <div className="flex gap-3 pt-2">
              <button type="button" onClick={onClose} className="btn-secondary flex-1 text-sm">Close</button>
              {canEdit && (
                <button type="button" onClick={save} disabled={saving || changed.length === 0 || problems.length > 0} className="btn-primary flex-1 text-sm">
                  {saving ? 'Saving…' : changed.length ? `Save ${changed.length} change${changed.length > 1 ? 's' : ''}` : 'No changes'}
                </button>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function metaOf(key) {
  for (const g of GROUPS) {
    const m = g.settings.find((s) => s.key === key)
    if (m) return m
  }
  return { key, label: key }
}
