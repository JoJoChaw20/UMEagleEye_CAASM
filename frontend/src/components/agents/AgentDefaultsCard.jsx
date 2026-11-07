// The tenant's default agent settings (GET/PATCH /tenants/:id/agent-policy), on the Agents
// page. A default applies to every agent of the tenant without an override of its own;
// a setting with no default stays each agent's own.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, SlidersHorizontal } from 'lucide-react'
import client from '../../api/client'
import { GROUPS, PolicyInput, invalid } from './policy'

export default function AgentDefaultsCard({ tenantId, onSaved }) {
  const [data, setData] = useState(null)
  const [draft, setDraft] = useState({})
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    if (!tenantId) { setData(null); return }
    try {
      const { data: d } = await client.get(`/tenants/${tenantId}/agent-policy`)
      setData(d)
      setDraft(Object.fromEntries(d.settings.map((s) => [s.key, s.value])))
    } catch { setData(null) }
  }, [tenantId])
  useEffect(() => { load() }, [load])

  const byKey = useMemo(() => Object.fromEntries((data?.settings ?? []).map((s) => [s.key, s])), [data])
  const changed = (data?.settings ?? []).filter((s) => (draft[s.key] ?? null) !== (s.value ?? null))
  const problems = (data?.settings ?? []).filter((s) => invalid(s.spec, draft[s.key]))
  if (!data) return null
  const canEdit = data.can_edit

  const save = async () => {
    setSaving(true); setError(null)
    try {
      const settings = Object.fromEntries(changed.map((s) => [s.key, draft[s.key] ?? null]))
      const { data: d } = await client.patch(`/tenants/${tenantId}/agent-policy`, { settings })
      setData(d)
      setDraft(Object.fromEntries(d.settings.map((s) => [s.key, s.value])))
      onSaved?.()
    } catch (err) {
      setError(err?.response?.data?.detail
        || (err?.response ? `Failed to save the default agent settings (HTTP ${err.response.status})`
          : 'Failed to save the default agent settings: the server did not answer (network, or the browser blocked the request)'))
    } finally { setSaving(false) }
  }

  return (
    <div className="glass-card p-6 space-y-4">
      <div>
        <h2 className="font-semibold text-dark-50 flex items-center gap-2 text-base">
          <SlidersHorizontal className="w-4 h-4 text-accent-cyan" />
          Default agent settings
        </h2>
        <p className="text-xs text-dark-400 mt-0.5">
          {canEdit
            ? "For every agent of this tenant without its own setting. \"Agent decides\" leaves it to each agent's own setting on its computer. Agents apply changes within a minute, between jobs."
            : 'Only the tenant superadmin can change these.'}
        </p>
      </div>
      {error && (
        <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      )}
      <div className="grid lg:grid-cols-2 gap-x-8 gap-y-4">
        {GROUPS.map((g) => (
          <div key={g.title} className="space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-dark-400">{g.title}</h3>
            {g.settings.filter((m) => byKey[m.key]).map((m) => {
              const s = byKey[m.key]
              const problem = invalid(s.spec, draft[s.key])
              return (
                <div key={m.key} className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <label htmlFor={`policy-${m.key}`} className="text-sm text-dark-50">{m.label}</label>
                    {m.help && <p className="text-xs text-dark-400">{m.help}</p>}
                    {problem && <p className="text-[11px] text-red-400">Must be {problem}</p>}
                  </div>
                  <PolicyInput
                    meta={m} spec={s.spec} value={draft[s.key] ?? null} disabled={!canEdit || saving}
                    fallback={m.key === 'local_scans' ? 'Off' : 'Agent decides'}
                    onChange={(v) => setDraft((d) => ({ ...d, [s.key]: m.key === 'local_scans' && v === null ? false : v }))}
                  />
                </div>
              )
            })}
          </div>
        ))}
      </div>
      {canEdit && (
        <div className="flex justify-end">
          <button type="button" onClick={save} disabled={saving || changed.length === 0 || problems.length > 0} className="btn-primary text-sm">
            {saving ? 'Saving…' : changed.length ? `Save ${changed.length} change${changed.length > 1 ? 's' : ''}` : 'No changes'}
          </button>
        </div>
      )}
    </div>
  )
}
