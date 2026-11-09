// The tenant's default agent settings (GET/PATCH /tenants/:id/agent-policy), on the Agents
// page's Defaults tab. A default applies to every agent of the tenant without a setting of
// its own; a setting with no default here is the built-in default.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Monitor, Network, Smartphone } from 'lucide-react'
import client from '../../api/client'
import { GROUPS, PolicyInput, invalid, same, show } from './policy'

const KINDS = [
  { kind: 'host', title: 'Computers', icon: Monitor, help: 'The agent installed on each computer.' },
  { kind: 'network', title: 'Network agents', icon: Network, help: 'Agents that read the routers and switches.' },
  { kind: 'mobile', title: 'Phones', icon: Smartphone, help: 'The EagleEye app on Android phones and tablets.' },
]

export default function AgentDefaultsCard({ tenantId, onSaved }) {
  const [data, setData] = useState(null)
  const [draft, setDraft] = useState({})
  const [advanced, setAdvanced] = useState(false)
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)
  const [rev, setRev] = useState(0)                 // remounts the inputs when the draft is reset

  const take = (d) => {
    setData(d)
    setDraft(Object.fromEntries(d.settings.map((s) => [s.key, s.value])))
    setRev((r) => r + 1)
  }
  const load = useCallback(async () => {
    if (!tenantId) { setData(null); return }
    try { take((await client.get(`/tenants/${tenantId}/agent-policy`)).data) } catch { setData(null) }
  }, [tenantId])
  useEffect(() => { load() }, [load])

  const byKey = useMemo(() => Object.fromEntries((data?.settings ?? []).map((s) => [s.key, s])), [data])
  if (!tenantId) {
    return <div className="glass-card p-6 text-sm text-dark-400">Pick a tenant above to see its default agent settings.</div>
  }
  if (!data) return null
  const changed = data.settings.filter((s) => !same(draft[s.key], s.value))
  const problems = data.settings.filter((s) => invalid(s.spec, draft[s.key]))
  const canEdit = data.can_edit

  const save = async () => {
    setSaving(true); setError(null)
    try {
      const settings = Object.fromEntries(changed.map((s) => [s.key, draft[s.key] ?? null]))
      take((await client.patch(`/tenants/${tenantId}/agent-policy`, { settings })).data)
      onSaved?.()
    } catch (err) {
      setError(err?.response?.data?.detail
        || (err?.response ? `Failed to save the default agent settings (HTTP ${err.response.status})`
          : 'Failed to save the default agent settings: the server did not answer (network, or the browser blocked the request)'))
    } finally { setSaving(false) }
  }

  const row = (m) => {
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
          key={`${m.key}-${rev}`} meta={m} spec={s.spec} value={draft[s.key] ?? null} disabled={!canEdit || saving}
          fallback={`Default: ${show(m, s.spec, s.builtin)}`}
          onChange={(v) => setDraft((d) => ({ ...d, [s.key]: v }))}
        />
      </div>
    )
  }

  return (
    <div className="glass-card p-6 space-y-6">
      <div>
        <h2 className="font-semibold text-dark-50 text-base">Default agent settings</h2>
        <p className="text-xs text-dark-400 mt-0.5 max-w-3xl">
          {canEdit
            ? 'For every agent of this tenant without a setting of its own (set in its panel on the Agents tab). Agents apply a change within a minute, between jobs.'
            : 'Only the tenant superadmin can change these.'}
        </p>
      </div>
      {error && (
        <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      )}
      {KINDS.map(({ kind, title, icon: Icon, help }) => {
        const groups = GROUPS.map((g) => ({
          ...g, items: g.settings.filter((m) => byKey[m.key]?.kinds?.includes(kind) && (advanced || !m.advanced)),
        })).filter((g) => g.items.length)
        if (!groups.length) return null
        return (
          <section key={kind} className="space-y-3">
            <div className="flex items-baseline gap-2 border-b border-dark-700/50 pb-2">
              <Icon className="w-4 h-4 text-accent-cyan self-center" />
              <h3 className="text-sm font-semibold text-dark-50">{title}</h3>
              <span className="text-xs text-dark-400">{help}</span>
            </div>
            <div className="grid lg:grid-cols-2 gap-x-8 gap-y-4">
              {groups.map((g) => (
                <div key={g.title} className="space-y-3">
                  <h4 className="text-xs font-semibold uppercase tracking-wide text-dark-400">{g.title}</h4>
                  {g.items.map(row)}
                </div>
              ))}
            </div>
          </section>
        )
      })}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <button type="button" onClick={() => setAdvanced((v) => !v)} className="text-xs text-eagle-400 hover:underline">
          {advanced ? 'Hide advanced settings' : 'Show advanced settings (intervals, hops)'}
        </button>
        {canEdit && (
          <div className="flex gap-2">
            {changed.length > 0 && <button type="button" onClick={() => take(data)} disabled={saving} className="btn-secondary text-sm">Undo</button>}
            <button type="button" onClick={save} disabled={saving || changed.length === 0 || problems.length > 0} className="btn-primary text-sm">
              {saving ? 'Saving…' : changed.length ? `Save ${changed.length} change${changed.length > 1 ? 's' : ''}` : 'No changes'}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
