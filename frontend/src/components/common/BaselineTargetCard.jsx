// The tenant's security-baseline target (backend lib/baseline.ts): the % of the 30 CIS-based checks a
// computer must pass. Below it, the computer gets one "Below Security Baseline" alert. Default 95%;
// the Tenant Superadmin may change it (50-100%), and every computer's alert follows at once.
import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, Check, RotateCcw, ShieldCheck } from 'lucide-react'
import client from '../../api/client'

export default function BaselineTargetCard({ tenantId }) {
  const [state, setState] = useState(null)
  const [draft, setDraft] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const [saved, setSaved] = useState(null)

  const load = useCallback(async () => {
    if (!tenantId) return
    try {
      const { data } = await client.get(`/tenants/${tenantId}/security-baseline`)
      setState(data); setDraft(String(data.target))
    } catch (err) {
      setError(err?.response?.data?.detail || 'Could not load the security-baseline target')
    }
  }, [tenantId])
  useEffect(() => { load() }, [load])

  if (!state) return error ? <p className="text-sm text-red-400">{error}</p> : null
  const value = Number(draft)
  const invalid = !draft || !Number.isInteger(value) || value < state.min || value > state.max

  const save = async (target) => {
    setSaving(true); setError(null); setSaved(null)
    try {
      const { data } = await client.put(`/tenants/${tenantId}/security-baseline`, { target })
      setState(data); setDraft(String(data.target))
      const c = data.alerts_change ?? {}
      setSaved(`Saved. ${c.opened ?? 0} alert(s) opened, ${c.resolved ?? 0} resolved, ${c.updated ?? 0} updated.`)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Could not save the target')
    } finally { setSaving(false) }
  }

  return (
    <div className="glass-card p-6 space-y-4">
      <div>
        <h2 className="font-semibold text-dark-50 flex items-center gap-2 text-base">
          <ShieldCheck className="w-4 h-4 text-accent-cyan" />
          Security-baseline target
        </h2>
        <p className="text-xs text-dark-400 mt-0.5 max-w-2xl">
          Each computer with an agent is checked against 30 settings after the CIS Benchmarks (the same number on Windows and
          Linux). A computer passing fewer than this share of them gets a "Below Security Baseline" alert, high under 80%.
          Checks the agent could not read are left out, never counted as passed.
          {!state.can_edit && ' Only the Tenant Superadmin can change the target.'}
        </p>
      </div>
      {error && (
        <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />{error}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <label htmlFor="baseline-target" className="text-dark-100">Target</label>
        <input id="baseline-target" type="number" min={state.min} max={state.max} step="1" inputMode="numeric"
          disabled={!state.can_edit || saving} value={draft}
          onChange={(e) => { setSaved(null); setDraft(e.target.value) }}
          className="input-field w-20 text-sm tabular-nums" />
        <span className="text-xs text-dark-400">% of checks passed</span>
        <span className="text-xs text-dark-500">Default {state.default}%</span>
        {state.target !== state.default && <span className="text-[11px] text-eagle-400">custom</span>}
      </div>
      {state.can_edit && (
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className="btn-primary text-sm flex items-center gap-2"
            disabled={saving || invalid || value === state.target} onClick={() => save(value)}>
            <Check className="w-4 h-4" />{saving ? 'Saving…' : 'Save target'}
          </button>
          <button type="button" className="btn-secondary text-sm flex items-center gap-2"
            disabled={saving || state.target === state.default} onClick={() => save(null)}>
            <RotateCcw className="w-4 h-4" />Use the default
          </button>
          {invalid && <span className="text-xs text-red-400">The target must be a whole number from {state.min} to {state.max}.</span>}
          {saved && <span className="text-xs text-emerald-400">{saved}</span>}
        </div>
      )}
    </div>
  )
}
