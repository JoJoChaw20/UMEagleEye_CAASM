// The tenant's fix-time targets (backend lib/alertRank.ts): how long each kind of alert may stay
// open before it is overdue. Defaults follow CISA BOD 22-01 (exploited CVEs in two weeks), PCI DSS
// 6.3.3 and common practice; the Tenant Superadmin may change them. Stored in hours.
import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, Check, RotateCcw, Timer } from 'lucide-react'
import client from '../../api/client'

const ROWS = [
  { key: 'compromise', label: 'Possible compromise', help: 'Threat intelligence seen on a device: investigate', unit: 'hours' },
  { key: 'kev_exposed', label: 'Exploited, internet-facing', help: 'A CVE exploited in the wild (CISA KEV or MyCERT) on an internet-facing device', unit: 'days' },
  { key: 'kev', label: 'Exploited, internal', help: 'A CVE exploited in the wild, CISA KEV or MyCERT (CISA BOD 22-01: two weeks)', unit: 'days' },
  { key: 'critical', label: 'Critical', help: 'Other critical vulnerabilities and exposures', unit: 'days' },
  { key: 'high', label: 'High', help: 'PCI DSS 6.3.3: critical patches within a month', unit: 'days' },
  { key: 'medium', label: 'Medium', help: '', unit: 'days' },
  { key: 'low', label: 'Low', help: '', unit: 'days' },
  { key: 'review', label: 'Review', help: 'New devices and changes to confirm', unit: 'days' },
]
const toUnit = (hours, unit) => (unit === 'days' ? hours / 24 : hours)
const toHours = (value, unit) => Math.round(Number(value) * (unit === 'days' ? 24 : 1))

export default function FixTargetsCard({ tenantId }) {
  const [policy, setPolicy] = useState(null)
  const [draft, setDraft] = useState({})
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const [saved, setSaved] = useState(false)

  const load = useCallback(async () => {
    if (!tenantId) return
    try {
      const { data } = await client.get(`/tenants/${tenantId}/sla-policy`)
      setPolicy(data)
      setDraft(Object.fromEntries(ROWS.map((r) => [r.key, String(toUnit(data.effective[r.key], r.unit))])))
    } catch (err) {
      setError(err?.response?.data?.detail || 'Could not load the fix-time targets')
    }
  }, [tenantId])
  useEffect(() => { load() }, [load])

  if (!policy) return error ? <p className="text-sm text-red-400">{error}</p> : null
  const canEdit = policy.can_edit

  const changed = ROWS.filter((r) => toHours(draft[r.key], r.unit) !== policy.effective[r.key])
  const invalid = ROWS.filter((r) => {
    const h = toHours(draft[r.key], r.unit)
    return !draft[r.key] || !Number.isFinite(h) || h < policy.min_hours || h > policy.max_hours
  })

  const save = async (targets) => {
    setSaving(true); setError(null); setSaved(false)
    try {
      const { data } = await client.put(`/tenants/${tenantId}/sla-policy`, { targets })
      setPolicy(data)
      setDraft(Object.fromEntries(ROWS.map((r) => [r.key, String(toUnit(data.effective[r.key], r.unit))])))
      setSaved(true)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Could not save the fix-time targets')
    } finally { setSaving(false) }
  }

  return (
    <div className="glass-card p-6 space-y-4">
      <div>
        <h2 className="font-semibold text-dark-50 flex items-center gap-2 text-base">
          <Timer className="w-4 h-4 text-accent-cyan" />
          Fix-time targets
        </h2>
        <p className="text-xs text-dark-400 mt-0.5 max-w-2xl">
          How long each kind of alert may stay open. An alert is due this long after it is first seen (or reopened);
          the Alerts page, Dashboard, notifications and reports mark it overdue after that.
          {!canEdit && ' Only the Tenant Superadmin can change them.'}
        </p>
      </div>
      {error && (
        <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />{error}
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-sm min-w-[520px]">
          <thead>
            <tr className="text-left text-[11px] uppercase tracking-wider text-dark-400">
              <th className="py-2 pr-3 font-medium">Alert</th>
              <th className="py-2 pr-3 font-medium">Target</th>
              <th className="py-2 font-medium">Default</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-700/50">
            {ROWS.map((r) => {
              const custom = policy.overrides[r.key] != null
              return (
                <tr key={r.key}>
                  <td className="py-2 pr-3">
                    <label htmlFor={`sla-${r.key}`} className="text-dark-100">{r.label}</label>
                    {r.help && <p className="text-[11px] text-dark-500">{r.help}</p>}
                  </td>
                  <td className="py-2 pr-3 whitespace-nowrap">
                    <input id={`sla-${r.key}`} type="number" min="1" step="1" inputMode="numeric" disabled={!canEdit || saving}
                      value={draft[r.key] ?? ''} onChange={(e) => { setSaved(false); setDraft((d) => ({ ...d, [r.key]: e.target.value })) }}
                      className="input-field w-20 text-sm tabular-nums" />
                    <span className="ml-2 text-xs text-dark-400">{r.unit}</span>
                    {custom && <span className="ml-2 text-[11px] text-eagle-400">custom</span>}
                  </td>
                  <td className="py-2 text-xs text-dark-400 tabular-nums">{toUnit(policy.defaults[r.key], r.unit)} {r.unit}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {canEdit && (
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className="btn-primary text-sm flex items-center gap-2"
            disabled={saving || changed.length === 0 || invalid.length > 0}
            onClick={() => save(Object.fromEntries(changed.map((r) => [r.key, toHours(draft[r.key], r.unit)])))}>
            <Check className="w-4 h-4" />{saving ? 'Saving…' : 'Save targets'}
          </button>
          <button type="button" className="btn-secondary text-sm flex items-center gap-2"
            disabled={saving || Object.keys(policy.overrides).length === 0}
            onClick={() => save(Object.fromEntries(ROWS.map((r) => [r.key, null])))}>
            <RotateCcw className="w-4 h-4" />Use the defaults
          </button>
          {invalid.length > 0 && <span className="text-xs text-red-400">Each target must be between 1 hour and 365 days.</span>}
          {saved && <span className="text-xs text-emerald-400">Saved. Due dates follow the new targets at once.</span>}
        </div>
      )}
    </div>
  )
}
