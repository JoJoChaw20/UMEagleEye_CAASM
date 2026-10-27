// The tenant's scan policy, on the Agents page: what the EagleEye agents may do on their own.
import { useState, useEffect, useCallback } from 'react'
import { Radar, RefreshCw, ToggleLeft, ToggleRight, AlertTriangle } from 'lucide-react'
import client from '../../api/client'

// Saved at once; each change is written to the audit log.
const SCAN_POLICY = [
  {
    key: 'auto_investigate_new_devices',
    label: 'Investigate new devices automatically',
    help: 'When passive listening finds a device it has not seen before, the agent that heard it runs an '
      + 'active scan of that one IP a few minutes later. The open ports and OS it finds are added to the '
      + 'new-device alert. Devices with an agent, phones whose private MAC changed, and IPs scanned in the '
      + 'last 24 hours are skipped; at most 10 such scans run per hour. Active scans can trip intrusion '
      + 'detection, so turn this on only where your security team allows probing.',
  },
  {
    key: 'allow_local_scans',
    label: 'Allow scans started on agent computers',
    help: 'Lets agents run active scans from their own "Scan now" button and local schedules. When off, '
      + 'active scans are started only from this dashboard (New scan, and new-device investigations).',
  },
]

export default function ScanPolicyCard({ tenantId, canEdit }) {
  const [tenant, setTenant] = useState(null)
  const load = useCallback(async () => {
    if (!tenantId) { setTenant(null); return }
    try {
      const { data } = await client.get(`/tenants/${tenantId}`)
      setTenant(data)
    } catch { setTenant(null) }
  }, [tenantId])
  useEffect(() => { load() }, [load])

  const [saving, setSaving] = useState(null)
  const [error, setError] = useState(null)
  const toggle = async (key) => {
    setSaving(key); setError(null)
    try {
      await client.patch(`/tenants/${tenant.tenant_id}`, { [key]: !tenant[key] })
      await load()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to save the scan policy')
    } finally { setSaving(null) }
  }
  if (!tenant || !('allow_local_scans' in tenant)) return null
  return (
    <div className="glass-card p-6 space-y-4">
      <div>
        <h2 className="font-semibold text-white flex items-center gap-2 text-base">
          <Radar className="w-4 h-4 text-accent-cyan" />
          Scan Policy
        </h2>
        <p className="text-xs text-dark-400 mt-0.5">
          {canEdit ? 'What the EagleEye agents of this tenant may do on their own.' : 'Only the tenant superadmin can change these.'}
        </p>
      </div>
      {error && (
        <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}
      {SCAN_POLICY.map(({ key, label, help }) => {
        const on = !!tenant[key]
        return (
          <div key={key} className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="text-sm text-white">{label}</p>
              <p className="text-xs text-dark-400 mt-0.5">{help}</p>
            </div>
            <button
              type="button" role="switch" aria-checked={on} aria-label={label}
              onClick={() => toggle(key)} disabled={!canEdit || saving !== null}
              className={`flex-shrink-0 flex items-center gap-1.5 text-sm disabled:opacity-50 ${on ? 'text-accent-green' : 'text-dark-400'}`}
            >
              {saving === key ? <RefreshCw className="w-5 h-5 animate-spin" />
                : on ? <ToggleRight className="w-6 h-6" /> : <ToggleLeft className="w-6 h-6" />}
              {on ? 'On' : 'Off'}
            </button>
          </div>
        )
      })}
    </div>
  )
}
