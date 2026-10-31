import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { Link } from 'react-router-dom'
import {
  Package, RefreshCw, Monitor, Bug, Clock3, AlertTriangle, XCircle, Download, Trash2, Play, MoreHorizontal,
} from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'
import PackageSearch from '../components/common/PackageSearch'
import { sbomRunProblems } from '../components/common/SbomRunNote'
import ComputerPanel from '../components/sbom/ComputerPanel'
import { Tabs, StatTile, Toast, useToast, Spinner, ago } from '../components/common/PageParts'

// SBOM: one row per computer. Every computer with an EagleEye agent should have one (the
// agent builds it daily with Syft and checks it with Grype); computers without one, or
// with an old one, show up here. Server: GET /sboms/computers.

const STATE = {
  running: { label: 'Running',     cls: 'bg-blue-500/10 text-blue-400 border-blue-500/30' },
  queued:  { label: 'Queued',      cls: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30' },
  failed:  { label: 'Failed',      cls: 'bg-red-500/10 text-red-400 border-red-500/30' },
  none:    { label: 'No SBOM yet', cls: 'bg-dark-600/40 text-dark-300 border-dark-500/30' },
  stale:   { label: 'Out of date', cls: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
  ok:      { label: 'Up to date',  cls: 'bg-green-500/10 text-accent-green border-green-500/30' },
}

function elapsed(from, now) {
  const s = Math.max(0, Math.floor((now - new Date(from).getTime()) / 1000))
  return s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`
}

function RowMenu({ items }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  useEffect(() => {
    if (!open) return undefined
    const close = (e) => { if (!ref.current?.contains(e.target)) setOpen(false) }
    window.addEventListener('mousedown', close)
    return () => window.removeEventListener('mousedown', close)
  }, [open])
  const shown = items.filter(Boolean)
  if (!shown.length) return null
  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen((v) => !v)} className="p-1.5 rounded hover:bg-dark-700/50 text-dark-400 hover:text-dark-100" aria-label="More actions" aria-expanded={open}>
        <MoreHorizontal className="w-4 h-4" />
      </button>
      {open && (
        <div className="absolute right-0 z-20 mt-1 w-48 rounded-lg border border-dark-700 bg-dark-850 shadow-xl py-1">
          {shown.map((it) => (
            <button key={it.label} onClick={() => { setOpen(false); it.onClick() }} disabled={it.disabled}
              className={`w-full text-left px-3 py-2 text-sm flex items-center gap-2 hover:bg-dark-700/50 disabled:opacity-40 ${it.danger ? 'text-red-400' : 'text-dark-200'}`}>
              <it.icon className="w-4 h-4" /> {it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

export default function SBOMPage() {
  const { user } = useAuth()
  const canManage = ['tenant_superadmin', 'tenant_admin'].includes(user?.role)
  const { toast, show: showToast } = useToast()
  const [tab, setTab] = useState('computers')
  const [tenantFilter, setTenantFilter] = useState('')
  const [computers, setComputers] = useState(null)
  const [staleHours, setStaleHours] = useState(48)
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState(null)
  const [busy, setBusy] = useState({})                   // asset_id → true while a request runs
  const [now, setNow] = useState(Date.now())

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await client.get('/sboms/computers', { params: tenantFilter ? { tenant_id: tenantFilter } : {} })
      setComputers(res.data.items || [])
      setStaleHours(res.data.stale_hours ?? 48)
    } catch (err) {
      showToast(err?.response?.data?.detail || 'Failed to load computers', 'error')
      setComputers((cur) => cur ?? [])
    } finally {
      setLoading(false)
    }
  }, [tenantFilter, showToast])
  useEffect(() => { load() }, [load])

  // While a run is queued or running: refresh every 5 s, and tick the elapsed time.
  const active = (computers ?? []).some((c) => c.state === 'running' || c.state === 'queued')
  useEffect(() => {
    if (!active) return undefined
    const poll = setInterval(load, 5000)
    const tick = setInterval(() => setNow(Date.now()), 1000)
    return () => { clearInterval(poll); clearInterval(tick) }
  }, [active, load])

  // Keep the open panel on the latest data for its computer
  useEffect(() => {
    if (selected && computers) setSelected((cur) => computers.find((c) => c.asset_id === cur?.asset_id) ?? cur)
  }, [computers]) // eslint-disable-line react-hooks/exhaustive-deps

  const withBusy = async (assetId, fn) => {
    setBusy((b) => ({ ...b, [assetId]: true }))
    try { await fn() } finally { setBusy((b) => { const n = { ...b }; delete n[assetId]; return n }) }
  }

  const runNow = (c) => withBusy(c.asset_id, async () => {
    try {
      const res = await client.post(`/assets/${c.asset_id}/scan-sbom`)
      showToast(res.data?.message || `SBOM queued for ${c.hostname || c.ip_address}`, 'success')
      await load()
    } catch (err) {
      showToast(err?.response?.data?.detail || 'Failed to queue the SBOM', 'error')
    }
  })

  const cancel = (c) => {
    if (!c.job?.scan_id || !confirm(`Cancel the SBOM run on ${c.hostname || c.ip_address}? Its results will be discarded when they arrive.`)) return
    withBusy(c.asset_id, async () => {
      try { await client.post(`/scans/${c.job.scan_id}/cancel`); await load() } catch (err) {
        showToast(err?.response?.data?.detail || 'Failed to cancel the SBOM run', 'error')
      }
    })
  }

  const remove = (c) => {
    if (!confirm(`Delete the SBOM of ${c.hostname || c.ip_address}?\n\nIts package list is removed. The agent builds a new one on its next daily run. This cannot be undone.`)) return
    withBusy(c.asset_id, async () => {
      try { await client.delete(`/sboms/by-asset/${c.asset_id}`); showToast('SBOM deleted', 'success'); await load() } catch (err) {
        showToast(err?.response?.data?.detail || 'Failed to delete the SBOM', 'error')
      }
    })
  }

  const download = async (c) => {
    try {
      const res = await client.get(`/sboms/${c.sbom.sbom_id}/download`, { responseType: 'blob' })
      const url = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = url
      a.download = `sbom-${(c.hostname || c.asset_id).replace(/[^\w.-]+/g, '_')}.cdx.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      showToast('Failed to download the SBOM file', 'error')
    }
  }

  const summary = useMemo(() => {
    const list = computers ?? []
    const withAgent = list.filter((c) => c.agent)
    return {
      agents: withAgent.length,
      covered: withAgent.filter((c) => c.sbom).length,
      packages: list.reduce((n, c) => n + (c.sbom?.component_count ?? 0), 0),
      cves: list.reduce((n, c) => n + c.cves.open, 0),
      critical: list.reduce((n, c) => n + c.cves.critical, 0),
      kev: list.reduce((n, c) => n + c.cves.kev, 0),
      stale: list.filter((c) => c.state === 'stale').length,
      missing: withAgent.filter((c) => !c.sbom).length,
    }
  }, [computers])

  return (
    <div className="space-y-6">
      <Toast toast={toast} />

      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Software Bill of Materials</h1>
          <p className="text-dark-400 text-sm mt-1 max-w-2xl">
            The software packages on each computer with an EagleEye agent, rebuilt daily and checked for known vulnerabilities.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <TenantSelector value={tenantFilter} onChange={setTenantFilter} />
          <button onClick={load} disabled={loading} className="btn-secondary flex items-center gap-2 text-sm">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatTile label="Coverage" icon={Monitor}
          value={computers ? `${summary.covered} of ${summary.agents}` : '—'}
          tone={computers && summary.missing > 0 ? 'warning' : 'default'}
          sub={summary.missing > 0 ? `${summary.missing} agent computer${summary.missing === 1 ? '' : 's'} without an SBOM` : 'agent computers with an SBOM'} />
        <StatTile label="Packages" icon={Package}
          value={computers ? summary.packages.toLocaleString() : '—'} sub="across all computers" />
        <Link to="/alerts?view=cve" className="block">
          <StatTile label="Open CVE alerts" icon={Bug}
            value={computers ? summary.cves.toLocaleString() : '—'} tone={summary.critical > 0 ? 'danger' : summary.cves > 0 ? 'warning' : 'good'}
            sub={computers ? `${summary.critical} critical${summary.kev ? ` · ${summary.kev} known exploited` : ''}` : ' '} />
        </Link>
        <StatTile label="Out of date" icon={Clock3}
          value={computers ? summary.stale : '—'} tone={summary.stale > 0 ? 'warning' : 'good'}
          sub={`SBOM older than ${Math.round(staleHours / 24)} days`} />
      </div>

      <Tabs label="SBOM views" active={tab} onChange={setTab} tabs={[
        { id: 'computers', label: 'Computers', count: computers?.length },
        { id: 'search', label: 'Package search' },
      ]} />

      {tab === 'search' ? <PackageSearch tenantId={tenantFilter} /> : (
        <div className="glass-card overflow-hidden">
          {computers === null ? <Spinner className="py-20" /> : computers.length === 0 ? (
            <div className="text-center py-16 text-dark-400 px-4">
              <Package className="w-14 h-14 mx-auto mb-4 opacity-20" />
              <p className="font-medium text-dark-200 mb-1">No computers yet</p>
              <p className="text-sm max-w-md mx-auto">Install the EagleEye agent on a computer (Agents page). It builds an SBOM of that computer every day.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr><th>Computer</th><th>Packages</th><th>Open CVEs</th><th>Last SBOM</th><th>Status</th><th className="w-px" /></tr>
                </thead>
                <tbody>
                  {computers.map((c) => {
                    const st = STATE[c.state] ?? STATE.none
                    const inProgress = c.state === 'running' || c.state === 'queued'
                    const problems = sbomRunProblems(c.sbom?.run)
                    return (
                      <tr key={c.asset_id} className="cursor-pointer hover:bg-dark-700/30" onClick={() => setSelected(c)}
                        tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') setSelected(c) }}>
                        <td>
                          <span className="text-sm font-medium text-dark-100">{c.hostname || c.ip_address}</span>
                          <span className="block text-xs text-dark-500">
                            <span className="font-mono">{c.ip_address}</span>
                            {c.agent ? ` · ${c.agent.name}` : ' · no agent'}
                          </span>
                        </td>
                        <td>
                          <span className="text-sm text-dark-100">{c.sbom?.component_count?.toLocaleString() ?? '—'}</span>
                          {problems > 0 && (
                            <span title={`${problems} folder(s) not listed in the last run; open the computer for details`}>
                              <AlertTriangle className="inline w-4 h-4 ml-1.5 text-amber-400 align-text-bottom" />
                            </span>
                          )}
                        </td>
                        <td onClick={(e) => e.stopPropagation()}>
                          {c.cves.open > 0 ? (
                            <Link to={`/alerts?view=cve&asset_id=${c.asset_id}&label=${encodeURIComponent(c.hostname || c.ip_address)}`} className="text-sm hover:underline">
                              <span className="text-dark-100">{c.cves.open}</span>
                              {c.cves.critical > 0 && <span className="text-red-400 text-xs ml-1.5">{c.cves.critical} critical</span>}
                              {c.cves.kev > 0 && <span className="text-red-400 text-xs ml-1.5">{c.cves.kev} exploited</span>}
                            </Link>
                          ) : <span className="text-dark-500 text-sm">{c.sbom ? '0' : '—'}</span>}
                        </td>
                        <td className={`text-xs whitespace-nowrap ${c.state === 'stale' ? 'text-amber-400' : 'text-dark-400'}`}
                          title={c.sbom ? new Date(c.sbom.generated_at).toLocaleString() : undefined}>
                          {ago(c.sbom?.generated_at, 'never')}
                        </td>
                        <td>
                          <span className={`text-xs px-2 py-0.5 rounded-full border font-medium whitespace-nowrap ${st.cls}`}
                            title={c.state === 'failed' ? (c.job?.failure_reason || 'The run failed without a reason') : undefined}>
                            {st.label}{c.state === 'running' && c.job?.mode === 'quick' ? ' (daily)' : ''}
                            {inProgress && c.job?.started_at ? ` · ${elapsed(c.job.started_at, now)}` : ''}
                          </span>
                          {c.state === 'failed' && c.job?.failure_reason && (
                            <p className="text-[11px] text-red-400/80 mt-1 max-w-xs truncate" title={c.job.failure_reason}>{c.job.failure_reason}</p>
                          )}
                        </td>
                        <td onClick={(e) => e.stopPropagation()}>
                          <div className="flex items-center justify-end gap-1">
                            {canManage && inProgress && c.job?.scan_id && (
                              <button onClick={() => cancel(c)} disabled={!!busy[c.asset_id]}
                                className="inline-flex items-center gap-1 px-2 py-1 rounded-lg border border-red-500/40 text-xs text-red-400 hover:bg-red-500/10 disabled:opacity-50">
                                <XCircle className="w-3.5 h-3.5" /> Cancel
                              </button>
                            )}
                            {canManage && !inProgress && c.agent && !c.sbom && (
                              <button onClick={() => runNow(c)} disabled={!!busy[c.asset_id]} className="btn-secondary text-xs py-1 px-2.5 inline-flex items-center gap-1 disabled:opacity-50">
                                <Play className="w-3.5 h-3.5" /> Run now
                              </button>
                            )}
                            <RowMenu items={[
                              canManage && c.agent && c.sbom && { label: 'Run now', icon: Play, onClick: () => runNow(c), disabled: inProgress || !!busy[c.asset_id] },
                              c.sbom && { label: 'Download file', icon: Download, onClick: () => download(c) },
                              canManage && c.sbom && { label: 'Delete SBOM', icon: Trash2, onClick: () => remove(c), danger: true, disabled: inProgress },
                            ]} />
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {selected && <ComputerPanel computer={selected} onClose={() => setSelected(null)} onDownload={download} />}
    </div>
  )
}
