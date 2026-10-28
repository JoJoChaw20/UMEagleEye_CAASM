import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import client from '../api/client'
import TenantSelector from '../components/common/TenantSelector'
import SecurityOverview from '../components/dashboard/SecurityOverview'
import PriorityActionCentre from '../components/dashboard/PriorityActionCentre'
import AssetVisibility from '../components/dashboard/AssetVisibility'
import ExposureAndChanges from '../components/dashboard/ExposureAndChanges'
import RemediationAndTrend from '../components/dashboard/RemediationAndTrend'
import { buildPriorityActions, dashboardHref } from '../components/dashboard/dashboardUtils'

export default function DashboardPage() {
  const navigate = useNavigate()
  const [tenantFilter, setTenantFilter] = useState('')
  const [summary, setSummary] = useState(null)
  const [posture, setPosture] = useState(null)
  const [history, setHistory] = useState([])
  const [recentChanges, setRecentChanges] = useState([])
  const [cveGroups, setCveGroups] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [errors, setErrors] = useState({})

  const loadDashboard = useCallback(async (background = false) => {
    if (background) setRefreshing(true)
    else {
      setLoading(true)
      setSummary(null); setPosture(null); setHistory([]); setRecentChanges([]); setCveGroups([])
    }
    const tenant = tenantFilter ? { tenant_id: tenantFilter } : {}
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
    const results = await Promise.allSettled([
      client.get('/dashboard/summary', { params: tenant }),
      client.get('/posture/current', { params: tenant }),
      client.get('/posture/history', { params: { limit: 30, ...tenant } }),
      client.get('/events', { params: { page: 1, page_size: 30, since, sort: 'time', ...tenant } }),
      client.get('/events/cve-groups', { params: { page: 1, page_size: 30, status: 'open', ...tenant } }),
    ])
    const values = results.map(result => result.status === 'fulfilled' ? result.value.data : null)
    const nextErrors = {
      summary: results[0].status === 'rejected',
      posture: results[1].status === 'rejected',
      history: results[2].status === 'rejected',
      changes: results[3].status === 'rejected',
      groups: results[4].status === 'rejected',
    }
    setSummary(values[0])
    setPosture(values[1])
    setHistory(values[2]?.items ?? [])
    setRecentChanges(values[3]?.items ?? [])
    setCveGroups(values[4]?.items ?? [])
    setErrors(nextErrors)
    setLoading(false)
    setRefreshing(false)
  }, [tenantFilter])

  useEffect(() => { loadDashboard() }, [loadDashboard])

  const priorityActions = useMemo(
    () => buildPriorityActions(summary?.priority_actions ?? [], cveGroups, 5),
    [summary?.priority_actions, cveGroups],
  )

  const openInventory = (filters = {}) => navigate(dashboardHref('/inventory', filters, tenantFilter))
  const openAlerts = (filters = {}) => navigate(dashboardHref('/alerts', filters, tenantFilter))
  const openPostureTrend = () => document.getElementById('posture-trend')?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  const openAgents = () => navigate(dashboardHref('/agents', {}, tenantFilter))
  const openAdvisories = () => navigate(dashboardHref('/advisories', {}, tenantFilter))

  return (
    <div className="dashboard-page mx-auto w-full max-w-[1800px] space-y-8 pb-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-eagle-400">UMEagleEye · CAASM</p>
          <h1 className="mt-1 text-3xl font-semibold tracking-tight text-dark-50">Security overview</h1>
          <p className="mt-2 max-w-2xl text-sm text-dark-400">From asset visibility to prioritized remediation, in one operational view.</p>
        </div>
        <div className="flex items-center gap-3">
          <TenantSelector value={tenantFilter} onChange={setTenantFilter} />
          <button type="button" onClick={() => loadDashboard(true)} disabled={loading || refreshing}
            className="inline-flex items-center gap-2 rounded-lg border border-dark-700 bg-dark-800/60 px-3 py-2 text-sm text-dark-200 transition-colors hover:border-eagle-500/50 disabled:opacity-50">
            <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />Refresh
          </button>
        </div>
      </header>

      {Object.values(errors).some(Boolean) && (
        <div role="status" className="glass-card border-amber-500/30 px-4 py-3 text-sm text-amber-300">
          Some dashboard data could not be loaded. Affected sections are marked unavailable; other data remains visible.
        </div>
      )}

      {summary?.collection?.recent_failures?.length > 0 && (
        <div role="status" className="glass-card flex items-start gap-3 border-red-500/30 px-4 py-3 text-sm">
          <span className="font-semibold text-red-400">Recent scan failure</span>
          <span className="text-dark-300">{summary.collection.recent_failures[0].scan_type} scan{summary.collection.recent_failures[0].subnet ? ` of ${summary.collection.recent_failures[0].subnet}` : ''} failed. Network inventory may be stale.</span>
          <button onClick={() => navigate('/discovery')} className="ml-auto whitespace-nowrap text-eagle-400 hover:underline">Review discovery →</button>
        </div>
      )}

      <SecurityOverview summary={summary} posture={posture} history={history} loading={loading} onAssets={() => openInventory({ scope: 'any' })} onAlerts={() => openAlerts({ sort: 'priority' })} onAgents={openAgents} onPosture={openPostureTrend} />
      <PriorityActionCentre actions={priorityActions} loading={loading} available={!errors.summary} tenantId={tenantFilter} />
      <AssetVisibility summary={summary} loading={loading} onInventory={openInventory} onAgents={openAgents} />
      <ExposureAndChanges overview={summary?.overview} surface={summary?.attack_surface} recentChanges={recentChanges} changesLoading={loading} changesError={errors.changes} tenantId={tenantFilter} />
      <RemediationAndTrend remediation={summary?.remediation} posture={posture} history={history} loading={loading} onManage={openAdvisories} tenantId={tenantFilter} />
    </div>
  )
}
