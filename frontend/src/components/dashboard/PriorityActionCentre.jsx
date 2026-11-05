import { AlertTriangle, ArrowUpRight, CircleCheck, ListFilter } from 'lucide-react'
import { Link } from 'react-router-dom'
import { alertLabel, playbook, renderDetail, SevBadge, timeAgo } from '../common/alertMeta'
import { dashboardHref, operationalTier, priorityContext } from './dashboardUtils'
import SectionHeader from '../ui/SectionHeader'

const tierStyle = {
  P0: 'border-red-500/40 bg-red-500/10 text-red-300',
  P1: 'border-red-500/30 bg-red-500/5 text-red-400',
  P2: 'border-amber-500/30 bg-amber-500/5 text-amber-400',
  P3: 'border-dark-600 bg-dark-900 text-dark-300',
}

function itemHref(item, tenantId) {
  if (item.kind === 'cve_group') {
    const params = { view: 'cve', asset_id: item.asset.asset_id, label: item.asset.hostname || item.asset.ip }
    if (item.details?.package_name) params.package = item.details.package_name
    return dashboardHref('/alerts', params, tenantId)
  }
  if (item.event_type === 'new_device' && item.asset?.asset_id) return dashboardHref(`/inventory/${encodeURIComponent(item.asset.asset_id)}`, {}, tenantId)
  return dashboardHref('/alerts', { event: item.event_id }, tenantId)
}

function Context({ item }) {
  const reasons = priorityContext(item)
  return reasons.length ? <div className="flex flex-wrap gap-1.5">
    {reasons.map(reason => <span key={reason} className="rounded-md border border-dark-700 bg-dark-900 px-2 py-0.5 text-[11px] text-dark-300">{reason}</span>)}
  </div> : <span className="text-xs text-dark-500">Priority score {Math.round(item.priority_score ?? 0)}</span>
}

export default function PriorityActionCentre({ actions, loading, available, tenantId }) {
  return (
    <section aria-labelledby="priority-actions-title">
      <SectionHeader id="priority-actions-title" title="Priority Action Centre" className="mb-4"
        description="Security issues requiring attention, prioritised by risk and operational impact."
        actions={<Link to={dashboardHref('/alerts', { sort: 'priority' }, tenantId)} className="btn-secondary">
          View all issues <ArrowUpRight className="h-4 w-4" />
        </Link>} />

      <div className="glass-card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1050px] text-left text-sm">
          <thead className="border-b border-dark-700 bg-dark-900/50 text-[11px] uppercase tracking-[0.06em] text-dark-400">
            <tr>
              <th className="px-5 py-3 font-medium">Priority</th>
              <th className="px-4 py-3 font-medium">Affected asset</th>
              <th className="px-4 py-3 font-medium">Security issue</th>
              <th className="px-4 py-3 font-medium">Risk context</th>
              <th className="px-4 py-3 font-medium">Asset owner / assignee</th>
              <th className="px-5 py-3 font-medium">Recommended action</th>
            </tr>
          </thead>
          {loading ? (
            <tbody><tr><td colSpan="6" className="px-5 py-10"><div className="space-y-3 animate-pulse">{[0, 1, 2].map(n => <div key={n} className="h-5 rounded bg-dark-700/50" />)}</div></td></tr></tbody>
          ) : !available ? (
            <tbody><tr><td colSpan="6" className="px-5 py-12 text-center text-sm text-dark-400">Priority data unavailable.</td></tr></tbody>
          ) : actions.length ? (
            <tbody className="divide-y divide-dark-700/50">
              {actions.map(item => {
                const tier = operationalTier(item)
                const action = item.recommended_action || playbook(item).text.split('\n')[0]
                const issue = item.kind === 'cve_group'
                  ? `${item.details.package_name || 'CVE remediation'} · ${item.cve_count} CVE${item.cve_count === 1 ? '' : 's'}`
                  : `${alertLabel(item)} · ${renderDetail(item)}`
                const assignee = item.assignee || item.assignees?.[0] || null
                return (
                  <tr key={item.key} className="align-top transition-colors hover:bg-eagle-500/[0.04]">
                    <td className="px-5 py-4">
                      <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-semibold ${tierStyle[tier.id]}`}>
                        {tier.id === 'P0' && <AlertTriangle className="h-3.5 w-3.5" />}{tier.id} · {tier.label}
                      </span>
                      {tier.id === 'P0' && <span className="mt-1 block text-[11px] text-dark-500">Possible compromise</span>}
                    </td>
                    <td className="px-4 py-4">
                      <Link to={dashboardHref(`/inventory/${encodeURIComponent(item.asset?.asset_id ?? '')}`, {}, tenantId)} className="font-medium text-dark-50 hover:text-eagle-400">
                        {item.asset?.hostname || item.asset?.ip || 'Unknown asset'}
                      </Link>
                      <div className="mt-1 text-xs capitalize text-dark-500">{item.asset?.device_type || 'type unknown'}{item.asset?.ip && item.asset?.hostname ? ` · ${item.asset.ip}` : ''}</div>
                    </td>
                    <td className="px-4 py-4">
                      <div className="max-w-[240px] font-medium text-dark-100">{issue}</div>
                      <div className="mt-1 flex items-center gap-2"><SevBadge sev={item.severity} /><span className="text-xs text-dark-500">{timeAgo(item.first_seen)}</span></div>
                    </td>
                    <td className="px-4 py-4"><Context item={item} /></td>
                    <td className="px-4 py-4">
                      <div className="text-xs text-dark-400">Owner</div><div className="text-dark-200">{item.asset?.owner || 'Unassigned'}</div>
                      <div className="mt-2 text-xs text-dark-400">Remediation assignee</div><div className="text-dark-200">{assignee || 'Unassigned'}</div>
                    </td>
                    <td className="px-5 py-4">
                      <p className="max-w-[260px] text-xs leading-relaxed text-dark-300">{action}</p>
                      <Link to={item.advisory_id ? dashboardHref('/advisories', {}, tenantId) : itemHref(item, tenantId)} state={item.advisory_id ? { openAdvisoryId: item.advisory_id } : undefined} className="mt-2 inline-flex items-center gap-1 text-xs font-medium text-eagle-400 hover:underline">
                        {item.advisory_id ? 'Open advisory' : item.kind === 'cve_group' ? 'Review fix group' : item.event_type === 'new_device' ? 'Open asset' : 'Open finding'} <ArrowUpRight className="h-3.5 w-3.5" />
                      </Link>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          ) : (
            <tbody><tr><td colSpan="6" className="px-5 py-14 text-center">
              <CircleCheck className="mx-auto h-8 w-8 text-accent-green" />
              <p className="mt-3 font-medium text-dark-200">No actionable open findings</p>
              <p className="mt-1 text-sm text-dark-500">New priorities will appear here when scans or threat intelligence identify them.</p>
            </td></tr></tbody>
          )}
        </table>
      </div>
      <div className="flex items-center gap-2 border-t border-dark-700/50 px-5 py-3 text-xs text-dark-500">
        <ListFilter className="h-3.5 w-3.5 flex-shrink-0" />Priorities map existing scores: P1 ≥100, P2 ≥75, P3 below 75. Direct threat-intel matches are P0 and indicate a possible compromise, not confirmation.
      </div>
      </div>
    </section>
  )
}
