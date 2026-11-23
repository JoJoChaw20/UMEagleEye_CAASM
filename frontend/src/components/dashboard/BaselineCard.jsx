import { Link } from 'react-router-dom'
import { dashboardHref } from './dashboardUtils'
import PanelHeading from '../ui/PanelHeading'
import { osLabel } from '../../utils/osLabel'

// The organisation's security baseline (workers/src/services/securityBaseline.ts baselineSummary): all
// passed checks over all judged checks of the scored computers, and how many reach the target.
export default function BaselineCard({ baseline: b, loading, tenantId }) {
  const below = b && b.percent != null && b.target != null && b.percent < b.target
  const cls = !b || b.percent == null ? 'text-dark-300' : below ? (b.percent < 80 ? 'text-red-400' : 'text-amber-400') : 'text-emerald-400'
  return <div className="glass-card p-5 lg:p-6">
    <PanelHeading title="Security baseline" detail="Computers' settings against 30 CIS-based checks, as many for Windows, Linux and macOS." />
    {loading ? <div className="h-20 animate-pulse rounded-lg bg-dark-700/35" />
      : !b || b.computers === 0 ? <p className="py-6 text-center text-sm text-dark-400">No computer has reported its baseline yet. Agents send it from the build of 23 November 2026.</p>
      : <>
        <div className="flex flex-wrap items-end gap-x-6 gap-y-2">
          <div>
            <span className={`font-display text-3xl font-semibold tabular-nums ${cls}`}>{b.percent == null ? '—' : `${b.percent}%`}</span>
            <span className="ml-2 text-xs text-dark-400">{b.target != null ? `target ${b.target}%` : 'each organisation\'s own target'}</span>
          </div>
          <Link to={dashboardHref('/alerts', { type: 'security_baseline' }, tenantId)} className="text-sm text-dark-200 hover:text-eagle-400">
            <span className="tabular-nums font-semibold">{b.at_target}</span> of <span className="tabular-nums">{b.assessed}</span> computers at target
          </Link>
        </div>
        {b.computers > b.assessed && <p className="mt-1 text-[11px] text-dark-500">{b.computers - b.assessed} more reported too few readable checks to score (agent not running as Administrator / root).</p>}
        <div className="mt-3 grid grid-cols-2 gap-2">
          {Object.entries(b.by_os).map(([os, v]) => <div key={os} className="rounded-md border border-dark-700/50 px-3 py-2">
            <span className="text-xs text-dark-400">{osLabel(os)}</span>
            <span className="block font-display text-xl font-semibold tabular-nums text-dark-100">{v.percent == null ? '—' : `${v.percent}%`}</span>
            <span className="text-[11px] text-dark-500">{v.at_target} of {v.assessed} at target</span>
          </div>)}
        </div>
        {b.lowest.length > 0 && <div className="mt-3">
          <p className="mb-1 text-xs font-medium text-dark-300">Lowest</p>
          <ul className="space-y-1 text-xs">
            {b.lowest.map(r => <li key={r.asset_id} className="flex justify-between gap-2">
              <Link to={`/inventory/${r.asset_id}#security-baseline`} className="truncate text-dark-200 hover:text-eagle-400">{r.hostname ?? r.asset_id.slice(0, 8)}</Link>
              <span className={`tabular-nums ${r.percent < r.target ? 'text-amber-400' : 'text-emerald-400'}`}>{r.percent}%</span>
            </li>)}
          </ul>
        </div>}
      </>}
  </div>
}
