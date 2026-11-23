import { Link } from 'react-router-dom'
import { dashboardHref } from './dashboardUtils'
import PanelHeading from '../ui/PanelHeading'
import { EVENT_TYPE_LABELS } from '../common/alertMeta'
import { hoursText, onTimeBand, workText } from '../../utils/fixTime'

const fmt = value => Number(value ?? 0).toLocaleString()
const BAND = { good: 'text-emerald-400', fair: 'text-amber-400', poor: 'text-red-400' }

// The management view of fix-time (workers/src/services/fixTime.ts): what is overdue or due in the next 7
// days, in alerts and estimated hours; the on-time share; and how long fixes actually take here.
export default function FixTimeCard({ fixTime, loading, tenantId }) {
  const ft = fixTime
  const onTime = ft?.on_time_30d ?? {}
  const tiles = ft ? [
    { label: 'Overdue', value: fmt(ft.overdue.count), sub: `${workText(ft.overdue.hours)} of work`, cls: ft.overdue.count ? 'text-red-400' : 'text-dark-100',
      to: dashboardHref('/alerts', { view: 'overdue' }, tenantId) },
    { label: 'Due in 7 days', value: fmt(ft.due_7d.count), sub: `${workText(ft.due_7d.hours)} of work`, cls: ft.due_7d.count ? 'text-amber-400' : 'text-dark-100',
      to: dashboardHref('/alerts', { view: 'due-soon' }, tenantId) },
    { label: 'Work waiting', value: `${Math.round(ft.open.hours)} h`, sub: `${fmt(ft.open.count)} open alerts${ft.open.hours >= 16 ? `, ~${Math.round(ft.open.hours / 0.8) / 10} working days` : ''}`, cls: 'text-dark-100' },
    { label: 'Fixed on time', value: onTime.pct == null ? '—' : `${onTime.pct}%`, sub: `${fmt(onTime.on_time)} of ${fmt(onTime.resolved)} in 30 days`,
      cls: BAND[onTimeBand(onTime.pct)] ?? 'text-dark-100' },
  ] : []
  return <div className="glass-card p-5 lg:p-6 xl:col-span-2">
    <PanelHeading title="Fix-time" detail="What is due, the work it takes, and how long fixes take here." />
    {loading ? <div className="h-20 animate-pulse rounded-lg bg-dark-700/35" /> : !ft ? <p className="py-6 text-center text-sm text-dark-400">Fix-time data unavailable.</p> : <>
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        {tiles.map(t => {
          const body = <>
            <span className="text-xs text-dark-400">{t.label}</span>
            <span className={`mt-1 block font-display text-2xl font-semibold tabular-nums ${t.cls}`}>{t.value}</span>
            <span className="text-[11px] text-dark-500">{t.sub}</span>
          </>
          return t.to
            ? <Link key={t.label} to={t.to} className="rounded-md border border-dark-700/50 px-3 py-2.5 hover:border-dark-600 hover:bg-dark-900">{body}</Link>
            : <div key={t.label} className="rounded-md border border-dark-700/50 px-3 py-2.5">{body}</div>
        })}
      </div>
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div>
          <p className="mb-1.5 text-xs font-medium text-dark-300">Work waiting, by kind</p>
          {ft.by_effort.length === 0 ? <p className="text-xs text-dark-500">No open alerts.</p> : <ul className="space-y-1 text-xs">
            {ft.by_effort.map(r => <li key={r.key} className="flex justify-between gap-2">
              <span className="text-dark-300">{r.label} <span className="text-dark-500">({workText(r.hours_each)} each)</span></span>
              <span className="tabular-nums text-dark-100">{fmt(r.open)} · {workText(r.hours)}{r.overdue ? <span className="text-red-400"> · {fmt(r.overdue)} overdue</span> : null}</span>
            </li>)}
          </ul>}
        </div>
        <div>
          <p className="mb-1.5 text-xs font-medium text-dark-300">Typical time to resolve here <span className="font-normal text-dark-500">(median, last 90 days)</span></p>
          {ft.time_to_resolve.length === 0 ? <p className="text-xs text-dark-500">Nothing resolved in 90 days yet.</p> : <ul className="space-y-1 text-xs">
            {ft.time_to_resolve.slice(0, 6).map(r => <li key={r.type} className="flex justify-between gap-2">
              <span className="text-dark-300">{EVENT_TYPE_LABELS[r.type] ?? r.type}</span>
              <span className={`tabular-nums ${r.reliable ? 'text-dark-100' : 'text-dark-500'}`} title={r.reliable ? undefined : `Fewer than ${ft.min_resolved} resolved: not yet a reliable guide`}>
                {hoursText(r.median_hours)} <span className="text-dark-500">({fmt(r.resolved)} resolved{r.reliable ? '' : ', too few'})</span>
              </span>
            </li>)}
          </ul>}
        </div>
      </div>
      <p className="mt-3 text-[11px] text-dark-500">Work is estimated per alert (investigate a compromise 4 h, harden a computer below the security baseline 2 h, upgrade a service or install OS updates 1 h, update a package or fix an exposure 30 min, review a change 15 min). Due dates follow your fix-time targets (Alerts › Alert rules).</p>
    </>}
  </div>
}
