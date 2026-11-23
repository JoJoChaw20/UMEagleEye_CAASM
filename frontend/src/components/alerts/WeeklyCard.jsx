// Week by week, on the Alerts page (GET /posture/weekly, workers/src/services/weekly.ts): the last finished
// week (Monday to Monday, Malaysia time) against the week before, and the recent weeks at a glance.
import { useEffect, useState } from 'react'
import { ArrowDownRight, ArrowUpRight, CalendarRange, Minus } from 'lucide-react'
import client from '../../api/client'
import { hoursText } from '../../utils/fixTime'

const fmt = (v) => (v == null ? '—' : Number(v).toLocaleString())
const weekDate = (ws) => new Date(`${ws}T00:00:00Z`).toLocaleDateString(undefined, { day: 'numeric', month: 'short', timeZone: 'UTC' })
// the measures the card compares (keys of lib/weekly.ts COMPARED)
const SHOWN = ['open_end', 'tier12', 'overdue_end', 'new', 'resolved', 'on_time_pct', 'median_resolve_hours', 'baseline_pct', 'baseline_at_target']
const SHORT = { open_end: 'Open', tier12: 'Compromise or exploited', overdue_end: 'Overdue', new: 'New', resolved: 'Resolved', on_time_pct: 'Fixed on time', median_resolve_hours: 'Median time to fix',
  baseline_pct: 'Security baseline', baseline_at_target: 'Computers at baseline target' }
const PCT = new Set(['on_time_pct', 'baseline_pct'])
const show = (key, v) => (v == null ? '—' : PCT.has(key) ? `${v}%` : key === 'median_resolve_hours' ? hoursText(v) : fmt(v))

function Change({ c }) {
  if (!c || c.delta == null) return <span className="text-dark-500 text-[11px]">no week before</span>
  const cls = c.trend === 'better' ? 'text-emerald-400' : c.trend === 'worse' ? 'text-red-400' : 'text-dark-400'
  const Icon = c.delta > 0 ? ArrowUpRight : c.delta < 0 ? ArrowDownRight : Minus
  const d = c.key === 'median_resolve_hours' ? hoursText(Math.abs(c.delta)) : PCT.has(c.key) ? `${Math.abs(c.delta)} pts` : fmt(Math.abs(c.delta))
  return <span className={`inline-flex items-center gap-0.5 text-[11px] tabular-nums ${cls}`}><Icon className="h-3 w-3" />{c.delta === 0 ? 'same' : d}</span>
}

export default function WeeklyCard({ tenantId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let live = true
    setData(null); setError('')
    client.get('/posture/weekly', { params: { weeks: 6, ...(tenantId ? { tenant_id: tenantId } : {}) } })
      .then((r) => { if (live) setData(r.data) })
      .catch((err) => { if (live) setError(err?.response?.data?.detail || 'Weekly history unavailable') })
    return () => { live = false }
  }, [tenantId])

  const last = data?.weeks?.[0]
  const changes = new Map((data?.vs_last_week ?? []).map((c) => [c.key, c]))
  return (
    <div className="glass-card p-6">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h3 className="text-lg font-semibold text-dark-100 flex items-center gap-2"><CalendarRange className="w-4 h-4 text-eagle-400" /> Week by week</h3>
          <p className="text-sm text-dark-400 mt-1">
            {last ? <>Week {last.iso_week} (from {weekDate(last.week_start)}) against the week before{last.backfilled && <span className="text-dark-500" title="Rebuilt from alert dates: alerts counted with today's severity and tier"> · rebuilt</span>}.</>
              : 'Each finished week (Monday to Monday) against the week before.'}
            {data?.current?.metrics && <span className="text-dark-500"> This week so far: {fmt(data.current.metrics.new)} new, {fmt(data.current.metrics.resolved)} resolved.</span>}
          </p>
        </div>
      </div>
      {error ? <p className="mt-3 text-sm text-dark-400">{error}</p>
        : !data ? <div className="mt-4 h-20 animate-pulse rounded-lg bg-dark-700/35" />
        : !last ? <p className="mt-3 text-sm text-dark-400">No finished week recorded yet: the first is recorded on Monday.</p>
        : <div className="mt-4 grid grid-cols-1 2xl:grid-cols-5 gap-4">
          <div className="2xl:col-span-2 grid grid-cols-2 sm:grid-cols-4 2xl:grid-cols-3 gap-2 content-start">
            {SHOWN.map((k) => { const c = changes.get(k); return (
              <div key={k} className="rounded-md border border-dark-700/50 px-3 py-2">
                <p className="text-[11px] text-dark-400 truncate" title={c?.label}>{SHORT[k]}</p>
                <p className="font-display text-lg font-semibold tabular-nums text-dark-50">{show(k, c?.now)}</p>
                <Change c={c} />
              </div>
            ) })}
          </div>
          <div className="2xl:col-span-3 overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-dark-400 border-b border-dark-700/60">
                <th className="py-1.5 text-left font-medium">Week</th><th className="py-1.5 text-right font-medium">Open</th>
                <th className="py-1.5 text-right font-medium" title="Possible compromise or exploited (tier 1-2)">Tier 1-2</th>
                <th className="py-1.5 text-right font-medium">Overdue</th><th className="py-1.5 text-right font-medium">New</th>
                <th className="py-1.5 text-right font-medium">Resolved</th><th className="py-1.5 text-right font-medium">On time</th>
                <th className="py-1.5 text-right font-medium">Devices</th>
              </tr></thead>
              <tbody>
                {data.weeks.map((w) => { const m = w.metrics; const t12 = (m.open_by_tier?.['1'] ?? 0) + (m.open_by_tier?.['2'] ?? 0); return (
                  <tr key={w.week_start} className="border-b border-dark-700/30">
                    <td className="py-1.5 whitespace-nowrap text-dark-200">{w.iso_week} <span className="text-dark-500">{weekDate(w.week_start)}</span></td>
                    <td className="py-1.5 text-right tabular-nums">{fmt(m.open_end)}</td>
                    <td className={`py-1.5 text-right tabular-nums ${t12 ? 'text-red-400' : ''}`}>{fmt(t12)}</td>
                    <td className={`py-1.5 text-right tabular-nums ${m.overdue_end ? 'text-amber-400' : ''}`}>{fmt(m.overdue_end)}</td>
                    <td className="py-1.5 text-right tabular-nums">{fmt(m.new)}</td>
                    <td className="py-1.5 text-right tabular-nums">{fmt(m.resolved)}</td>
                    <td className="py-1.5 text-right tabular-nums">{m.on_time_pct == null ? '—' : `${m.on_time_pct}%`}</td>
                    <td className="py-1.5 text-right tabular-nums">{fmt(m.assets_total)}{m.assets_added ? <span className="text-emerald-400"> +{m.assets_added}</span> : null}</td>
                  </tr>
                ) })}
              </tbody>
            </table>
          </div>
        </div>}
    </div>
  )
}
