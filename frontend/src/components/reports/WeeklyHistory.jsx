// Weekly history (GET /posture/weekly, workers/src/services/weekly.ts): one record per finished week
// (Monday to Monday, Malaysia time), the change from last week and from the baseline week the tenant
// chose, and this week so far.
import { useCallback, useEffect, useState } from 'react'
import { ArrowDownRight, ArrowUpRight, Flag, Minus } from 'lucide-react'
import client from '../../api/client'
import PanelHeading from '../ui/PanelHeading'
import { hoursText } from '../../utils/fixTime'

const fmt = (v) => (v == null ? '—' : Number(v).toLocaleString())
const weekDate = (ws) => new Date(`${ws}T00:00:00Z`).toLocaleDateString(undefined, { day: 'numeric', month: 'short', timeZone: 'UTC' })

function Trend({ c }) {
  if (!c || c.delta == null) return <span className="text-dark-500">—</span>
  const cls = c.trend === 'better' ? 'text-emerald-400' : c.trend === 'worse' ? 'text-red-400' : 'text-dark-400'
  const Icon = c.delta > 0 ? ArrowUpRight : c.delta < 0 ? ArrowDownRight : Minus
  return <span className={`inline-flex items-center gap-0.5 tabular-nums ${cls}`}><Icon className="h-3.5 w-3.5" />{c.delta > 0 ? '+' : ''}{c.delta}</span>
}

export default function WeeklyHistory({ tenantId, isPlatform, title = 'Weekly history' }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(null)

  const load = useCallback(async () => {
    if (isPlatform && !tenantId) { setData(null); return }
    setError('')
    try {
      const res = await client.get('/posture/weekly', { params: { weeks: 12, ...(tenantId ? { tenant_id: tenantId } : {}) } })
      setData(res.data)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load the weekly history')
    }
  }, [tenantId, isPlatform])
  useEffect(() => { load() }, [load])

  const setBaseline = async (week) => {
    setSaving(week ?? 'none')
    try {
      await client.put(`/tenants/${tenantId}/baseline-week`, { week_start: week })
      await load()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to set the baseline')
    } finally {
      setSaving(null)
    }
  }

  const base = new Map((data?.vs_baseline ?? []).map(b => [b.key, b]))
  const last = data?.weeks?.[0]
  const cur = data?.current?.metrics

  return <div className="glass-card p-5 lg:p-6 space-y-4">
    <PanelHeading title={title}
      detail="One record per week (Monday to Monday, Malaysia time): what changed, and how this compares with last week and your baseline week." />
    {isPlatform && !tenantId ? <p className="text-sm text-dark-400">Choose a tenant above to see its weekly history.</p>
      : error ? <p className="text-sm text-red-400">{error}</p>
      : !data ? <div className="h-24 animate-pulse rounded-lg bg-dark-700/35" />
      : <>
        {cur && <p className="text-xs text-dark-400">
          This week so far ({data.current.iso_week}, from {weekDate(data.current.week_start)}): {fmt(cur.new)} new alerts, {fmt(cur.resolved)} resolved,
          {' '}{fmt(cur.open_end)} open, {fmt(cur.overdue_end)} overdue.
        </p>}

        {last ? <div>
          <p className="mb-1.5 text-xs font-medium text-dark-300">
            Week {last.iso_week} (from {weekDate(last.week_start)}) compared
            {last.backfilled && <span className="ml-1 font-normal text-dark-500" title="Rebuilt from alert dates: alerts counted with today's severity and tier; devices removed since are not known">(reconstructed)</span>}
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-dark-400 border-b border-dark-700/60">
                <th className="py-1.5 text-left font-medium">Measure</th>
                <th className="py-1.5 text-right font-medium">{last.iso_week}</th>
                <th className="py-1.5 text-right font-medium">Week before</th>
                <th className="py-1.5 text-right font-medium">Change</th>
                <th className="py-1.5 text-right font-medium">{data.baseline_week ? `vs baseline (${weekDate(data.baseline_week)})` : 'vs baseline'}</th>
              </tr></thead>
              <tbody>
                {data.vs_last_week.map(c => <tr key={c.key} className="border-b border-dark-700/30">
                  <td className="py-1.5 text-dark-200">{c.label}</td>
                  <td className="py-1.5 text-right tabular-nums text-dark-100">{fmt(c.now)}</td>
                  <td className="py-1.5 text-right tabular-nums text-dark-400">{fmt(c.then)}</td>
                  <td className="py-1.5 text-right"><Trend c={c} /></td>
                  <td className="py-1.5 text-right">{data.baseline_week ? <><Trend c={base.get(c.key)} /> <span className="text-dark-500">(was {fmt(base.get(c.key)?.then)})</span></> : <span className="text-dark-500">—</span>}</td>
                </tr>)}
              </tbody>
            </table>
          </div>
          {!data.baseline_week && <p className="mt-1.5 text-[11px] text-dark-500">No baseline week chosen{data.can_set_baseline ? ': pick one in the table below (for example the week you started using UMEagleEye).' : ' (your Tenant Superadmin chooses it).'}</p>}
        </div> : <p className="text-sm text-dark-400">No finished week recorded yet: the first is recorded on Monday.</p>}

        {data.weeks.length > 0 && <div className="overflow-x-auto">
          <table className="data-table text-xs">
            <thead><tr>
              <th>Week</th><th className="text-right">Devices</th><th className="text-right">Open</th><th className="text-right">Tier 1-2</th>
              <th className="text-right">Overdue</th><th className="text-right">New</th><th className="text-right">Resolved</th>
              <th className="text-right">On time</th><th className="text-right">Median fix</th><th className="text-right">KEV</th>
              <th className="text-right">Sightings</th><th className="text-right">Posture</th><th />
            </tr></thead>
            <tbody>
              {data.weeks.map(w => {
                const m = w.metrics
                const t12 = (m.open_by_tier?.['1'] ?? 0) + (m.open_by_tier?.['2'] ?? 0)
                const isBase = data.baseline_week === w.week_start
                return <tr key={w.week_start}>
                  <td className="whitespace-nowrap">
                    <span className="text-dark-100">{w.iso_week}</span> <span className="text-dark-500">{weekDate(w.week_start)}</span>
                    {w.backfilled && <span className="ml-1 text-[10px] text-dark-500" title="Rebuilt from alert dates">rebuilt</span>}
                  </td>
                  <td className="text-right tabular-nums">{fmt(m.assets_total)}{m.assets_added ? <span className="text-emerald-400"> +{m.assets_added}</span> : null}{m.assets_removed ? <span className="text-dark-400"> −{m.assets_removed}</span> : null}</td>
                  <td className="text-right tabular-nums">{fmt(m.open_end)}</td>
                  <td className={`text-right tabular-nums ${t12 ? 'text-red-400' : ''}`}>{fmt(t12)}</td>
                  <td className={`text-right tabular-nums ${m.overdue_end ? 'text-amber-400' : ''}`}>{fmt(m.overdue_end)}</td>
                  <td className="text-right tabular-nums">{fmt(m.new)}</td>
                  <td className="text-right tabular-nums">{fmt(m.resolved)}</td>
                  <td className="text-right tabular-nums">{m.on_time_pct == null ? '—' : `${m.on_time_pct}%`}</td>
                  <td className="text-right tabular-nums">{m.median_resolve_hours == null ? '—' : hoursText(m.median_resolve_hours)}</td>
                  <td className="text-right tabular-nums">{fmt(m.kev_open_end)}</td>
                  <td className="text-right tabular-nums">{fmt(m.sightings_new)}</td>
                  <td className="text-right tabular-nums">{fmt(m.posture_score)}</td>
                  <td className="text-right whitespace-nowrap">
                    {isBase ? <span className="inline-flex items-center gap-1 text-eagle-400"><Flag className="h-3 w-3" />Baseline
                      {data.can_set_baseline && <button onClick={() => setBaseline(null)} disabled={!!saving} className="ml-1 text-dark-500 hover:text-dark-200 underline">clear</button>}</span>
                      : data.can_set_baseline && <button onClick={() => setBaseline(w.week_start)} disabled={!!saving}
                        className="text-dark-400 hover:text-eagle-400 underline">{saving === w.week_start ? 'Saving…' : 'Set as baseline'}</button>}
                  </td>
                </tr>
              })}
            </tbody>
          </table>
        </div>}
        <p className="text-[11px] text-dark-500">Recorded every Monday for the week just ended, and a Weekly Summary report is made for it. Weeks marked "rebuilt" were reconstructed from alert dates: alerts counted with today's severity and tier.</p>
      </>}
  </div>
}
