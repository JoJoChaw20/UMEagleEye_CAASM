import { ArrowDownRight, ArrowRight, ArrowUpRight, Clock3 } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { CHART_TOOLTIP_STYLE } from '../common/alertMeta'
import { dashboardHref, historicalScoreChange } from './dashboardUtils'
import SectionHeader from '../ui/SectionHeader'
import PanelHeading from '../ui/PanelHeading'

const fmt = value => Number(value ?? 0).toLocaleString()
const STATUSES = [
  { id: 'open', label: 'Open', color: 'bg-sev-critical', text: 'text-red-400' },
  { id: 'acknowledged', label: 'Acknowledged', color: 'bg-sev-medium', text: 'text-amber-400' },
  { id: 'in_progress', label: 'In progress', color: 'bg-eagle-500', text: 'text-eagle-400' },
  { id: 'resolved', label: 'Resolved', color: 'bg-sev-low', text: 'text-emerald-400' },
]

function RemediationProgress({ remediation, loading, onManage, tenantId }) {
  const counts = Object.fromEntries(STATUSES.map(s => [s.id, Number(remediation?.by_status?.[s.id] ?? 0)]))
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0)
  return <div className="glass-card p-5 lg:p-6">
    <PanelHeading title="Remediation progress" detail="Advisory lifecycle and overdue response work."
      action={<button type="button" onClick={onManage} className="inline-flex items-center gap-1 text-xs font-medium text-eagle-400 hover:text-eagle-300">Manage advisories <ArrowRight className="h-3.5 w-3.5" /></button>} />
    {loading ? <div className="h-3 animate-pulse rounded-full bg-dark-700/50" /> : !remediation ? <p className="py-8 text-center text-sm text-dark-400">Advisory status data unavailable.</p> : <>
      <div className="flex h-2.5 gap-px overflow-hidden rounded-full bg-dark-700/50" role="img" aria-label={`${fmt(total)} advisories by lifecycle status`}>
        {STATUSES.map(status => counts[status.id] > 0 && <span key={status.id} className={`${status.color} transition-[width] duration-700 ease-out`} style={{ width: `${counts[status.id] / (total || 1) * 100}%` }} title={`${status.label}: ${fmt(counts[status.id])}`} />)}
      </div>
      <div className="mt-4 grid grid-cols-2 gap-2">
        {STATUSES.map(status => <Link key={status.id} to={dashboardHref('/advisories', { status: status.id }, tenantId)} className="rounded-md border border-transparent px-2.5 py-2 transition-colors hover:border-dark-700 hover:bg-dark-900">
          <span className="flex items-center justify-between gap-2"><span className="inline-flex items-center gap-2 text-xs text-dark-400"><span className={`h-2 w-2 rounded-sm ${status.color}`} />{status.label}</span><span className={`font-display text-base font-semibold tabular-nums ${status.text}`}>{fmt(counts[status.id])}</span></span>
        </Link>)}
      </div>
      <div className="mt-4 flex items-center justify-between border-t border-dark-700/50 pt-4">
        <Link to={dashboardHref('/advisories', { status: 'open' }, tenantId)} className="text-xs text-dark-400 hover:text-eagle-400">Unassigned: <span className="font-semibold text-dark-100">{fmt(remediation.unassigned)}</span></Link>
        <Link to={dashboardHref('/advisories', { status: 'open' }, tenantId)} className={`inline-flex items-center gap-1.5 text-sm ${remediation.sla_breaches > 0 ? 'text-red-400' : 'text-dark-300'}`}>
          <Clock3 className="h-4 w-4" />{fmt(remediation.sla_breaches)} past 72h SLA
        </Link>
      </div>
    </>}
  </div>
}

function SecurityPostureTrend({ posture, history, loading }) {
  const change = historicalScoreChange(history)
  const data = history.map(point => ({
    date: new Date(point.timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
    score: Number(point.overall_score),
    total_assets: Number(point.total_assets),
  }))
  const deltaColor = change?.delta > 0 ? 'text-emerald-400' : change?.delta < 0 ? 'text-red-400' : 'text-dark-400'
  return <div id="posture-trend" className="glass-card p-5 lg:p-6">
    <PanelHeading title="Security posture trend" detail="Daily reconstructed score · last 30 days" className="mb-4"
      action={change && <span className={`inline-flex items-center gap-1 text-sm font-medium ${deltaColor}`}>{change.delta > 0 ? <ArrowUpRight className="h-4 w-4" /> : change.delta < 0 ? <ArrowDownRight className="h-4 w-4" /> : null}{change.delta > 0 ? '+' : ''}{change.delta} in 7 days</span>} />
    <div className="mb-3 flex items-end gap-3"><span className="font-display text-3xl font-semibold leading-none tabular-nums text-dark-50">{posture?.overall_score == null ? '—' : posture.overall_score}</span><span className="pb-1 text-xs text-dark-400">current score / 100</span>{change && <span className="pb-1 text-xs text-dark-500">previous {change.previous}</span>}</div>
    {loading ? <div className="h-[190px] animate-pulse rounded-lg bg-dark-700/35" /> : data.length < 2 ? <div className="flex h-[190px] items-center justify-center text-sm text-dark-400">Not enough historical data to show a trend.</div> :
      <ResponsiveContainer width="100%" height={190}>
        <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <defs><linearGradient id="postureTrendFill" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="rgb(var(--eagle-500))" stopOpacity={0.22} /><stop offset="95%" stopColor="rgb(var(--eagle-500))" stopOpacity={0} /></linearGradient></defs>
          <CartesianGrid vertical={false} stroke="rgb(var(--dark-700))" strokeDasharray="2 4" />
          <XAxis dataKey="date" minTickGap={24} tick={{ fill: 'rgb(var(--dark-400))', fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} tick={{ fill: 'rgb(var(--dark-400))', fontSize: 11 }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={CHART_TOOLTIP_STYLE} formatter={value => [`${value}/100`, 'Posture score']} />
          <Area type="monotone" dataKey="score" stroke="rgb(var(--eagle-400))" fill="url(#postureTrendFill)" strokeWidth={2} dot={false} activeDot={{ r: 4, fill: 'rgb(var(--dark-800))', stroke: 'rgb(var(--eagle-400))', strokeWidth: 2 }} />
        </AreaChart>
      </ResponsiveContainer>}
    <p className="mt-2 text-[11px] text-dark-500">History is reconstructed from asset creation dates and findings open at each day end; no synthetic points are added.</p>
  </div>
}

export default function RemediationAndTrend({ remediation, posture, history, loading, onManage, tenantId }) {
  return <section aria-labelledby="remediation-trend-title">
    <SectionHeader id="remediation-trend-title" title="Remediation & security trends" className="mb-4"
      description="Follow-through on known risks, and how the scored posture is changing." />
    <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-2"><RemediationProgress remediation={remediation} loading={loading} onManage={onManage} tenantId={tenantId} /><SecurityPostureTrend posture={posture} history={history} loading={loading} /></div>
  </section>
}
