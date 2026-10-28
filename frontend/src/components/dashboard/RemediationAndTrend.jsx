import { ArrowDownRight, ArrowUpRight, CheckCircle2, Clock3, TrendingUp } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { CHART_TOOLTIP_STYLE } from '../common/alertMeta'
import { dashboardHref, historicalScoreChange } from './dashboardUtils'

const fmt = value => Number(value ?? 0).toLocaleString()
const STATUSES = [
  { id: 'open', label: 'Open', color: 'bg-red-400', text: 'text-red-400' },
  { id: 'acknowledged', label: 'Acknowledged', color: 'bg-amber-400', text: 'text-amber-400' },
  { id: 'in_progress', label: 'In progress', color: 'bg-blue-400', text: 'text-blue-400' },
  { id: 'resolved', label: 'Resolved', color: 'bg-emerald-400', text: 'text-emerald-400' },
]

function RemediationProgress({ remediation, loading, onManage, tenantId }) {
  const counts = Object.fromEntries(STATUSES.map(s => [s.id, Number(remediation?.by_status?.[s.id] ?? 0)]))
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0)
  return <div className="glass-card p-5 lg:p-6">
    <div className="mb-5 flex items-start justify-between gap-3">
      <div className="flex items-center gap-3"><span className="rounded-lg border border-dark-700/70 bg-dark-900/40 p-2 text-dark-300"><CheckCircle2 className="h-4 w-4" /></span><div><h3 className="font-semibold text-dark-100">Remediation progress</h3><p className="mt-1 text-xs text-dark-400">Advisory lifecycle and overdue response work.</p></div></div>
      <button type="button" onClick={onManage} className="text-xs text-eagle-400 hover:underline">Manage advisories →</button>
    </div>
    {loading ? <div className="h-3 animate-pulse rounded-full bg-dark-700/50" /> : !remediation ? <p className="py-8 text-center text-sm text-dark-400">Advisory status data unavailable.</p> : <>
      <div className="flex h-3 overflow-hidden rounded-full bg-dark-700/50" role="img" aria-label={`${fmt(total)} advisories by lifecycle status`}>
        {STATUSES.map(status => counts[status.id] > 0 && <span key={status.id} className={`${status.color} transition-all`} style={{ width: `${counts[status.id] / (total || 1) * 100}%` }} title={`${status.label}: ${fmt(counts[status.id])}`} />)}
      </div>
      <div className="mt-4 grid grid-cols-2 gap-2">
        {STATUSES.map(status => <Link key={status.id} to={dashboardHref('/advisories', { status: status.id }, tenantId)} className="rounded-lg px-2 py-2 hover:bg-dark-700/20">
          <span className="flex items-center justify-between gap-2"><span className="text-xs text-dark-400">{status.label}</span><span className={`font-semibold tabular-nums ${status.text}`}>{fmt(counts[status.id])}</span></span>
        </Link>)}
      </div>
      <div className="mt-4 flex items-center justify-between border-t border-dark-700/50 pt-4">
        <Link to={dashboardHref('/advisories', { status: 'open' }, tenantId)} className="text-xs text-dark-400 hover:text-eagle-300">Unassigned: <span className="font-semibold text-dark-100">{fmt(remediation.unassigned)}</span></Link>
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
    <div className="mb-4 flex items-start justify-between gap-3">
      <div className="flex items-center gap-3"><span className="rounded-lg border border-dark-700/70 bg-dark-900/40 p-2 text-dark-300"><TrendingUp className="h-4 w-4" /></span><div><h3 className="font-semibold text-dark-100">Security posture trend</h3><p className="mt-1 text-xs text-dark-400">Daily reconstructed score · last 30 days</p></div></div>
      {change && <span className={`inline-flex items-center gap-1 text-sm font-medium ${deltaColor}`}>{change.delta > 0 ? <ArrowUpRight className="h-4 w-4" /> : change.delta < 0 ? <ArrowDownRight className="h-4 w-4" /> : null}{change.delta > 0 ? '+' : ''}{change.delta} in 7 days</span>}
    </div>
    <div className="mb-3 flex items-end gap-3"><span className="text-3xl font-semibold tracking-tight tabular-nums text-dark-50">{posture?.overall_score == null ? '—' : posture.overall_score}</span><span className="pb-1 text-xs text-dark-400">current score / 100</span>{change && <span className="pb-1 text-xs text-dark-500">previous {change.previous}</span>}</div>
    {loading ? <div className="h-[190px] animate-pulse rounded-lg bg-dark-700/35" /> : data.length < 2 ? <div className="flex h-[190px] items-center justify-center text-sm text-dark-400">Not enough historical data to show a trend.</div> :
      <ResponsiveContainer width="100%" height={190}>
        <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <defs><linearGradient id="postureTrendFill" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#3393ff" stopOpacity={0.2} /><stop offset="95%" stopColor="#3393ff" stopOpacity={0} /></linearGradient></defs>
          <CartesianGrid vertical={false} stroke="rgb(var(--dark-700))" />
          <XAxis dataKey="date" minTickGap={24} tick={{ fill: 'rgb(var(--dark-400))', fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} tick={{ fill: 'rgb(var(--dark-400))', fontSize: 11 }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={CHART_TOOLTIP_STYLE} formatter={value => [`${value}/100`, 'Posture score']} />
          <Area type="monotone" dataKey="score" stroke="#3393ff" fill="url(#postureTrendFill)" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
        </AreaChart>
      </ResponsiveContainer>}
    <p className="mt-2 text-[11px] text-dark-500">History is reconstructed from asset creation dates and findings open at each day end; no synthetic points are added.</p>
  </div>
}

export default function RemediationAndTrend({ remediation, posture, history, loading, onManage, tenantId }) {
  return <section aria-labelledby="remediation-trend-title">
    <div className="mb-4"><h2 id="remediation-trend-title" className="text-lg font-semibold tracking-tight text-dark-100">Remediation & security trends</h2><p className="mt-1 text-sm text-dark-400">Track follow-through on known risks and how the scored posture is changing.</p></div>
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2"><RemediationProgress remediation={remediation} loading={loading} onManage={onManage} tenantId={tenantId} /><SecurityPostureTrend posture={posture} history={history} loading={loading} /></div>
  </section>
}
