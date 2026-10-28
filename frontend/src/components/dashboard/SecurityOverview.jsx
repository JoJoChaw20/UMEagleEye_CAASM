import { Activity, ArrowDownRight, ArrowUpRight, Boxes, CircleAlert, Globe2, ShieldCheck } from 'lucide-react'
import { historicalScoreChange } from './dashboardUtils'

const number = (value) => value == null ? '—' : Number(value).toLocaleString()

function MetricCard({ icon: Icon, label, value, detail, tone = 'neutral', onClick }) {
  const body = (
    <>
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-medium text-dark-300">{label}</span>
        <span className="rounded-lg border border-dark-700/70 bg-dark-900/40 p-2 text-dark-400"><Icon className="h-4 w-4" /></span>
      </div>
      <div className={`mt-4 text-3xl font-semibold tracking-tight tabular-nums ${tone === 'critical' ? 'text-red-400' : tone === 'warning' ? 'text-amber-400' : 'text-dark-50'}`}>{value}</div>
      <p className="mt-1.5 min-h-5 text-xs text-dark-400">{detail}</p>
    </>
  )
  const cls = `glass-card p-5 text-left min-w-0 ${onClick ? 'transition-colors hover:border-eagle-500/50 hover:bg-dark-800/80 focus:outline-none focus:ring-2 focus:ring-eagle-500/50' : ''}`
  return onClick
    ? <button type="button" onClick={onClick} className={cls}>{body}</button>
    : <div className={cls}>{body}</div>
}

export default function SecurityOverview({ summary, posture, history, loading, onAssets, onAlerts, onAgents, onPosture }) {
  const overview = summary?.overview
  const collection = summary?.collection
  const score = posture?.overall_score
  const delta = historicalScoreChange(history)
  const historicalAssets = history
    .filter(point => point.timestamp && new Date(point.timestamp).getTime() <= Date.now() - 7 * 86400000)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
    .at(-1)?.total_assets
  const assetDelta = overview?.known_assets != null && historicalAssets != null ? overview.known_assets - Number(historicalAssets) : null
  const down = (collection?.agents_offline ?? 0) + (collection?.agents_degraded ?? 0)
  const scoreTone = score == null ? 'neutral' : score < 50 ? 'critical' : score < 80 ? 'warning' : 'neutral'

  const data = [
    { label: 'Known assets', icon: Boxes, value: number(overview?.known_assets), detail: overview ? `${number(overview.new_assets_7d)} discovered in 7 days${assetDelta == null ? '' : ` · ${assetDelta > 0 ? '+' : ''}${assetDelta} vs 7 days ago`}` : 'Inventory unavailable', onClick: onAssets },
    { label: 'Urgent issues', icon: CircleAlert, value: number(overview?.urgent_issues), tone: overview?.urgent_issues > 0 ? 'critical' : 'neutral', detail: overview ? `${number(overview.urgent_issues_new_7d)} identified in 7 days · score ≥100` : 'Priority data unavailable', onClick: onAlerts },
    { label: 'High-risk exposures', icon: Globe2, value: number(overview?.high_risk_exposure_assets), tone: overview?.high_risk_exposure_assets > 0 ? 'warning' : 'neutral', detail: 'Internet-facing assets with open critical or high findings', onClick: onAlerts },
    { label: 'Agent health', icon: Activity, value: collection ? `${number(collection.agents_online)} / ${number(collection.agents_total)}` : '—', tone: down > 0 ? 'warning' : 'neutral', detail: collection ? `${number(down)} offline or degraded · registered agents only` : 'Agent status unavailable', onClick: onAgents },
    { label: 'Security posture', icon: ShieldCheck, value: score == null ? '—' : `${score} / 100`, tone: scoreTone, detail: delta ? `${delta.delta > 0 ? '+' : ''}${delta.delta} vs 7 days ago` : 'Historical comparison unavailable', onClick: onPosture },
  ]

  return (
    <section aria-labelledby="overview-title">
      <div className="mb-4 flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h2 id="overview-title" className="text-lg font-semibold tracking-tight text-dark-100">Organization security overview</h2>
          <p className="mt-1 text-sm text-dark-400">Known assets, urgent risk, monitoring health, and current posture.</p>
        </div>
        {delta && <span className={`inline-flex items-center gap-1 text-xs ${delta.delta >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
          {delta.delta >= 0 ? <ArrowUpRight className="h-3.5 w-3.5" /> : <ArrowDownRight className="h-3.5 w-3.5" />}
          Posture {delta.delta > 0 ? 'improved' : delta.delta < 0 ? 'declined' : 'unchanged'} over 7 days
        </span>}
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {data.map(item => <MetricCard key={item.label} {...item} />)}
      </div>
      <p className="mt-2 text-right text-xs text-dark-500">
        {loading ? 'Refreshing dashboard…' : summary?.generated_at ? `Updated ${new Date(summary.generated_at).toLocaleString()}` : 'Update time unavailable'}
        <span className="ml-2">Windows: new assets 7d · security changes 24h · posture trend 30d</span>
      </p>
    </section>
  )
}
