import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react'
import PostureGauge, { postureBand } from '../ui/PostureGauge'
import Sparkline from '../ui/Sparkline'
import { historicalScoreChange } from './dashboardUtils'

const number = (value) => value == null ? '—' : Number(value).toLocaleString()

// History points sorted oldest → newest, and the index of the last point at least
// 7 days old (the comparison the deltas use), for the sparkline guide.
function useSeries(history) {
  const points = [...history]
    .filter((p) => p.timestamp)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
  const cutoff = Date.now() - 7 * 86400000
  let weekAgo = -1
  points.forEach((p, i) => { if (new Date(p.timestamp).getTime() <= cutoff) weekAgo = i })
  return { points, weekAgo: weekAgo >= 0 ? weekAgo : null }
}

function Delta({ value, suffix = 'vs 7 days ago', goodWhenUp = true }) {
  if (value == null) return <span className="text-xs text-dark-500">No 7-day comparison yet</span>
  const good = value === 0 || goodWhenUp == null ? null : (value > 0) === goodWhenUp
  const Icon = value > 0 ? ArrowUpRight : value < 0 ? ArrowDownRight : Minus
  const tone = good == null ? 'text-dark-400' : good ? 'text-emerald-400' : 'text-red-400'
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium ${tone}`}>
      <Icon className="h-3.5 w-3.5" />{value > 0 ? '+' : ''}{value} <span className="font-normal text-dark-400">{suffix}</span>
    </span>
  )
}

function Tile({ label, value, tone = 'neutral', detail, onClick, foot }) {
  const valueTone = tone === 'critical' ? 'text-red-400' : tone === 'warning' ? 'text-amber-400' : 'text-dark-50'
  return (
    <button type="button" onClick={onClick}
      className="group flex min-w-0 flex-col rounded-xl border border-dark-700/80 bg-dark-800 p-5 text-left shadow-panel transition-[border-color,transform] duration-200 ease-out hover:-translate-y-px hover:border-eagle-500/50">
      <span className="flex items-center justify-between gap-3">
        <span className="flex items-center gap-2.5"><span aria-hidden="true" className="trace-node transition-colors group-hover:bg-eagle-400" /><span className="text-sm font-medium text-dark-200">{label}</span></span>
        <ArrowUpRight className="h-4 w-4 text-dark-600 transition-colors group-hover:text-eagle-400" />
      </span>
      <span className={`mt-3 font-display text-[32px] font-semibold leading-none tabular-nums ${valueTone}`}>{value}</span>
      <span className="mt-2 min-h-[2.5em] text-xs leading-relaxed text-dark-400">{detail}</span>
      <span className="mt-auto pt-3">{foot}</span>
    </button>
  )
}

function Meter({ parts, label }) {
  const total = parts.reduce((sum, p) => sum + p.value, 0)
  return (
    <span className="block" role="img" aria-label={label}>
      <span className="flex h-1.5 overflow-hidden rounded-full bg-dark-700/70">
        {total > 0 && parts.map((p) => p.value > 0 && (
          <span key={p.key} className={`${p.className} transition-[width] duration-700 ease-out`} style={{ width: `${(p.value / total) * 100}%` }} />
        ))}
      </span>
      <span className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-dark-400">
        {parts.map((p) => (
          <span key={p.key} className="inline-flex items-center gap-1.5"><span className={`h-1.5 w-1.5 rounded-full ${p.className}`} />{p.label} {number(p.value)}</span>
        ))}
      </span>
    </span>
  )
}

export default function SecurityOverview({ summary, posture, history, loading, onAssets, onAlerts, onAgents, onPosture }) {
  const overview = summary?.overview
  const collection = summary?.collection
  const surface = summary?.attack_surface
  const score = posture?.overall_score
  const delta = historicalScoreChange(history)
  const { points, weekAgo } = useSeries(history)
  const band = postureBand(loading ? null : score)

  const weekAgoAssets = weekAgo != null ? points[weekAgo]?.total_assets : null
  const assetDelta = overview?.known_assets != null && weekAgoAssets != null ? overview.known_assets - Number(weekAgoAssets) : null
  const online = Number(collection?.agents_online ?? 0)
  const degraded = Number(collection?.agents_degraded ?? 0)
  const offline = Number(collection?.agents_offline ?? 0)
  const down = offline + degraded
  const exposed = Number(overview?.high_risk_exposure_assets ?? 0)
  const facing = Number(surface?.internet_facing_total ?? 0)
  const ph = loading ? '…' : '—'

  return (
    <section aria-labelledby="overview-title" className="grid grid-cols-1 gap-4 xl:grid-cols-12">
      <h2 id="overview-title" className="sr-only">Organization security overview</h2>

      {/* Posture dial */}
      <div className="flex flex-col rounded-xl border border-dark-700/80 bg-dark-800 p-5 shadow-panel xl:col-span-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2.5"><span aria-hidden="true" className="trace-node" /><h3 className="text-base font-semibold text-dark-50">Security posture</h3></div>
            <p className="mt-1 pl-[17.5px] text-xs text-dark-400">Scored live from open findings</p>
          </div>
          <span className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold ${band.chip} ${band.text}`}>{band.label}</span>
        </div>

        <div className="mt-4 flex flex-1 flex-col items-center justify-center">
          <PostureGauge score={score} loading={loading} />
          <div className="mt-2"><Delta value={delta?.delta ?? null} /></div>
        </div>

        <div className="mt-4 border-t border-dark-700/70 pt-3">
          <div className="mb-1.5 flex items-center justify-between text-[11px] text-dark-400">
            <span>Score, last 30 days</span>
            {weekAgo != null && <span className="inline-flex items-center gap-1.5"><span className="inline-block h-3 border-l border-dashed border-dark-500" />7 days ago</span>}
          </div>
          {loading ? <div className="h-9 animate-pulse rounded bg-dark-700/40" />
            : <Sparkline values={points.map((p) => p.overall_score)} min={0} max={100} height={36} markIndex={weekAgo}
                color={band.color} label="Posture score over the last 30 days" />}
          <div className="mt-3 flex items-center justify-between gap-2 text-xs">
            <span className="text-dark-400">
              Open critical <span className="font-semibold tabular-nums text-dark-100">{number(posture?.open_critical_events)}</span>
              <span className="mx-1.5 text-dark-600">·</span>
              high <span className="font-semibold tabular-nums text-dark-100">{number(posture?.open_high_events)}</span>
            </span>
            <button type="button" onClick={onPosture} className="font-medium text-eagle-400 hover:text-eagle-300">Trend detail</button>
          </div>
        </div>
      </div>

      {/* KPI tiles */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:col-span-8">
        <Tile label="Known assets" value={overview ? number(overview.known_assets) : ph} onClick={onAssets}
          detail={overview ? `${number(overview.new_assets_7d)} discovered in the last 7 days` : 'Inventory unavailable'}
          foot={<span className="block">
            <span className="mb-1 flex items-center justify-between text-[11px] text-dark-400"><span>Inventory size, 30 days</span><Delta value={assetDelta} goodWhenUp={null} suffix="in 7 days" /></span>
            <Sparkline values={points.map((p) => p.total_assets)} height={28} markIndex={weekAgo} label="Known assets over the last 30 days" />
          </span>} />

        <Tile label="Urgent issues" value={overview ? number(overview.urgent_issues) : ph} onClick={onAlerts}
          tone={overview?.urgent_issues > 0 ? 'critical' : 'neutral'}
          detail={overview ? `${number(overview.urgent_issues_new_7d)} new in 7 days · priority score 100 or more` : 'Priority data unavailable'}
          foot={<span className="block">
            <span className="mb-1 block text-[11px] text-dark-400">Open critical findings, 30 days</span>
            <Sparkline values={points.map((p) => p.open_critical_events)} height={28} markIndex={weekAgo} color="rgb(var(--sev-critical))" label="Open critical findings over the last 30 days" />
          </span>} />

        <Tile label="High-risk exposures" value={overview ? number(overview.high_risk_exposure_assets) : ph} onClick={onAlerts}
          tone={exposed > 0 ? 'warning' : 'neutral'}
          detail="Internet-facing assets with open critical or high findings"
          foot={<Meter label={`${exposed} of ${facing} internet-facing assets have high-risk findings`} parts={[
            { key: 'risk', label: 'High-risk', value: exposed, className: 'bg-amber-400' },
            { key: 'rest', label: 'Other internet-facing', value: Math.max(0, facing - exposed), className: 'bg-dark-500' },
          ]} />} />

        <Tile label="Agent health" onClick={onAgents}
          value={collection ? <span className="inline-flex items-center gap-3">{number(online)}<span className="text-xl text-dark-500">/ {number(collection.agents_total)}</span>{online > 0 && <span className="live-dot bg-accent-cyan" />}</span> : ph}
          tone={down > 0 ? 'warning' : 'neutral'}
          detail={!collection ? 'Agent status unavailable' : Number(collection.agents_total ?? 0) === 0 ? 'No agents registered yet. Add one on the Agents page.' : down > 0 ? `${number(down)} offline or reporting late` : 'Every registered agent is reporting'}
          foot={collection && <Meter label={`${online} online, ${degraded} late, ${offline} offline`} parts={[
            { key: 'on', label: 'Online', value: online, className: 'bg-accent-cyan' },
            { key: 'late', label: 'Late', value: degraded, className: 'bg-amber-400' },
            { key: 'off', label: 'Offline', value: offline, className: 'bg-red-400' },
          ]} />} />
      </div>
    </section>
  )
}
