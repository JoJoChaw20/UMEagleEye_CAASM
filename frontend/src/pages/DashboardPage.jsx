import { useState, useEffect, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Shield, AlertTriangle, TrendingUp, TrendingDown, Globe, Radio, Server,
  ChevronRight, Network, HelpCircle, Clock, PackageSearch, Fingerprint, Sparkles, Minus,
  Target, Wrench, ShieldAlert, ShieldCheck, ArrowRight,
} from 'lucide-react'
import { AreaChart, Area, ResponsiveContainer, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts'
import client from '../api/client'
import TenantSelector from '../components/common/TenantSelector'
import {
  SevBadge, StatusBadge, alertLabel, renderDetail, playbook, timeAgo, CHART_TOOLTIP_STYLE,
  CONCERNS, riskReasons, SEVERITY_COLORS, RISKY_PORTS,
} from '../components/common/alertMeta'
import {
  ConcernCard, SeverityStack, ReasonChips, PriorityTier, DueLabel, fmtNum,
} from '../components/common/triageViz'

export default function DashboardPage() {
  const navigate = useNavigate()
  const [posture, setPosture]     = useState(null)
  const [history, setHistory]     = useState([])
  const [stats, setStats]         = useState(null)
  const [summary, setSummary]     = useState(null)
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [tenantFilter, setTenantFilter] = useState('')

  const loadDashboardData = useCallback(async () => {
    setLoading(true)
    setError(null)
    // Never leave the previous tenant's numbers on screen while loading
    setPosture(null); setHistory([]); setStats(null); setSummary(null)
    try {
      const tParam = tenantFilter ? { tenant_id: tenantFilter } : {}
      // allSettled: one slow or failing panel must not blank the whole page
      const [postureRes, historyRes, statsRes, summaryRes] = await Promise.allSettled([
        client.get('/posture/current', { params: tParam }),
        client.get('/posture/history', { params: { limit: 30, ...tParam } }),
        client.get('/events/stats/summary', { params: tParam }),
        client.get('/dashboard/summary', { params: tParam }),
      ])
      const ok = (r) => r.status === 'fulfilled' ? r.value.data : null
      setPosture(ok(postureRes))
      setHistory(ok(historyRes)?.items || [])
      setStats(ok(statsRes))
      setSummary(ok(summaryRes))
      if ([postureRes, historyRes, statsRes, summaryRes].some(r => r.status === 'rejected')) {
        setError('Some dashboard data failed to load. Numbers below may be incomplete.')
      }
    } catch (err) {
      console.error('Dashboard load error:', err)
      setError('Some dashboard data failed to load. Numbers below may be incomplete.')
    } finally {
      setLoading(false)
    }
  }, [tenantFilter])

  useEffect(() => { loadDashboardData() }, [loadDashboardData])

  const score = posture?.overall_score ?? null
  const scoreColor = score == null ? '#7b7f87' : score >= 80 ? '#00e676' : score >= 50 ? '#ffc400' : '#ff5252'
  const weekAgoScore = history.length >= 8 ? history[history.length - 8]?.overall_score : null
  const scoreDelta = score != null && weekAgoScore != null ? score - weekAgoScore : null

  const trendData = history.map((h) => ({
    day: new Date(h.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
    score: h.overall_score,
    critical: h.open_critical_events,
  }))

  const col = summary?.collection
  const surface = summary?.attack_surface
  const hygiene = summary?.hygiene
  const openAlerts = (q) => navigate(`/alerts?${new URLSearchParams(q).toString()}`)

  return (
    <div className="space-y-6">
      {/* ── Header + collection health ── */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-dark-50">Security Overview</h1>
          <p className="text-dark-400 text-sm mt-1">What is dangerous right now, why, and what to do first</p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <TenantSelector value={tenantFilter} onChange={setTenantFilter} />
          <CollectionStatus col={col} loading={loading} />
        </div>
      </div>

      {error && (
        <div className="glass-card px-4 py-2 text-sm text-accent-amber border-amber-500/30">{error}</div>
      )}
      {col?.recent_failures?.length > 0 && (
        <div className="glass-card px-4 py-2.5 text-sm border-red-500/30 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-accent-red mt-0.5 flex-shrink-0" />
          <div className="text-dark-200">
            <span className="font-medium text-accent-red">Scan failed</span> — {col.recent_failures[0].scan_type} scan
            {col.recent_failures[0].subnet ? ` of ${col.recent_failures[0].subnet}` : ''} {timeAgo(col.recent_failures[0].started_at)}
            {col.recent_failures[0].reason ? `: ${col.recent_failures[0].reason}` : ''}.
            <span className="text-dark-400"> Data for that network may be stale. </span>
            <Link to="/discovery" className="text-eagle-400 hover:underline">Check discovery →</Link>
          </div>
        </div>
      )}

      {/* ── Verdict ── */}
      <SituationBanner loading={loading} summary={summary} stats={stats}
        score={score} scoreColor={scoreColor} scoreDelta={scoreDelta} drivers={posture?.score_drivers}
        onOpen={openAlerts} />

      {/* ── What to worry about ── */}
      <section>
        <SectionTitle title="Needs attention" hint="Each card counts open alerts in one category. Click a card to open exactly those alerts." />
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4">
          {CONCERNS.map(meta => {
            const c = summary?.concerns?.find(x => x.id === meta.id)
            return (
              <ConcernCard key={meta.id} meta={meta} loading={loading} count={c?.count ?? 0} examples={c?.examples}
                onOpen={() => openAlerts({ view: meta.id })} />
            )
          })}
        </div>
      </section>

      {/* ── Do these first + where the risk sits ── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="glass-card p-5 xl:col-span-2">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-base font-semibold text-dark-100 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-eagle-400" /> Do these first
            </h3>
            <Link to="/alerts" className="text-xs text-eagle-400 hover:underline flex items-center gap-0.5">Full queue <ChevronRight className="w-3.5 h-3.5" /></Link>
          </div>
          <p className="text-xs text-dark-500 mb-4">Top 5 open alerts. The chips show why each one is ranked this high.</p>
          {loading ? <Skeleton rows={5} /> : summary?.priority_actions?.length > 0 ? (
            <ol className="space-y-2.5">
              {summary.priority_actions.map((a, i) => <ActionRow key={a.event_id} a={a} rank={i + 1} onClick={() => navigate(`/alerts?event=${a.event_id}`)} />)}
            </ol>
          ) : (
            <div className="text-center py-8 text-dark-400">
              <Shield className="w-10 h-10 mx-auto mb-2 opacity-30" />
              <p className="text-sm">No open alerts. {col?.agents_total === 0 ? 'Deploy an agent and run your first scan.' : 'Keep scans and SBOMs current to stay that way.'}</p>
            </div>
          )}
        </div>

        <div className="glass-card p-5">
          <h3 className="text-base font-semibold text-dark-100 flex items-center gap-2 mb-1">
            <Target className="w-4 h-4 text-accent-red" /> Most at-risk assets
          </h3>
          <p className="text-xs text-dark-500 mb-4">Ranked by their worst open alert, then by how many critical and high alerts they carry.</p>
          {loading ? <Skeleton rows={6} /> : summary?.risky_assets?.length ? (
            <ul className="space-y-3.5">
              {summary.risky_assets.map(a => (
                <li key={a.asset_id}>
                  <button onClick={() => openAlerts({ q: a.ip || a.hostname })} className="w-full text-left group">
                    <div className="flex items-center gap-2 text-sm min-w-0">
                      <PriorityTier score={a.top_priority} />
                      <span className="text-dark-100 font-medium truncate group-hover:text-eagle-300">{a.hostname || a.ip}</span>
                      {a.internet_facing && <Globe className="w-3.5 h-3.5 text-accent-amber flex-shrink-0" title="Internet-facing" />}
                      <span className="ml-auto text-xs text-dark-400 whitespace-nowrap">{fmtNum(a.open)} open</span>
                    </div>
                    <p className="text-[11px] text-dark-500 mt-0.5 mb-1.5">
                      <span className="capitalize">{a.device_type}</span>{a.hostname && a.ip ? ` · ${a.ip}` : ''} · criticality {a.criticality}/10
                      {a.by_severity.critical > 0 && <span className="text-red-400"> · {fmtNum(a.by_severity.critical)} critical</span>}
                    </p>
                    <SeverityStack counts={a.by_severity} height={6} legend={false} />
                  </button>
                </li>
              ))}
            </ul>
          ) : <Empty text="No assets with open alerts." />}
        </div>
      </div>

      {/* ── Patch plan ── */}
      <PatchBacklog loading={loading} data={summary?.patch_backlog} onOpen={openAlerts} />

      {/* ── Attack surface ── */}
      <section>
        <SectionTitle title="Attack surface" hint="What an attacker can reach, from the latest scans. Click a row to see its alerts." />
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="glass-card p-5 xl:col-span-2">
            <PanelHead icon={Globe} title="Internet-facing assets" sub="Reachable from outside your network, so they get attacked first." />
            {loading ? <Skeleton rows={5} /> : surface?.internet_facing?.length ? (
              <>
                <div className="flex flex-wrap gap-2 mb-4">
                  <SummaryPill value={surface.internet_facing_total} label="reachable from the internet" />
                  <SummaryPill value={surface.internet_facing_risky ?? 0} label="expose a risky service" tone={surface.internet_facing_risky ? 'bad' : 'ok'} />
                  <SummaryPill value={surface.internet_facing_inferred ?? 0} label="inferred, not confirmed" tone="muted"
                    title="Inferred from the agent's default gateway. Confirm or correct the exposure in Assets." />
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-xs text-dark-500 text-left border-b border-dark-700">
                        <th className="py-2 font-medium">Asset</th>
                        <th className="py-2 font-medium">Open ports</th>
                        <th className="py-2 font-medium">Open alerts</th>
                        <th className="py-2 font-medium text-right">Exposure</th>
                      </tr>
                    </thead>
                    <tbody>
                      {surface.internet_facing.map(a => (
                        <tr key={a.asset_id} onClick={() => openAlerts({ q: a.ip })}
                          className="border-b border-dark-700/40 hover:bg-dark-700/20 cursor-pointer align-top">
                          <td className="py-2.5 pr-3">
                            <p className="text-dark-100 font-medium">{a.hostname || a.ip}</p>
                            <p className="text-[11px] text-dark-500"><span className="capitalize">{a.device_type}</span>{a.hostname ? <span className="font-mono"> · {a.ip}</span> : ''}</p>
                          </td>
                          <td className="py-2.5 pr-3"><PortChips ports={a.ports} /></td>
                          <td className="py-2.5 pr-3 whitespace-nowrap">
                            {a.open_alerts > 0
                              ? <span className="inline-flex items-center gap-2"><SevBadge sev={a.worst_open_severity} /><span className="text-xs text-dark-300">{a.open_alerts} open</span></span>
                              : <span className="text-xs text-emerald-400 inline-flex items-center gap-1"><ShieldCheck className="w-3.5 h-3.5" />None</span>}
                          </td>
                          <td className="py-2.5 text-right">
                            <span className={`text-[11px] px-2 py-0.5 rounded-full border whitespace-nowrap ${a.confirmed ? 'border-eagle-500/40 text-eagle-300' : 'border-dark-600 text-dark-400'}`}
                              title={a.confirmed ? 'Confirmed by an analyst' : "Inferred from the agent's gateway"}>
                              {a.confirmed ? 'Confirmed' : 'Inferred'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {surface.internet_facing_total > surface.internet_facing.length && (
                  <Link to="/assets" className="text-xs text-eagle-400 hover:underline inline-flex items-center gap-0.5 mt-3">
                    {surface.internet_facing_total - surface.internet_facing.length} more in Assets <ChevronRight className="w-3.5 h-3.5" />
                  </Link>
                )}
              </>
            ) : <Empty text="No internet-facing assets identified." />}
          </div>

          <div className="glass-card p-5">
            <PanelHead icon={Radio} title="Risky services on the network" sub="Services attackers scan for first. Each should have a reason to be open." />
            {loading ? <Skeleton rows={5} /> : surface?.risky_services?.length ? (
              <ul className="divide-y divide-dark-700/50">
                {surface.risky_services.slice(0, 8).map(r => (
                  <li key={r.port}>
                    <button onClick={() => r.hosts.length === 1 ? openAlerts({ q: r.hosts[0].ip }) : openAlerts({ view: 'exposed_services' })}
                      title={r.hosts.map(h => h.hostname || h.ip).join(', ')}
                      className="w-full text-left flex items-center gap-3 py-2.5 hover:bg-dark-700/20 rounded px-1">
                      <div className="min-w-0 flex-1">
                        <p className="text-sm text-dark-100 font-medium">{r.service} <span className="font-mono text-xs text-dark-500">port {r.port}</span></p>
                        <p className="text-[11px] text-dark-500">on {r.host_count} host{r.host_count === 1 ? '' : 's'}</p>
                      </div>
                      {r.internet_facing > 0
                        ? <span className="text-[11px] px-2 py-0.5 rounded-full border border-red-500/40 bg-red-500/10 text-red-300 whitespace-nowrap">{r.internet_facing} internet-facing</span>
                        : <span className="text-[11px] text-dark-500 whitespace-nowrap">internal only</span>}
                    </button>
                  </li>
                ))}
              </ul>
            ) : <Empty text="No risky services (Telnet, SMB, RDP, databases…) seen in scans." />}
          </div>
        </div>
      </section>

      {/* ── Network devices + asset mix ── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="glass-card p-5 xl:col-span-2">
          <PanelHead icon={Network} title="Network devices" sub="Routers, switches and firewalls. Their firmware is checked over SNMPv3." />
          {loading ? <Skeleton rows={5} /> : surface?.network_devices?.length ? (
            <NetworkDevices surface={surface} onOpen={openAlerts} />
          ) : <Empty text="No routers or switches identified yet." />}
        </div>

        <div className="glass-card p-5">
          <PanelHead icon={Server} title="Asset mix" sub={`${fmtNum(Object.values(surface?.device_mix ?? {}).reduce((s, n) => s + n, 0))} assets by type`} />
          {loading ? <Skeleton rows={5} /> : surface ? (
            <div className="space-y-3">
              {Object.entries(surface.device_mix).sort((x, y) => y[1] - x[1]).map(([type, n]) => {
                const totalAssets = Object.values(surface.device_mix).reduce((s, x) => s + x, 0) || 1
                return (
                  <div key={type}>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="capitalize text-dark-200">{type === 'iot' ? 'IoT' : type}</span>
                      <span className="tabular-nums text-dark-100 font-semibold">{n}</span>
                    </div>
                    <div className="h-2 rounded bg-dark-700/50 overflow-hidden">
                      <div className="h-full rounded" style={{ width: `${(n / totalAssets) * 100}%`, background: '#3393ff' }} />
                    </div>
                  </div>
                )
              })}
              {surface.device_mix.unknown > 0 && (
                <p className="text-xs text-dark-400 pt-1">
                  {surface.device_mix.unknown} unknown device{surface.device_mix.unknown === 1 ? '' : 's'} can't be risk-scored properly. Label them in <Link to="/assets" className="text-eagle-400 hover:underline">Assets</Link>.
                </p>
              )}
            </div>
          ) : null}
        </div>
      </div>

      {/* ── Trend ── */}
      <div className="glass-card p-5">
        <PanelHead icon={TrendingUp} title="Posture score, last 30 days" sub="Recalculated at the end of each day from open critical and high alerts. Higher is better." />
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={trendData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
            <defs>
              <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3393ff" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#3393ff" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} stroke="rgb(var(--dark-700))" />
            <XAxis dataKey="day" tick={{ fill: 'rgb(var(--dark-400))', fontSize: 11 }} axisLine={false} tickLine={false} minTickGap={24} />
            <YAxis domain={[0, 100]} ticks={[0, 50, 80, 100]} tick={{ fill: 'rgb(var(--dark-400))', fontSize: 11 }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={CHART_TOOLTIP_STYLE} formatter={(v, name) => [v, name === 'score' ? 'Posture score' : 'Open critical']} />
            <Area type="monotone" dataKey="score" stroke="#3393ff" fill="url(#scoreGradient)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* ── Hygiene work queues ── */}
      <section>
        <SectionTitle title="Coverage gaps" hint="Not attacks, but each one hides attacks from you. Clear them so the numbers above stay true." />
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <HygieneCard icon={Fingerprint} title="New devices this week" data={hygiene?.new_devices_7d} loading={loading}
            why="Joined the network in the last 7 days."
            action="Confirm an owner; isolate if unclaimed after 24h"
            row={a => [a.hostname || a.ip, a.vendor ?? 'Unknown vendor']}
            onClick={() => openAlerts({ view: 'new_devices' })} />
          <HygieneCard icon={HelpCircle} title="Unidentified devices" data={hygiene?.unidentified} loading={loading}
            why="No type, vendor or hostname, so their risk can't be scored."
            action="Label them in Assets"
            row={a => [a.ip, a.mac ?? 'No MAC']}
            to="/assets" />
          <HygieneCard icon={Clock} title={`Not seen in ${hygiene?.stale_after_days ?? 7} days`} data={hygiene?.stale_assets} loading={loading}
            why="No scan has reached them recently. Moved, retired, or out of coverage."
            action="Verify, then retire or fix scan coverage"
            row={a => [a.hostname || a.ip, a.last_scanned ? `last seen ${timeAgo(a.last_scanned)}` : 'never scanned']}
            to="/assets" />
          <HygieneCard icon={PackageSearch} title="Servers & PCs without SBOM" data={hygiene?.no_sbom} loading={loading}
            why="No software inventory, so their CVEs are invisible."
            action="Run an SBOM scan on them"
            row={a => [a.hostname || a.ip, a.device_type]}
            to="/sbom" />
        </div>
      </section>
    </div>
  )
}

// ── Pieces ─────────────────────────────────────────────────────
function CollectionStatus({ col, loading }) {
  if (loading || !col) return <span className="text-xs text-dark-500">Checking agents…</span>
  const healthy = col.agents_total > 0 && col.agents_online === col.agents_total && col.recent_failures.length === 0
  const none = col.agents_total === 0
  const color = none ? 'bg-dark-500' : healthy ? 'bg-accent-green' : col.agents_online === 0 ? 'bg-accent-red' : 'bg-accent-amber'
  const last = col.last_active_scan?.completed_at
  return (
    <Link to="/agents" className="flex items-center gap-2 text-xs text-dark-300 hover:text-white glass-card px-3 py-1.5"
      title={col.agents.map(a => `${a.name}: ${a.online ? 'online' : 'offline'} (${timeAgo(a.last_heartbeat)})`).join('\n')}>
      <span className={`w-2 h-2 rounded-full ${color} ${healthy ? 'animate-pulse' : ''}`} />
      {none ? 'No agents deployed' : `${col.agents_online}/${col.agents_total} agents online`}
      <span className="text-dark-500">·</span>
      <span>last active scan {last ? timeAgo(last) : 'never'}</span>
      {col.last_passive_scan?.completed_at && <><span className="text-dark-500">·</span><span>passive {timeAgo(col.last_passive_scan.completed_at)}</span></>}
    </Link>
  )
}

function Delta({ value, goodWhenUp }) {
  if (value == null) return null
  if (value === 0) return <span className="text-xs text-dark-400 inline-flex items-center gap-0.5"><Minus className="w-3 h-3" />0 vs 7d</span>
  const good = goodWhenUp ? value > 0 : value < 0
  const Icon = value > 0 ? TrendingUp : TrendingDown
  return (
    <span className={`text-xs inline-flex items-center gap-0.5 ${good ? 'text-accent-green' : 'text-accent-red'}`}>
      <Icon className="w-3.5 h-3.5" />{value > 0 ? '+' : ''}{value} vs 7d
    </span>
  )
}

function SectionTitle({ title, hint }) {
  return (
    <div className="flex items-baseline gap-3 flex-wrap mb-3">
      <h2 className="text-base font-semibold text-dark-100">{title}</h2>
      {hint && <span className="text-xs text-dark-500">{hint}</span>}
    </div>
  )
}

// One sentence that answers "how bad is it right now?", plus the three numbers
// that back it up. Wording is driven by the concern counts, worst first.
function SituationBanner({ loading, summary, stats, score, scoreColor, scoreDelta, drivers, onOpen }) {
  const count = (id) => summary?.concerns?.find(c => c.id === id)?.count ?? 0
  const first = (id) => summary?.concerns?.find(c => c.id === id)?.examples?.[0]
  const cti = count('threat_intel'), exposed = count('exposed_services'), identity = count('identity')
  const exploitable = count('exploitable'), devices = count('new_devices')
  const today = exposed + identity
  const plural = (n, word) => `${fmtNum(n)} ${word}${n === 1 ? '' : 's'}`

  let tone, Icon, headline, detail, cta
  if (loading || !summary) {
    tone = 'neutral'; Icon = Shield; headline = 'Assessing your environment…'; detail = ''
  } else if (cti > 0) {
    tone = 'critical'; Icon = ShieldAlert
    headline = `Possible active compromise: ${cti} threat-intel match${cti === 1 ? '' : 'es'}`
    detail = 'A live threat feed matched something on your network. Isolate the affected hosts and escalate before anything else.'
    cta = { label: 'Open threat-intel alerts', q: { view: 'threat_intel' } }
  } else if (today > 0) {
    tone = 'critical'; Icon = ShieldAlert
    headline = `${plural(today, 'issue')} need${today === 1 ? 's' : ''} action today`
    const parts = []
    if (exposed) parts.push(`${plural(exposed, 'risky service')} opened`)
    if (identity) parts.push(plural(identity, 'device identity change'))
    const ex = first(exposed ? 'exposed_services' : 'identity')
    detail = parts.join(' and ') + (ex
      ? `. Worst: ${alertLabel(ex)}, ${renderDetail(ex)} on ${ex.asset.hostname || ex.asset.ip}${ex.asset.internet_facing ? ' (internet-facing)' : ''}.`
      : '.')
    cta = { label: 'Review now', q: { view: exposed ? 'exposed_services' : 'identity' } }
  } else if (exploitable > 0) {
    tone = 'serious'; Icon = ShieldAlert
    headline = `No live incidents. ${plural(exploitable, 'likely-exploited CVE')} to patch this week`
    detail = 'These vulnerabilities are being exploited in the wild or sit on internet-facing hosts. Patch them before the general backlog.'
    cta = { label: 'Open exploitable CVEs', q: { view: 'exploitable' } }
  } else {
    tone = 'good'; Icon = ShieldCheck
    headline = 'Nothing urgent right now'
    detail = devices > 0
      ? `${plural(devices, 'new device')} still need an owner. Otherwise, keep scans and SBOMs current.`
      : 'Keep scans and SBOMs current to stay that way.'
  }

  const toneCls = {
    critical: 'border-red-500/50 bg-red-500/[0.07]', serious: 'border-orange-500/40 bg-orange-500/[0.06]',
    good: 'border-emerald-500/40 bg-emerald-500/[0.05]', neutral: '',
  }[tone]
  const iconCls = { critical: 'text-red-400', serious: 'text-orange-400', good: 'text-emerald-400', neutral: 'text-dark-400' }[tone]
  const net = stats ? (stats.new_7d ?? 0) - (stats.resolved_7d ?? 0) : null
  const label = score == null ? '' : score >= 80 ? 'Good' : score >= 50 ? 'Fair' : 'Poor'

  return (
    <div className={`glass-card ${toneCls} p-5 grid grid-cols-1 lg:grid-cols-[1fr_auto] gap-5`}>
      <div className="flex gap-4 min-w-0">
        <Icon className={`w-10 h-10 flex-shrink-0 ${iconCls}`} />
        <div className="min-w-0">
          <p className="text-xl font-bold text-dark-50 leading-snug">{headline}</p>
          {detail && <p className="text-sm text-dark-300 mt-1.5 leading-relaxed">{detail}</p>}
          {cta && (
            <button onClick={() => onOpen(cta.q)} className="btn-primary text-sm py-1.5 px-3 mt-3 inline-flex items-center gap-1.5">
              {cta.label} <ArrowRight className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 lg:w-[480px]">
        <Metric label="Posture score" title={drivers?.length ? drivers.map(d => `${d.label}: ${d.impact}`).join('\n') : undefined}
          value={<span style={{ color: scoreColor }}>{score ?? '—'}<span className="text-sm text-dark-500 font-normal">/100</span></span>}
          sub={<span className="inline-flex items-center gap-1.5">{label}<Delta value={scoreDelta} goodWhenUp /></span>}>
          <div className="h-1.5 rounded bg-dark-700 mt-2 overflow-hidden">
            <div className="h-full rounded" style={{ width: `${score ?? 0}%`, background: scoreColor }} />
          </div>
        </Metric>
        <Metric label="Past SLA" onClick={() => onOpen({ view: 'overdue' })}
          value={<span className={(stats?.sla_breaches ?? 0) > 0 ? 'text-red-400' : 'text-dark-50'}>{stats ? fmtNum(stats.sla_breaches) : '—'}</span>}
          sub="critical > 3 days, high > 7 days" />
        <Metric label="Backlog this week"
          value={net == null ? '—' : <span className={net > 0 ? 'text-orange-400' : 'text-emerald-400'}>{net > 0 ? '+' : ''}{fmtNum(net)}</span>}
          sub={stats ? `${fmtNum(stats.new_7d)} new · ${fmtNum(stats.resolved_7d)} closed` : ''} />
      </div>
    </div>
  )
}

function Metric({ label, value, sub, title, onClick, children }) {
  const Tag = onClick ? 'button' : 'div'
  return (
    <Tag onClick={onClick} title={title}
      className={`text-left rounded-lg bg-dark-900/50 border border-dark-700/60 px-3 py-2.5 ${onClick ? 'hover:border-eagle-500/40' : ''}`}>
      <p className="text-[11px] uppercase tracking-wide text-dark-500 font-semibold">{label}</p>
      <p className="text-2xl font-bold text-dark-50 mt-0.5">{value}</p>
      <div className="text-[11px] text-dark-400 mt-0.5">{sub}</div>
      {children}
    </Tag>
  )
}

// One ranked action: what, where, why it ranks, what to do, and by when.
function ActionRow({ a, rank, onClick }) {
  const guide = playbook(a)
  return (
    <li>
      <button onClick={onClick}
        className="w-full text-left rounded-lg border border-dark-700 border-l-4 hover:bg-dark-700/20 hover:border-eagle-500/40 px-3 py-3 transition-colors flex gap-3"
        style={{ borderLeftColor: SEVERITY_COLORS[a.severity] }}>
        <span className="text-2xl font-bold text-dark-500 w-6 text-center leading-none pt-0.5">{rank}</span>
        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex items-center gap-2 flex-wrap">
            <PriorityTier score={a.priority_score} />
            <span className="text-sm text-dark-50 font-semibold">{alertLabel(a)}</span>
            <span className="font-mono text-xs text-accent-cyan">{renderDetail(a)}</span>
            <span className="ml-auto"><StatusBadge status={a.status} /></span>
          </div>
          <p className="text-xs text-dark-400">
            on <span className="text-dark-100 font-medium">{a.asset.hostname || a.asset.ip}</span>
            {a.asset.hostname && a.asset.ip ? <span className="font-mono"> ({a.asset.ip})</span> : ''}
            <span className="capitalize"> · {a.asset.device_type}</span> · first seen {timeAgo(a.first_seen)}
            {a.occurrences > 1 ? ` · seen ${a.occurrences}×` : ''}
          </p>
          <ReasonChips reasons={riskReasons(a)} />
          <div className="flex items-start gap-3 rounded bg-dark-900/50 px-2.5 py-1.5">
            <p className="text-xs text-dark-200 flex-1">
              <span className="text-eagle-300 font-semibold">Next: </span>{a.recommended_action ? a.recommended_action.split('\n')[0] : guide.text}
            </p>
            <DueLabel e={a} />
          </div>
        </div>
      </button>
    </li>
  )
}

// "Which upgrades clear the most CVE alerts": turns a large backlog into a
// short patch plan.
function PatchBacklog({ loading, data, onOpen }) {
  if (!loading && !data?.total) return null
  const top = data?.packages?.[0]
  const share = (n) => data?.total ? Math.round((n / data.total) * 100) : 0
  const maxAlerts = Math.max(1, ...(data?.packages ?? []).map(p => p.alerts))
  return (
    <div className="glass-card p-5">
      <div className="flex items-center justify-between flex-wrap gap-2 mb-1">
        <h3 className="text-base font-semibold text-dark-100 flex items-center gap-2">
          <Wrench className="w-4 h-4 text-eagle-400" /> CVE backlog: patch plan
        </h3>
        <button onClick={() => onOpen({ view: 'cve' })} className="text-xs text-eagle-400 hover:underline flex items-center gap-0.5">
          All CVE alerts <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </div>
      <p className="text-xs text-dark-500 mb-4">Known vulnerabilities from SBOM scans, grouped by package. Upgrading the top rows clears the most alerts.</p>
      {loading || !data ? <Skeleton rows={5} /> : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
            <Fact value={fmtNum(data.total)} label={`open CVE alerts on ${data.hosts} host${data.hosts === 1 ? '' : 's'}`} />
            <Fact value={`${share(data.fixable)}%`} label={`already have a fixed version (${fmtNum(data.fixable)} alerts)`} tone="good" />
            {top && <Fact value={`${share(top.alerts)}%`} tone="serious"
              label={<>come from one package: <span className="font-mono text-dark-100">{top.package}</span></>} />}
          </div>
          <div className="mb-5">
            <p className="text-xs text-dark-400 mb-1.5">Backlog by severity (click to filter)</p>
            <SeverityStack counts={data.by_severity} onSelect={(sev) => onOpen({ view: 'cve', severity: sev })} />
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-dark-500 text-left border-b border-dark-700">
                  <th className="py-2 font-medium">Package</th>
                  <th className="py-2 font-medium">Installed → upgrade to</th>
                  <th className="py-2 font-medium text-right">Hosts</th>
                  <th className="py-2 font-medium pl-4 w-[34%]">Alerts this upgrade clears</th>
                  <th className="py-2 font-medium text-right">Critical</th>
                </tr>
              </thead>
              <tbody>
                {data.packages.map(p => (
                  <tr key={p.package} onClick={() => onOpen({ view: 'cve', q: p.package })}
                    className="border-b border-dark-700/40 hover:bg-dark-700/20 cursor-pointer">
                    <td className="py-2.5 font-mono text-dark-100 whitespace-nowrap">{p.package}
                      {p.max_epss >= 0.1 && (
                        <span className="ml-2 font-sans text-[10px] px-1.5 py-0.5 rounded border border-orange-500/30 text-orange-300 bg-orange-500/10">exploited in the wild</span>
                      )}
                    </td>
                    <td className="py-2.5 font-mono text-xs text-dark-300 whitespace-nowrap">
                      {p.installed.slice(0, 2).join(', ')}{p.installed.length > 2 ? '…' : ''}
                      {p.upgrade_to && <> <span className="text-dark-500">→</span> <span className="text-emerald-400">≥ {p.upgrade_to}</span></>}
                    </td>
                    <td className="py-2.5 text-right tabular-nums text-dark-200">{p.hosts}</td>
                    <td className="py-2.5 pl-4">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-2 rounded bg-dark-700/50 overflow-hidden">
                          <div className="h-full rounded" style={{ width: `${(p.alerts / maxAlerts) * 100}%`, background: '#3393ff' }} />
                        </div>
                        <span className="text-xs tabular-nums text-dark-100 w-24 text-right">
                          {fmtNum(p.alerts)} <span className="text-dark-500">({share(p.alerts)}%)</span>
                        </span>
                      </div>
                    </td>
                    <td className={`py-2.5 text-right tabular-nums font-semibold ${p.critical ? 'text-red-400' : 'text-dark-500'}`}>{p.critical}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}

function Fact({ value, label, tone }) {
  const cls = { good: 'text-emerald-400', serious: 'text-orange-400' }[tone] ?? 'text-dark-50'
  return (
    <div className="rounded-lg bg-dark-900/50 border border-dark-700/60 px-4 py-3">
      <p className={`text-3xl font-bold ${cls}`}>{value}</p>
      <p className="text-xs text-dark-400 mt-1">{label}</p>
    </div>
  )
}

function PanelHead({ icon: Icon, title, sub }) {
  return (
    <div className="mb-4">
      <h3 className="text-base font-semibold text-dark-100 flex items-center gap-2"><Icon className="w-4 h-4 text-eagle-400" />{title}</h3>
      {sub && <p className="text-xs text-dark-500 mt-1">{sub}</p>}
    </div>
  )
}

function SummaryPill({ value, label, tone, title }) {
  const cls = {
    bad:   'border-red-500/40 bg-red-500/10 text-red-300',
    ok:    'border-emerald-500/30 bg-emerald-500/5 text-emerald-300',
    muted: 'border-dark-600 text-dark-300',
  }[tone] ?? 'border-dark-600 bg-dark-900/50 text-dark-100'
  return (
    <span title={title} className={`inline-flex items-baseline gap-1.5 text-xs px-2.5 py-1 rounded-full border ${cls}`}>
      <span className="text-sm font-bold tabular-nums">{fmtNum(value)}</span>{label}
    </span>
  )
}

// Open ports as chips; commonly attacked services are named and highlighted.
function PortChips({ ports, max = 6 }) {
  if (!ports?.length) return <span className="text-xs text-dark-500">none seen</span>
  const sorted = [...ports].sort((a, b) => (RISKY_PORTS[b] ? 1 : 0) - (RISKY_PORTS[a] ? 1 : 0) || a - b)
  return (
    <span className="inline-flex flex-wrap gap-1">
      {sorted.slice(0, max).map(p => RISKY_PORTS[p]
        ? <span key={p} className="text-[11px] px-1.5 py-0.5 rounded border border-red-500/40 bg-red-500/10 text-red-300 whitespace-nowrap">{RISKY_PORTS[p]} {p}</span>
        : <span key={p} className="text-[11px] px-1.5 py-0.5 rounded border border-dark-600 text-dark-300 font-mono">{p}</span>)}
      {sorted.length > max && <span className="text-[11px] text-dark-500 self-center">+{sorted.length - max}</span>}
    </span>
  )
}

function NetworkDevices({ surface, onOpen }) {
  const total = surface.network_devices_total
  const unmanaged = surface.network_devices_unmanaged
  const managed = total - unmanaged
  const shown = surface.network_devices.slice(0, 8)
  return (
    <>
      <div className="rounded-lg bg-dark-900/50 border border-dark-700/60 p-3 mb-4">
        <div className="flex items-baseline justify-between gap-3 flex-wrap mb-2">
          <p className="text-sm text-dark-100">
            <span className="font-bold text-emerald-400">{managed}</span> of {total} verified over SNMP
            {unmanaged > 0 && <span className="text-dark-400"> · <span className="font-semibold text-dark-200">{unmanaged}</span> unverified</span>}
          </p>
        </div>
        <div className="flex h-2 gap-[2px] rounded overflow-hidden bg-dark-700/40">
          {managed > 0 && <span className="block h-full" style={{ width: `${(managed / total) * 100}%`, background: '#00e676' }} />}
          {unmanaged > 0 && <span className="block h-full bg-dark-500" style={{ width: `${(unmanaged / total) * 100}%` }} />}
        </div>
        {unmanaged > 0 && (
          <p className="text-xs text-dark-400 mt-2">
            Unverified devices didn't answer SNMP, so their model and firmware can't be checked for known vulnerabilities. Enable SNMPv3 on them.
          </p>
        )}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-dark-500 text-left border-b border-dark-700">
              <th className="py-2 font-medium">Device</th>
              <th className="py-2 font-medium">Vendor / model</th>
              <th className="py-2 font-medium">Firmware check</th>
              <th className="py-2 font-medium text-right">Open alerts</th>
            </tr>
          </thead>
          <tbody>
            {shown.map(n => (
              <tr key={n.asset_id} onClick={() => onOpen({ q: n.ip })} className="border-b border-dark-700/40 hover:bg-dark-700/20 cursor-pointer">
                <td className="py-2.5 pr-3 max-w-[220px]">
                  <p className="text-dark-100 font-medium truncate" title={n.hostname || n.ip}>{n.hostname || n.ip}</p>
                  {n.hostname && <p className="text-[11px] text-dark-500 font-mono">{n.ip}</p>}
                </td>
                <td className="py-2.5 pr-3 max-w-[260px]">
                  <p className={`text-xs truncate ${n.snmp_managed || n.vendor ? 'text-dark-300' : 'text-dark-500'}`} title={n.snmp_sysdescr ?? n.vendor ?? ''}>
                    {n.snmp_managed ? n.snmp_sysdescr : (n.vendor ?? 'Unknown vendor')}
                  </p>
                  {n.snmp_managed && n.interfaces > 0 && <p className="text-[11px] text-dark-500">{n.interfaces} interfaces</p>}
                </td>
                <td className="py-2.5 pr-3">
                  {n.snmp_managed
                    ? <span className="text-[11px] px-2 py-0.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 inline-flex items-center gap-1 whitespace-nowrap"><ShieldCheck className="w-3 h-3" />Verified</span>
                    : <span className="text-[11px] px-2 py-0.5 rounded-full border border-dark-600 text-dark-400 whitespace-nowrap">No SNMP</span>}
                </td>
                <td className={`py-2.5 text-right tabular-nums ${n.open_alerts ? 'text-orange-400 font-semibold' : 'text-dark-500'}`}>{n.open_alerts || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {total > shown.length && (
        <Link to="/assets" className="text-xs text-eagle-400 hover:underline inline-flex items-center gap-0.5 mt-3">
          {total - shown.length} more in Assets <ChevronRight className="w-3.5 h-3.5" />
        </Link>
      )}
    </>
  )
}

function HygieneCard({ icon: Icon, title, data, loading, why, action, row, onClick, to }) {
  const count = data?.count ?? 0
  const clear = !loading && count === 0
  const body = (
    <>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-dark-100 flex items-center gap-2"><Icon className="w-4 h-4 text-dark-400 flex-shrink-0" />{title}</p>
          <p className="text-xs text-dark-400 mt-1">{why}</p>
        </div>
        <span className={`text-3xl font-bold leading-none ${clear ? 'text-dark-500' : 'text-yellow-400'}`}>{loading ? '…' : fmtNum(count)}</span>
      </div>
      {clear ? (
        <p className="text-xs text-emerald-400 mt-4 inline-flex items-center gap-1"><ShieldCheck className="w-3.5 h-3.5" />Nothing to do</p>
      ) : !loading && (
        <>
          <ul className="mt-4 divide-y divide-dark-700/50 border-y border-dark-700/50">
            {data.items.slice(0, 3).map((a, i) => {
              const [primary, secondary] = row(a)
              return (
                <li key={a.asset_id ?? i} className="flex items-center justify-between gap-3 py-1.5 text-xs">
                  <span className="text-dark-200 truncate" title={primary}>{primary}</span>
                  <span className="text-dark-500 truncate text-right first-letter:uppercase" title={secondary}>{secondary}</span>
                </li>
              )
            })}
          </ul>
          <p className="text-xs text-dark-300 mt-3"><span className="text-eagle-300 font-semibold">Do: </span>{action}</p>
          <span className="text-xs text-eagle-400 inline-flex items-center gap-0.5 mt-2">View all {fmtNum(count)} <ChevronRight className="w-3.5 h-3.5" /></span>
        </>
      )}
    </>
  )
  const cls = 'glass-card p-5 flex flex-col text-left w-full hover:border-eagle-500/40 transition-colors'
  if (to) return <Link to={to} className={cls}>{body}</Link>
  return <button onClick={onClick} className={cls}>{body}</button>
}

function Empty({ text }) {
  return <p className="text-xs text-dark-500 py-4 text-center">{text}</p>
}

function Skeleton({ rows = 3 }) {
  return (
    <div className="space-y-2 animate-pulse">
      {Array.from({ length: rows }).map((_, i) => <div key={i} className="h-4 bg-dark-700/60 rounded" />)}
    </div>
  )
}
