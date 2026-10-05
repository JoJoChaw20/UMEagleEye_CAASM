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
  CONCERNS, riskReasons, SEVERITY_COLORS,
} from '../components/common/alertMeta'
import {
  ConcernCard, SeverityStack, ReasonChips, PriorityTier, DueLabel, fmtNum,
} from '../components/common/triageViz'

const DEVICE_COLORS = { server: '#3393ff', workstation: '#22d3ee', network: '#a78bfa', iot: '#f59e0b', unknown: '#6b7280' }

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
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Panel icon={Radio} title="Exposed risky services" hint="from latest active scans">
          {loading ? <Skeleton rows={4} /> : surface?.risky_services?.length ? (
            <table className="w-full text-xs">
              <thead><tr className="text-dark-500 text-left"><th className="py-1 font-medium">Service</th><th className="font-medium">Hosts</th><th className="font-medium">Internet</th></tr></thead>
              <tbody>
                {surface.risky_services.slice(0, 8).map(r => (
                  <tr key={r.port} className="border-t border-dark-700/50 hover:bg-dark-700/20 cursor-pointer"
                    title={r.hosts.map(h => h.hostname || h.ip).join(', ')}
                    onClick={() => r.hosts.length === 1 ? openAlerts({ q: r.hosts[0].ip }) : openAlerts({ view: 'exposed_services' })}>
                    <td className="py-1.5 text-dark-200">{r.service} <span className="text-dark-500 font-mono">{r.port}</span></td>
                    <td className="text-dark-200">{r.host_count}</td>
                    <td className={r.internet_facing ? 'text-accent-red font-semibold' : 'text-dark-500'}>{r.internet_facing || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <Empty text="No risky services (Telnet, SMB, RDP, databases…) seen in scans." />}
        </Panel>

        <Panel icon={Globe} title={`Internet-facing assets (${surface?.internet_facing_total ?? 0})`} hint="edge devices get attacked first">
          {loading ? <Skeleton rows={4} /> : surface?.internet_facing?.length ? (
            <ul className="space-y-1.5">
              {surface.internet_facing.map(a => (
                <li key={a.asset_id}>
                  <button onClick={() => openAlerts({ q: a.ip })} className="w-full text-left flex items-center gap-2 text-xs hover:bg-dark-700/20 rounded px-1 py-0.5">
                    <span className="text-dark-200 truncate">{a.hostname || a.ip}</span>
                    {!a.confirmed && <span className="text-[10px] text-dark-500" title="Inferred from the agent's gateway — confirm in Assets">inferred</span>}
                    <span className="font-mono text-dark-500 truncate">{a.ports.slice(0, 5).join(',')}{a.ports.length > 5 ? '…' : ''}</span>
                    <span className="ml-auto">{a.worst_open_severity ? <SevBadge sev={a.worst_open_severity} /> : <span className="text-dark-500">clean</span>}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : <Empty text="No internet-facing assets identified." />}
        </Panel>

        <Panel icon={Server} title="Asset mix" hint={`${Object.values(surface?.device_mix ?? {}).reduce((s, n) => s + n, 0)} assets`}>
          {loading ? <Skeleton rows={4} /> : surface ? (
            <div className="space-y-2">
              {Object.entries(surface.device_mix).map(([type, n]) => {
                const totalAssets = Object.values(surface.device_mix).reduce((s, x) => s + x, 0) || 1
                return (
                  <div key={type} className="text-xs">
                    <div className="flex justify-between text-dark-300 mb-0.5">
                      <span className="capitalize">{type}</span><span className="font-mono">{n}</span>
                    </div>
                    <div className="h-1.5 rounded bg-dark-700 overflow-hidden">
                      <div className="h-full rounded" style={{ width: `${(n / totalAssets) * 100}%`, background: DEVICE_COLORS[type] }} />
                    </div>
                  </div>
                )
              })}
              {surface.top_os?.length > 0 && (
                <p className="text-[11px] text-dark-500 pt-1">
                  Top OS: {surface.top_os.slice(0, 3).map(o => `${o.name} (${o.count})`).join(' · ')}
                </p>
              )}
            </div>
          ) : null}
        </Panel>
      </div>

      {/* ── Network devices + trend ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Panel icon={Network} title={`Network devices (${surface?.network_devices_total ?? 0})`}
          hint={surface?.network_devices_unmanaged ? `${surface.network_devices_unmanaged} not answering SNMP` : 'model & firmware via SNMPv3'}>
          {loading ? <Skeleton rows={4} /> : surface?.network_devices?.length ? (
            <ul className="space-y-2">
              {surface.network_devices.map(n => (
                <li key={n.asset_id} className="text-xs">
                  <div className="flex items-center gap-2">
                    <span className="text-dark-200">{n.hostname || n.ip}</span>
                    <span className="font-mono text-dark-500">{n.hostname ? n.ip : ''}</span>
                    {n.open_alerts > 0 && <span className="ml-auto text-accent-amber">{n.open_alerts} open</span>}
                  </div>
                  <p className={`truncate ${n.snmp_managed ? 'text-dark-400' : 'text-dark-500 italic'}`} title={n.snmp_sysdescr ?? ''}>
                    {n.snmp_managed ? `${n.snmp_sysdescr}${n.interfaces ? ` · ${n.interfaces} ifaces` : ''}` : `No SNMP response${n.vendor ? ` · ${n.vendor}` : ''} — can't verify firmware`}
                  </p>
                </li>
              ))}
            </ul>
          ) : <Empty text="No routers or switches identified yet." />}
        </Panel>

        <div className="glass-card p-5 lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-dark-200 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-eagle-400" /> Posture score trend
            </h3>
            <span className="text-xs text-dark-400">Last 30 days · open alerts at each day's end</span>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={trendData}>
              <defs>
                <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3393ff" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3393ff" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2028" />
              <XAxis dataKey="day" tick={{ fill: '#7b7f87', fontSize: 11 }} axisLine={{ stroke: '#1e2028' }} />
              <YAxis domain={[0, 100]} tick={{ fill: '#7b7f87', fontSize: 11 }} axisLine={{ stroke: '#1e2028' }} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE}
                formatter={(v, name) => [v, name === 'score' ? 'Score' : 'Open critical']} />
              <Area type="monotone" dataKey="score" stroke="#3393ff" fill="url(#scoreGradient)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Hygiene work queues ── */}
      <div>
        <h3 className="text-sm font-semibold text-dark-200 mb-3">Hygiene — things that quietly weaken coverage</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <HygieneCard icon={Fingerprint} title="New devices (7d)" data={hygiene?.new_devices_7d} loading={loading}
            advice="Confirm each has an owner. Unclaimed after 24h → isolate."
            render={a => <>{a.hostname || a.ip}<span className="text-dark-500"> · {a.vendor ?? 'unknown vendor'}</span></>}
            onClick={() => openAlerts({ view: 'new_devices' })} />
          <HygieneCard icon={HelpCircle} title="Unidentified" data={hygiene?.unidentified} loading={loading}
            advice="No type, vendor or hostname. Label them so risk is scored correctly."
            render={a => <>{a.ip}<span className="text-dark-500"> · {a.mac ?? 'no MAC'}</span></>}
            to="/assets" />
          <HygieneCard icon={Clock} title={`Not seen in ${hygiene?.stale_after_days ?? 7}d`} data={hygiene?.stale_assets} loading={loading}
            advice="Decommissioned, moved, or outside scan coverage. Verify or retire."
            render={a => <>{a.hostname || a.ip}<span className="text-dark-500"> · {a.last_scanned ? timeAgo(a.last_scanned) : 'never scanned'}</span></>}
            to="/assets" />
          <HygieneCard icon={PackageSearch} title="Servers/PCs without SBOM" data={hygiene?.no_sbom} loading={loading}
            advice="CVE detection is blind on these hosts until an SBOM scan runs."
            render={a => <>{a.hostname || a.ip}<span className="text-dark-500 capitalize"> · {a.device_type}</span></>}
            to="/sbom" />
        </div>
        {hygiene?.identity_changes_open > 0 && (
          <button onClick={() => openAlerts({ view: 'identity' })}
            className="mt-3 text-xs text-accent-amber hover:underline inline-flex items-center gap-1">
            <AlertTriangle className="w-3.5 h-3.5" />
            {hygiene.identity_changes_open} open MAC/hostname change{hygiene.identity_changes_open === 1 ? '' : 's'} — possible spoofing or hardware swap. Review →
          </button>
        )}
      </div>
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

function Panel({ icon: Icon, title, hint, children }) {
  return (
    <div className="glass-card p-5">
      <div className="flex items-baseline justify-between gap-2 mb-3">
        <h3 className="text-sm font-semibold text-dark-200 flex items-center gap-2"><Icon className="w-4 h-4 text-eagle-400" />{title}</h3>
        {hint && <span className="text-[11px] text-dark-500 text-right">{hint}</span>}
      </div>
      {children}
    </div>
  )
}

function HygieneCard({ icon: Icon, title, data, loading, advice, render, onClick, to }) {
  const count = data?.count ?? 0
  const body = (
    <>
      <div className="flex items-center justify-between mb-1">
        <span className="text-sm text-dark-200 flex items-center gap-1.5"><Icon className="w-4 h-4 text-dark-400" />{title}</span>
        <span className={`text-xl font-bold ${count > 0 ? 'text-accent-amber' : 'text-dark-500'}`}>{loading ? '…' : count}</span>
      </div>
      <p className="text-[11px] text-dark-500 mb-2">{advice}</p>
      {count > 0 && (
        <ul className="space-y-0.5">
          {data.items.slice(0, 4).map((a, i) => <li key={a.asset_id ?? i} className="text-xs text-dark-300 truncate">{render(a)}</li>)}
          {count > 4 && <li className="text-xs text-eagle-400">+{count - 4} more →</li>}
        </ul>
      )}
    </>
  )
  const cls = 'glass-card p-4 block text-left w-full hover:border-eagle-500/40 transition-colors'
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
