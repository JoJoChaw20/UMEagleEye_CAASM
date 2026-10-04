import { useState, useEffect, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Shield, AlertTriangle, TrendingUp, TrendingDown, Globe, Radio, Server, Timer, Crosshair,
  ChevronRight, Network, HelpCircle, Clock, PackageSearch, Fingerprint, Sparkles, Minus,
} from 'lucide-react'
import { AreaChart, Area, ResponsiveContainer, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts'
import client from '../api/client'
import TenantSelector from '../components/common/TenantSelector'
import {
  SevBadge, StatusBadge, alertLabel, renderDetail, playbook, timeAgo, CHART_TOOLTIP_STYLE,
} from '../components/common/alertMeta'

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
          <h1 className="text-2xl font-bold text-white">Security Posture Dashboard</h1>
          <p className="text-dark-400 text-sm mt-1">What needs attention now, and why</p>
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

      {/* ── Headline numbers ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="flex items-center justify-between mb-3">
            <span className="text-dark-400 text-sm">Posture Score</span>
            <Delta value={scoreDelta} goodWhenUp />
          </div>
          <p className="text-3xl font-bold" style={{ color: scoreColor }}>{score ?? '—'}<span className="text-sm text-dark-400 font-normal"> / 100</span></p>
          {posture?.score_drivers?.length > 0 ? (
            <ul className="mt-2 space-y-0.5">
              {posture.score_drivers.map((d, i) => (
                <li key={i} className="text-xs text-dark-400 flex justify-between gap-2">
                  <span className="truncate">{d.label}</span><span className="font-mono text-accent-red">{d.impact}</span>
                </li>
              ))}
            </ul>
          ) : <p className="text-xs text-dark-400 mt-1">{score === 100 ? 'No open critical or high alerts' : 'out of 100'}</p>}
        </div>

        <HeadlineCard
          icon={AlertTriangle} tone="red" label="Open critical / high"
          value={<><span className="text-accent-red">{stats?.by_severity?.critical ?? 0}</span><span className="text-dark-500 text-xl"> / </span><span className="text-orange-400">{stats?.by_severity?.high ?? 0}</span></>}
          sub={`${stats?.open_total ?? 0} open alerts in total`}
          onClick={() => openAlerts({ view: 'open' })}
        />
        <HeadlineCard
          icon={TrendingUp} tone="cyan" label="This week"
          value={<><span>{stats?.new_7d ?? 0}</span><span className="text-dark-500 text-base font-normal"> new · </span><span className="text-accent-green">{stats?.resolved_7d ?? 0}</span><span className="text-dark-500 text-base font-normal"> closed</span></>}
          sub={stats ? ((stats.new_7d ?? 0) > (stats.resolved_7d ?? 0) ? 'Backlog is growing — prioritise closing' : 'Backlog is shrinking') : ''}
        />
        <HeadlineCard
          icon={Timer} tone="amber" label="Past SLA"
          value={<span className={(stats?.sla_breaches ?? 0) > 0 ? 'text-accent-amber' : 'text-white'}>{stats?.sla_breaches ?? 0}</span>}
          sub={`critical >72h · high >7d${stats?.mttr_hours != null ? ` · MTTR ${stats.mttr_hours < 48 ? stats.mttr_hours + 'h' : Math.round(stats.mttr_hours / 24) + 'd'}` : ''}`}
          onClick={() => openAlerts({ view: 'exposed' })}
        />
      </div>

      {/* ── Priority actions ── */}
      <div className="glass-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-dark-200 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-eagle-400" /> Priority actions
            <span className="text-xs text-dark-500 font-normal">ranked by risk × internet exposure × asset criticality</span>
          </h3>
          <Link to="/alerts" className="text-xs text-eagle-400 hover:underline flex items-center gap-0.5">Open queue <ChevronRight className="w-3.5 h-3.5" /></Link>
        </div>
        {loading ? <Skeleton rows={3} /> : summary?.priority_actions?.length > 0 ? (
          <ol className="space-y-2">
            {summary.priority_actions.map((a, i) => {
              const guide = playbook(a)
              const cti = a.event_type === 'cti_match' || a.details?.has_cti_match
              return (
                <li key={a.event_id}>
                  <button onClick={() => navigate(`/alerts?event=${a.event_id}`)}
                    className="w-full text-left rounded-lg border border-dark-700 hover:border-eagle-500/40 hover:bg-dark-700/20 px-3 py-2.5 transition-colors">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-dark-500 font-mono text-xs w-4">{i + 1}</span>
                      <SevBadge sev={a.severity} />
                      {cti && <span className="text-[11px] text-accent-red inline-flex items-center gap-0.5"><Crosshair className="w-3 h-3" />threat intel</span>}
                      <span className="text-sm text-white font-medium">{alertLabel(a)}</span>
                      <span className="font-mono text-xs text-accent-cyan">{renderDetail(a)}</span>
                      <span className="text-xs text-dark-400">on</span>
                      <span className="text-sm text-dark-200">{a.asset.hostname || a.asset.ip}</span>
                      {a.asset.internet_facing && <Globe className="w-3.5 h-3.5 text-accent-amber" />}
                      {a.details?.epss_score >= 0.01 && <span className="text-xs text-dark-400">EPSS {(a.details.epss_score * 100).toFixed(0)}%</span>}
                      <span className="ml-auto flex items-center gap-2">
                        <StatusBadge status={a.status} />
                        <span className="text-xs text-dark-500">{timeAgo(a.first_seen)}</span>
                      </span>
                    </div>
                    <p className="text-xs text-dark-300 mt-1 pl-6">
                      <span className="font-mono text-eagle-300 mr-1.5">[{guide.urgency}]</span>
                      {a.recommended_action ? a.recommended_action.split('\n')[0] : guide.text}
                    </p>
                  </button>
                </li>
              )
            })}
          </ol>
        ) : (
          <div className="text-center py-8 text-dark-400">
            <Shield className="w-10 h-10 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No open alerts. {col?.agents_total === 0 ? 'Deploy an agent and run your first scan.' : 'Keep scans and SBOMs current to stay that way.'}</p>
          </div>
        )}
      </div>

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
                    onClick={() => r.hosts.length === 1 ? openAlerts({ q: r.hosts[0].ip }) : openAlerts({ view: 'ports' })}>
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
            onClick={() => openAlerts({ view: 'devices' })} />
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
          <button onClick={() => openAlerts({ view: 'drift' })}
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

function HeadlineCard({ icon: Icon, tone, label, value, sub, onClick }) {
  const tones = { red: 'bg-accent-red/20 text-accent-red', cyan: 'bg-accent-cyan/20 text-accent-cyan', amber: 'bg-accent-amber/20 text-accent-amber' }
  const Tag = onClick ? 'button' : 'div'
  return (
    <Tag onClick={onClick} className="stat-card text-left w-full">
      <div className="flex items-center justify-between mb-3">
        <span className="text-dark-400 text-sm">{label}</span>
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${tones[tone]}`}><Icon className="w-4 h-4" /></div>
      </div>
      <p className="text-3xl font-bold text-white">{value}</p>
      <p className="text-xs text-dark-400 mt-1">{sub}</p>
    </Tag>
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
