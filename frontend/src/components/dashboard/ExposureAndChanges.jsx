import { ArrowUpRight, Crosshair, Globe2, History, ShieldAlert, Wrench } from 'lucide-react'
import { Link } from 'react-router-dom'
import { alertLabel, renderDetail, timeAgo, RISKY_PORTS } from '../common/alertMeta'
import { classifyRecentChanges, dashboardHref } from './dashboardUtils'

const fmt = value => value == null ? '—' : Number(value).toLocaleString()

function ExposureMetric({ icon: Icon, label, value, detail, to, tone = 'neutral', tenantId }) {
  return <Link to={dashboardHref(to.split('?')[0], Object.fromEntries(new URLSearchParams(to.split('?')[1] ?? '')), tenantId)} className="group rounded-xl border border-dark-700/60 bg-dark-900/25 p-4 transition-colors hover:border-eagle-500/40 hover:bg-dark-900/45">
    <div className="flex items-center justify-between gap-2"><span className="text-sm font-medium text-dark-200 group-hover:text-eagle-300">{label}</span><Icon className="h-4 w-4 text-dark-500" /></div>
    <div className={`mt-3 text-3xl font-semibold tracking-tight tabular-nums ${tone === 'critical' && value > 0 ? 'text-red-400' : tone === 'warning' && value > 0 ? 'text-amber-400' : 'text-dark-100'}`}>{fmt(value)}</div>
    <p className="mt-1 text-xs text-dark-500">{detail}</p>
  </Link>
}

function changeTitle(event) {
  const d = event.details ?? {}
  if (event.event_type === 'new_device') return 'New device discovered'
  if (event.event_type === 'port_opened' && RISKY_PORTS[d.port]) return `${RISKY_PORTS[d.port]} service opened`
  if (event.event_type === 'port_opened') return 'Port opened'
  if (event.event_type === 'config_change' && d.changed_attribute === 'internet_facing') return 'Internet exposure changed'
  return alertLabel(event)
}

function RecentChange({ event, tenantId }) {
  const d = event.details ?? {}
  const asset = event.asset_hostname || event.asset_ip || 'Unknown asset'
  const suffix = event.event_type === 'config_change' && d.changed_attribute === 'internet_facing'
    ? (d.to ? 'Became internet-facing' : 'No longer internet-facing')
    : renderDetail(event)
  const badge = event.severity === 'critical' || event.severity === 'high'
  return <Link to={dashboardHref('/alerts', { event: event.event_id }, tenantId)} className="flex items-start gap-3 rounded-lg px-2 py-3 hover:bg-dark-700/20">
    <span className={`mt-1.5 h-2 w-2 flex-shrink-0 rounded-full ${badge ? 'bg-amber-400' : 'bg-dark-500'}`} />
    <span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium text-dark-200">{changeTitle(event)}</span><span className="mt-1 block truncate text-xs text-dark-500">{asset}{suffix && suffix !== '—' ? ` · ${suffix}` : ''}</span></span>
    <span className="flex-shrink-0 text-xs text-dark-500">{timeAgo(event.first_seen)}</span>
  </Link>
}

export default function ExposureAndChanges({ overview, surface, recentChanges, changesLoading, changesError, tenantId }) {
  const changes = classifyRecentChanges(recentChanges)
  return (
    <section aria-labelledby="exposure-title">
      <div className="mb-4">
        <h2 id="exposure-title" className="text-lg font-semibold tracking-tight text-dark-100">Security exposure & recent changes</h2>
        <p className="mt-1 text-sm text-dark-400">Separate current weaknesses from changes first observed in the last 24 hours.</p>
      </div>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div className="glass-card p-5 lg:p-6">
          <div className="mb-5 flex items-center gap-3"><span className="rounded-lg border border-dark-700/70 bg-dark-900/40 p-2 text-dark-300"><ShieldAlert className="h-4 w-4" /></span><div><h3 className="font-semibold text-dark-100">Security exposure</h3><p className="mt-1 text-xs text-dark-400">Open findings, with finding and asset counts kept distinct.</p></div></div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <ExposureMetric icon={Crosshair} label="Known Exploited CVEs" value={overview?.kev_cves} detail={`${fmt(overview?.kev_assets)} affected assets`} to="/alerts?view=exploitable" tone="critical" tenantId={tenantId} />
            <ExposureMetric icon={Crosshair} label="Threat-intel matches" value={overview?.threat_intel_matches} detail={`${fmt(overview?.threat_intel_assets)} affected assets · possible indicators`} to="/alerts?view=threat_intel" tone="critical" tenantId={tenantId} />
            <ExposureMetric icon={Globe2} label="Internet-facing with high-risk findings" value={overview?.high_risk_exposure_assets} detail="Unique assets with open critical/high findings" to="/alerts?severity=critical%2Chigh&internet_facing=true" tone="warning" tenantId={tenantId} />
            <ExposureMetric icon={Wrench} label="High-priority CVE fix groups" value={overview?.high_priority_fix_groups} detail="Asset + package + version groups, priority score ≥75" to="/alerts?view=cve" tenantId={tenantId} />
          </div>
          <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-dark-700/50 pt-4">
            <p className="text-xs text-dark-400">Current internet-facing inventory: <Link to={dashboardHref('/inventory', { internet_facing: 'true' }, tenantId)} className="font-semibold text-dark-100 hover:text-eagle-300">{fmt(surface?.internet_facing_total)} assets</Link></p>
            <Link to={dashboardHref('/inventory', { internet_facing: 'true' }, tenantId)} className="text-xs text-eagle-400 hover:underline">Review exposed assets →</Link>
          </div>
          {!!surface?.risky_services?.length && <div className="mt-4">
            <p className="mb-2 text-xs font-medium uppercase tracking-wide text-dark-500">Observed risky services</p>
            <div className="flex flex-wrap gap-2">{surface.risky_services.slice(0, 5).map(service => <Link key={service.port} to={dashboardHref('/inventory', { port: service.port }, tenantId)} className="rounded-lg border border-dark-700/70 px-2.5 py-1.5 text-xs text-dark-300 hover:border-eagle-500/40 hover:text-eagle-300">
              {service.service} · {service.host_count} host{service.host_count === 1 ? '' : 's'}{service.internet_facing > 0 && <span className="ml-1 text-amber-400">· {service.internet_facing} exposed</span>}
            </Link>)}</div>
            <p className="mt-2 text-[11px] text-dark-500">Port observations describe current scan data; they are distinct from high-risk alert counts.</p>
          </div>}
          <p className="mt-4 text-xs text-dark-500">Threat-intel matches are possible compromise indicators and are not confirmation of compromise.</p>
        </div>

        <div className="glass-card p-5 lg:p-6">
          <div className="mb-4 flex items-center justify-between gap-3">
            <div className="flex items-center gap-3"><span className="rounded-lg border border-dark-700/70 bg-dark-900/40 p-2 text-dark-300"><History className="h-4 w-4" /></span><div><h3 className="font-semibold text-dark-100">Observed security changes</h3><p className="mt-1 text-xs text-dark-400">First seen in the last 24 hours · not every change is malicious.</p></div></div>
            <Link to={dashboardHref('/alerts', { view: 'drift' }, tenantId)} className="flex-shrink-0 text-xs text-eagle-400 hover:underline">All drift <ArrowUpRight className="inline h-3.5 w-3.5" /></Link>
          </div>
          {changesLoading ? <div className="space-y-3 animate-pulse py-3">{[0,1,2,3].map(n => <div key={n} className="h-10 rounded bg-dark-700/50" />)}</div>
            : changesError ? <p className="py-8 text-center text-sm text-dark-400">Recent change data unavailable.</p>
              : changes.length ? <div className="divide-y divide-dark-700/50">{changes.map(event => <RecentChange key={event.event_id} event={event} tenantId={tenantId} />)}</div>
                : <p className="py-10 text-center text-sm text-dark-400">No supported security changes observed in the last 24 hours.</p>}
        </div>
      </div>
    </section>
  )
}
