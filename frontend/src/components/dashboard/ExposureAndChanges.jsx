import { ArrowRight, ArrowUpRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import { alertLabel, renderDetail, timeAgo, RISKY_PORTS } from '../common/alertMeta'
import { classifyRecentChanges, dashboardHref } from './dashboardUtils'
import SectionHeader from '../ui/SectionHeader'
import PanelHeading from '../ui/PanelHeading'

const fmt = value => value == null ? '—' : Number(value).toLocaleString()

// One cell of the exposure grid: a divided 2x2 inside the single panel, no inner cards.
function ExposureMetric({ label, value, detail, to, tone = 'neutral', tenantId }) {
  return <Link to={dashboardHref(to.split('?')[0], Object.fromEntries(new URLSearchParams(to.split('?')[1] ?? '')), tenantId)}
    className="group relative flex flex-col p-5 transition-colors hover:bg-eagle-500/[0.05] sm:[&:nth-child(odd)]:border-r sm:[&:nth-child(-n+2)]:border-b max-sm:[&:not(:last-child)]:border-b border-dark-700/70">
    <span className="flex items-start justify-between gap-2">
      <span className="text-sm font-medium text-dark-200 group-hover:text-eagle-400">{label}</span>
      <ArrowUpRight className="h-4 w-4 flex-shrink-0 text-dark-600 transition-colors group-hover:text-eagle-400" />
    </span>
    <span className={`mt-3 font-display text-3xl font-semibold leading-none tabular-nums ${tone === 'critical' && value > 0 ? 'text-red-400' : tone === 'warning' && value > 0 ? 'text-amber-400' : 'text-dark-50'}`}>{fmt(value)}</span>
    <span className="mt-1.5 text-xs text-dark-400">{detail}</span>
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
  return <Link to={dashboardHref('/alerts', { event: event.event_id }, tenantId)} className="group flex items-start gap-3 rounded-md px-2 py-3 transition-colors hover:bg-eagle-500/[0.05]">
    <span className={`mt-1.5 h-2 w-2 flex-shrink-0 rounded-full ${badge ? 'bg-accent-amber' : 'border border-dark-500'}`} />
    <span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium text-dark-100 group-hover:text-eagle-400">{changeTitle(event)}</span><span className="mt-1 block truncate text-xs text-dark-500">{asset}{suffix && suffix !== '—' ? ` · ${suffix}` : ''}</span></span>
    <span className="flex-shrink-0 text-xs text-dark-500">{timeAgo(event.first_seen)}</span>
  </Link>
}

export default function ExposureAndChanges({ overview, surface, recentChanges, changesLoading, changesError, tenantId }) {
  const changes = classifyRecentChanges(recentChanges)
  return (
    <section aria-labelledby="exposure-title">
      <SectionHeader id="exposure-title" title="Security exposure & recent changes" className="mb-4"
        description="Current weaknesses, kept apart from changes first observed in the last 24 hours." />
      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-2">
        <div className="glass-card overflow-hidden">
          <div className="px-5 pt-5 lg:px-6 lg:pt-6">
            <PanelHeading title="Security exposure" detail="Open findings, with finding and asset counts kept distinct." className="mb-4" />
          </div>
          <div className="grid grid-cols-1 border-y border-dark-700/70 sm:grid-cols-2">
            <ExposureMetric label="Known exploited CVEs" value={overview?.kev_cves} detail={`${fmt(overview?.kev_assets)} affected assets`} to="/alerts?view=exploitable" tone="critical" tenantId={tenantId} />
            <ExposureMetric label="Threat-intel matches" value={overview?.threat_intel_matches} detail={`${fmt(overview?.threat_intel_assets)} affected assets · possible indicators`} to="/alerts?view=threat_intel" tone="critical" tenantId={tenantId} />
            <ExposureMetric label="Internet-facing with high-risk findings" value={overview?.high_risk_exposure_assets} detail="Unique assets with open critical/high findings" to="/alerts?severity=critical%2Chigh&internet_facing=true" tone="warning" tenantId={tenantId} />
            <ExposureMetric label="High-priority CVE fix groups" value={overview?.high_priority_fix_groups} detail="Asset + package + version groups, priority score ≥75" to="/alerts?view=cve" tenantId={tenantId} />
          </div>
          <div className="px-5 pb-5 lg:px-6 lg:pb-6">
            <div className="flex flex-wrap items-center justify-between gap-2 pt-4">
              <p className="text-xs text-dark-400">Current internet-facing inventory: <Link to={dashboardHref('/inventory', { internet_facing: 'true' }, tenantId)} className="font-semibold text-dark-100 hover:text-eagle-400">{fmt(surface?.internet_facing_total)} assets</Link></p>
              <Link to={dashboardHref('/inventory', { internet_facing: 'true' }, tenantId)} className="inline-flex items-center gap-1 text-xs font-medium text-eagle-400 hover:text-eagle-300">Review exposed assets <ArrowRight className="h-3.5 w-3.5" /></Link>
            </div>
            {!!surface?.risky_services?.length && <div className="mt-4">
              <p className="mb-2 text-xs font-medium uppercase tracking-wide text-dark-500">Observed risky services</p>
              <div className="flex flex-wrap gap-2">{surface.risky_services.slice(0, 5).map(service => <Link key={service.port} to={dashboardHref('/inventory', { port: service.port }, tenantId)} className="rounded-md border border-dark-700 bg-dark-900 px-2.5 py-1.5 text-xs text-dark-300 transition-colors hover:border-eagle-500/50 hover:text-eagle-400">
                {service.service} · {service.host_count} host{service.host_count === 1 ? '' : 's'}{service.internet_facing > 0 && <span className="ml-1 text-amber-400">· {service.internet_facing} exposed</span>}
              </Link>)}</div>
              <p className="mt-2 text-[11px] text-dark-500">Port observations describe current scan data; they are distinct from high-risk alert counts.</p>
            </div>}
            <p className="mt-4 text-xs text-dark-500">Threat-intel matches are possible compromise indicators and are not confirmation of compromise.</p>
          </div>
        </div>

        <div className="glass-card p-5 lg:p-6">
          <PanelHeading title="Observed security changes" detail="First seen in the last 24 hours · not every change is malicious." className="mb-4"
            action={<Link to={dashboardHref('/alerts', { view: 'drift' }, tenantId)} className="inline-flex items-center gap-1 text-xs font-medium text-eagle-400 hover:text-eagle-300">All drift <ArrowUpRight className="h-3.5 w-3.5" /></Link>} />
          {changesLoading ? <div className="space-y-3 animate-pulse py-3">{[0,1,2,3].map(n => <div key={n} className="h-10 rounded bg-dark-700/50" />)}</div>
            : changesError ? <p className="py-8 text-center text-sm text-dark-400">Recent change data unavailable.</p>
              : changes.length ? <div className="divide-y divide-dark-700/50">{changes.map(event => <RecentChange key={event.event_id} event={event} tenantId={tenantId} />)}</div>
                : <div className="flex flex-col items-center gap-3 py-8 text-center">
                    <span aria-hidden="true" className="flex w-24 items-center"><span className="trace-line" /><span className="trace-node" /></span>
                    <p className="text-sm text-dark-300">No supported security changes in the last 24 hours.</p>
                    <p className="max-w-sm text-xs text-dark-500">New devices, opened ports, exposure and software changes appear here as scans and agents report them.</p>
                  </div>}
        </div>
      </div>
    </section>
  )
}
