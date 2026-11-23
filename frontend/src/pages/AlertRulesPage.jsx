// Alert rules: a sub-page of Alerts. What UMEagleEye raises an alert for, where each kind comes from, how
// alerts are ranked (the four tiers of workers/src/lib/alertRank.ts) and the fix-time targets, which the
// tenant's Tenant Superadmin can change here (components/common/FixTargetsCard.jsx).
import { Fragment, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, Layers, ListChecks } from 'lucide-react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'
import FixTargetsCard from '../components/common/FixTargetsCard'
import BaselineTargetCard from '../components/common/BaselineTargetCard'
import { EVENT_TYPE_LABELS, TYPE_GROUPS } from '../components/common/alertMeta'
import { hoursText } from '../utils/fixTime'

// Where each kind of alert comes from, and the estimated work to close one (workers/src/lib/alertRank.ts
// EFFORT_HOURS: compromise 4 h, hardening 2 h, service or Windows update 1 h, package or exposure 30 min, review 15 min).
const SOURCE = {
  cve_detected: { from: 'The computer\'s agent: its software list (SBOM) checked for known CVEs', work: 'Update the package: 30 min' },
  vulnerable_service: { from: 'Active scans: a service\'s version from its banner, checked against NVD', work: 'Upgrade the service: 1 h' },
  os_patch_missing: { from: 'The computer\'s agent: its Windows build against Microsoft\'s monthly fixes; on Linux, the updates its distribution\'s security channel has waiting', work: 'Install the updates, with a restart: 1 h' },
  cti_match: { from: 'Threat intelligence (feeds and your events) against device addresses and names, installed software and packages', work: 'Investigate: 4 h; a weak match is reviewed: 15 min' },
  cti_sighting: { from: 'The computer\'s agent: its DNS look-ups, connections and running programs against the threat list, on the computer', work: 'Investigate: 4 h' },
  exposure: { from: 'Active scans: what a port answers (Telnet, a database without a password, RDP, TLS…)', work: 'Fix the setting or close the port: 30 min' },
  port_opened: { from: 'Scans and the drift audit: a port not in the device\'s baseline', work: 'Risky port 30 min; other ports reviewed: 15 min' },
  security_baseline: { from: 'The computer\'s agent: its security settings, judged against the target set below', work: 'Harden the computer\'s settings: 2 h' },
  config_change: { from: 'The drift audit (every 6 hours and after scans): against the device\'s baseline', work: 'Review: 15 min' },
  version_downgrade: { from: 'The drift audit', work: 'Review: 15 min' },
  new_device: { from: 'Scans and passive listening: a device seen for the first time', work: 'Review: 15 min' },
}

const day = (h) => (h == null ? '—' : hoursText(h))

export default function AlertRulesPage() {
  const { isPlatformSuperadmin, user } = useAuth()
  const [tenantFilter, setTenantFilter] = useState('')
  const tenantId = isPlatformSuperadmin ? tenantFilter : user?.tenantId
  const [policy, setPolicy] = useState(null)       // the targets in force, for the tier table

  useEffect(() => {
    if (!tenantId) { setPolicy(null); return }
    client.get(`/tenants/${tenantId}/sla-policy`).then((r) => setPolicy(r.data.effective)).catch(() => setPolicy(null))
  }, [tenantId])

  const p = policy ?? {}
  const TIERS = [
    { n: 1, name: 'Possible compromise', cls: 'text-red-400', what: 'Threat intelligence seen on a device and rated high or critical: a computer looked up or connected to a listed domain or IP, runs a program whose file is listed malware, has a listed address or name, or has a release published as malware installed.', target: `Investigate within ${day(p.compromise)}` },
    { n: 2, name: 'Exploited', cls: 'text-orange-400', what: 'A vulnerability attackers are known to exploit (on CISA\'s KEV list), in a package or a service, or a missing Windows update that fixes one.', target: `Fix within ${day(p.kev_exposed)} if internet-facing, ${day(p.kev)} otherwise` },
    { n: 3, name: 'Fix', cls: 'text-amber-400', what: 'Other vulnerable packages, services and Windows updates, risky set-ups (exposures), a risky port that opened, and computers below the security baseline. Ranked within the tier by risk: CVSS, exploit chance (EPSS), the device\'s criticality, internet-facing.', target: `By severity: critical ${day(p.critical)}, high ${day(p.high)}, medium ${day(p.medium)}, low ${day(p.low)}` },
    { n: 4, name: 'Review', cls: 'text-dark-300', what: 'New devices, configuration and version changes, other new ports, watched software, and weaker threat-intel matches (a low-confidence listing, a package matched by name only).', target: `Review within ${day(p.review)}` },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          {/* a block of its own: .page-title is inline-flex and would sit beside it */}
          <Link to="/alerts" className="flex w-fit items-center gap-1 text-xs text-dark-400 hover:text-eagle-400"><ArrowLeft className="h-3.5 w-3.5" /> Alerts</Link>
          <h1 className="page-title mt-1">Alert rules</h1>
          <p className="text-dark-400 text-sm mt-1 max-w-3xl">What UMEagleEye raises an alert for, how alerts are ranked, and how long each may stay open.</p>
        </div>
        {isPlatformSuperadmin && <TenantSelector value={tenantFilter} onChange={setTenantFilter} />}
      </div>

      <div className="glass-card p-6 space-y-3">
        <h3 className="text-lg font-semibold text-dark-100 flex items-center gap-2"><Layers className="w-4 h-4 text-eagle-400" /> How alerts are ranked</h3>
        <p className="text-sm text-dark-400">Every open alert sits in one of four tiers; the queue shows tier 1 first, then by risk within each tier.{!tenantId && ' Choose a tenant to see its targets.'}</p>
        <ol className="space-y-2">
          {TIERS.map((t) => (
            <li key={t.n} className="rounded-md border border-dark-700/50 p-3 grid grid-cols-1 md:grid-cols-[12rem_1fr_16rem] gap-2 text-sm">
              <span className={`font-semibold ${t.cls}`}>Tier {t.n} · {t.name}</span>
              <span className="text-dark-300">{t.what}</span>
              <span className="text-dark-200 md:text-right">{policy ? t.target : '—'}</span>
            </li>
          ))}
        </ol>
      </div>

      <div className="glass-card p-6 space-y-3">
        <h3 className="text-lg font-semibold text-dark-100 flex items-center gap-2"><ListChecks className="w-4 h-4 text-eagle-400" /> What raises an alert</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-xs text-dark-400 border-b border-dark-700/60">
              <th className="py-2 text-left font-medium">Alert</th><th className="py-2 text-left font-medium">When</th>
              <th className="py-2 text-left font-medium">Comes from</th><th className="py-2 text-left font-medium">Estimated work</th>
            </tr></thead>
            <tbody>
              {TYPE_GROUPS.map((g) => (
                <Fragment key={g.label}>
                  <tr><td colSpan={4} className="pt-3 pb-1 text-xs font-semibold uppercase tracking-wide text-dark-500">{g.label}</td></tr>
                  {Object.entries(g.types).map(([type, when]) => (
                    <tr key={type} className="border-b border-dark-700/30 align-top">
                      <td className="py-2 pr-3 text-dark-100 whitespace-nowrap">{EVENT_TYPE_LABELS[type] ?? type}</td>
                      <td className="py-2 pr-3 text-dark-300">{when}</td>
                      <td className="py-2 pr-3 text-dark-400">{SOURCE[type]?.from ?? '—'}</td>
                      <td className="py-2 text-dark-400 whitespace-nowrap">{SOURCE[type]?.work ?? '—'}</td>
                    </tr>
                  ))}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-dark-500">Vulnerabilities, exposures and threat-intel listings resolve on their own when a later scan or upload no longer finds the problem; agent sightings, changes and new devices are closed by a person. A closed alert reopens if the problem comes back, and its fix-time clock restarts.</p>
      </div>

      {tenantId ? <FixTargetsCard tenantId={tenantId} /> : <div className="glass-card p-6 text-sm text-dark-400">Choose a tenant above to see its fix-time targets.</div>}
      {tenantId && <BaselineTargetCard tenantId={tenantId} />}
    </div>
  )
}
