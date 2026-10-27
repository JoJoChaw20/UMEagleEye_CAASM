// "Why this alert": what was observed on the asset (evidence), what it was compared
// with (knowledge) and the rule that turned the two into an alert. Built from the alert's
// details only, so it works for every alert the server stores.
import { Eye, BookOpen, Scale } from 'lucide-react'
import { RISKY_PORTS, riskReasons } from './alertMeta'

const host = (e) => e.asset?.hostname || e.asset?.ip_address || 'this asset'

function chain(e) {
  const d = e.details ?? {}
  const where = host(e)
  switch (e.event_type) {
    case 'cve_detected': {
      const known = [`${d.cve_id}${d.cvss_base_score ? `: CVSS ${d.cvss_base_score}` : ''}${d.epss_score != null ? `, ${(d.epss_score * 100).toFixed(1)}% chance of exploitation in 30 days (EPSS)` : ''}`]
      if (d.kev) known.push("On CISA's Known Exploited Vulnerabilities list: attackers are using it now")
      for (const t of d.ti_event_titles ?? []) known.push(`Named in threat-intel event "${t}"`)
      return {
        evidence: `${d.package_name}${d.package_version ? ` ${d.package_version}` : ''} is in ${where}'s SBOM (packages listed by the EagleEye agent on that computer)`,
        knowledge: known,
        rule: 'R1 · A package with a known vulnerability (Grype matched it against its vulnerability database)',
      }
    }
    case 'os_patch_missing': {
      const known = d.patch_status === 'unsupported'
        ? ['Microsoft has stopped releasing security updates for this Windows version']
        : [`Microsoft has released build ${d.latest_build ?? 'newer'}${d.kb ? ` (KB${d.kb})` : ''}, which fixes ${Number(d.cves ?? 0).toLocaleString()} CVEs this build is missing`]
      if (d.exploited) known.push(`${d.exploited} of them ${d.exploited === 1 ? 'is' : 'are'} marked "exploited" by Microsoft: attackers are using ${d.exploited === 1 ? 'it' : 'them'} now`)
      return {
        evidence: `${where} runs ${d.product ?? 'Windows'}, build ${d.build ?? '?'} (EagleEye agent inventory)`,
        knowledge: known,
        rule: "R8 · A Windows build older than Microsoft's fixed builds (Security Update Guide) is missing those fixes",
      }
    }
    case 'cti_match': {
      const sources = (d.sources ?? []).join(', ') || 'a threat feed'
      if (d.match_kind === 'watchlist') {
        return {
          evidence: `${d.observed} is ${d.matched_on === 'package' ? `a package in ${where}'s SBOM` : `installed on ${where} (agent inventory)`}`,
          knowledge: [`"${d.indicator_value}" is on the software watchlist of ${sources}`],
          rule: 'R6 · Software a threat-intel event watches is present: exposure to what the event warns about, not a compromise',
        }
      }
      const what = d.matched_on === 'ip' ? `public IP ${d.observed}` : `hostname ${d.observed}`
      const how = d.indicator_type === 'domain' && d.observed !== d.indicator_value
        ? ` (a subdomain of ${d.indicator_value})`
        : d.indicator_type === 'url' ? ` (it hosts ${d.indicator_value})` : ''
      return {
        evidence: `${where}'s ${what}`,
        knowledge: [`${d.indicator_type === 'ip' ? 'The IP' : d.indicator_type === 'url' ? 'A URL on it' : 'The domain'} is listed by ${sources}${how}`],
        rule: 'R5 · An address or name of your own asset is in threat intel: treat as a possible compromise',
      }
    }
    case 'port_opened':
    case 'port_closed':
      return {
        evidence: `A scan of ${where} found port ${d.port} ${e.event_type === 'port_opened' ? 'open' : 'closed'}${RISKY_PORTS[d.port] ? ` (${RISKY_PORTS[d.port]})` : ''}`,
        knowledge: [`The asset's baseline had it ${e.event_type === 'port_opened' ? 'closed' : 'open'}`],
        rule: 'Drift · The asset differs from its accepted baseline',
      }
    case 'new_device':
      return {
        evidence: `A ${d.source === 'passive_scan' ? 'passive' : 'network'} scan saw ${d.ip ?? 'a device'}${d.mac ? ` (${d.mac})` : ''}${d.hostname ? `, ${d.hostname}` : ''}`,
        knowledge: ['No known asset in this organisation had that identity'],
        rule: 'Discovery · A device nobody has claimed joined the network',
      }
    default:
      if (d.from != null || d.to != null) {
        return {
          evidence: `${where} now reports ${d.changed_attribute ?? d.package ?? 'a change'}: ${String(d.to ?? '—')}`,
          knowledge: [`The asset's baseline had ${String(d.from ?? '—')}`],
          rule: 'Drift · The asset differs from its accepted baseline',
        }
      }
      return null
  }
}

function Step({ icon: Icon, label, children }) {
  return (
    <div className="flex gap-2.5">
      <Icon className="w-4 h-4 text-eagle-400 mt-0.5 shrink-0" />
      <div className="min-w-0">
        <p className="text-[11px] uppercase tracking-wide text-dark-500">{label}</p>
        <div className="text-xs text-dark-200 break-words">{children}</div>
      </div>
    </div>
  )
}

export default function WhyAlert({ event }) {
  const c = chain(event)
  if (!c) return null
  const reasons = riskReasons({ ...event, asset_internet_facing: event.asset?.is_internet_facing, asset_criticality: event.asset?.criticality_score })
  return (
    <div className="rounded-lg border border-dark-700 bg-dark-800/40 p-3 space-y-2.5">
      <p className="text-sm font-semibold text-dark-100">Why this alert</p>
      <Step icon={Eye} label="Evidence">{c.evidence}</Step>
      <Step icon={BookOpen} label="Compared with">
        <ul className="space-y-0.5">{c.knowledge.map((k, i) => <li key={i}>{k}</li>)}</ul>
      </Step>
      <Step icon={Scale} label="Rule">{c.rule}</Step>
      {reasons.length > 0 && (
        <p className="text-[11px] text-dark-400">Ranked up by: {reasons.map(r => r.label).join(' · ')}</p>
      )}
    </div>
  )
}
