// "Why this alert": what was observed on the asset (evidence), what it was compared
// with (knowledge) and the rule that turned the two into an alert. Built from the alert's
// details only, so it works for every alert the server stores.
import { Eye, BookOpen, Scale, Radar } from 'lucide-react'
import { RISKY_PORTS, riskReasons, affectedVersions, versionList, isPackageAlert } from './alertMeta'

const host = (e) => e.asset?.hostname || e.asset?.ip_address || 'this asset'

function chain(e) {
  const d = e.details ?? {}
  const where = host(e)
  switch (e.event_type) {
    case 'cve_detected': {
      if (isPackageAlert(d)) {
        const n = d.cve_count ?? 0
        const copies = (d.installed_versions ?? []).map(v => v.version)
        const known = [`Grype lists ${n} CVE${n === 1 ? '' : 's'} for ${d.package_name} ${versionList(copies.length ? copies : [d.package_version])}${d.max_cvss ? ` (worst CVSS ${d.max_cvss}` : ''}${d.max_cvss && d.max_epss ? `, highest ${(d.max_epss * 100).toFixed(1)}% chance of exploitation in 30 days (EPSS))` : d.max_cvss ? ')' : ''}`]
        if (d.kev_count) known.push(`${d.kev_count} of them ${d.kev_count === 1 ? 'is' : 'are'} on CISA's Known Exploited Vulnerabilities list: attackers are using ${d.kev_count === 1 ? 'it' : 'them'} now`)
        for (const t of d.ti_event_titles ?? []) known.push(`Named in threat-intel event "${t}"`)
        known.push(d.fix_to ? `Upgrading to ${d.fix_to} fixes ${d.fixable_count ?? n} of them${d.no_fix_count ? `; ${d.no_fix_count} have no fix yet` : ''}` : 'No fixed version is published yet')
        return {
          evidence: `${d.package_name} ${versionList(copies.length ? copies : [d.package_version])} ${copies.length > 1 ? 'are' : 'is'} in ${where}'s SBOM (packages listed by the EagleEye agent on that computer)`,
          knowledge: known,
          rule: 'R1 · A package with known vulnerabilities (Grype matched it against its vulnerability database); one alert per package, its CVEs inside',
        }
      }
      const known = [`${d.cve_id}${d.cvss_base_score ? `: CVSS ${d.cvss_base_score}` : ''}${d.epss_score != null ? `, ${(d.epss_score * 100).toFixed(1)}% chance of exploitation in 30 days (EPSS)` : ''}`]
      if (d.kev) known.push("On CISA's Known Exploited Vulnerabilities list: attackers are using it now")
      for (const t of d.ti_event_titles ?? []) known.push(`Named in threat-intel event "${t}"`)
      return {
        evidence: affectedVersions(d).length > 1
          ? `${d.package_name} ${versionList(affectedVersions(d).map(v => v.version))} are in ${where}'s SBOM (packages listed by the EagleEye agent on that computer)`
          : `${d.package_name}${d.package_version ? ` ${d.package_version}` : ''} is in ${where}'s SBOM (packages listed by the EagleEye agent on that computer)`,
        knowledge: known,
        rule: 'R1 · A package with a known vulnerability (Grype matched it against its vulnerability database)',
      }
    }
    case 'security_baseline': {
      const failed = d.failed_checks ?? []
      return {
        evidence: `${where} passes ${d.passed} of ${d.judged} security-baseline checks (${d.percent}%), from the settings its EagleEye agent read`,
        knowledge: [
          `The organisation's target is ${d.target}% (Alert rules page)`,
          ...(failed.length ? [`Failed: ${failed.slice(0, 6).map(c => c.label).join('; ')}${failed.length > 6 ? ` and ${failed.length - 6} more` : ''}`] : []),
        ],
        rule: 'R10 · A computer below its organisation\'s security-baseline target (30 checks after the CIS Benchmarks, as many for Windows, Linux and macOS)',
      }
    }
    case 'os_patch_missing': {
      if (d.platform === 'linux') {
        const names = (d.packages ?? []).slice(0, 5).map(p => p.name).join(', ')
        return {
          evidence: `${where} runs ${d.product ?? 'Linux'}; its package manager lists ${d.updates} update${d.updates === 1 ? '' : 's'} from the security channel not yet installed (EagleEye agent inventory)`,
          knowledge: [`The distribution published these as security fixes${names ? `: ${names}${d.updates > 5 ? ', …' : ''}` : ''}`],
          rule: 'R8 · Security updates the distribution has released but the computer has not installed (apt / dnf security channel)',
        }
      }
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
      if (d.match_kind === 'sighting') {
        const did = d.matched_on === 'connection'
          ? `${where} connected to ${d.observed}${d.port ? ` on port ${d.port}` : ''}${d.process ? ` (program ${d.process})` : ''}`
          : `${where} looked up ${d.observed} (a DNS answer it received)`
        const listed = d.indicator_type === 'url'
          ? `${d.indicator_value} hosts a URL listed by ${sources}${d.listed_urls?.length ? ` (${d.listed_urls[0]})` : ''}`
          : `${d.indicator_type === 'ip' ? 'The IP' : 'The domain'} ${d.indicator_value} is listed by ${sources}${d.observed !== d.indicator_value ? ` (${d.observed} is under it)` : ''}`
        return {
          evidence: `${did}, ${(d.count ?? 1).toLocaleString()} time${d.count === 1 ? '' : 's'} (EagleEye agent; checked on the computer, only matches are sent)`,
          knowledge: [listed],
          rule: 'R7 · A computer contacted a domain or IP in threat intel: treat as a possible compromise',
        }
      }
      if (d.match_kind === 'public_address') {
        const listed = (d.listings ?? []).slice(0, 4).map((l) => l.kind === 'range'
          ? `${l.source} lists the range ${l.value}${l.ref ? ` (${l.ref})` : ''}: networks hijacked or run by criminals`
          : `${l.source} lists ${l.value}${l.kind === 'c2' ? ' as a command-and-control or malware server' : l.kind === 'malware' ? ' (a malware download on it)' : ''}${l.confidence != null ? ` (${Math.round(l.confidence * 100)}% confidence)` : ''}`)
        return {
          evidence: `${d.address_status === 'ours' ? "The organisation's own public address" : 'A public address your agents connect from (not yet confirmed as the organisation\'s)'} ${d.indicator_value}; the alert sits on ${where}, its gateway or the computer that reported it`,
          knowledge: listed.length ? listed : [`Listed by ${sources}`],
          rule: d.address_status === 'ours'
            ? "R11 · The organisation's own public address is on a blocklist: something behind it is probably infected or misused"
            : 'R11 · A public address agents connect from is on a blocklist: confirm whose it is (a review item until marked ours)',
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
    case 'vulnerable_service': {
      const known = [`NVD lists ${d.cve_count ?? 'known'} CVE${d.cve_count === 1 ? '' : 's'} for ${d.product} ${d.version ?? ''}${d.max_cvss ? ` (worst CVSS ${d.max_cvss})` : ''}`]
      if (d.kev_count) known.push(`${d.kev_count} of them ${d.kev_count === 1 ? 'is' : 'are'} on CISA's Known Exploited Vulnerabilities list`)
      if (d.distro) known.push(`The banner names ${d.distro}: the distribution may have backported the fixes (lower confidence)`)
      if (d.outside_sbom) known.push("The device's SBOM does not list this version, so its package scan cannot see it (a container, or a program installed by hand)")
      return {
        evidence: `A scan of ${where} found port ${d.port} answering "${d.seen ?? `${d.product} ${d.version ?? ''}`}", identified as ${d.vendor ? `${d.vendor} ` : ''}${d.product} ${d.version ?? ''} (Rapid7 Recog fingerprints)`,
        knowledge: known,
        rule: 'R9 · A product version with known CVEs on a device without an SBOM (version from the network banner)',
      }
    }
    case 'exposure': {
      const ev = d.evidence ?? {}
      if (d.rule === 'internet_view') {
        return {
          evidence: `Shodan InternetDB sees port ${d.port} (${ev.service ?? 'a service'}) open on the organisation's public address ${ev.public_ip}${ev.checked_at ? ` (asked ${new Date(ev.checked_at).toLocaleDateString()})` : ''}; the alert sits on ${where}, its gateway or the computer that reported it`,
          knowledge: [d.fix ?? 'A management or remote-access service open to the internet is a way in'],
          rule: `Exposure · ${d.title ?? 'Open to the internet'} (closes when Shodan no longer sees it; Shodan rebuilds its data weekly)`,
        }
      }
      const seen = [
        ev.product && `${ev.product}${ev.version ? ` ${ev.version}` : ''}`,
        ev.realm && `a login prompt (realm "${ev.realm}")`, ev.title && `a page titled "${ev.title}"`,
        ev.http_status && `HTTP ${ev.http_status}`, ev.not_after && `a certificate valid until ${new Date(ev.not_after).toLocaleDateString()}`,
        ev.security && `RDP security "${ev.security}"`, ev.dialect && `SMB ${ev.dialect} without required signing`,
        ev.checked, ev.what && `${ev.what}, and the asset is internet-facing`,
      ].filter(Boolean)
      return {
        evidence: `An active scan of ${where} found port ${d.port} open${seen.length ? `: ${seen.join(', ')}` : ''}`,
        knowledge: [d.fix ?? 'This configuration is a known risk'],
        rule: `Exposure · ${d.title ?? 'A risky configuration seen now'} (stays open while scans still see it)`,
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
        evidence: `${d.source === 'network_agent' ? 'The network agent found' : `A ${d.source === 'passive_scan' ? 'passive' : 'network'} scan saw`} ${d.ip ?? 'a device'}${d.mac ? ` (${d.mac})` : ''}${d.hostname ? `, ${d.hostname}` : ''}`,
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

// What the targeted active scan of a new device found (tenant setting "Investigate new
// devices automatically"; details.investigation, written by the server).
function investigationText(inv, ip) {
  const when = (t) => (t ? ` (${new Date(t).toLocaleString()})` : '')
  switch (inv.status) {
    case 'queued':
      return `An active scan of ${ip ?? 'this device'} is queued; the agent that heard it runs it a few minutes after it was found.`
    case 'no_answer':
      return `The active scan got no answer${when(inv.completed_at)}: the device left the network or blocks probes.`
    case 'failed':
      return `The active scan did not run: ${inv.reason ?? 'unknown reason'}.`
    case 'completed': {
      const ports = (inv.open_ports ?? []).map((p) =>
        [`${p.port}/${p.protocol ?? 'tcp'}`, p.service, [p.product, p.version].filter(Boolean).join(' ')].filter(Boolean).join(' '))
      return [
        ports.length ? `Open ports: ${ports.join(', ')}` : 'No open ports found',
        inv.os ? `OS guess: ${inv.os}` : null,
        inv.hostname ? `Name: ${inv.hostname}` : null,
      ].filter(Boolean).join(' · ') + when(inv.completed_at)
    }
    default:
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
      {event.event_type === 'new_device' && event.details?.investigation && investigationText(event.details.investigation, event.details.ip) && (
        <Step icon={Radar} label="Investigated">{investigationText(event.details.investigation, event.details.ip)}</Step>
      )}
      {reasons.length > 0 && (
        <p className="text-[11px] text-dark-400">Ranked up by: {reasons.map(r => r.label).join(' · ')}</p>
      )}
    </div>
  )
}
