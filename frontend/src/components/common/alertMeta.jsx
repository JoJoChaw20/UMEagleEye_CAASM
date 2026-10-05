// Shared alert vocabulary for the Dashboard and Alerts pages: labels, detail
// rendering, status badges and the junior-analyst playbook.
import { Crosshair, Radio, Fingerprint, Bug, MonitorSmartphone } from 'lucide-react'

export const SEVERITY_COLORS = {
  critical: '#ff5252',
  high:     '#ff9800',
  medium:   '#ffc400',
  low:      '#00e676',
}

export const EVENT_TYPE_LABELS = {
  cve_detected:      'CVE Detected',
  cti_match:         'Threat Intel Match',
  port_opened:       'Port Opened',
  port_closed:       'Port Closed',
  version_downgrade: 'Version Downgrade',
  version_upgrade:   'Version Upgrade',
  config_change:     'Config Change',
  new_package:       'New Package',
  removed_package:   'Removed Package',
  new_device:        'New Device',
}

const CONFIG_CHANGE_LABELS = {
  hostname:        'Hostname Changed',
  mac_address:     'MAC Address Changed',
  internet_facing: 'Exposure Changed',
  device_type:     'Device Type Changed',
  availability:    'Asset Offline',
  os_version:      'OS Version Changed',
  package_version: 'Package Updated',
  firmware:        'Firmware Changed',
}

// Must match workers/src/lib/exposure.ts RISKY_PORTS
export const RISKY_PORTS = {
  21: 'FTP', 23: 'Telnet', 135: 'MS-RPC', 139: 'NetBIOS', 161: 'SNMP', 445: 'SMB',
  1433: 'MS SQL', 2375: 'Docker API', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
  5900: 'VNC', 6379: 'Redis', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB',
}

export function alertLabel(e) {
  if (e.event_type === 'config_change') return CONFIG_CHANGE_LABELS[e.details?.changed_attribute] ?? 'Config Change'
  return EVENT_TYPE_LABELS[e.event_type] || e.event_type
}

// One-line evidence for the table
export function renderDetail(e) {
  const d = e.details ?? {}
  if (d.cve_id) return d.cve_id
  if (d.indicator_value) return d.indicator_value
  if (e.event_type === 'config_change') {
    if (d.changed_attribute === 'internet_facing') {
      return `${d.from ? 'Internet-facing' : 'Internal'} → ${d.to ? 'Internet-facing' : 'Internal'}`
    }
    return d.from != null && d.to != null ? `${d.from} → ${d.to}` : (d.changed_attribute ?? '—')
  }
  if (e.event_type === 'port_opened' || e.event_type === 'port_closed') {
    const svc = RISKY_PORTS[d.port]
    return `Port ${d.port}${d.protocol ? `/${d.protocol}` : ''}${svc ? ` (${svc})` : ''}`
  }
  if (e.event_type === 'version_downgrade' || e.event_type === 'version_upgrade') {
    const target = d.package ?? 'OS'
    return d.from && d.to ? `${target}: ${d.from} → ${d.to}` : target
  }
  if (e.event_type === 'new_package')     return `+${d.package ?? ''}${d.version ? ` ${d.version}` : ''}`
  if (e.event_type === 'removed_package') return `-${d.package ?? ''}`
  if (e.event_type === 'new_device')      return `New: ${d.ip ?? ''}${d.mac ? ` (${d.mac})` : ''}`
  return d.changed_attribute ?? '—'
}

// The alert categories to look at before the general backlog. Ids and meaning
// must match workers/src/lib/concerns.ts — the backend does the counting.
export const CONCERNS = [
  {
    id: 'threat_intel', title: 'Threat-intel matches', short: 'Threat intel', icon: Crosshair, tone: 'critical',
    why: 'A live threat feed flagged something on your asset. Possible active compromise.',
    action: 'Isolate and escalate now',
  },
  {
    id: 'exposed_services', title: 'Risky services opened', short: 'Risky services', icon: Radio, tone: 'critical',
    why: 'Newly opened ports attackers scan for first (SMB, RDP, databases…), or a host newly reachable from the internet.',
    action: 'Close or firewall within 24h',
  },
  {
    id: 'identity', title: 'Device identity changed', short: 'Identity changes', icon: Fingerprint, tone: 'serious',
    why: 'Same IP now answers with a different MAC or hostname. Spoofing, or an unrecorded hardware swap.',
    action: 'Verify within 24h',
  },
  {
    id: 'exploitable', title: 'Likely-exploited CVEs', short: 'Exploitable CVEs', icon: Bug, tone: 'serious',
    why: '≥10% chance of exploitation in the next 30 days (EPSS), or critical on an internet-facing host.',
    action: 'Patch within 72h',
  },
  {
    id: 'new_devices', title: 'Unclaimed new devices', short: 'New devices', icon: MonitorSmartphone, tone: 'warning',
    why: 'Devices that joined the network and nobody has confirmed yet.',
    action: 'Find the owner or isolate',
  },
]

export const TONE = {
  critical: { text: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/40',    bar: '#ff5252' },
  serious:  { text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/40', bar: '#ff9800' },
  warning:  { text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/40', bar: '#ffc400' },
  good:     { text: 'text-emerald-400', bg: 'bg-emerald-500/5', border: 'border-dark-700/50',  bar: '#00e676' },
}

// Priority score (backend lib/priority.ts) → a tier a human can act on.
// ≥100 needs internet exposure, a critical asset or a threat-intel hit on top
// of a severe finding, so P1 stays rare.
export function priorityTier(score) {
  if (score == null) return null
  if (score >= 100) return { tier: 'P1', label: 'Urgent',   cls: 'bg-red-500/20 text-red-300 border-red-500/50' }
  if (score >= 75)  return { tier: 'P2', label: 'High',     cls: 'bg-orange-500/15 text-orange-300 border-orange-500/40' }
  if (score >= 45)  return { tier: 'P3', label: 'Normal',   cls: 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30' }
  return              { tier: 'P4', label: 'Low',      cls: 'bg-dark-700 text-dark-300 border-dark-600' }
}

// The facts that pushed an alert up the queue, as short chips. `e` may be a
// queue row (asset_* fields) or a dashboard item (nested asset).
export function riskReasons(e) {
  const d = e.details ?? {}
  const exposed = e.asset_internet_facing ?? e.asset?.internet_facing
  const crit = e.asset_criticality ?? e.asset?.criticality
  const out = []
  if (e.event_type === 'cti_match' || d.has_cti_match) out.push({ label: 'Threat intel hit', tone: 'critical' })
  if (exposed) out.push({ label: 'Internet-facing', tone: 'critical' })
  if (d.port != null && RISKY_PORTS[d.port]) out.push({ label: `${RISKY_PORTS[d.port]} is a common attack target`, tone: 'serious' })
  if (d.epss_score >= 0.1) out.push({ label: `${Math.round(d.epss_score * 100)}% exploit chance`, tone: 'serious' })
  if (d.cvss_base_score >= 9) out.push({ label: `CVSS ${d.cvss_base_score}`, tone: 'serious' })
  if (crit >= 8) out.push({ label: `Critical asset ${crit}/10`, tone: 'serious' })
  if (Array.isArray(d.fix_versions) && d.fix_versions.length) out.push({ label: 'Fix available', tone: 'good' })
  return out
}

// Deadline from the playbook urgency, measured from first_seen.
export function dueInfo(e) {
  const hours = playbook(e).hours
  if (hours == null || !e.first_seen) return null
  if (hours === 0) return { label: 'Act now', overdue: true }
  const left = new Date(e.first_seen).getTime() + hours * 3600000 - Date.now()
  const fmt = (ms) => {
    const h = Math.abs(ms) / 3600000
    return h < 48 ? `${Math.max(1, Math.round(h))}h` : `${Math.round(h / 24)}d`
  }
  return left < 0 ? { label: `Overdue ${fmt(left)}`, overdue: true } : { label: `Due in ${fmt(left)}`, overdue: false }
}

export const DRIFT_TYPES = new Set([
  'port_opened', 'port_closed', 'version_downgrade', 'version_upgrade',
  'config_change', 'new_package', 'removed_package',
])

// Response window per playbook urgency, in hours (0 = immediately)
const URGENCY_HOURS = { 'Now': 0, '≤24h': 24, '≤72h': 72, '≤3d': 72, 'Patch cycle': 720, 'Review': 168 }

// First step for a junior analyst, per alert kind. Static on purpose: fast,
// consistent, and available even when no AI advisory has been generated.
export function playbook(e) {
  const p = basePlaybook(e)
  return { ...p, hours: URGENCY_HOURS[p.urgency] ?? null }
}

function basePlaybook(e) {
  const d = e.details ?? {}
  const exposed = e.asset_internet_facing ?? e.asset?.internet_facing
  if (e.event_type === 'cti_match' || d.has_cti_match) {
    return { urgency: 'Now', text: 'Treat as possible compromise. Isolate the host from the network and escalate to a senior analyst before touching it.' }
  }
  switch (e.event_type) {
    case 'cve_detected': {
      const epss = d.epss_score ?? 0
      const fix = Array.isArray(d.fix_versions) && d.fix_versions.length ? ` to ${d.fix_versions[0]}` : ''
      if (exposed || epss >= 0.1 || e.severity === 'critical') {
        return { urgency: '≤72h', text: `Patch ${d.package_name ?? 'the package'}${fix}. Internet exposure or high exploit likelihood — do not wait for the patch cycle.` }
      }
      return { urgency: 'Patch cycle', text: `Schedule upgrade of ${d.package_name ?? 'the package'}${fix} in the next patch window.` }
    }
    case 'port_opened': {
      const svc = RISKY_PORTS[d.port]
      return svc
        ? { urgency: '≤24h', text: `${svc} (port ${d.port}) is a commonly attacked service. Confirm with the asset owner; if not required, close it or firewall it to admin hosts only.` }
        : { urgency: '≤3d', text: `Confirm port ${d.port} is expected with the asset owner. If yes, accept the risk; if not, close it.` }
    }
    case 'port_closed':
      return { urgency: 'Review', text: 'Check the service was intentionally stopped. If expected, accept the change to update the baseline.' }
    case 'new_device':
      return { urgency: '≤24h', text: 'Identify the device from MAC vendor, hostname and open ports. If nobody can claim it within 24h, isolate it as a rogue device.' }
    case 'version_downgrade':
      return { urgency: '≤24h', text: 'Confirm whether this was a planned rollback. An unexplained downgrade can reintroduce old CVEs or indicate tampering.' }
    case 'version_upgrade':
    case 'new_package':
    case 'removed_package':
      return { urgency: 'Review', text: 'Match against a change ticket. If planned, accept the change to update the baseline.' }
    case 'config_change':
      switch (d.changed_attribute) {
        case 'mac_address':
          return { urgency: '≤24h', text: 'Same IP, different hardware. Check the switch port and DHCP logs — possible spoofing or an unrecorded hardware swap.' }
        case 'internet_facing':
          return d.to
            ? { urgency: 'Now', text: 'Host became internet-facing. Confirm the firewall/NAT change was approved; if not, revert it immediately.' }
            : { urgency: 'Review', text: 'Host is no longer internet-facing. Confirm this was intended and accept the change.' }
        case 'firmware':
          return { urgency: '≤3d', text: 'Network device firmware changed. Match against a change ticket and confirm the image is vendor-signed.' }
        case 'hostname':
          return { urgency: 'Review', text: 'Confirm the rename with the asset owner, then accept the change.' }
        default:
          return { urgency: 'Review', text: 'Confirm the change was planned, then accept it or investigate.' }
      }
    default:
      return { urgency: 'Review', text: 'Review the evidence and decide: resolve, accept the risk, or mark as false positive.' }
  }
}

export const STATUS_META = {
  open:           { label: 'Open',           cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  in_progress:    { label: 'In progress',    cls: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  resolved:       { label: 'Resolved',       cls: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' },
  false_positive: { label: 'False positive', cls: 'bg-dark-600/40 text-dark-300 border-dark-500/40' },
  accepted_risk:  { label: 'Accepted risk',  cls: 'bg-amber-500/15 text-amber-400 border-amber-500/30' },
}

export function StatusBadge({ status }) {
  const m = STATUS_META[status] ?? STATUS_META.open
  return <span className={`text-xs px-2 py-0.5 rounded-full border font-medium whitespace-nowrap ${m.cls}`}>{m.label}</span>
}

export function SevBadge({ sev }) {
  const cls = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high:     'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low:      'bg-green-500/20 text-green-400 border-green-500/30',
  }[sev] ?? 'bg-dark-700 text-dark-300 border-dark-600'
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-semibold uppercase tracking-wide ${cls}`}>
      {sev}
    </span>
  )
}

export function timeAgo(ts) {
  if (!ts) return '—'
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

export const CHART_TOOLTIP_STYLE = {
  background: 'rgb(var(--dark-700))', border: '1px solid rgb(var(--dark-500))', borderRadius: '8px',
  color: 'rgb(var(--dark-100))', boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
}
