// Shared alert vocabulary for the Dashboard and Alerts pages: labels, detail
// rendering, status badges and the junior-analyst playbook.

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

export const DRIFT_TYPES = new Set([
  'port_opened', 'port_closed', 'version_downgrade', 'version_upgrade',
  'config_change', 'new_package', 'removed_package',
])

// First step for a junior analyst, per alert kind. Static on purpose: fast,
// consistent, and available even when no AI advisory has been generated.
export function playbook(e) {
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
