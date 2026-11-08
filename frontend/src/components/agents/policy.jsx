// Agent settings an admin sets from the dashboard (workers/src/lib/agentPolicy.ts):
// labels, groups and one input that shows where a value comes from. A setting left at
// "default" follows the tenant default, or, when the tenant set nothing, stays the
// agent's own setting (what its user chose on that computer).
import { useState } from 'react'

export const ROLES = [
  { key: 'inventory', label: 'Inventory', help: "Reports its own computer: hardware, security settings, software, and the SBOM with its CVEs." },
  { key: 'sensor', label: 'Sensor', help: 'Listens passively on its network for the devices there (ARP, mDNS, NetBIOS, DHCP, SSDP).' },
  { key: 'scanner', label: 'Scanner', help: 'Runs the active scans the dashboard sends it (New scan, new-device investigations).' },
  { key: 'collector', label: 'Collector', help: 'A network agent: reads the routers and switches over SNMP (ARP and MAC tables, CDP/LLDP neighbours) to find every device and the switch port it is on.' },
]

const hours = (s) => (s % 3600 === 0 ? `${s / 3600} h` : s % 60 === 0 ? `${s / 60} min` : `${s} s`)

export const GROUPS = [
  {
    title: 'Scanning',
    settings: [
      { key: 'scanner', label: 'Runs scans sent from the dashboard' },
      { key: 'local_scans', label: 'May start its own scans', help: 'The "Scan now" button on that computer.' },
      {
        key: 'scan_engine', label: 'Scan engine', options: {
          auto: 'Nmap (built-in sweep without it)', own: 'EagleEye engine (no Nmap needed)', compare: 'Both, with a comparison report',
        },
      },
      {
        key: 'scan_ports', label: 'Ports (EagleEye engine)', options: {
          base: 'Base: 13 server and remote-access ports', consumer: 'Consumer: + phones, TVs, printers, cameras (36)',
          wide: 'Wide: + server, directory and industrial ports (90)',
        },
      },
    ],
  },
  {
    title: 'Passive listening',
    settings: [
      { key: 'passive', label: 'Listen for devices on its network' },
      { key: 'passive_interval', label: 'Upload what was heard every', unit: 's', format: hours },
      {
        key: 'passive_backend', label: 'Capture with', options: {
          auto: 'Automatic', npcap: 'Npcap', native: "Built in (Windows' own capture driver)",
        },
      },
    ],
  },
  {
    title: 'Inventory',
    settings: [
      { key: 'inventory', label: "Report this computer's inventory" },
      { key: 'inventory_interval', label: 'Every', unit: 's', format: hours },
      { key: 'inventory_user_software', label: 'Include software users installed for themselves' },
      { key: 'inventory_admin_names', label: 'Include the names of local administrator accounts' },
    ],
  },
  {
    title: 'SBOM',
    settings: [
      { key: 'sbom', label: "Build the SBOM and check it for CVEs" },
      { key: 'sbom_interval', label: 'Every', unit: 's', format: hours },
    ],
  },
  {
    title: 'Network devices (network agents)',
    settings: [
      { key: 'network_poll', label: 'Read the routers and switches' },
      {
        key: 'network_seeds', label: 'Start from', placeholder: '10.0.0.1',
        help: 'The routers or switches it reads first, one address per line. Their SNMP credentials stay on the agent.',
      },
      {
        key: 'network_ranges', label: 'Allowed ranges', placeholder: '10.0.0.0/8',
        help: 'It follows CDP/LLDP neighbours only inside these ranges, one per line. With none, it reads only the seeds.',
      },
      { key: 'network_depth', label: 'Hops from a seed', unit: 'hops' },
      { key: 'network_interval', label: 'Every', unit: 's', format: hours },
    ],
  },
]

export const SOURCE_LABEL = {
  agent: 'Set for this agent',
  tenant: 'Tenant default',
  local: "Agent's own setting",
  unknown: 'Not reported (agent before 2.4.0)',
}

export function show(meta, spec, value) {
  if (value === null || value === undefined) return '—'
  if (spec?.type === 'bool') return value ? 'On' : 'Off'
  if (spec?.type === 'list') return value.length ? value.join(', ') : 'none'
  if (meta.options) return meta.options[value] ?? String(value)
  return meta.format ? meta.format(value) : String(value)
}

// One setting: "default" (no value set here) or a value. `fallback` describes what
// "default" means for it (e.g. "Tenant default: On").
export function PolicyInput({ meta, spec, value, onChange, disabled, fallback }) {
  const id = `policy-${meta.key}`
  if (spec.type === 'list') return <ListInput id={id} meta={meta} value={value} onChange={onChange} disabled={disabled} fallback={fallback} />
  if (spec.type === 'int') {
    return (
      <div className="flex items-center gap-2">
        <input
          id={id} type="number" min={spec.min} max={spec.max} step={1} disabled={disabled}
          value={value ?? ''} placeholder={fallback}
          onChange={(e) => onChange(e.target.value === '' ? null : Number(e.target.value))}
          className="input-field w-32 text-sm" aria-label={meta.label}
        />
        <span className="text-xs text-dark-400">{meta.unit}{value != null && meta.format ? ` (${meta.format(value)})` : ''}</span>
      </div>
    )
  }
  const options = spec.type === 'bool' ? { true: 'On', false: 'Off' } : Object.fromEntries(spec.values.map((v) => [v, meta.options?.[v] ?? v]))
  return (
    <select
      id={id} disabled={disabled} aria-label={meta.label} className="input-field text-sm max-w-xs"
      value={value === null || value === undefined ? '' : String(value)}
      onChange={(e) => {
        const raw = e.target.value
        onChange(raw === '' ? null : spec.type === 'bool' ? raw === 'true' : raw)
      }}
    >
      <option value="">{fallback}</option>
      {Object.entries(options).map(([v, label]) => <option key={v} value={v}>{label}</option>)}
    </select>
  )
}

// A list of addresses or ranges, one per line (or comma-separated). Empty = default.
function ListInput({ id, meta, value, onChange, disabled, fallback }) {
  const [text, setText] = useState(() => (value ?? []).join('\n'))
  return (
    <textarea
      id={id} rows={3} disabled={disabled} aria-label={meta.label} className="input-field text-sm w-56 font-mono"
      value={text} placeholder={value == null ? `${fallback}\n(e.g. ${meta.placeholder})` : meta.placeholder}
      onChange={(e) => {
        setText(e.target.value)
        const items = e.target.value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
        onChange(items.length ? items : null)
      }}
    />
  )
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

// Whether a value is valid for its setting (ints and lists are typed freely).
export function invalid(spec, value) {
  if (value === null || value === undefined) return null
  if (spec.type === 'list') {
    if (value.length > spec.max) return `at most ${spec.max}`
    const bad = value.find((v) => {
      if (spec.item === 'ip') return !IPV4.test(v)
      const [ip, bits, extra] = v.split('/')
      return extra !== undefined || !IPV4.test(ip) || !/^\d{1,2}$/.test(bits ?? '') || Number(bits) > 32
    })
    return bad ? `${spec.item === 'ip' ? 'IPv4 addresses' : 'ranges like 10.0.0.0/8'} (not "${bad}")` : null
  }
  if (spec.type !== 'int') return null
  if (!Number.isInteger(value) || value < spec.min || value > spec.max) return `${spec.min} to ${spec.max}`
  return null
}

// Whether two values of a setting are the same (lists compare by their items).
export function same(a, b) {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null)
}
