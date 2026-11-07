// Agent settings an admin sets from the dashboard (workers/src/lib/agentPolicy.ts):
// labels, groups and one input that shows where a value comes from. A setting left at
// "default" follows the tenant default, or, when the tenant set nothing, stays the
// agent's own setting (what its user chose on that computer).

export const ROLES = [
  { key: 'inventory', label: 'Inventory', help: "Reports its own computer: hardware, security settings, software, and the SBOM with its CVEs." },
  { key: 'sensor', label: 'Sensor', help: 'Listens passively on its network for the devices there (ARP, mDNS, NetBIOS, DHCP, SSDP).' },
  { key: 'scanner', label: 'Scanner', help: 'Runs the active scans the dashboard sends it (New scan, new-device investigations).' },
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
  if (meta.options) return meta.options[value] ?? String(value)
  return meta.format ? meta.format(value) : String(value)
}

// One setting: "default" (no value set here) or a value. `fallback` describes what
// "default" means for it (e.g. "Tenant default: On").
export function PolicyInput({ meta, spec, value, onChange, disabled, fallback }) {
  const id = `policy-${meta.key}`
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

// Whether a value is valid for its setting (ints are typed freely).
export function invalid(spec, value) {
  if (value === null || value === undefined || spec.type !== 'int') return null
  if (!Number.isInteger(value) || value < spec.min || value > spec.max) return `${spec.min} to ${spec.max}`
  return null
}
