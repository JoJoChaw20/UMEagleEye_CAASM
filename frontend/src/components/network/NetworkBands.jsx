// Every network the tenant's agents see (GET /network/map `networks`, workers/src/lib/mapNetworks.ts),
// one band each, stacked: the internet, the network's gateway, then its devices. A band opens in
// place to show all its devices grouped by type. Dotted line: the route to the internet; dashed:
// seen by an agent (the measured cables are in the Routers and switches section below).
import { Link } from 'react-router-dom'
import {
  AlertTriangle, ChevronDown, ChevronRight, Cpu, ExternalLink, Eye, Globe, HelpCircle, Layers, Monitor, Network,
  Router, Server, Smartphone, X, Zap,
} from 'lucide-react'
import { TONE } from '../common/alertMeta'
import { formatSeen } from '../../utils/time'

export const COLOUR_MODES = [
  { id: 'kind', label: 'Kind' },
  { id: 'cves', label: 'Open CVEs' },
  { id: 'exposure', label: 'Exposure' },
]

const COLLAPSED = 3                      // devices a closed band shows
const TYPE_ORDER = ['server', 'workstation', 'network', 'mobile', 'iot', 'unknown']
const TYPE_LABEL = {
  server: 'Servers', workstation: 'Workstations', network: 'Network devices', mobile: 'Phones and tablets',
  iot: 'IoT devices', unknown: 'Not identified yet',
}
const TYPE_ICON = { server: Server, workstation: Monitor, network: Network, mobile: Smartphone, iot: Cpu }
const TYPE_TONE = {
  server: 'text-series-3', workstation: 'text-series-2', network: 'text-series-1', mobile: 'text-series-6', iot: 'text-series-5',
}
const fmt = (n) => Number(n).toLocaleString()
const plural = (n, one, many = `${one}s`) => `${fmt(n)} ${n === 1 ? one : many}`

/** How a device looks in a colour mode: its tone (TONE entry or null), a line of text, a dashed outline. */
export function deviceLook(d, mode) {
  const a = d.alerts
  if (mode === 'cves') {
    if (a.cve_critical > 0) return { tone: TONE.critical, line: `${fmt(a.cve_open)} open · ${fmt(a.cve_critical)} critical` }
    if (a.cve_high > 0) return { tone: TONE.serious, line: `${fmt(a.cve_open)} open · ${fmt(a.cve_high)} high` }
    if (a.cve_open > 0) return { tone: TONE.warning, line: `${fmt(a.cve_open)} open` }
    // CVEs come from the SBOM a computer's agent builds: without one, nothing was checked
    return d.agent === 'host' ? { tone: null, line: 'No open CVEs' } : { tone: null, line: 'Not checked: no SBOM', dashed: true }
  }
  if (mode === 'exposure') {
    if (!a.exposure_open) return { tone: null, line: 'No exposure alerts' }
    const sev = a.exposure_severity
    const tone = sev === 'critical' ? TONE.critical : sev === 'high' ? TONE.serious : TONE.warning
    return { tone, line: `${plural(a.exposure_open, 'exposure alert')}${sev ? ` (${sev})` : ''}` }
  }
  return { tone: null, line: null }
}

function coverageOf(net) {
  if (net.coverage === 'none') {
    return { text: 'No computer agent on this network', cls: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/40', Icon: AlertTriangle }
  }
  const what = net.coverage === 'watched' ? 'listens and scans' : net.coverage === 'listen_only' ? 'listens only' : 'scans only'
  return { text: `${plural(net.agents.length, 'agent')} · ${what}`, cls: 'text-eagle-400 bg-eagle-500/10 border-eagle-500/30', Icon: Eye }
}

function NodeBox({ icon: Icon, tone = 'text-dark-400', title, sub, mono = true, onClick, selected, label }) {
  const body = (
    <>
      <Icon className={`w-5 h-5 flex-shrink-0 ${tone}`} aria-hidden="true" />
      <span className="min-w-0 text-left">
        <span className="block text-sm font-semibold text-dark-50 truncate">{title}</span>
        {sub && <span className={`block text-[11px] text-dark-400 truncate ${mono ? 'font-mono' : ''}`}>{sub}</span>}
      </span>
    </>
  )
  const cls = `w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg border bg-dark-800 ${selected ? 'border-eagle-500 ring-2 ring-eagle-500/30' : 'border-dark-700/80'}`
  return onClick
    ? <button type="button" onClick={onClick} aria-label={label} className={`${cls} hover:border-eagle-500/60`}>{body}</button>
    : <div className={cls}>{body}</div>
}

function DeviceCard({ d, mode, selected, onSelect }) {
  const look = deviceLook(d, mode)
  const Icon = TYPE_ICON[d.device_type] ?? HelpCircle
  const border = look.tone ? look.tone.border : look.dashed ? 'border-dashed border-dark-500/70' : 'border-dark-700/80'
  const tags = [d.agent === 'host' && 'its own agent', d.agent === 'mobile' && 'phone app', d.measured && 'on a switch port'].filter(Boolean)
  return (
    <button type="button" onClick={() => onSelect(d)} aria-pressed={selected}
      className={`w-full text-left flex items-start gap-2.5 px-3 py-2 rounded-lg border ${look.tone ? look.tone.bg : 'bg-dark-800'} ${border} ${selected ? 'ring-2 ring-eagle-500/50' : ''} hover:border-eagle-500/60`}>
      <Icon className={`w-[18px] h-[18px] mt-0.5 flex-shrink-0 ${look.tone ? look.tone.text : TYPE_TONE[d.device_type] ?? 'text-dark-400'}`} aria-hidden="true" />
      <span className="min-w-0">
        <span className="block text-sm font-semibold text-dark-50 truncate" title={d.label}>{d.label}</span>
        {look.line && <span className={`block text-xs ${look.tone ? look.tone.text : 'text-dark-300'}`}>{look.line}</span>}
        <span className="block text-[11px] text-dark-400 truncate">
          <span className="font-mono">{d.ip}</span>{tags.length > 0 && ` · ${tags.join(' · ')}`}
        </span>
      </span>
    </button>
  )
}

const GRID = 'grid gap-2 [grid-template-columns:repeat(auto-fill,minmax(min(210px,100%),1fr))]'

export function NetworkBand({ net, devices, mode, open, onToggle, selection, onSelectNetwork, onSelectDevice }) {
  const cov = coverageOf(net)
  const netSelected = selection?.type === 'network' && selection.key === net.key
  const isSelected = (d) => selection?.type === 'device' && selection.key === net.key && selection.asset_id === d.asset_id
  const shown = open ? devices : devices.slice(0, COLLAPSED)
  const hidden = net.device_count - shown.length
  const groups = open
    ? TYPE_ORDER.map((t) => ({ t, items: devices.filter((d) => (TYPE_LABEL[d.device_type] ? d.device_type : 'unknown') === t) }))
      .filter((g) => g.items.length)
    : [{ t: null, items: shown }]

  return (
    <section aria-label={`Network ${net.key}`}
      className={`rounded-xl border p-4 space-y-3 ${netSelected ? 'border-eagle-500 ring-1 ring-eagle-500/30 bg-eagle-500/5'
        : net.coverage === 'none' ? 'border-dashed border-yellow-500/50 bg-dark-800' : 'border-dark-700/80 bg-dark-850'}`}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <button type="button" onClick={() => onSelectNetwork(net)} className="text-left group">
          <span className="block text-sm font-semibold text-dark-50 group-hover:text-eagle-400 font-mono">{net.key}</span>
          <span className="block text-xs text-dark-400">
            {plural(net.device_count, 'device')}{net.last_seen && ` · seen ${formatSeen(net.last_seen).text}`}
          </span>
        </button>
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full border ${cov.cls}`}>
            <cov.Icon className="w-3.5 h-3.5" aria-hidden="true" /> {cov.text}
          </span>
          {net.device_count > 0 && (
            <button type="button" onClick={() => onToggle(net.key)} aria-expanded={open}
              className="btn-secondary text-xs inline-flex items-center gap-1">
              {open ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              {open ? 'Close' : 'Open'}
            </button>
          )}
        </div>
      </div>

      <div className="flex flex-wrap gap-x-6 gap-y-3 items-start">
        <div className="w-44 flex-shrink-0 flex flex-col items-stretch">
          <NodeBox icon={Globe} title="Internet" />
          <div className="mx-auto h-5 border-l-2 border-dotted border-dark-500" aria-hidden="true" />
          {net.gateway ? (
            <NodeBox icon={Router} tone="text-series-1" title={net.gateway.label && net.gateway.label !== net.gateway.ip ? net.gateway.label : 'Gateway'}
              sub={net.gateway.ip} onClick={() => onSelectNetwork(net)} label={`Gateway ${net.gateway.ip}`} />
          ) : (
            <NodeBox icon={Router} title="Gateway not known" sub="no agent reported one" mono={false} />
          )}
          {net.gateway_macs.length > 1 && (
            <p className="mt-2 text-[11px] text-yellow-400 flex gap-1"><AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
              Two gateways answer at this address: maybe two sites on one range</p>
          )}
        </div>

        <div className="flex-1 min-w-[16rem] border-l-2 border-dashed border-dark-500/50 pl-4 space-y-3">
          {net.device_count === 0 && <p className="text-sm text-dark-400 py-2">Nothing found here yet.</p>}
          {groups.map((g) => (
            <div key={g.t ?? 'all'} className="space-y-1.5">
              {g.t && <h4 className="text-xs font-semibold text-dark-300">{TYPE_LABEL[g.t]} <span className="font-normal text-dark-400">{g.items.length}</span></h4>}
              <div className={GRID}>
                {g.items.map((d) => <DeviceCard key={d.asset_id} d={d} mode={mode} selected={isSelected(d)} onSelect={(x) => onSelectDevice(net, x)} />)}
                {!open && hidden > 0 && (
                  <button type="button" onClick={() => onToggle(net.key)}
                    className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg border border-dashed border-dark-500/70 bg-dark-800 hover:border-eagle-500/60 text-left">
                    <Layers className="w-[18px] h-[18px] text-dark-400" aria-hidden="true" />
                    <span><span className="block text-sm font-semibold text-dark-50">+{fmt(hidden)} more</span>
                      <span className="block text-xs text-dark-400">Open the network</span></span>
                  </button>
                )}
              </div>
            </div>
          ))}
          {open && net.device_count > devices.length && (
            <p className="text-xs text-dark-400">
              Showing {fmt(devices.length)} of {fmt(net.device_count)}. Find the others with the search above, or in{' '}
              <Link to={`/inventory?q=${encodeURIComponent(net.key.split('/')[0].split('.').slice(0, 3).join('.') + '.')}`} className="text-eagle-400 hover:underline">Inventory</Link>.
            </p>
          )}
          {net.measured_count > 0 && (
            <p className="text-xs text-dark-400">{plural(net.measured_count, 'device')} here {net.measured_count === 1 ? 'is' : 'are'} also on a measured switch port (Routers and switches, below).</p>
          )}
        </div>
      </div>
    </section>
  )
}

function Row({ k, children }) {
  return (
    <div className="grid grid-cols-[6.5rem_1fr] gap-3">
      <dt className="text-dark-400">{k}</dt>
      <dd className="text-dark-100 min-w-0 break-words">{children}</dd>
    </div>
  )
}

export function NetworkPanel({ net, open, onToggle, onClose }) {
  const cves = net.devices.reduce((s, d) => s + d.alerts.cve_open, 0)
  const critical = net.devices.reduce((s, d) => s + d.alerts.cve_critical, 0)
  const exposures = net.devices.reduce((s, d) => s + d.alerts.exposure_open, 0)
  const withAgent = net.devices.filter((d) => d.agent).length
  return (
    <PanelShell kind="Network" title={net.key} onClose={onClose}>
      <dl className="text-sm space-y-2">
        <Row k="Gateway">
          {net.gateway ? <><span className="font-mono">{net.gateway.ip}</span>
            {net.gateway.mac && <span className="block font-mono text-xs text-dark-400 lowercase">{net.gateway.mac}</span>}</> : 'Not known'}
        </Row>
        <Row k="Devices">{fmt(net.device_count)}{withAgent > 0 && <span className="text-dark-400">, {withAgent} with an agent</span>}</Row>
        <Row k="Watched by">
          {net.agents.length === 0 ? <span className="text-yellow-400">No computer agent: nothing listens or scans here</span>
            : net.agents.map((a) => (
              <span key={a.agent_id} className="block">{a.name}{' '}
                <span className="text-dark-400">{a.listens && a.scans ? 'listens and scans' : a.listens ? 'listens' : a.scans ? 'scans' : 'neither (both off)'}</span>
              </span>
            ))}
        </Row>
        {net.phones.length > 0 && <Row k="Phone apps">{net.phones.map((p) => p.name).join(', ')}</Row>}
        <Row k="Open CVEs">{cves > 0 ? <><b className="text-red-400">{fmt(cves)}</b>{critical > 0 && <span className="text-dark-400">, {fmt(critical)} critical</span>}</> : 'None'}</Row>
        <Row k="Exposure">{exposures > 0 ? plural(exposures, 'open alert') : 'None'}</Row>
        {net.last_seen && <Row k="Last seen">{formatSeen(net.last_seen).text}</Row>}
      </dl>
      {net.gateway_macs.length > 1 && (
        <p className="text-xs text-yellow-400 bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-2.5">
          Gateways with {net.gateway_macs.length} different MAC addresses answered at {net.gateway?.ip}. This range is probably used at
          more than one site; its devices are shown together.
        </p>
      )}
      <div className="flex flex-col gap-2">
        {net.device_count > 0 && <button type="button" onClick={() => onToggle(net.key)} className="btn-primary text-sm">{open ? 'Close this network' : 'Open this network'}</button>}
        <Link to="/discovery" className="btn-secondary text-sm text-center">New scan (Discovery)</Link>
      </div>
    </PanelShell>
  )
}

export function DevicePanel({ net, device: d, onClose, onBlast }) {
  const a = d.alerts
  return (
    <PanelShell kind={d.device_type ? `Device (${d.device_type})` : 'Device'} title={d.label} onClose={onClose}>
      <dl className="text-sm space-y-2">
        <Row k="Address"><span className="font-mono">{d.ip}</span>{d.mac && <span className="block font-mono text-xs text-dark-400 lowercase">{d.mac}</span>}</Row>
        <Row k="Network"><span className="font-mono">{net.key}</span>{net.gateway && <span className="text-dark-400"> via {net.gateway.ip}</span>}</Row>
        <Row k="Agent">{d.agent === 'host' ? 'Its own agent (inventory and SBOM)' : d.agent === 'mobile' ? 'The EagleEye phone app' : 'None: seen on the network'}</Row>
        <Row k="Open CVEs">{a.cve_open > 0
          ? <><b className="text-red-400">{fmt(a.cve_open)}</b><span className="text-dark-400">{a.cve_critical > 0 && `, ${fmt(a.cve_critical)} critical`}{a.kev > 0 && `, ${fmt(a.kev)} known exploited`}</span></>
          : d.agent === 'host' ? 'None' : 'Not checked (no SBOM)'}</Row>
        <Row k="Exposure">{a.exposure_open > 0 ? `${plural(a.exposure_open, 'open alert')}${a.exposure_severity ? ` (${a.exposure_severity})` : ''}` : 'None'}</Row>
        {d.criticality != null && <Row k="Criticality">{d.criticality}/10</Row>}
        {d.measured && <Row k="Switch port">Measured: see Routers and switches</Row>}
        <Row k="Last seen">{formatSeen(d.last_seen).text}</Row>
      </dl>
      <div className="flex flex-wrap gap-2">
        <Link to={`/inventory/${d.asset_id}`} className="btn-primary text-sm inline-flex items-center gap-2">Open asset <ExternalLink className="w-3.5 h-3.5" /></Link>
        <button type="button" onClick={() => onBlast(d.asset_id)} className="btn-secondary text-sm inline-flex items-center gap-2"
          title="What would be affected if this device were compromised or went down (assets in My Assets)">
          <Zap className="w-3.5 h-3.5" /> Blast radius
        </button>
      </div>
    </PanelShell>
  )
}

function PanelShell({ kind, title, onClose, children }) {
  return (
    <aside className="glass-card p-4 space-y-4" aria-label={`${kind} details`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-dark-400">{kind}</p>
          <p className="text-base font-semibold text-dark-50 break-all">{title}</p>
        </div>
        <button type="button" onClick={onClose} className="text-dark-400 hover:text-dark-50" aria-label="Close"><X className="w-4 h-4" /></button>
      </div>
      {children}
    </aside>
  )
}
