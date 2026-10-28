import { useNavigate } from 'react-router-dom'
import { ArrowUpRight, CircleCheck, HardDrive, ShieldAlert } from 'lucide-react'

const TYPE_META = {
  workstation: { label: 'Workstations', color: 'bg-blue-500' },
  server: { label: 'Servers', color: 'bg-indigo-400' },
  network: { label: 'Network', color: 'bg-cyan-400' },
  iot: { label: 'IoT', color: 'bg-amber-400' },
  mobile: { label: 'Mobile', color: 'bg-purple-400' },
  unknown: { label: 'Unknown', color: 'bg-dark-400' },
}
const fmt = value => Number(value ?? 0).toLocaleString()

function PanelTitle({ icon: Icon, title, detail }) {
  return <div className="mb-5 flex items-start gap-3">
    <span className="rounded-lg border border-dark-700/70 bg-dark-900/40 p-2 text-dark-300"><Icon className="h-4 w-4" /></span>
    <div><h3 className="font-semibold text-dark-100">{title}</h3><p className="mt-1 text-xs text-dark-400">{detail}</p></div>
  </div>
}

function GapRow({ label, definition, count, onClick, warning = false }) {
  return <button type="button" onClick={onClick} className="group flex w-full items-center justify-between gap-3 rounded-lg px-2 py-3 text-left hover:bg-dark-700/20 focus:outline-none focus:ring-2 focus:ring-eagle-500/50">
    <span className="min-w-0"><span className="block text-sm font-medium text-dark-200 group-hover:text-eagle-300">{label}</span><span className="mt-1 block text-xs text-dark-500">{definition}</span></span>
    <span className="flex flex-shrink-0 items-center gap-2"><span className={`text-xl font-semibold tabular-nums ${warning && count > 0 ? 'text-amber-400' : 'text-dark-100'}`}>{fmt(count)}</span><ArrowUpRight className="h-4 w-4 text-dark-500 group-hover:text-eagle-400" /></span>
  </button>
}

export default function AssetVisibility({ summary, loading, onInventory, onAgents }) {
  const navigate = useNavigate()
  const surface = summary?.attack_surface
  const mix = surface?.device_mix
  const total = summary?.overview?.known_assets
  const max = Math.max(1, ...Object.values(mix ?? {}).map(Number))
  const hygiene = summary?.hygiene
  const coverage = summary?.coverage
  const collection = summary?.collection
  const unknown = Number(mix?.unknown ?? 0)
  const gaps = [
    { label: 'Assets without an owner', definition: 'Known assets with no assigned owner', count: summary?.overview?.assets_without_owner, onClick: () => navigate('/inventory?gap=owner') },
    { label: 'Eligible computers without an agent', definition: `${fmt(coverage?.agent_capable)} servers and workstations eligible`, count: coverage?.no_agent?.count, onClick: () => navigate('/inventory?gap=no_agent') },
    { label: 'Stale inventory', definition: `Not scanned in ${hygiene?.stale_after_days ?? 7} days`, count: hygiene?.stale_assets?.count, onClick: () => navigate('/inventory?gap=stale') },
    { label: 'Missing SBOM', definition: 'Servers and workstations without software inventory', count: hygiene?.no_sbom?.count, onClick: () => navigate('/inventory?gap=no_sbom') },
    { label: 'Endpoint posture issues', definition: 'Managed assets with a failed endpoint security check', count: coverage?.posture?.machines_with_failures, onClick: () => navigate('/inventory?gap=posture_issues') },
    { label: 'Offline or degraded agents', definition: 'Agent heartbeats indicate interrupted monitoring', count: (collection?.agents_offline ?? 0) + (collection?.agents_degraded ?? 0), onClick: onAgents },
    { label: 'Network devices without SNMP management', definition: 'Known routers and switches without SNMP system data', count: surface?.network_devices_unmanaged, onClick: () => onInventory({ device_type: 'network' }) },
  ]

  return (
    <section aria-labelledby="asset-visibility-title">
      <div className="mb-4">
        <h2 id="asset-visibility-title" className="text-lg font-semibold tracking-tight text-dark-100">Asset visibility & coverage</h2>
        <p className="mt-1 text-sm text-dark-400">What is in the environment, and where monitoring or ownership is incomplete.</p>
      </div>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div className="glass-card p-5 lg:p-6">
          <PanelTitle icon={HardDrive} title="Asset landscape" detail={total == null ? 'Known asset records' : `${fmt(total)} unique asset records · ${fmt(summary?.overview?.new_assets_7d)} newly discovered in 7 days`} />
          {loading ? <div className="space-y-4 animate-pulse">{[0,1,2,3].map(n => <div key={n} className="h-7 rounded bg-dark-700/50" />)}</div>
            : !mix ? <p className="py-8 text-center text-sm text-dark-400">Asset distribution unavailable.</p>
              : <div className="space-y-3.5">
                {Object.entries(mix).filter(([, count]) => count > 0).sort((a,b) => b[1] - a[1]).map(([type,count]) => {
                  const meta = TYPE_META[type] ?? { label: type, color: 'bg-dark-400' }
                  return <button key={type} type="button" onClick={() => onInventory({ device_type: type })} className="group w-full text-left focus:outline-none focus:ring-2 focus:ring-eagle-500/50 rounded">
                    <span className="mb-1.5 flex items-center justify-between gap-3 text-sm"><span className="text-dark-200 group-hover:text-eagle-300">{meta.label}</span><span className="tabular-nums text-dark-100">{fmt(count)}</span></span>
                    <span className="block h-2 overflow-hidden rounded-full bg-dark-700/60"><span className={`block h-full rounded-full ${meta.color} opacity-80`} style={{ width: `${Math.max(1, Number(count) / max * 100)}%` }} /></span>
                  </button>
                })}
                {!total && <div className="py-5 text-center text-sm text-dark-400">No known assets yet. <button onClick={() => navigate('/discovery')} className="text-eagle-400 hover:underline">Start discovery</button></div>}
                <p className="pt-1 text-xs text-dark-500">Each bar is a device-type count. Asset totals use unique inventory records.</p>
              </div>}
        </div>

        <div className="glass-card p-5 lg:p-6">
          <PanelTitle icon={ShieldAlert} title="Visibility & coverage gaps" detail="Each count has a defined asset scope; no coverage percentages are inferred." />
          {loading ? <div className="space-y-4 animate-pulse">{[0,1,2,3].map(n => <div key={n} className="h-10 rounded bg-dark-700/50" />)}</div>
            : !summary ? <p className="py-8 text-center text-sm text-dark-400">Coverage data unavailable.</p>
              : <div className="-mx-2 divide-y divide-dark-700/50">
                {gaps.map(gap => <GapRow key={gap.label} {...gap} />)}
                {unknown > 0 && <GapRow label="Unidentified device types" definition="Device type is unknown; classify in Inventory" count={unknown} onClick={() => onInventory({ device_type: 'unknown' })} warning />}
                {gaps.every(gap => Number(gap.count ?? 0) === 0) && unknown === 0 && <div className="px-2 py-5 text-sm text-emerald-400"><CircleCheck className="mr-2 inline h-4 w-4" />No listed visibility gaps.</div>}
              </div>}
        </div>
      </div>
    </section>
  )
}
