import { useNavigate } from 'react-router-dom'
import { ArrowRight, ArrowUpRight, CircleCheck } from 'lucide-react'
import SectionHeader from '../ui/SectionHeader'
import PanelHeading from '../ui/PanelHeading'

const TYPE_META = {
  workstation: { label: 'Workstations', color: 'bg-series-1' },
  server: { label: 'Servers', color: 'bg-series-3' },
  network: { label: 'Network', color: 'bg-series-2' },
  iot: { label: 'IoT', color: 'bg-series-5' },
  mobile: { label: 'Mobile', color: 'bg-series-6' },
  unknown: { label: 'Unknown', color: 'bg-series-4' },
}
const fmt = value => Number(value ?? 0).toLocaleString()


function GapRow({ label, definition, count, onClick, warning = false }) {
  return <button type="button" onClick={onClick} className="group flex w-full items-center justify-between gap-3 rounded-lg px-2 py-3 text-left transition-colors hover:bg-eagle-500/[0.05]">
    <span className="min-w-0"><span className="block text-sm font-medium text-dark-200 group-hover:text-eagle-400">{label}</span><span className="mt-1 block text-xs text-dark-500">{definition}</span></span>
    <span className="flex flex-shrink-0 items-center gap-2"><span className={`font-display text-xl font-semibold tabular-nums ${warning && count > 0 ? 'text-amber-400' : 'text-dark-100'}`}>{fmt(count)}</span><ArrowUpRight className="h-4 w-4 text-dark-500 transition-colors group-hover:text-eagle-400" /></span>
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
      <SectionHeader id="asset-visibility-title" title="Asset visibility & coverage" className="mb-4"
        description="What is in the environment, and where monitoring or ownership is incomplete." />
      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-2">
        <div className="glass-card p-5 lg:p-6">
          <PanelHeading title="Asset landscape" detail={total == null ? 'Known asset records' : `${fmt(total)} unique asset records · ${fmt(summary?.overview?.new_assets_7d)} newly discovered in 7 days`} />
          {loading ? <div className="space-y-4 animate-pulse">{[0,1,2,3].map(n => <div key={n} className="h-7 rounded bg-dark-700/50" />)}</div>
            : !mix ? <p className="py-8 text-center text-sm text-dark-400">Asset distribution unavailable.</p>
              : <div className="space-y-3.5">
                {Object.entries(mix).filter(([, count]) => count > 0).sort((a,b) => b[1] - a[1]).map(([type,count]) => {
                  const meta = TYPE_META[type] ?? { label: type, color: 'bg-dark-400' }
                  return <button key={type} type="button" onClick={() => onInventory({ device_type: type })} className="group w-full rounded text-left">
                    <span className="mb-1.5 flex items-center justify-between gap-3 text-sm"><span className="inline-flex items-center gap-2 text-dark-200 group-hover:text-eagle-400"><span className={`h-2 w-2 rounded-sm ${meta.color}`} />{meta.label}</span><span className="tabular-nums text-dark-100">{fmt(count)}</span></span>
                    <span className="block h-1.5 overflow-hidden rounded-full bg-dark-700/60"><span className={`block h-full rounded-full ${meta.color} transition-[width] duration-700 ease-out`} style={{ width: `${Math.max(1, Number(count) / max * 100)}%` }} /></span>
                  </button>
                })}
                {!total && <div className="flex flex-col items-center gap-3 py-6 text-center">
                  <span aria-hidden="true" className="flex w-24 items-center"><span className="trace-line" /><span className="trace-node" /></span>
                  <p className="text-sm text-dark-300">No known assets yet.</p>
                  <p className="max-w-xs text-xs text-dark-500">Run a discovery scan from an agent, or add assets by hand in the Inventory.</p>
                  <button type="button" onClick={() => navigate('/discovery')} className="btn-secondary mt-1">Start discovery <ArrowRight className="h-4 w-4" /></button>
                </div>}
                <p className="pt-1 text-xs text-dark-500">Each bar is a device-type count. Asset totals use unique inventory records.</p>
              </div>}
        </div>

        <div className="glass-card p-5 lg:p-6">
          <PanelHeading title="Visibility & coverage gaps" detail="Each count has a defined asset scope; no coverage percentages are inferred." />
          {loading ? <div className="space-y-4 animate-pulse">{[0,1,2,3].map(n => <div key={n} className="h-10 rounded bg-dark-700/50" />)}</div>
            : !summary ? <p className="py-8 text-center text-sm text-dark-400">Coverage data unavailable.</p>
              : <div className="-mx-2 divide-y divide-dark-700/50">
                {gaps.map(gap => <GapRow key={gap.label} {...gap} />)}
                {unknown > 0 && <GapRow label="Unidentified device types" definition="Device type is unknown; classify in Inventory" count={unknown} onClick={() => onInventory({ device_type: 'unknown' })} warning />}
                {gaps.every(gap => Number(gap.count ?? 0) === 0) && unknown === 0 && <div className="px-2 py-5 text-sm text-accent-green"><CircleCheck className="mr-2 inline h-4 w-4" />No listed visibility gaps.</div>}
              </div>}
        </div>
      </div>
    </section>
  )
}
