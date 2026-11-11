// The Network page's first view: the whole picture. The internet on top, each network's gateway
// under it and the network itself as a card (its range, devices, who watches it, what is open on it).
// Picking a card opens that network's map (NetworkBands.jsx NetworkTopology). Beside it, the tenant
// at a glance and the button that works out the relationships between assets again.
import { useState } from 'react'
import { ChevronRight, Globe, Network, RefreshCw, Router } from 'lucide-react'
import client from '../../api/client'
import { CoverageChips, PanelShell, Row, fmt, plural } from './NetworkBands'

/** The gateway a network card hangs from: the reported gateway, or the measured router that is it. */
function gatewayOf(net, map) {
  if (net.gateway) {
    const label = net.gateway.label && net.gateway.label !== net.gateway.ip ? net.gateway.label : 'Gateway'
    return { label, sub: net.gateway.ip, known: true }
  }
  const root = net.measured_roots.map((r) => map.nodes.find((n) => n.id === r)).find(Boolean)
  return root ? { label: root.label, sub: root.ip ?? 'router', known: true } : { label: 'Gateway not known', sub: 'no agent reported one', known: false }
}

function NetworkCard({ net, map, matches, onOpen }) {
  const gw = gatewayOf(net, map)
  const cves = net.devices.reduce((s, d) => s + d.alerts.cve_open, 0)
  const critical = net.devices.reduce((s, d) => s + d.alerts.cve_critical, 0)
  const exposures = net.devices.reduce((s, d) => s + d.alerts.exposure_open, 0)
  const withAgent = net.devices.filter((d) => d.agent).length
  const infra = net.measured_roots.length
    ? new Set(map.nodes.filter((n) => (n.kind === 'router' || n.kind === 'switch') && net.measured_roots.includes(rootOf(n, map))).map((n) => n.id)).size : 0
  const unwatched = net.agents.length === 0 && net.measured_roots.length === 0
  return (
    <div className="flex flex-col items-center h-full">
      <div className="h-5 border-l-2 border-dotted border-dark-500" aria-hidden="true" />
      <div className={`w-44 flex items-center gap-2 px-3 py-2 rounded-lg border bg-dark-800 ${gw.known ? 'border-eagle-500/40' : 'border-dashed border-dark-500/70'}`}>
        <Router className={`w-4 h-4 flex-shrink-0 ${gw.known ? 'text-series-1' : 'text-dark-400'}`} aria-hidden="true" />
        <span className="min-w-0">
          <span className="block text-xs font-semibold text-dark-50 truncate">{gw.label}</span>
          <span className={`block text-[11px] text-dark-400 truncate ${gw.known ? 'font-mono' : ''}`}>{gw.sub}</span>
        </span>
      </div>
      <div className="h-4 border-l-2 border-dashed border-dark-500/60" aria-hidden="true" />
      <button type="button" onClick={() => onOpen(net.key)}
        className={`w-full flex-1 text-left rounded-xl border p-3.5 space-y-2 hover:border-eagle-500/70 hover:bg-eagle-500/5 ${unwatched
          ? 'border-dashed border-yellow-500/50 bg-dark-800' : 'border-dark-700/80 bg-dark-850'}`}>
        <span className="flex items-start justify-between gap-2">
          <span className="min-w-0">
            <span className={`block text-sm font-semibold text-dark-50 ${net.title ? '' : 'font-mono'}`}>{net.title ?? net.key}</span>
            {net.subnets.length > 0 && <span className="block text-[11px] text-dark-400 font-mono truncate" title={net.subnets.join(', ')}>with {net.subnets.join(', ')}</span>}
          </span>
          <ChevronRight className="w-4 h-4 text-dark-400 flex-shrink-0 mt-0.5" aria-hidden="true" />
        </span>
        <span className="block text-xs text-dark-300">
          {plural(net.device_count, 'device')}{withAgent > 0 && `, ${withAgent} with an agent`}
          {infra > 0 && <span className="text-dark-400"> · {plural(infra, 'router or switch', 'routers and switches')} read</span>}
        </span>
        <span className="flex flex-wrap gap-1.5"><CoverageChips net={net} small /></span>
        <span className="block text-xs">
          {cves > 0 ? <><b className="text-red-400">{fmt(cves)} open CVEs</b>{critical > 0 && <span className="text-dark-400">, {fmt(critical)} critical</span>}</>
            : <span className="text-dark-400">No open CVEs</span>}
          {exposures > 0 && <span className="text-orange-400"> · {plural(exposures, 'exposure alert')}</span>}
        </span>
        {matches > 0 && <span className="block text-xs text-accent-amber">{plural(matches, 'match', 'matches')} here</span>}
      </button>
    </div>
  )
}

function rootOf(n, map) {
  let cur = n
  for (let i = 0; i < 64 && cur?.parent; i++) cur = map.nodes.find((x) => x.id === cur.parent) ?? null
  return cur?.id ?? n.id
}

/** The internet, then each network's gateway and card; the cards wrap into rows. */
export function NetworksOverview({ networks, map, matchCount, onOpen }) {
  return (
    <div className="flex flex-col items-center">
      <div className="w-44 flex items-center gap-2.5 px-3 py-2.5 rounded-lg border border-dark-700/80 bg-dark-800">
        <Globe className="w-5 h-5 text-dark-400" aria-hidden="true" />
        <span className="text-sm font-semibold text-dark-50">Internet</span>
      </div>
      <div className="h-5 border-l-2 border-dotted border-dark-500" aria-hidden="true" />
      <div className="w-full grid gap-y-6 [grid-template-columns:repeat(auto-fill,minmax(min(17rem,100%),1fr))]">
        {networks.map((n) => (
          <div key={n.key} className="px-2 border-t-2 border-dotted border-dark-500/60">
            <NetworkCard net={n} map={map} matches={matchCount(n)} onOpen={onOpen} />
          </div>
        ))}
      </div>
    </div>
  )
}

/** The tenant at a glance, and the relationships button (Blast radius and Connected use them). */
export function OverviewPanel({ networks, map, canInfer }) {
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)        // {ok, text}
  const devices = networks.reduce((s, n) => s + n.device_count, 0)
  const withAgent = networks.reduce((s, n) => s + n.devices.filter((d) => d.agent).length, 0)
  const unwatched = networks.filter((n) => n.agents.length === 0 && n.measured_roots.length === 0).length
  const infra = map.nodes.filter((n) => n.kind === 'router' || n.kind === 'switch').length
  const cves = networks.reduce((s, n) => s + n.devices.reduce((t, d) => t + d.alerts.cve_open, 0), 0)
  const critical = networks.reduce((s, n) => s + n.devices.reduce((t, d) => t + d.alerts.cve_critical, 0), 0)
  const exposures = networks.reduce((s, n) => s + n.devices.reduce((t, d) => t + d.alerts.exposure_open, 0), 0)
  const computerAgents = [...new Map(networks.flatMap((n) => n.agents).map((a) => [a.agent_id, a.name])).values()]

  // Topology first, so assets have their network layer; relationships are built even if it fails.
  const update = async () => {
    setBusy(true); setResult(null)
    let warning = ''
    try {
      await client.post('/topology/infer')
    } catch (e) {
      warning = `The topology step failed (HTTP ${e?.response?.status ?? 'error'}), so the older topology was used. `
    }
    try {
      const res = await client.post('/relationships/infer')
      const n = res.data?.relationships_created ?? 0
      setResult({ ok: !warning, text: `${warning}${plural(n, 'relationship')} worked out.` })
    } catch (err) {
      setResult({ ok: false, text: err?.response?.data?.detail || 'Could not work out the relationships' })
    } finally { setBusy(false) }
  }

  return (
    <PanelShell kind="Whole network" title={`${plural(networks.length, 'network')}`}>
      <dl className="text-sm space-y-2">
        <Row k="Devices">{fmt(devices)}{withAgent > 0 && <span className="text-dark-400">, {withAgent} with an agent</span>}</Row>
        <Row k="Not watched"><span className={unwatched ? 'text-yellow-400' : ''}>{unwatched === 0 ? 'Every network has an agent' : plural(unwatched, 'network')}</span></Row>
        <Row k="Computer agents">{computerAgents.length ? computerAgents.join(', ') : 'None'}</Row>
        <Row k="Network agents">{map.agents.length ? map.agents.map((a) => a.name).join(', ') : 'None'}{infra > 0 && <span className="text-dark-400"> ({plural(infra, 'router or switch', 'routers and switches')})</span>}</Row>
        <Row k="Open CVEs">{cves > 0 ? <><b className="text-red-400">{fmt(cves)}</b>{critical > 0 && <span className="text-dark-400">, {fmt(critical)} critical</span>}</> : 'None'}</Row>
        <Row k="Exposure">{exposures > 0 ? plural(exposures, 'open alert') : 'None'}</Row>
      </dl>
      <p className="text-xs text-dark-400">Pick a network to see its map: its gateway, the routers and switches a network agent read, and every device on it.</p>
      {canInfer && (
        <div className="space-y-2 border-t border-dark-700/60 pt-3">
          <p className="text-xs text-dark-400">
            Blast radius and each asset's Connected list use the relationships between your assets, worked out from scans and the
            measured cables. Work them out again after new scans or a network agent crawl.
          </p>
          <button type="button" onClick={update} disabled={busy} className="btn-secondary text-sm w-full inline-flex items-center justify-center gap-2">
            {busy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Network className="w-4 h-4" />}
            {busy ? 'Working out relationships…' : 'Update relationships'}
          </button>
          {result && <p className={`text-xs ${result.ok ? 'text-emerald-400' : 'text-yellow-400'}`} role="status">{result.text}</p>}
        </div>
      )}
    </PanelShell>
  )
}
