import { useEffect, useMemo, useState } from 'react'
import { X, Wifi } from 'lucide-react'
import client from '../../api/client'

// A full (active) scan, run by one agent. Passive listening needs no scan: agents listen
// all the time. "Automatic" lets the server pick the online agent with the Scanner role
// that is on the range's network (GET /scans/route shows which, and why); an agent that is
// not on it scans only when picked here (through a router: no MAC addresses).

const ipNum = (ip) => ip.split('.').reduce((n, o) => n * 256 + Number(o), 0)
/** Whether an IPv4 address is in a CIDR ("192.168.36.60" in "192.168.36.0/24"). */
function inCidr(ip, cidr) {
  const [net, bits] = cidr.split('/')
  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || !net) return false
  const size = 2 ** (32 - Number(bits))
  return Math.floor(ipNum(ip) / size) === Math.floor(ipNum(net) / size)
}

function validateSubnet(value) {
  const v = value.trim()
  if (!v) return 'Enter an IP address or a range'
  const [ip, prefix] = v.split('/')
  const octet = '(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)'
  if (!new RegExp(`^${octet}(\\.${octet}){3}$`).test(ip)) return 'Use an IPv4 address or range, e.g. 192.168.1.0/24'
  if (prefix !== undefined) {
    const n = Number(prefix)
    if (!Number.isInteger(n) || n < 16 || n > 32) return 'Use a range from /16 to /32'
  }
  return null
}

export default function NewScanModal({ agents: allAgents, networks, initial, onClose, onSubmit }) {
  // A network agent reads routers and switches; it does not run scans (the server refuses it)
  const agents = useMemo(() => allAgents.filter((a) => a.kind !== 'network'), [allAgents])
  const online = agents.filter((a) => a.status === 'online')
  // The network each agent was last on (networks are newest first)
  const lastNetwork = useMemo(() => {
    const out = {}
    // Reported (2.5.1+): the one holding the agent's own address (a lab VM is also on its NAT
    // card's network, which may come first), else the first
    for (const a of agents) if (a.networks?.length) out[a.agent_id] = a.networks.find((n) => inCidr(a.local_ip, n)) ?? a.networks[0]
    for (const n of networks) for (const id of n.agent_ids) if (!out[id]) out[id] = n.subnet
    return out
  }, [agents, networks])

  const [agentId, setAgentId] = useState(initial?.agentId ?? 'auto')
  const [subnet, setSubnet] = useState(initial?.subnet ?? (initial?.agentId ? lastNetwork[initial.agentId] ?? '' : networks[0]?.subnet ?? ''))
  const [route, setRoute] = useState(null)          // the server's pick for this range
  const [touched, setTouched] = useState(!!initial?.subnet)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  // Follow the chosen agent's network until the range is edited by hand
  useEffect(() => { if (!touched && agentId && agentId !== 'auto') setSubnet(lastNetwork[agentId] ?? '') }, [agentId, touched, lastNetwork])
  // Which agent "Automatic" would use for this range (asked a moment after typing stops)
  useEffect(() => {
    if (agentId !== 'auto' || validateSubnet(subnet)) { setRoute(null); return undefined }
    let live = true
    const t = setTimeout(() => {
      client.get('/scans/route', { params: { subnet: subnet.trim() } })
        .then((r) => live && setRoute(r.data))
        .catch(() => live && setRoute(null))
    }, 350)
    return () => { live = false; clearTimeout(t) }
  }, [agentId, subnet])
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const subnetError = validateSubnet(subnet)
  const agent = agents.find((a) => a.agent_id === agentId)

  const submit = async (e) => {
    e.preventDefault()
    if (subnetError || !agentId || (agentId === 'auto' && route && !route.agent_id)) return
    setSubmitting(true)
    setError(null)
    try {
      await onSubmit({ subnet: subnet.trim(), agent_id: agentId })
      onClose()
    } catch (err) {
      const d = err?.response?.data
      setError(d?.detail || d?.error?.issues?.[0]?.message || 'Failed to start the scan')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-dark-950/70 p-4" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-labelledby="new-scan-title" className="glass-card w-full max-w-md p-6 space-y-4" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h2 id="new-scan-title" className="text-lg font-semibold text-dark-50">New full scan</h2>
          <button onClick={onClose} className="text-dark-400 hover:text-dark-50" title="Close"><X className="w-5 h-5" /></button>
        </div>

        {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}

        {online.length === 0 ? (
          <p className="text-sm text-dark-300">No agent is online. Start the EagleEye agent on a computer in the network you want to scan.</p>
        ) : (
          <form onSubmit={submit} className="space-y-4">
            <div>
              <label htmlFor="scan-agent" className="block text-xs text-dark-400 mb-1">Agent that runs it</label>
              <select id="scan-agent" value={agentId} onChange={(e) => setAgentId(e.target.value)} className="input-field w-full text-sm">
                <option value="auto">Automatic: the agent on that network (recommended)</option>
                {agents.map((a) => (
                  <option key={a.agent_id} value={a.agent_id} disabled={a.status !== 'online'}>
                    {a.name}{a.status !== 'online' ? ` (${a.status})` : lastNetwork[a.agent_id] ? ` · on ${lastNetwork[a.agent_id]}` : ''}
                  </option>
                ))}
              </select>
              {agentId === 'auto' ? (
                route && (route.agent_id
                  ? <p className="text-[11px] text-green-400 mt-1">Runs on {route.name}: {route.reason.replace(`${route.name} `, '')}.</p>
                  : (
                    <div className="text-[11px] text-yellow-400 mt-1 space-y-1">
                      <p>{route.reason}</p>
                      {route.routed?.length > 0 && (
                        <p className="flex flex-wrap gap-1">
                          {route.routed.map((r) => (
                            <button key={r.agent_id} type="button" onClick={() => { setAgentId(r.agent_id); setTouched(true) }}
                              className="px-2 py-0.5 rounded border border-yellow-500/40 hover:bg-yellow-500/10">Scan through {r.name}</button>
                          ))}
                        </p>
                      )}
                      {route.networks?.length > 0 && (
                        <p className="flex flex-wrap gap-1">
                          {route.networks.map((n) => (
                            <button key={n} type="button" onClick={() => { setSubnet(n); setTouched(true) }}
                              className="px-2 py-0.5 rounded border border-yellow-500/40 hover:bg-yellow-500/10 font-mono">{n}</button>
                          ))}
                        </p>
                      )}
                    </div>
                  ))
              ) : (
                <p className="text-[11px] text-dark-500 mt-1">The agent can only reach networks its computer is connected to; others only through a router (no MAC addresses).</p>
              )}
            </div>
            <div>
              <label htmlFor="scan-range" className="block text-xs text-dark-400 mb-1">Range or address</label>
              <input id="scan-range" type="text" value={subnet} onChange={(e) => { setSubnet(e.target.value); setTouched(true) }}
                placeholder="192.168.1.0/24" className={`input-field w-full text-sm font-mono ${subnet && subnetError ? 'border-red-500/60' : ''}`} />
              {subnet && subnetError && <p className="text-xs text-red-400 mt-1">{subnetError}</p>}
              {agentId !== 'auto' && agent && lastNetwork[agentId] && subnet.trim() !== lastNetwork[agentId] && (
                <button type="button" onClick={() => { setSubnet(lastNetwork[agentId]); setTouched(false) }} className="text-[11px] text-eagle-400 hover:underline mt-1">
                  Use {agent.name}'s network ({lastNetwork[agentId]})
                </button>
              )}
            </div>
            <div className="flex gap-3 pt-1">
              <button type="button" onClick={onClose} className="btn-secondary flex-1 text-sm">Cancel</button>
              <button type="submit" disabled={submitting || !!subnetError || !agentId || (agentId === 'auto' && route && !route.agent_id)}
                className="btn-primary flex-1 text-sm flex items-center justify-center gap-2 disabled:opacity-50">
                {submitting ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Wifi className="w-4 h-4" />}
                Start scan
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
