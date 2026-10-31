import { useEffect, useMemo, useState } from 'react'
import { X, Wifi } from 'lucide-react'

// A full (active) scan, run by one agent. Passive listening needs no scan: agents listen
// all the time. The range starts as the network the chosen agent was last on.

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

export default function NewScanModal({ agents, networks, initial, onClose, onSubmit }) {
  const online = agents.filter((a) => a.status === 'online')
  // The network each agent was last on (networks are newest first)
  const lastNetwork = useMemo(() => {
    const out = {}
    for (const n of networks) for (const id of n.agent_ids) if (!out[id]) out[id] = n.subnet
    return out
  }, [networks])

  const [agentId, setAgentId] = useState(initial?.agentId ?? online[0]?.agent_id ?? '')
  const [subnet, setSubnet] = useState(initial?.subnet ?? (online[0] ? lastNetwork[online[0].agent_id] ?? '' : ''))
  const [touched, setTouched] = useState(!!initial?.subnet)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  // Follow the chosen agent's network until the range is edited by hand
  useEffect(() => { if (!touched && agentId) setSubnet(lastNetwork[agentId] ?? '') }, [agentId, touched, lastNetwork])
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const subnetError = validateSubnet(subnet)
  const agent = agents.find((a) => a.agent_id === agentId)

  const submit = async (e) => {
    e.preventDefault()
    if (subnetError || !agentId) return
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-labelledby="new-scan-title" className="glass-card w-full max-w-md p-6 space-y-4" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h2 id="new-scan-title" className="text-lg font-semibold text-white">New full scan</h2>
          <button onClick={onClose} className="text-dark-400 hover:text-white" title="Close"><X className="w-5 h-5" /></button>
        </div>

        {error && <p className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg p-3">{error}</p>}

        {online.length === 0 ? (
          <p className="text-sm text-dark-300">No agent is online. Start the EagleEye agent on a computer in the network you want to scan.</p>
        ) : (
          <form onSubmit={submit} className="space-y-4">
            <div>
              <label htmlFor="scan-agent" className="block text-xs text-dark-400 mb-1">Agent that runs it</label>
              <select id="scan-agent" value={agentId} onChange={(e) => setAgentId(e.target.value)} className="input-field w-full text-sm">
                {agents.map((a) => (
                  <option key={a.agent_id} value={a.agent_id} disabled={a.status !== 'online'}>
                    {a.name}{a.status !== 'online' ? ` (${a.status})` : lastNetwork[a.agent_id] ? ` · on ${lastNetwork[a.agent_id]}` : ''}
                  </option>
                ))}
              </select>
              <p className="text-[11px] text-dark-500 mt-1">The agent can only reach networks its computer is connected to.</p>
            </div>
            <div>
              <label htmlFor="scan-range" className="block text-xs text-dark-400 mb-1">Range or address</label>
              <input id="scan-range" type="text" value={subnet} onChange={(e) => { setSubnet(e.target.value); setTouched(true) }}
                placeholder="192.168.1.0/24" className={`input-field w-full text-sm font-mono ${subnet && subnetError ? 'border-red-500/60' : ''}`} />
              {subnet && subnetError && <p className="text-xs text-red-400 mt-1">{subnetError}</p>}
              {agent && lastNetwork[agentId] && subnet.trim() !== lastNetwork[agentId] && (
                <button type="button" onClick={() => { setSubnet(lastNetwork[agentId]); setTouched(false) }} className="text-[11px] text-eagle-400 hover:underline mt-1">
                  Use {agent.name}'s network ({lastNetwork[agentId]})
                </button>
              )}
            </div>
            <div className="flex gap-3 pt-1">
              <button type="button" onClick={onClose} className="btn-secondary flex-1 text-sm">Cancel</button>
              <button type="submit" disabled={submitting || !!subnetError || !agentId}
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
