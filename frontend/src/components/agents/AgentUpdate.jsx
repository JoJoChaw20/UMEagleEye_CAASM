// The agent's build and updates from the dashboard (workers/src/lib/agentUpdate.ts, POST /agents/:id/update).
// The agent checks that the package is signed by the project before installing it (agent-gui/eagleeye/update).
import { useCallback, useEffect, useState } from 'react'
import { ArrowUpCircle, CheckCircle2, Loader2, XCircle } from 'lucide-react'
import client from '../../api/client'
import { useAuth } from '../../context/AuthContext'
import { requiresTitle } from '../../utils/actions'

// 0.1.0+20261123T050648Z.91bc695 → "23 Nov 2026, 05:06 UTC (91bc695)"
export function buildLabel(build) {
  if (!build) return null
  if (build === 'dev') return 'development copy'
  const m = /\+(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})\d{2}Z(?:\.([0-9a-f]+))?$/.exec(build)
  if (!m) return build
  const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]))
  return `${d.toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })}${m[6] ? ` (${m[6]})` : ''}`
}

export default function AgentUpdate({ agent, onUpdated }) {
  const { can, catalog } = useAuth()
  const [detail, setDetail] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const load = useCallback(async () => {
    try { setDetail((await client.get(`/agents/${agent.agent_id}`)).data) } catch { /* the list's data is enough */ }
  }, [agent.agent_id])
  useEffect(() => { load() }, [load])
  const a = detail ?? agent
  const last = detail?.last_update
  const running = last && (last.status === 'pending' || last.status === 'running')
  useEffect(() => {                                    // follow an update until the new build checks in
    if (!running) return undefined
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [running, load])

  const start = async () => {
    setBusy(true); setError(null)
    try {
      await client.post(`/agents/${agent.agent_id}/update`)
      await load()
      onUpdated?.()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Could not start the update')
    } finally { setBusy(false) }
  }

  const u = a.update
  const canUpdate = can('agent.update')
  return (
    <div className="rounded-lg border border-dark-700/60 p-4 space-y-2 text-sm">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <p className="text-dark-400 text-xs">Build</p>
          <p className="text-dark-100">{buildLabel(a.build) ?? <span className="text-dark-500">not reported (older than dashboard updates)</span>}</p>
        </div>
        {u?.state === 'available' && !running && (
          <button onClick={start} disabled={busy || !canUpdate} title={canUpdate ? `Install build ${buildLabel(u.latest)}` : requiresTitle('agent.update', catalog)}
            className="btn-primary text-sm inline-flex items-center gap-1.5 disabled:opacity-50">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowUpCircle className="w-4 h-4" />} Update agent
          </button>
        )}
        {u?.state === 'current' && <span className="text-xs text-green-400 inline-flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5" /> Newest build</span>}
      </div>
      {u?.state === 'available' && !running && <p className="text-xs text-amber-300">A newer build is published: {buildLabel(u.latest)}.</p>}
      {u?.state === 'manual' && <p className="text-xs text-dark-400">{u.reason}.</p>}
      {running && (
        <p className="text-xs text-eagle-300 inline-flex items-center gap-1.5">
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
          {last.status === 'pending' ? 'Waiting for the agent to pick up the update' : 'Installing: the agent restarts and checks in with the new build'}
          {last.build ? ` (${buildLabel(last.build)})` : ''}
        </p>
      )}
      {last && last.status === 'completed' && !running && (
        <p className="text-xs text-dark-400 inline-flex items-center gap-1.5"><CheckCircle2 className="w-3.5 h-3.5 text-green-400" /> Last update installed {new Date(last.completed_at).toLocaleString()}.</p>
      )}
      {last && last.status === 'failed' && (
        <p className="text-xs text-red-300 inline-flex items-start gap-1.5"><XCircle className="w-3.5 h-3.5 mt-0.5 shrink-0" /> Last update failed: {last.failure_reason}</p>
      )}
      {error && <p className="text-xs text-red-300">{error}</p>}
      <p className="text-[11px] text-dark-500">The agent installs only packages signed by the UMEagleEye project, and never an older build.</p>
    </div>
  )
}
