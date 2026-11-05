import { useEffect, useState } from 'react'
import client from '../../api/client'

// Live agent counts for the rail: polls /agents every 60 s while the tab is visible.
// Returns null until the first answer (or when the call is not allowed).
export default function useAgentPulse() {
  const [pulse, setPulse] = useState(null)

  useEffect(() => {
    let cancelled = false
    const load = () => {
      if (document.visibilityState === 'hidden') return
      client.get('/agents')
        .then((res) => {
          if (cancelled) return
          const list = res.data?.agents ?? []
          const active = list.filter((a) => a.status !== 'retired')
          setPulse({
            total: active.length,
            online: active.filter((a) => a.status === 'online').length,
            degraded: active.filter((a) => a.status === 'degraded').length,
            checkedAt: Date.now(),
          })
        })
        .catch(() => { if (!cancelled) setPulse(null) })
    }
    load()
    const timer = setInterval(load, 60_000)
    document.addEventListener('visibilitychange', load)
    return () => {
      cancelled = true
      clearInterval(timer)
      document.removeEventListener('visibilitychange', load)
    }
  }, [])

  return pulse
}
