// Whether an agent is online, late or offline, by how long ago it last checked in. A computer's
// agent and the network agent send a heartbeat every 30 seconds; a phone (the Android agent) only
// every 15 minutes, about every 25 while it dozes (Galaxy A14, 9 Nov) and later still overnight, so it is online for 35 minutes after a check-in and only offline after 6 hours.
// One rule for the Agents page, the dashboard, notifications and the asset page's jobs.

export type Liveness = 'online' | 'degraded' | 'offline'

/** Minutes since the last heartbeat within which an agent of this kind is online / still only late. */
export function livenessMinutes(kind: string | null | undefined): { online: number; late: number } {
  return kind === 'mobile' ? { online: 35, late: 360 } : { online: 2, late: 10 }
}

export function agentLiveness(lastHeartbeat: Date | string | null, kind: string | null | undefined, now = Date.now()): Liveness {
  if (!lastHeartbeat) return 'offline'
  const minutes = (now - new Date(lastHeartbeat).getTime()) / 60_000
  const m = livenessMinutes(kind)
  return minutes < m.online ? 'online' : minutes < m.late ? 'degraded' : 'offline'
}
