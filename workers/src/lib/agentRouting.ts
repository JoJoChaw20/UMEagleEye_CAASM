// Which agent scans a network, and how well each network is covered by agents. PURE.
//
// Agents 2.5.1+ report the IPv4 networks they are directly on (their real adapters). An
// older agent reports only its own address: it is taken to be on the /24 around it, and
// the reason says so. A scan goes to an online agent with the Scanner role that is ON the
// target network (it sees MAC addresses; the most specific network wins, then an agent
// that is not busy, then the latest heartbeat). An agent off the network could scan it
// through a router (no MACs, slower, often filtered): only when the admin picks that agent
// (2026-11-07 decision). A range spanning several agents' networks is refused, with those
// networks listed, so each can be scanned by its own agent.

export interface RouteAgent {
  agent_id: string
  name: string
  online: boolean              // heartbeat in the last 2 minutes
  // the Agents page's rule (lib/agentLiveness.ts): 'degraded' = reporting late (2 to 10 minutes);
  // coverage counts a late agent, scans go only to an online one. Absent: from `online`.
  liveness?: 'online' | 'degraded' | 'offline'
  scanner: boolean | null      // effective policy; null = not reported (runs dashboard scans)
  passive: boolean | null
  networks: string[]           // reported by the agent (2.5.1+)
  local_ip: string | null      // its own address (every agent)
  busy: boolean                // an active scan pending or running for it
  last_heartbeat: string | null
}

export interface Cidr { net: number; prefix: number; text: string }

function ipToInt(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null
    n = n * 256 + Number(p)
  }
  return n >>> 0
}

const maskOf = (prefix: number) => (prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0)

export function parseCidr(value: string): Cidr | null {
  const [ip, len] = value.trim().split('/')
  const n = ipToInt(ip ?? '')
  const prefix = len === undefined ? 32 : Number(len)
  if (n === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null
  const net = (n & maskOf(prefix)) >>> 0
  return { net, prefix, text: `${[24, 16, 8, 0].map((s) => (net >>> s) & 255).join('.')}/${prefix}` }
}

/** outer holds all of inner. */
export function contains(outer: Cidr, inner: Cidr): boolean {
  return outer.prefix <= inner.prefix && ((inner.net & maskOf(outer.prefix)) >>> 0) === outer.net
}

/** The networks an agent is on, and whether they are guessed (older agent: its /24). */
export function agentNetworks(a: Pick<RouteAgent, 'networks' | 'local_ip'>): { nets: Cidr[]; guessed: boolean } {
  const nets = a.networks.map(parseCidr).filter((c): c is Cidr => c !== null && c.prefix >= 8 && c.prefix <= 30)
  if (nets.length) return { nets, guessed: false }
  const own = a.local_ip ? parseCidr(`${a.local_ip}/24`) : null
  return { nets: own ? [own] : [], guessed: own !== null }
}

export interface RouteDecision {
  agent_id: string | null
  name: string | null
  reason: string
  on_link: boolean
  networks?: string[]                                    // a range spanning these: scan them one by one
  routed?: { agent_id: string; name: string }[]         // may scan it through a router, if chosen
}

const byPreference = (x: { a: RouteAgent; prefix: number }, y: { a: RouteAgent; prefix: number }) =>
  (y.prefix - x.prefix) || (Number(x.a.busy) - Number(y.a.busy))
  || String(y.a.last_heartbeat ?? '').localeCompare(String(x.a.last_heartbeat ?? ''))

export function chooseAgent(target: string, agents: RouteAgent[]): RouteDecision {
  const t = parseCidr(target)
  if (!t) return { agent_id: null, name: null, reason: `${target} is not an IPv4 address or range`, on_link: false }
  const eligible = agents.filter((a) => a.online && a.scanner !== false)
  if (!eligible.length) {
    return { agent_id: null, name: null, on_link: false,
      reason: 'No online agent runs dashboard scans (an agent must be online with its Scanner role on).' }
  }
  const onLink: { a: RouteAgent; prefix: number; net: Cidr; guessed: boolean }[] = []
  const inside = new Set<string>()
  for (const a of eligible) {
    const { nets, guessed } = agentNetworks(a)
    for (const net of nets) {
      if (contains(net, t)) onLink.push({ a, prefix: net.prefix, net, guessed })
      else if (contains(t, net)) inside.add(net.text)
    }
  }
  if (onLink.length) {
    const best = onLink.sort(byPreference)[0]!
    const others = new Set(onLink.map((o) => o.a.agent_id)).size - 1
    return {
      agent_id: best.a.agent_id, name: best.a.name, on_link: true,
      reason: `${best.a.name} is on ${best.net.text}${best.guessed ? ' (taken from its address: it does not report its networks)' : ''}`
        + (best.a.busy ? '; it has a scan queued already' : '')
        + (others > 0 ? `; ${others} other agent${others > 1 ? 's are' : ' is'} on it too` : ''),
    }
  }
  if (inside.size) {
    const networks = [...inside].sort()
    return { agent_id: null, name: null, on_link: false, networks,
      reason: `${t.text} spans ${networks.length} networks with their own agents. Scan them one at a time: ${networks.join(', ')}.` }
  }
  return {
    agent_id: null, name: null, on_link: false,
    routed: eligible.map((a) => ({ agent_id: a.agent_id, name: a.name })),
    reason: `No online agent is on ${t.text}. Choose an agent to scan it through a router (slower, without MAC addresses, and firewalls may block it).`,
  }
}

// 'offline': agents are on it, but none has checked in for over 10 minutes (not the same as none).
// 'left': no agent is on it now, but one was (a laptop taken to another network): see withLeft.
export type CoverageState = 'covered' | 'scan_only' | 'listen_only' | 'offline' | 'left' | 'no_agent'
export interface AgentBrief { agent_id: string; name: string; late: boolean }
export interface NetworkCoverage {
  state: CoverageState
  sensors: AgentBrief[]                               // online or late, passive listening, on the network
  scanners: AgentBrief[]                              // online or late, Scanner role, on the network
  duplicate_sensors: boolean                          // more than one sensor: one can stop listening
  late: boolean                                       // every agent counted is reporting late
  offline: { agent_id: string; name: string; last_heartbeat: string | null }[]   // on it, not checking in
  left?: { agent_id: string; name: string; at: string; now_on: string | null }[]  // were on it, now elsewhere
}

const livenessOf = (a: RouteAgent) => a.liveness ?? (a.online ? 'online' : 'offline')

/**
 * How a network is covered by the agents on it. An agent reporting late still counts (a VM that
 * paused for a few minutes does not make its network "No agent"); one offline is listed apart.
 */
export function coverageOf(network: string, agents: RouteAgent[]): NetworkCoverage | null {
  const n = parseCidr(network)
  if (!n) return null
  const onIt = agents.filter((a) => agentNetworks(a).nets.some((net) => contains(net, n) || contains(n, net)))
  const counted = onIt.filter((a) => livenessOf(a) !== 'offline')
  const brief = (a: RouteAgent): AgentBrief => ({ agent_id: a.agent_id, name: a.name, late: livenessOf(a) === 'degraded' })
  const sensors = counted.filter((a) => a.passive === true).map(brief)
  const scanners = counted.filter((a) => a.scanner !== false).map(brief)
  const state: CoverageState = sensors.length && scanners.length ? 'covered' : scanners.length ? 'scan_only'
    : sensors.length ? 'listen_only' : onIt.length ? 'offline' : 'no_agent'
  return {
    state, sensors, scanners, duplicate_sensors: sensors.length > 1,
    late: counted.length > 0 && counted.every((a) => livenessOf(a) === 'degraded'),
    offline: onIt.filter((a) => livenessOf(a) === 'offline')
      .map((a) => ({ agent_id: a.agent_id, name: a.name, last_heartbeat: a.last_heartbeat })),
  }
}

/**
 * A network no agent is on now: the agents whose records are on it (Discovery's agent_ids, last at
 * `lastAt`) and which still exist are listed as having left it, with the network each is on now.
 */
export function withLeft(c: NetworkCoverage | null, agentIds: string[], lastAt: string, agents: RouteAgent[]): NetworkCoverage | null {
  if (!c || c.state !== 'no_agent') return c
  const left = agents.filter((a) => agentIds.includes(a.agent_id))
    .map((a) => ({ agent_id: a.agent_id, name: a.name, at: lastAt, now_on: agentNetworks(a).nets[0]?.text ?? null }))
  return left.length ? { ...c, state: 'left', left } : c
}

/** How many of these addresses are in the network. */
export function countIn(network: string, ips: string[]): number {
  const n = parseCidr(network)
  if (!n) return 0
  return ips.filter((ip) => {
    const c = parseCidr(ip)
    return c !== null && contains(n, c)
  }).length
}
