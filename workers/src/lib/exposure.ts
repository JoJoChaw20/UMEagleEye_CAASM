// Services that are routinely abused when exposed: clear-text admin protocols,
// remote desktop, file sharing, and databases/caches that ship without auth.
// Used to score new-port drift and to build the dashboard exposure panel.
export const RISKY_PORTS: Record<number, string> = {
  21:    'FTP',
  23:    'Telnet',
  135:   'MS-RPC',
  139:   'NetBIOS',
  161:   'SNMP',
  445:   'SMB',
  1433:  'MS SQL',
  2375:  'Docker API',
  3306:  'MySQL',
  3389:  'RDP',
  5432:  'PostgreSQL',
  5900:  'VNC',
  6379:  'Redis',
  9200:  'Elasticsearch',
  11211: 'Memcached',
  27017: 'MongoDB',
}

export function isRiskyPort(port: number): boolean {
  return port in RISKY_PORTS
}

// Severity for a port that appeared since the baseline.
// Risky service → high, or critical when the host is internet-facing.
// Other well-known ports → medium; ephemeral/high ports → low.
export function newPortSeverity(port: number, internetFacing: boolean): 'low' | 'medium' | 'high' | 'critical' {
  if (isRiskyPort(port)) return internetFacing ? 'critical' : 'high'
  if (port < 1024) return internetFacing ? 'high' : 'medium'
  return internetFacing ? 'medium' : 'low'
}

// Numeric-aware version comparison ("10.0" > "9.4", "1.2.10" > "1.2.9").
// Returns <0, 0, >0. Non-numeric segments fall back to string order.
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.\-+_:~]/)
  const pb = b.split(/[.\-+_:~]/)
  const len = Math.max(pa.length, pb.length)
  for (let i = 0; i < len; i++) {
    const x = pa[i] ?? '0'
    const y = pb[i] ?? '0'
    const nx = /^\d+$/.test(x) ? parseInt(x, 10) : NaN
    const ny = /^\d+$/.test(y) ? parseInt(y, 10) : NaN
    if (!isNaN(nx) && !isNaN(ny)) {
      if (nx !== ny) return nx - ny
    } else if (x !== y) {
      return x < y ? -1 : 1
    }
  }
  return 0
}

export function isIPv4(v: string | null | undefined): v is string {
  if (!v || !/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || v === '0.0.0.0') return false
  return v.split('.').every(o => Number(o) <= 255)
}

// Internet exposure: an analyst override always wins; otherwise the host is treated
// as exposed only when it is the agent's reported gateway (real evidence). The old
// ".1 / .254" positional fallback was removed — it was the same kind of guess that
// made ordinary hosts look like gateways and fed the +2 criticality term. With no
// override and no reported gateway we now say "not exposed" rather than guess.
export function resolveInternetFacing(ip: string, agentGatewayIp: string | null | undefined, override: boolean | null | undefined): boolean {
  if (override !== null && override !== undefined) return override
  if (agentGatewayIp) return ip === agentGatewayIp
  return false
}
