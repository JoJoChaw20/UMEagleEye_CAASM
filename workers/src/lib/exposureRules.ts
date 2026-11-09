// Exposure rules (step 3, Part 2): risky configurations an active scan sees on a device NOW, as
// standing alerts. A port-opened alert says what changed; an exposure says what is wrong, for as
// long as it is wrong, also on a device that has had it since its first scan. Pure functions: the
// database side is services/exposure.ts.
//
// Evidence comes from each port entry of the agent's own engine (agent 2.6+ adds `facts`: TLS,
// HTTP, SMB, RDP, auth). Ports from older agents or Nmap have no facts: the port-only rules apply.

export type Severity = 'low' | 'medium' | 'high' | 'critical'
const LEVELS: Severity[] = ['low', 'medium', 'high', 'critical']

export interface PortFacts {
  tls?: { version?: string; not_before?: string; not_after?: string; self_signed?: boolean; subject_cn?: string }
  http?: { status?: number; server?: string; title?: string; realm?: string }
  smb?: { dialect?: string; signing_required?: boolean }
  rdp?: { security?: string; nla_required?: boolean }
  auth?: 'none' | 'required'
}

export interface PortEntry {
  port: number
  protocol?: string
  service?: string
  product?: string
  version?: string
  facts?: PortFacts
}

export interface DeviceContext {
  internetFacing: boolean
  criticality: number | null          // 1-10
  deviceType: string | null
  osName?: string | null
  now: Date
}

export type RuleId =
  | 'telnet' | 'ftp_cleartext' | 'http_login_cleartext' | 'db_no_auth' | 'smb_signing_off'
  | 'rdp_no_nla' | 'rdp_internet' | 'vnc' | 'internet_admin_port' | 'tls_expired' | 'tls_expiring'

export interface RuleMeta { title: string; base: Severity; fix: string }

export const RULES: Record<RuleId, RuleMeta> = {
  telnet: { title: 'Telnet open', base: 'high',
    fix: 'Turn Telnet off and manage the device over SSH; Telnet sends passwords in clear text.' },
  ftp_cleartext: { title: 'FTP without encryption', base: 'medium',
    fix: 'Use SFTP or FTPS, or turn FTP off; FTP sends passwords and files in clear text.' },
  http_login_cleartext: { title: 'Login page without HTTPS', base: 'medium',
    fix: 'Serve the login over HTTPS (or redirect HTTP to HTTPS); passwords typed here cross the network in clear text.' },
  db_no_auth: { title: 'Database answers without a password', base: 'critical',
    fix: 'Require a password (Redis: requirepass / ACL users) and bind it to the addresses that need it.' },
  smb_signing_off: { title: 'SMB signing not required (server)', base: 'medium',
    fix: 'Require SMB signing on this server (Group Policy: "Microsoft network server: Digitally sign communications (always)"); unsigned SMB allows NTLM relay.' },
  rdp_no_nla: { title: 'RDP without Network Level Authentication', base: 'high',
    fix: 'Require Network Level Authentication for Remote Desktop, so the login screen is not offered before the user authenticates.' },
  rdp_internet: { title: 'RDP reachable from the internet', base: 'critical',
    fix: 'Do not expose Remote Desktop to the internet: put it behind a VPN or a Remote Desktop Gateway with MFA.' },
  vnc: { title: 'VNC open', base: 'high',
    fix: 'Turn VNC off or reach it only through a VPN or SSH tunnel; VNC is often weakly protected and unencrypted.' },
  internet_admin_port: { title: 'Database or admin service reachable from the internet', base: 'high',
    fix: 'Close this port to the internet (firewall), and reach the service through a VPN.' },
  tls_expired: { title: 'TLS certificate expired', base: 'medium',
    fix: 'Renew the certificate; clients either warn users (who learn to click through) or refuse to connect.' },
  tls_expiring: { title: 'TLS certificate expires within 30 days', base: 'low',
    fix: 'Renew the certificate before it expires.' },
}

// Ports whose exposure rule needs no facts: their port-opened alert is folded into the exposure (drift).
export const ALWAYS_EXPOSED_PORTS = new Set([21, 23, 5900, 5901, 5902, 5903])
const VNC_PORTS = new Set([5900, 5901, 5902, 5903])
// Reachable from the internet, each is an exposure on its own (RDP has its own rule).
const ADMIN_PORTS: Record<number, string> = {
  22: 'SSH', 445: 'SMB', 139: 'NetBIOS', 135: 'MS-RPC', 1433: 'MS SQL', 1521: 'Oracle', 3306: 'MySQL',
  5432: 'PostgreSQL', 5985: 'WinRM', 5986: 'WinRM (TLS)', 6379: 'Redis', 9200: 'Elasticsearch',
  11211: 'Memcached', 27017: 'MongoDB', 2375: 'Docker API', 2379: 'etcd', 10250: 'Kubelet',
}
const LOGIN_HINT = /\b(log ?in|sign ?in|logon|password|admin(istrator)?|authenticat)/i
const TLS_SERVICES = /(^|-)(https|ssl|tls)|imaps|pop3s|smtps|ldaps|ftps/i

export interface ExposureFinding {
  rule: RuleId
  port: number
  severity: Severity
  title: string
  fix: string
  evidence: Record<string, unknown>
}

/** Severity with the device's weight: one level up when it faces the internet, one more when its
 *  criticality is 8 or higher; never above critical. */
export function weighted(base: Severity, ctx: Pick<DeviceContext, 'internetFacing' | 'criticality'>): Severity {
  let i = LEVELS.indexOf(base)
  if (ctx.internetFacing) i++
  if ((ctx.criticality ?? 0) >= 8) i++
  return LEVELS[Math.min(i, LEVELS.length - 1)]!
}

const isServer = (ctx: DeviceContext) =>
  ctx.deviceType === 'server' || /server|domain controller/i.test(ctx.osName ?? '')

function entries(ports: unknown): PortEntry[] {
  if (!Array.isArray(ports)) return []
  return ports.filter((p): p is PortEntry => !!p && typeof p === 'object' && Number.isInteger((p as PortEntry).port))
    .filter((p) => (p.protocol ?? 'tcp') === 'tcp')
}

/** The exposures of one device, from the ports its last active scan saw. */
export function exposuresOf(ports: unknown, ctx: DeviceContext): ExposureFinding[] {
  const out: ExposureFinding[] = []
  const add = (rule: RuleId, p: PortEntry, evidence: Record<string, unknown>) => {
    const meta = RULES[rule]
    out.push({ rule, port: p.port, severity: weighted(meta.base, ctx), title: meta.title, fix: meta.fix,
      evidence: { port: p.port, service: p.service || null, product: p.product || null, version: p.version || null, ...evidence } })
  }
  for (const p of entries(ports)) {
    const service = (p.service ?? '').toLowerCase()
    const f = p.facts ?? {}
    const tls = !!f.tls || TLS_SERVICES.test(service)
    if (p.port === 23 || service === 'telnet') add('telnet', p, {})
    if ((p.port === 21 || service === 'ftp') && !tls) add('ftp_cleartext', p, {})
    if (VNC_PORTS.has(p.port) || service.startsWith('vnc')) add('vnc', p, {})
    if (f.http && !tls && (f.http.status === 401 || f.http.realm || LOGIN_HINT.test(f.http.title ?? ''))) {
      add('http_login_cleartext', p, { http_status: f.http.status ?? null, realm: f.http.realm ?? null, title: f.http.title ?? null })
    }
    if (f.auth === 'none') add('db_no_auth', p, { checked: 'a read-only query was answered without a password' })
    if (f.smb?.signing_required === false && isServer(ctx)) add('smb_signing_off', p, { dialect: f.smb.dialect ?? null })
    // classic RDP security, or TLS chosen although NLA (CredSSP) was offered: no NLA either way
    if (f.rdp && (f.rdp.security === 'rdp' || f.rdp.security === 'tls' || f.rdp.nla_required === false)) {
      add('rdp_no_nla', p, { security: f.rdp.security ?? null })
    }
    if (ctx.internetFacing && (p.port === 3389 || service === 'ms-wbt-server')) add('rdp_internet', p, {})
    else if (ctx.internetFacing && ADMIN_PORTS[p.port]) add('internet_admin_port', p, { what: ADMIN_PORTS[p.port] })
    const notAfter = f.tls?.not_after ? new Date(f.tls.not_after) : null
    if (notAfter && !isNaN(notAfter.getTime())) {
      const days = Math.floor((notAfter.getTime() - ctx.now.getTime()) / 86_400_000)
      const cert = { not_after: f.tls!.not_after, subject: f.tls!.subject_cn ?? null, days_left: days }
      if (days < 0) add('tls_expired', p, cert)
      else if (days <= 30) add('tls_expiring', p, cert)
    }
  }
  // SMB signing belongs to the device, not the port: one alert (on 445, else the first), not one
  // per SMB port (Samba on the lab VM answered on 139 and 445).
  const smb = out.filter((f) => f.rule === 'smb_signing_off')
  if (smb.length > 1) {
    const keep = smb.find((f) => f.port === 445) ?? smb[0]!
    return out.filter((f) => f.rule !== 'smb_signing_off' || f === keep)
  }
  return out
}

export const exposureKey = (rule: string, port: number) => `${rule}:${port}`

const str = (v: unknown, max: number) => (typeof v === 'string' && v ? v.slice(0, max) : undefined)
const bool = (v: unknown) => (typeof v === 'boolean' ? v : undefined)
const drop = <T extends object>(o: T): T | undefined => {
  const kept = Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T
  return Object.keys(kept).length ? kept : undefined
}

/** An agent's `facts` of one port, kept to the fields the rules and the asset page use, size-capped
 *  (they come from devices on the network: any text there is the device's own). */
export function cleanFacts(raw: unknown): PortFacts | undefined {
  if (!raw || typeof raw !== 'object') return undefined
  const r = raw as Record<string, Record<string, unknown> | unknown>
  const o = (k: string) => (r[k] && typeof r[k] === 'object' ? r[k] as Record<string, unknown> : null)
  const tls = o('tls'), http = o('http'), smb = o('smb'), rdp = o('rdp')
  return drop({
    tls: tls ? drop({ version: str(tls.version, 16), not_before: str(tls.not_before, 32), not_after: str(tls.not_after, 32),
      self_signed: bool(tls.self_signed), subject_cn: str(tls.subject_cn, 120) }) ?? {} : undefined,
    http: http ? drop({ status: Number.isInteger(http.status) ? http.status as number : undefined, server: str(http.server, 120),
      title: str(http.title, 100), realm: str(http.realm, 80) }) : undefined,
    smb: smb ? drop({ dialect: str(smb.dialect, 24), signing_required: bool(smb.signing_required) }) : undefined,
    rdp: rdp ? drop({ security: str(rdp.security, 16), nla_required: bool(rdp.nla_required) }) : undefined,
    auth: r.auth === 'none' || r.auth === 'required' ? r.auth : undefined,
  } as PortFacts)
}

export interface OpenExposure {
  eventId: string
  status: string                     // open | in_progress | resolved | false_positive | accepted_risk
  rule: string
  port: number
}

export interface ExposurePlan {
  create: ExposureFinding[]
  refresh: { eventId: string; finding: ExposureFinding; reopen: boolean }[]
  resolve: string[]                  // event ids
}

/** What one active scan of a device does to its exposure alerts. `scannedPorts`: the ports the scan
 *  checked (agent 2.6+); an alert closes only when its port was checked and the problem is gone.
 *  Without the list (older agents, Nmap) nothing closes by absence. False positives and accepted
 *  risks are left as they are. */
export function planExposure(findings: ExposureFinding[], existing: OpenExposure[],
  scannedPorts: Set<number> | null): ExposurePlan {
  const plan: ExposurePlan = { create: [], refresh: [], resolve: [] }
  // One alert per device, rule and port. Should there be two (assets merged), the open one is kept
  // and the other closes; otherwise it would stay open, never refreshed.
  const live = (s: string) => s === 'open' || s === 'in_progress'
  const byKey = new Map<string, OpenExposure>()
  for (const e of existing) {
    const key = exposureKey(e.rule, e.port)
    const kept = byKey.get(key)
    if (!kept || (!live(kept.status) && live(e.status))) {
      if (kept && live(kept.status)) plan.resolve.push(kept.eventId)
      byKey.set(key, e)
    } else if (live(e.status)) plan.resolve.push(e.eventId)
  }
  const seen = new Set<string>()
  for (const f of findings) {
    const key = exposureKey(f.rule, f.port)
    if (seen.has(key)) continue
    seen.add(key)
    const e = byKey.get(key)
    if (!e) plan.create.push(f)
    else if (e.status === 'false_positive' || e.status === 'accepted_risk') continue
    else plan.refresh.push({ eventId: e.eventId, finding: f, reopen: e.status === 'resolved' })
  }
  for (const e of byKey.values()) {
    if (seen.has(exposureKey(e.rule, e.port))) continue
    if (live(e.status) && scannedPorts?.has(e.port)) plan.resolve.push(e.eventId)
  }
  return plan
}
