// What the internet sees on the organisation's public addresses (D4 step 3), from Shodan InternetDB:
// the open ports, the products Shodan recognised (CPE), hostnames, tags and the CVEs it guesses. An
// address marked as the organisation's own gets an exposure alert for each risky port open to the
// internet; Shodan's CVEs are shown, never alerted on (its own docs say they include unverified ones).
// Pure; the database and fetching side is services/internetView.ts.
import { RISKY_PORTS } from './exposure'

export const INTERNETDB_URL = 'https://internetdb.shodan.io/'
// InternetDB is rebuilt weekly: an address is asked again after this long
export const RECHECK_MS = 7 * 86_400_000
// At most this many addresses per run (each is a subrequest of the run)
export const PER_RUN = 20
export const INTERNET_RULE = 'internet_view'

export interface InternetView {
  found: boolean              // false: InternetDB has nothing on the address (HTTP 404)
  ports: number[]
  cpes: string[]
  hostnames: string[]
  tags: string[]
  vulns: string[]
}

const strings = (v: unknown, max: number, len = 120): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').map((x) => x.slice(0, len)).slice(0, max) : []

/** InternetDB's answer for one IP, cleaned; null when it is not one. */
export function parseInternetDb(body: unknown): InternetView | null {
  if (!body || typeof body !== 'object') return null
  const b = body as Record<string, unknown>
  if (!Array.isArray(b.ports)) return null
  const ports = [...new Set(b.ports.filter((p): p is number => Number.isInteger(p) && p > 0 && p < 65536))].sort((x, y) => x - y)
  return {
    found: true, ports: ports.slice(0, 200), cpes: strings(b.cpes, 50), hostnames: strings(b.hostnames, 20, 253),
    tags: strings(b.tags, 20, 40), vulns: strings(b.vulns, 200, 30).filter((v) => /^CVE-\d{4}-\d+$/i.test(v)),
  }
}

export const NOTHING: InternetView = { found: false, ports: [], cpes: [], hostnames: [], tags: [], vulns: [] }

// Management and remote-access ports that should not face the internet, beyond RISKY_PORTS (lib/exposure.ts:
// Telnet, FTP, SMB, RDP, VNC, databases, container APIs...).
const ADMIN_EXTRA: Record<number, string> = {
  22: 'SSH', 2222: 'SSH', 7547: 'Router management (TR-069)', 8291: 'MikroTik Winbox', 10000: 'Webmin',
  5985: 'WinRM', 5986: 'WinRM (TLS)', 623: 'IPMI', 1723: 'PPTP VPN', 9100: 'Printer (raw)',
}

/** Every port that raises an alert when open to the internet (the Network page marks them). */
export const ALERT_PORTS: number[] = [...new Set([...Object.keys(RISKY_PORTS), ...Object.keys(ADMIN_EXTRA)].map(Number))].sort((a, b) => a - b)

export type Severity = 'low' | 'medium' | 'high' | 'critical'
export interface InternetFinding { port: number; service: string; severity: Severity; title: string; fix: string }

/** The alerts an address's open ports deserve: risky services critical, other management ports high.
 *  Web, mail and VPN ports are expected on an internet address and raise nothing. */
export function internetFindings(view: InternetView): InternetFinding[] {
  const out: InternetFinding[] = []
  for (const port of view.ports) {
    const risky = RISKY_PORTS[port]
    const admin = ADMIN_EXTRA[port]
    if (!risky && !admin) continue
    const service = risky ?? admin!
    out.push({
      port, service, severity: risky ? 'critical' : 'high', title: `${service} open to the internet`,
      fix: `Close port ${port} on the firewall or router (remove the port-forward), or limit it to known addresses; reach ${service} through a VPN instead.`,
    })
  }
  return out
}

export interface InternetWant { assetId: string; port: number; finding: InternetFinding; details: Record<string, unknown> }
export interface InternetHave { eventId: string; assetId: string; port: number; status: string; severity: string }
export interface InternetPlan {
  create: InternetWant[]
  refresh: { eventId: string; want: InternetWant; reopen: boolean }[]
  resolve: string[]
}

/** One exposure alert per (asset, port). Ports Shodan no longer sees close; decisions stay closed. */
export function planInternetAlerts(want: readonly InternetWant[], have: readonly InternetHave[]): InternetPlan {
  const plan: InternetPlan = { create: [], refresh: [], resolve: [] }
  const key = (a: string, p: number) => `${a}|${p}`
  const wanted = new Map(want.map((w) => [key(w.assetId, w.port), w]))
  const seen = new Set<string>()
  for (const h of have) {
    const k = key(h.assetId, h.port)
    if (seen.has(k)) {
      if (h.status === 'open' || h.status === 'in_progress') plan.resolve.push(h.eventId)   // a duplicate
      continue
    }
    seen.add(k)
    if (h.status === 'false_positive' || h.status === 'accepted_risk') continue
    const w = wanted.get(k)
    if (!w) {
      if (h.status === 'open' || h.status === 'in_progress') plan.resolve.push(h.eventId)
      continue
    }
    plan.refresh.push({ eventId: h.eventId, want: w, reopen: h.status === 'resolved' })
  }
  for (const [k, w] of wanted) if (!seen.has(k)) plan.create.push(w)
  return plan
}

/** The alert's details, shaped like the scan-based exposures (rule, port, title, fix, evidence). */
export function internetDetails(f: InternetFinding, ip: string, publicAddressId: string, checkedAt: string, view: InternetView): Record<string, unknown> {
  const cpes = view.cpes.slice(0, 5)
  return {
    rule: INTERNET_RULE, port: f.port, title: f.title, fix: f.fix,
    evidence: { port: f.port, service: f.service, public_ip: ip, public_address_id: publicAddressId, source: 'Shodan InternetDB', checked_at: checkedAt, cpes },
  }
}
