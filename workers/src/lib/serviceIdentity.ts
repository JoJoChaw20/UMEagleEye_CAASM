// Step 3, Part 3: vulnerable services seen from the network. Which product and version each open
// port runs (from its banner, with Recog: lib/recog.ts), and what the alert for a product says once
// NVD has listed its CVEs (services/serviceCves.ts). On a device with an SBOM only what the SBOM
// does not list counts (a container, a program installed by hand). Pure functions.
import { cpe23, recognize, type RecogDb } from './recog'

export interface ServiceEntry {
  port: number
  protocol?: string
  service?: string | null
  product?: string | null
  version?: string | null
  banner?: string | null
  facts?: { http?: { server?: string } } | null
}

export interface IdentifiedService {
  port: number
  vendor: string | null
  product: string
  family: string | null
  version: string | null
  cpe: string | null                  // CPE 2.3 with the version, for NVD; null when no version is known
  seen: string                        // the text it was recognised from
  distro: string | null               // e.g. "Ubuntu": the distribution may have backported fixes
}

const DISTRO = /\b(ubuntu|debian|deb\d+u\d+|el\d+(?:_\d+)?|centos|red ?hat|rhel|fedora|alpine|suse|raspbian|amzn\d*)\b/i

function source(e: ServiceEntry): { db: RecogDb; text: string } | null {
  const service = (e.service ?? '').toLowerCase()
  const banner = (e.banner ?? '').trim()
  if (/^SSH-\d/.test(banner) || service === 'ssh') {
    const text = banner.replace(/^SSH-[\d.]+-/, '').trim()
    return text ? { db: 'ssh', text } : null
  }
  const server = e.facts?.http?.server
  if (server) return { db: 'http_server', text: server }
  if (!banner) return null
  const reply = banner.replace(/^\d{3}[- ]/, '')
  if (service === 'ftp' || e.port === 21) return { db: 'ftp', text: reply }
  if (/smtp|submission/.test(service) || [25, 465, 587].includes(e.port)) return { db: 'smtp', text: reply }
  if (service === 'telnet' || e.port === 23) return { db: 'telnet', text: banner }
  return null
}

function fromRecog(port: number, seen: string, r: Record<string, string> | null): IdentifiedService | null {
  const product = r?.['service.product'] ?? r?.['os.product']
  if (!r || !product) return null
  const svc = !!r['service.product']
  const version = (svc ? r['service.version'] : r['os.version']) ?? null
  return {
    port, product, version,
    vendor: (svc ? r['service.vendor'] : r['os.vendor']) ?? null,
    family: (svc ? r['service.family'] : r['os.family']) ?? null,
    cpe: cpe23(svc ? r['service.cpe23'] : r['os.cpe23']),
    seen: seen.slice(0, 200),
    distro: DISTRO.exec(seen)?.[1] ?? null,
  }
}

/** What runs on each open TCP port (and, from the SNMP description, the device's own OS). */
export function identifyServices(services: unknown, snmpSysDescr?: string | null): IdentifiedService[] {
  const out: IdentifiedService[] = []
  for (const e of Array.isArray(services) ? services as ServiceEntry[] : []) {
    if (!e || !Number.isInteger(e.port) || (e.protocol ?? 'tcp') !== 'tcp') continue
    const src = source(e)
    const id = src ? fromRecog(e.port, src.text, recognize(src.db, src.text)) : null
    if (id) out.push(id)
  }
  if (snmpSysDescr) {
    const id = fromRecog(161, snmpSysDescr, recognize('snmp', snmpSysDescr))
    if (id) out.push(id)
  }
  return out
}

export interface SbomPackage { name: string; version: string }

const GENERIC = new Set(['server', 'http', 'software', 'project', 'the'])

/** The words a package of this product is named with ("openssh", "httpd", "apache"). */
export function sbomNames(s: Pick<IdentifiedService, 'product' | 'family'>): string[] {
  return [...new Set(`${s.product} ${s.family ?? ''}`.toLowerCase().split(/[^a-z0-9]+/)
    .filter((t) => t.length >= 3 && !GENERIC.has(t)))]
}

/** Whether a device's SBOM lists this product at this version (Grype then checks it, with the
 *  distribution's fixes): a package named after the product ("openssh-server", "apache2" for Apache
 *  HTTPD) whose version starts with the banner's ("1:10.2p1-2ubuntu3.8" for 10.2p1). When it does
 *  not, the port is served by something the package list misses: a container, a program installed
 *  by hand. */
export function inSbom(s: Pick<IdentifiedService, 'product' | 'family' | 'version'>, packages: SbomPackage[]): boolean {
  const names = sbomNames(s)
  const v = s.version?.toLowerCase()
  return packages.some((p) => {
    if (!names.some((t) => p.name.toLowerCase().includes(t))) return false
    if (!v) return true
    const pv = p.version.toLowerCase().replace(/^\d+:/, '')
    return pv.startsWith(v) && !/\d/.test(pv.charAt(v.length))
  })
}

/** The key of one product on one device: an alert per product, whatever its version. */
export const productKey = (s: Pick<IdentifiedService, 'vendor' | 'product'>) =>
  `${(s.vendor ?? '').toLowerCase()}:${s.product.toLowerCase()}`

export interface CveRef { id: string; cvss: number | null; kev?: boolean }
export type Severity = 'low' | 'medium' | 'high' | 'critical'
const LEVELS: Severity[] = ['low', 'medium', 'high', 'critical']

export interface ServiceFinding {
  key: string
  severity: Severity
  details: Record<string, unknown>
}

/** The alert for one identified product with its CVEs (null: no CVE, nothing to say). Severity: the
 *  worst CVSS; at least high when one is exploited in the wild (CISA KEV); one level lower when the
 *  banner names a distribution (it may have backported the fixes), one higher when internet-facing. */
export function serviceFinding(s: IdentifiedService, cves: CveRef[], internetFacing: boolean): ServiceFinding | null {
  if (!cves.length) return null
  const sorted = [...cves].sort((a, b) => Number(!!b.kev) - Number(!!a.kev) || (b.cvss ?? 0) - (a.cvss ?? 0))
  const max = Math.max(...cves.map((c) => c.cvss ?? 0))
  const kev = cves.filter((c) => c.kev).length
  let i = max >= 9 ? 3 : max >= 7 ? 2 : max >= 4 ? 1 : 0
  if (kev) i = Math.max(i, 2)
  if (s.distro) i -= 1
  if (internetFacing) i += 1
  const severity = LEVELS[Math.max(0, Math.min(3, i))]!
  return {
    key: productKey(s),
    severity,
    details: {
      source: 'network', confidence: 'banner', key: productKey(s),
      product: s.product, vendor: s.vendor, version: s.version, cpe: s.cpe, port: s.port, seen: s.seen,
      distro: s.distro, cve_count: cves.length, max_cvss: max || null, kev_count: kev,
      cves: sorted.slice(0, 25).map((c) => ({ id: c.id, cvss: c.cvss, ...(c.kev ? { kev: true } : {}) })),
    },
  }
}

export interface OpenServiceAlert { eventId: string; status: string; key: string }

export interface ServicePlan {
  create: ServiceFinding[]
  refresh: { eventId: string; finding: ServiceFinding; reopen: boolean }[]
  resolve: { eventId: string; why: string }[]
}

/** What answers on an open alert's own port now: the same product at the version the device's SBOM
 *  lists ('sbom'), the same product at a version without CVEs ('no_cve'), or neither (null). */
export type OnAlertPort = 'sbom' | 'no_cve' | null

/** A device's vulnerable-service alerts after a scan: one per product. One closes when its port now
 *  runs a version without CVEs, or the version the SBOM lists (its CVEs come from the package list),
 *  or when the scan checked its port and the product is gone. Always judged on the alert's own port:
 *  the packaged nginx on 80 says nothing about the container's nginx on 8000. `findings` are only the
 *  products the SBOM does not cover. */
export function planServices(findings: ServiceFinding[], existing: OpenServiceAlert[],
  opts: { onAlertPort: (key: string) => OnAlertPort; checkedPortsOf: (key: string) => boolean }): ServicePlan {
  const plan: ServicePlan = { create: [], refresh: [], resolve: [] }
  const live = (s: string) => s === 'open' || s === 'in_progress'
  const byKey = new Map(existing.map((e) => [e.key, e]))
  const found = new Set<string>()
  for (const f of findings) {
    found.add(f.key)
    const e = byKey.get(f.key)
    if (!e) plan.create.push(f)
    else if (e.status === 'false_positive' || e.status === 'accepted_risk') continue
    else plan.refresh.push({ eventId: e.eventId, finding: f, reopen: e.status === 'resolved' })
  }
  for (const e of existing) {
    if (!live(e.status) || found.has(e.key)) continue
    const now = opts.onAlertPort(e.key)
    if (now === 'sbom') plan.resolve.push({ eventId: e.eventId, why: "The version now running is the one in this device's SBOM, whose CVEs come from its package list." })
    else if (now === 'no_cve') plan.resolve.push({ eventId: e.eventId, why: 'The version now running has no known CVE.' })
    else if (opts.checkedPortsOf(e.key)) plan.resolve.push({ eventId: e.eventId, why: 'No longer seen: an active scan checked the port and the product is gone.' })
  }
  return plan
}
