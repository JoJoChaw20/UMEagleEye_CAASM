/**
 * Criticality v2 (1–10): how IMPORTANT an asset is, if it were compromised.
 *
 * Differences from v1 (lib/criticality.ts, kept unchanged for comparison/rollback):
 *  - Importance only. "No owner" is a governance gap, not importance, so it no longer
 *    adds a point. Weakness (patches, antivirus, encryption) lives in the separate
 *    endpoint posture score (lib/endpointPosture.ts) and never changes this score.
 *  - Every factor says where it came from (agent, analyst, scan, hostname), and the
 *    result carries a confidence, so "Server (confirmed by agent)" and "server
 *    (inferred from ports)" are not presented as the same certainty.
 *  - A directory service (domain controller) counts as a role: from the agent's
 *    reported role, or Kerberos + LDAP seen by a scan, so agentless DCs score the same.
 *  - Only ports seen by NETWORK SCANS count (osInfo.ports). Ports the agent lists from
 *    inside the machine are shown on the asset page but never scored: they may not be
 *    reachable, and only agent assets have them (fairness rules 2 and 5).
 *  - Unknown stays unknown: a never-port-scanned asset is reported as such (low
 *    confidence), not treated as having no services.
 *
 * Same base, exposure, port and hostname weights as v1, so the two are comparable.
 * Pure; tested by scripts/scoring-v2-demo.ts.
 */

export type FactorSource = 'manual' | 'agent' | 'scan' | 'analyst' | 'inferred' | 'hostname'
export interface CriticalityFactor { label: string; points: number; source: FactorSource }

export interface ScoringInputV2 {
  deviceType: string
  /** 'manual' | 'agent' | 'auto' (scans); anything else counts as 'auto'. */
  deviceTypeSource?: string | null
  isInternetFacing: boolean
  /** Analyst-confirmed exposure (non-null = confirmed). */
  internetFacingOverride?: boolean | null
  hostname: string | null | undefined
  /** Asset os_info; osInfo.ports holds the ports network scans saw. */
  osInfo: Record<string, unknown>
  /** OS role the agent on the machine reported (workstation | server | domain_controller). */
  agentRole?: string | null
  /** Classifier v2 hint (lib/deviceHints.ts): names where an inferred type came from. */
  deviceTypeHint?: { type: string | null; label: string; confidence: string; auto: boolean; evidence: string } | null
}

export interface ScoringBreakdownV2 {
  base: number
  role: number
  internetFacing: number
  portRisk: number
  hostnameHints: number
}
export interface ScoringResultV2 {
  model: 2
  score: number
  confidence: 'high' | 'medium' | 'low'
  breakdown: ScoringBreakdownV2
  details: CriticalityFactor[]
  factors: string[]                 // the details as text (same shape as v1's factors)
  /** Facts the score could not use because they are not known yet. */
  unknowns: string[]
}

// mobile = 3 like a workstation (v1 has no mobile entry and also falls back to 3), so filing a
// phone as mobile never raises its importance.
const BASE_SCORE: Record<string, number> = { network: 6, server: 5, iot: 4, workstation: 3, mobile: 3, unknown: 3 }
const TYPE_LABEL: Record<string, string> = { network: 'Network device', server: 'Server', iot: 'IoT device', mobile: 'Mobile device', workstation: 'Workstation', unknown: 'Unidentified device' }
const HIGH_RISK_PORTS: Record<number, string> = { 21: 'FTP', 23: 'Telnet', 445: 'SMB', 1433: 'MSSQL', 3389: 'RDP', 4444: 'Metasploit', 5900: 'VNC' }
const DB_PORTS = new Set([1521, 3306, 5432, 5984, 6379, 9200, 27017])
const KERBEROS = 88
const LDAP = [389, 636]

// Port entries as stored by scan ingest: numbers, "22/tcp" strings or { port } objects
// (the same parsing as v1).
function extractPortNumbers(raw: unknown[]): number[] {
  return raw
    .map(p => (typeof p === 'object' && p !== null && 'port' in p ? Number((p as Record<string, unknown>).port) : parseInt(String(p), 10)))
    .filter(n => !isNaN(n) && n > 0)
}

const sign = (n: number) => (n > 0 ? `+${n}` : n < 0 ? `−${-n}` : '0')

export function computeCriticalityV2(input: ScoringInputV2): ScoringResultV2 {
  const details: CriticalityFactor[] = []
  const unknowns: string[] = []
  const add = (label: string, points: number, source: FactorSource) => details.push({ label, points, source })

  // ── Device type, with where it came from ──
  const type = BASE_SCORE[input.deviceType] !== undefined ? input.deviceType : 'unknown'
  const typeSource: FactorSource = input.deviceTypeSource === 'manual' ? 'manual'
    : input.deviceTypeSource === 'agent' ? 'agent' : 'scan'
  const typeHint = input.deviceTypeHint
  const fromHint = typeSource === 'scan' && !!typeHint?.auto && typeHint.type === type
  const typeHow = type === 'unknown' ? 'type not identified'
    : typeSource === 'manual' ? 'set by hand' : typeSource === 'agent' ? 'confirmed by agent'
      : fromHint ? `inferred from ${typeHint!.evidence}` : 'inferred from scans'
  const base = BASE_SCORE[type]!
  add(`${TYPE_LABEL[type]} (${typeHow})`, base, typeSource)
  if (type === 'unknown') {
    unknowns.push(typeHint ? `device type (suggested: ${typeHint.label}, ${typeHint.confidence} confidence)` : 'device type')
  }

  // ── Network-reachable services (scan-observed only) ──
  const portsScanned = Array.isArray(input.osInfo?.['ports'])
  const ports = portsScanned ? extractPortNumbers(input.osInfo['ports'] as unknown[]) : []
  if (!portsScanned) unknowns.push('open ports (no active scan yet)')

  // ── Role ──
  let role = 0
  if (input.agentRole === 'domain_controller') {
    role = 2; add('Directory service: domain controller (reported by agent)', 2, 'agent')
  } else if (ports.includes(KERBEROS) && LDAP.some(p => ports.includes(p))) {
    role = 2; add('Directory service: Kerberos and LDAP reachable (seen by scan)', 2, 'scan')
  }

  // ── Exposure ──
  let internetFacing = 0
  if (input.isInternetFacing) {
    internetFacing = 2
    const confirmed = input.internetFacingOverride != null
    add(`Internet-facing (${confirmed ? 'confirmed by analyst' : 'inferred: it is the gateway'})`, 2, confirmed ? 'analyst' : 'inferred')
  }
  let portRisk = 0
  const risky = ports.filter(p => HIGH_RISK_PORTS[p]).slice(0, 2)
  if (risky.length) {
    portRisk += risky.length
    add(`Reachable high-risk service ${risky.map(p => `${HIGH_RISK_PORTS[p]} ${p}`).join(', ')} (seen by scan)`, risky.length, 'scan')
  }
  if (ports.some(p => DB_PORTS.has(p))) {
    portRisk += 1; add('Reachable database service (seen by scan)', 1, 'scan')
  }
  if (ports.length >= 10) {
    portRisk += 1; add(`${ports.length} reachable ports, wide surface (seen by scan)`, 1, 'scan')
  }

  // ── Hostname hints (same rules as v1) ──
  const h = (input.hostname ?? '').toLowerCase()
  let hostnameHints = 0
  const hint = (re: RegExp, label: string, pts: number) => {
    if (re.test(h)) { hostnameHints += pts; add(label, pts, 'hostname') }
  }
  hint(/\b(prod|production|live|critical)\b/, 'Production hostname', 1)
  hint(/\b(db|sql|database|mysql|postgres|oracle|redis|mongo)\b/, 'Database hostname', 1)
  hint(/\b(gw|gateway|fw|firewall|core|border|dmz|proxy)\b/, 'Network perimeter hostname', 1)
  hint(/\b(dev|develop|test|staging|lab|sandbox|qa)\b/, 'Non-production hostname', -1)

  const raw = base + role + internetFacing + portRisk + hostnameHints
  const score = Math.max(1, Math.min(10, raw))

  // Confidence: high = type set by hand or by the agent AND ports scanned; low = the
  // type or the ports are unknown; medium otherwise (type inferred from scans).
  const confidence: ScoringResultV2['confidence'] = unknowns.length ? 'low'
    : (typeSource === 'manual' || typeSource === 'agent') ? 'high' : 'medium'

  return {
    model: 2,
    score,
    confidence,
    breakdown: { base, role, internetFacing, portRisk, hostnameHints },
    details,
    factors: details.map(d => `${d.label} (${sign(d.points)})`),
    unknowns,
  }
}
