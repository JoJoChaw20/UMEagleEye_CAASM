/**
 * Criticality scoring formula (1–10) for a single asset.
 *
 * Score = base(deviceType)
 *       + isInternetFacing bonus
 *       + port-risk bonus
 *       + hostname-hint bonus/penalty
 *       + topology-layer bonus
 * Clamped to [1, 10].
 *
 * Designed so users understand every point: a breakdown object and a
 * human-readable factors array are returned alongside the final score.
 */

// Ports that imply high lateral-movement / takeover risk
const HIGH_RISK_PORTS = new Set([
  21,   // FTP
  23,   // Telnet
  445,  // SMB
  1433, // MSSQL
  3389, // RDP
  4444, // Metasploit default
  5900, // VNC
])

// Ports that imply a data-store is exposed
const DB_PORTS = new Set([
  1521,  // Oracle
  3306,  // MySQL/MariaDB
  5432,  // PostgreSQL
  5984,  // CouchDB
  6379,  // Redis
  9200,  // Elasticsearch
  27017, // MongoDB
])

// Base score by device type
const BASE_SCORE: Record<string, number> = {
  network:     6,
  server:      5,
  iot:         4,
  workstation: 3,
  unknown:     3,
}

export interface ScoringInput {
  deviceType: string
  isInternetFacing: boolean
  hostname: string | null | undefined
  /** osInfo from the assets table — may contain a "ports" array populated by scan ingest */
  osInfo: Record<string, unknown>
  /** Layer from topology_nodes (1 = internet-facing gateway … 6 = IoT leaf) */
  topologyLayer?: number | null
}

export interface ScoringBreakdown {
  base: number
  internetFacing: number
  portRisk: number
  hostnameHints: number
  topologyLayer: number
}

export interface ScoringResult {
  score: number          // final clamped value
  breakdown: ScoringBreakdown
  factors: string[]      // one line per non-zero contribution
}

export function computeCriticality(input: ScoringInput): ScoringResult {
  const { deviceType, isInternetFacing, hostname, osInfo, topologyLayer } = input
  const factors: string[] = []

  // ── 1. Base score ────────────────────────────────────────────────
  const base = BASE_SCORE[deviceType] ?? 3
  factors.push(`${deviceType} (base ${base})`)

  // ── 2. Internet-facing exposure ──────────────────────────────────
  const internetFacing = isInternetFacing ? 2 : 0
  if (isInternetFacing) factors.push('internet-facing (+2)')

  // ── 3. Port risk ─────────────────────────────────────────────────
  const rawPorts: unknown[] = Array.isArray(osInfo.ports) ? osInfo.ports : []
  const portNums = rawPorts
    .map(p => {
      if (typeof p === 'object' && p !== null && 'port' in p)
        return Number((p as Record<string, unknown>).port)
      return parseInt(String(p), 10)
    })
    .filter(n => !isNaN(n) && n > 0)

  let portRisk = 0
  const riskyFound: number[] = []
  let hasDbPort = false

  for (const port of portNums) {
    if (HIGH_RISK_PORTS.has(port) && riskyFound.length < 2) riskyFound.push(port)
    if (DB_PORTS.has(port)) hasDbPort = true
  }

  if (riskyFound.length > 0) {
    portRisk += riskyFound.length  // already capped at 2 by loop
    factors.push(`high-risk port(s) ${riskyFound.join('/')} (+${riskyFound.length})`)
  }
  if (hasDbPort) {
    portRisk += 1
    factors.push('database service port (+1)')
  }
  if (portNums.length >= 10) {
    portRisk += 1
    factors.push(`${portNums.length} open ports, wide surface (+1)`)
  }

  // ── 4. Hostname hints ────────────────────────────────────────────
  const h = (hostname ?? '').toLowerCase()
  let hostnameHints = 0

  if (/\b(prod|production|live|critical)\b/.test(h)) {
    hostnameHints += 1; factors.push('production hostname (+1)')
  }
  if (/\b(db|sql|database|mysql|postgres|oracle|redis|mongo)\b/.test(h)) {
    hostnameHints += 1; factors.push('database hostname (+1)')
  }
  if (/\b(gw|gateway|fw|firewall|core|border|dmz|proxy)\b/.test(h)) {
    hostnameHints += 1; factors.push('network perimeter hostname (+1)')
  }
  if (/\b(dev|develop|test|staging|lab|sandbox|qa)\b/.test(h)) {
    hostnameHints -= 1; factors.push('non-production hostname (−1)')
  }

  // ── 5. Topology layer bonus ──────────────────────────────────────
  let topologyBonus = 0
  if (topologyLayer === 1) {
    topologyBonus = 3; factors.push('topology L1 internet gateway (+3)')
  } else if (topologyLayer === 2) {
    topologyBonus = 2; factors.push('topology L2 core network (+2)')
  } else if (topologyLayer === 3) {
    topologyBonus = 1; factors.push('topology L3 distribution (+1)')
  }

  // ── Final score ──────────────────────────────────────────────────
  const raw = base + internetFacing + portRisk + hostnameHints + topologyBonus
  const score = Math.max(1, Math.min(10, raw))

  return {
    score,
    breakdown: { base, internetFacing, portRisk, hostnameHints, topologyLayer: topologyBonus },
    factors,
  }
}
