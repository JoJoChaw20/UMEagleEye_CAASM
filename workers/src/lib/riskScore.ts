// Composite risk score of a CVE finding (0-100) and its severity, used by CVE ingest
// (routes/sbom.ts). Pure, so the formula is unit-tested and reused by the read-only
// reliability evaluation (scripts/risk-reliability.ts).

export type Severity = 'critical' | 'high' | 'medium' | 'low'

/** Severity from CVSS; Grype's own label only when the finding has no CVSS score. */
export function mapSeverity(cvss: number, grypeSev: string): Severity {
  if (cvss >= 9.0) return 'critical'
  if (cvss >= 7.0) return 'high'
  if (cvss >= 4.0) return 'medium'
  if (cvss === 0) {
    const s = grypeSev.toLowerCase()
    if (s === 'critical') return 'critical'
    if (s === 'high') return 'high'
    if (s === 'medium') return 'medium'
  }
  return 'low'
}

export function computeRiskScore(cvss: number, epss: number, criticality: number, ctiMatch: boolean): number {
  // Normalise all components to 0-100 scale before weighting:
  // CVSS (0-10) → *10 → 0-100, weight 40%
  // EPSS (0-1)  → *100 → 0-100, weight 35%
  // Criticality (1-10) → *10 → 0-100, weight 15%
  // CTI match flat 10 pts
  const score = (cvss * 10 * 0.40) + (epss * 100 * 0.35) + (Math.max(criticality, 1) * 10 * 0.15) + (ctiMatch ? 10 : 0)
  return Math.round(Math.min(score, 100) * 100) / 100
}

/** An open CVE alert as stored: its scored inputs and its asset's criticality today. */
export interface AlertScoreRow {
  eventId: string
  cvss: number | null
  epss: number | null
  ctiMatch: boolean | null
  stored: number | null
  criticality: number | null
}

/**
 * Alerts whose stored score no longer matches the formula. Ingest scores an alert with the
 * criticality its asset had at the last SBOM upload; when criticality changes in between
 * (a rescore, a scan that finds a new service), the alert keeps the old value until then.
 * Missing inputs count as ingest counts them: no CVSS or EPSS is 0, no criticality is 5.
 */
export function planAlertScores(rows: AlertScoreRow[]): Array<{ eventId: string; score: number }> {
  const out: Array<{ eventId: string; score: number }> = []
  for (const r of rows) {
    const score = computeRiskScore(r.cvss ?? 0, r.epss ?? 0, r.criticality ?? 5, !!r.ctiMatch)
    if (r.stored == null || Math.abs(r.stored - score) >= 0.005) out.push({ eventId: r.eventId, score })
  }
  return out
}
