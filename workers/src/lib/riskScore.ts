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
