import type { DB } from '../db/client'
import { recomputePackageAlerts } from './packageAlerts'

export type AlertScoreScope = { tenantId: string } | { assetIds: string[] }

/**
 * Bring open SBOM package alerts in `scope` in line with their asset's current criticality:
 * the alert's score is its riskiest CVE's composite score (lib/packageAlerts.ts), which uses
 * criticality. Called after a rescore, so a criticality change reaches the Alerts queue at
 * once instead of at the computer's next SBOM upload. Returns how many alerts changed.
 */
export async function refreshCveAlertScores(db: DB, scope: AlertScoreScope): Promise<number> {
  return recomputePackageAlerts(db, scope)
}
