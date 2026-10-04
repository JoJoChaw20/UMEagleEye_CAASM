import { sql } from 'drizzle-orm'
import { events, assets } from '../db/schema'

// Triage priority used to rank the Alerts queue and the dashboard's
// "Priority actions". Higher = work on it first.
//
//   base      composite risk score (0-100) when scored (CVEs), otherwise a
//             severity floor so drift/device alerts rank sensibly beside CVEs
//   ×1.5      asset is internet-facing
//   +2×crit   asset criticality (1-10)
//   +200      threat-intel match — possible active compromise, always first
//
// Requires `assets` to be joined on events.asset_id.
export const priorityExpr = sql<number>`round((
  COALESCE(${events.compositeRiskScore}::numeric,
    CASE ${events.severity}
      WHEN 'critical' THEN 70 WHEN 'high' THEN 50 WHEN 'medium' THEN 30 ELSE 10 END)
  * CASE WHEN ${assets.isInternetFacing} THEN 1.5 ELSE 1 END
  + COALESCE(${assets.criticalityScore}, 5) * 2
  + CASE WHEN ${events.eventType} = 'cti_match'
           OR (${events.details}->>'has_cti_match')::boolean IS TRUE THEN 200 ELSE 0 END
)::numeric, 1)::float`
