import { sql } from 'drizzle-orm'
import { events, assets } from '../db/schema'
import { RISKY_PORTS } from './exposure'
import { SLA_DEFAULTS } from './alertRank'

// Triage order for the Alerts queue, the dashboard, reports and the assistant: the SQL form of
// lib/alertRank.ts (tier, then a 0-100 score comparable across alert types; read that file for
// the rules). priorityExpr is one number, higher first: (5 - tier) x 1000 + score, so every
// caller that sorts by it follows the tiers, and tierOfPriority() reads the tier back.
// alertRank.test.ts checks these expressions against the pure functions.
//
// Requires `assets` to be joined on events.asset_id.

const d = (key: string) => sql`${events.details}->>${key}`
const num = (key: string) => sql`COALESCE((${d(key)})::numeric, 0)`
const KEV = sql`(${d('kev')} = 'true' OR ${num('kev_count')} > 0)`
const RISKY = sql.raw(`ARRAY[${Object.keys(RISKY_PORTS).join(',')}]`)
const CRIT10 = sql`GREATEST(COALESCE(${assets.criticalityScore}, 5), 1) * 10`

export const tierExpr = sql<number>`(CASE
  WHEN ${events.eventType} = 'cti_match' THEN
    CASE WHEN ${d('match_kind')} = 'watchlist' THEN 4 WHEN ${events.severity} IN ('critical', 'high') THEN 1 ELSE 4 END
  WHEN ${KEV} OR (${events.eventType} = 'os_patch_missing' AND ${num('exploited')} > 0) THEN 2
  WHEN ${events.eventType} IN ('cve_detected', 'vulnerable_service', 'os_patch_missing', 'exposure') THEN 3
  WHEN ${events.eventType} = 'port_opened' AND (${d('port')}) ~ '^[0-9]+$' AND (${d('port')})::int = ANY(${RISKY}) THEN 3
  ELSE 4 END)`

const BASE = sql`(CASE ${events.severity} WHEN 'critical' THEN 85 WHEN 'high' THEN 70 WHEN 'medium' THEN 50 ELSE 30 END)`
const baseScoreExpr = sql`(CASE
  WHEN ${events.eventType} = 'cve_detected' AND ${events.compositeRiskScore} IS NOT NULL THEN
    ${events.compositeRiskScore}::numeric
    * CASE WHEN ${d('shape')} = 'package' AND COALESCE((${d('fixable_count')})::int, 1) = 0 AND NOT ${KEV} THEN 0.5 ELSE 1 END
  WHEN ${events.eventType} = 'vulnerable_service' AND ${d('max_cvss')} IS NOT NULL THEN
    0.40 * (${d('max_cvss')})::numeric * 10 + 0.15 * ${CRIT10} + CASE WHEN ${KEV} THEN 10 ELSE 0 END
  WHEN ${events.eventType} = 'os_patch_missing' THEN
    0.40 * CASE WHEN ${num('exploited')} > 0 OR ${num('critical')} > 0 THEN 9.0 ELSE 7.5 END * 10 + 0.15 * ${CRIT10}
    + CASE WHEN ${num('exploited')} > 0 THEN 10 ELSE 0 END
  ELSE 0.85 * ${BASE} + 0.15 * ${CRIT10} END)`

/** 0-100. Internet-facing adds 15 once, for alert types whose severity does not already include it. */
export const rankScoreExpr = sql<number>`round(LEAST(100, ${baseScoreExpr}
  + CASE WHEN ${assets.isInternetFacing} AND ${events.eventType} NOT IN ('exposure', 'vulnerable_service', 'port_opened', 'new_device', 'config_change')
         THEN 15 ELSE 0 END)::numeric, 1)::float`

export const priorityExpr = sql<number>`((5 - ${tierExpr}) * 1000 + ${rankScoreExpr})::float`

/** The fix-time target that applies (lib/alertRank.ts slaKeyOf). */
export const slaKeyExpr = sql<string>`(CASE ${tierExpr}
  WHEN 1 THEN 'compromise'
  WHEN 2 THEN CASE WHEN ${assets.isInternetFacing} THEN 'kev_exposed' ELSE 'kev' END
  WHEN 4 THEN 'review'
  ELSE ${events.severity}::text END)`

// The defaults as SQL literals (constants from alertRank.ts, never user input)
const DEFAULT_WHENS = sql.raw(Object.entries(SLA_DEFAULTS).map(([k, h]) => `WHEN '${k}' THEN ${Number(h)}`).join(' '))

/** Hours: the tenant's own target (tenants.sla_policy, kept valid by cleanSlaPolicy) or the default. */
export const slaHoursExpr = sql<number>`COALESCE(
  (SELECT (t.sla_policy->>${slaKeyExpr})::int FROM tenants t WHERE t.tenant_id = ${assets.tenantId}),
  (CASE ${slaKeyExpr} ${DEFAULT_WHENS} END))`

/** When the fix-time clock started: first seen, or the last time the alert reopened. */
export const clockStartExpr = sql`COALESCE(${events.reopenedAt}, ${events.firstSeen})`
export const dueAtExpr = sql<string>`(${clockStartExpr} + make_interval(hours => ${slaHoursExpr}))`
/** overdue / due_soon (last quarter of the window) / on_track */
export const dueStatusExpr = sql<string>`(CASE
  WHEN now() > ${dueAtExpr} THEN 'overdue'
  WHEN now() > ${dueAtExpr} - make_interval(hours => ${slaHoursExpr}) / 4 THEN 'due_soon'
  ELSE 'on_track' END)`
