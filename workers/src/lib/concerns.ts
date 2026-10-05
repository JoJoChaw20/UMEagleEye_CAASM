import { and, eq, inArray, or, sql, type SQL } from 'drizzle-orm'
import { events, assets } from '../db/schema'

// "Concerns" are the handful of alert categories a security engineer should look
// at before the general backlog. One definition, used by the dashboard cards,
// the alerts page counts and the GET /events?concern= filter, so the number on a
// card always equals the length of the list it opens.
//
// All conditions require `assets` to be joined on events.asset_id.

export const CONCERN_IDS = ['threat_intel', 'exposed_services', 'identity', 'exploitable', 'new_devices'] as const
export type ConcernId = typeof CONCERN_IDS[number]

// EPSS at or above this = meaningful chance of exploitation within 30 days
export const EPSS_LIKELY = 0.1

const hasCtiMatch = sql`${events.details}->'has_cti_match' = 'true'::jsonb`
const epssAtLeast = (v: number) => sql`(CASE WHEN jsonb_typeof(${events.details}->'epss_score') = 'number'
  THEN (${events.details}->>'epss_score')::float ELSE 0 END) >= ${v}`

export function concernCondition(id: ConcernId): SQL {
  switch (id) {
    case 'threat_intel':
      return or(eq(events.eventType, 'cti_match'), hasCtiMatch)!
    case 'exposed_services':
      // Risky/low ports newly opened (severity already folds in risky port and
      // internet exposure), or a host that just became internet-facing.
      return or(
        and(eq(events.eventType, 'port_opened'), inArray(events.severity, ['critical', 'high'])),
        and(eq(events.eventType, 'config_change'),
          sql`${events.details}->>'changed_attribute' = 'internet_facing'`,
          sql`${events.details}->'to' = 'true'::jsonb`),
      )!
    case 'identity':
      return and(eq(events.eventType, 'config_change'),
        sql`${events.details}->>'changed_attribute' IN ('mac_address', 'hostname')`)!
    case 'exploitable':
      return and(eq(events.eventType, 'cve_detected'), or(
        epssAtLeast(EPSS_LIKELY),
        and(eq(events.severity, 'critical'), eq(assets.isInternetFacing, true)),
      ))!
    case 'new_devices':
      return eq(events.eventType, 'new_device')
  }
}

export function isConcernId(v: string | undefined): v is ConcernId {
  return !!v && (CONCERN_IDS as readonly string[]).includes(v)
}

// One SELECT list computing every concern count with FILTER clauses.
export const concernCountColumns = Object.fromEntries(
  CONCERN_IDS.map(id => [id, sql<number>`count(*) filter (where ${concernCondition(id)})::int`]),
) as Record<ConcernId, SQL<number>>
