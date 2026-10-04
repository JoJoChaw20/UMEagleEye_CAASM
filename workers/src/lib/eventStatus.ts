import { inArray, sql } from 'drizzle-orm'
import { events } from '../db/schema'

export type EventStatus = typeof events.$inferSelect['status']

// Statuses that still need analyst work. Every "open"/"unresolved" count in the
// app must use this one definition so the dashboard, alerts, posture and
// reports agree with each other.
export const OPEN_STATUSES: EventStatus[] = ['open', 'in_progress']
export const CLOSED_STATUSES: EventStatus[] = ['resolved', 'false_positive', 'accepted_risk']

export const isOpenEvent = () => inArray(events.status, OPEN_STATUSES)

// An event was open at `at` if it had been raised by then and was not yet
// closed. False positives never counted, so they are excluded outright.
export const wasOpenAt = (at: Date) => sql`(
  ${events.firstSeen} <= ${at}
  AND ${events.status} <> 'false_positive'
  AND (${events.resolvedAt} IS NULL OR ${events.resolvedAt} > ${at})
)`

// Posture score shared by /posture/current, /posture/history and the cron
// snapshot. Inputs are OPEN critical/high findings only.
export function postureScore(openCritical: number, openHigh: number, totalAssets: number, criticalAssets: number): number {
  let score = 100
  score -= Math.min(openCritical * 5, 40)
  score -= Math.min(openHigh * 2, 20)
  if (totalAssets > 0 && criticalAssets / totalAssets > 0.2) score -= 10
  return Math.max(0, Math.min(100, Math.round(score)))
}
