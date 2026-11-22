// Two facts about an alert that reports, the dashboard and the ranking all need, defined once.
//
//   exploited      a CVE on CISA's Known Exploited Vulnerabilities list: an SBOM package alert's
//                  `kev` flag, or a vulnerable service (scan banner) with `kev_count` > 0
//   direct intel   threat intelligence seen on a host: an indicator match (R5) or a sighting (R7).
//                  A watchlist hit (R6: software a threat event watches is installed) is not
//                  evidence of a threat, and neither is a CVE merely named by a feed.
import { sql } from 'drizzle-orm'
import { events } from '../db/schema'

type Details = Record<string, unknown>

/** PURE. The alert carries a CVE exploited in the wild. */
export function isKevAlert(d: Details): boolean {
  return d.kev === true || Number(d.kev_count ?? 0) > 0
}

/** PURE. The alert is threat intelligence seen on a host, not a watchlist hit. */
export function isDirectIntel(type: string, d: Details): boolean {
  return type === 'cti_match' && d.match_kind !== 'watchlist'
}

/** PURE. A Windows update id as people write it: MSRC data stores "5132061", shown as "KB5132061". */
export function kbLabel(kb: unknown): string | null {
  if (kb == null || kb === '') return null
  const s = String(kb).trim()
  return /^\d+$/.test(s) ? `KB${s}` : s
}

export const KEV_ALERT =sql`(${events.details}->>'kev' = 'true' OR COALESCE((${events.details}->>'kev_count')::int, 0) > 0)`
export const DIRECT_INTEL = sql`(${events.eventType} = 'cti_match' AND COALESCE(${events.details}->>'match_kind', '') <> 'watchlist')`
