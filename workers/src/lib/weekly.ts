/**
 * Weekly history: the week boundaries and the comparisons. PURE (services/weekly.ts reads the data).
 *
 * A week runs Monday 00:00 to the next Monday 00:00, Malaysia time (UTC+8, no daylight saving): the
 * week the SOC reports on. It is named by its Monday as a date (2026-11-16) and as an ISO week
 * (2026-W47).
 */

export const MYT_OFFSET_MS = 8 * 3_600_000
const DAY = 86_400_000
const WEEK = 7 * DAY

/** The Monday (Malaysia time) of the week `at` falls in, as yyyy-mm-dd. */
export function weekStartOf(at: Date): string {
  const local = new Date(at.getTime() + MYT_OFFSET_MS)          // wall clock in Malaysia, read as UTC
  const dow = (local.getUTCDay() + 6) % 7                      // Monday 0 ... Sunday 6
  const monday = new Date(Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate()) - dow * DAY)
  return monday.toISOString().slice(0, 10)
}

/** The instants a week covers: [start, end) in UTC. */
export function weekBounds(weekStart: string): { start: Date; end: Date } {
  const start = new Date(Date.parse(`${weekStart}T00:00:00Z`) - MYT_OFFSET_MS)
  return { start, end: new Date(start.getTime() + WEEK) }
}

export function addWeeks(weekStart: string, n: number): string {
  return new Date(Date.parse(`${weekStart}T00:00:00Z`) + n * WEEK).toISOString().slice(0, 10)
}

/** ISO 8601 week name of a Monday: 2026-W47. */
export function isoWeek(weekStart: string): string {
  const d = new Date(`${weekStart}T00:00:00Z`)
  const thursday = new Date(d.getTime() + 3 * DAY)              // the ISO year is the Thursday's
  const year = thursday.getUTCFullYear()
  const jan4 = new Date(Date.UTC(year, 0, 4))
  const week1Monday = jan4.getTime() - ((jan4.getUTCDay() + 6) % 7) * DAY
  const n = Math.round((d.getTime() - week1Monday) / WEEK) + 1
  return `${year}-W${String(n).padStart(2, '0')}`
}

/** The finished weeks to record now: the last `max` before the current one, oldest first. */
export function finishedWeeks(now: Date, max: number): string[] {
  const current = weekStartOf(now)
  return Array.from({ length: max }, (_, i) => addWeeks(current, -(max - i)))
}

export interface WeekMetrics {
  assets_total: number
  assets_added: number
  assets_removed: number | null      // only when the week before was recorded live
  open_end: number                   // open when the week ended
  open_by_tier: Record<'1' | '2' | '3' | '4', number>
  open_by_severity: Record<'critical' | 'high' | 'medium' | 'low', number>
  open_by_type: Record<string, number>
  overdue_end: number                // open and past the fix-time target when the week ended
  new: number                        // first seen that week
  resolved: number                   // fixed that week
  closed_other: number               // closed as false positive or accepted risk that week
  median_resolve_hours: number | null
  on_time: number                    // of `resolved`, fixed by their due date
  on_time_pct: number | null
  kev_open_end: number
  sightings_new: number
  posture_score: number | null       // the last daily snapshot of the week
  // The security baseline (services/securityBaseline.ts baselineSummary) when the week was recorded as it
  // ended; null for a reconstructed week (settings cannot be read back from alert dates).
  baseline_pct?: number | null
  baseline_at_target?: number | null
}

/** The numbers compared week to week, and which way is better. */
export const COMPARED: Array<{ key: keyof WeekMetrics | 'tier12'; label: string; better: 'down' | 'up' }> = [
  { key: 'open_end', label: 'Open alerts', better: 'down' },
  { key: 'tier12', label: 'Compromise or exploited (tier 1-2)', better: 'down' },
  { key: 'overdue_end', label: 'Overdue', better: 'down' },
  { key: 'new', label: 'New alerts', better: 'down' },
  { key: 'resolved', label: 'Resolved', better: 'up' },
  { key: 'on_time_pct', label: 'Fixed on time (%)', better: 'up' },
  { key: 'median_resolve_hours', label: 'Median time to resolve (h)', better: 'down' },
  { key: 'kev_open_end', label: 'Open exploited (KEV)', better: 'down' },
  { key: 'assets_total', label: 'Devices', better: 'up' },
  { key: 'posture_score', label: 'Posture score', better: 'up' },
  { key: 'baseline_pct', label: 'Security baseline (%)', better: 'up' },
  { key: 'baseline_at_target', label: 'Computers at baseline target', better: 'up' },
]

export function valueOf(m: WeekMetrics, key: (typeof COMPARED)[number]['key']): number | null {
  if (key === 'tier12') return (m.open_by_tier?.['1'] ?? 0) + (m.open_by_tier?.['2'] ?? 0)
  const v = m[key as keyof WeekMetrics]
  return typeof v === 'number' ? v : null
}

export interface Change { key: string; label: string; now: number | null; then: number | null; delta: number | null; trend: 'better' | 'worse' | 'same' | null }

/** Each compared number now against `then` (the week before). */
export function compareWeeks(now: WeekMetrics, then: WeekMetrics | null): Change[] {
  return COMPARED.map(({ key, label, better }) => {
    const a = valueOf(now, key)
    const b = then ? valueOf(then, key) : null
    const delta = a == null || b == null ? null : Math.round((a - b) * 10) / 10
    const trend = delta == null ? null : delta === 0 ? 'same' : (delta < 0) === (better === 'down') ? 'better' : 'worse'
    return { key, label, now: a, then: b, delta, trend }
  })
}
