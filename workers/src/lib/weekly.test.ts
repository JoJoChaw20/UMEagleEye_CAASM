import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { addWeeks, compareWeeks, finishedWeeks, isoWeek, weekBounds, weekStartOf, type WeekMetrics } from './weekly'

test('a week starts on Monday 00:00 Malaysia time (Sunday 16:00 UTC)', () => {
  assert.equal(weekStartOf(new Date('2026-11-22T15:59:59Z')), '2026-11-16')   // Sunday 23:59 MYT
  assert.equal(weekStartOf(new Date('2026-11-22T16:00:00Z')), '2026-11-23')   // Monday 00:00 MYT
  assert.equal(weekStartOf(new Date('2026-11-16T00:00:00Z')), '2026-11-16')   // Monday 08:00 MYT
  const { start, end } = weekBounds('2026-11-16')
  assert.equal(start.toISOString(), '2026-11-15T16:00:00.000Z')
  assert.equal(end.toISOString(), '2026-11-22T16:00:00.000Z')
})

test('ISO week names, across a year end', () => {
  assert.equal(isoWeek('2026-11-16'), '2026-W47')
  assert.equal(isoWeek('2025-12-29'), '2026-W01')       // ISO 2026 starts on Monday 29 Dec 2025
  assert.equal(isoWeek('2027-01-04'), '2027-W01')
  assert.equal(addWeeks('2026-12-28', 1), '2027-01-04')
})

test('finished weeks: the ones before the current week, oldest first', () => {
  assert.deepEqual(finishedWeeks(new Date('2026-11-22T10:00:00Z'), 3), ['2026-10-26', '2026-11-02', '2026-11-09'])
  // on Monday just after midnight MYT, the week that just ended is finished
  assert.deepEqual(finishedWeeks(new Date('2026-11-22T16:30:00Z'), 1), ['2026-11-16'])
})

const week = (over: Partial<WeekMetrics>): WeekMetrics => ({
  assets_total: 10, assets_added: 0, assets_removed: null, open_end: 100, open_by_tier: { 1: 1, 2: 2, 3: 90, 4: 7 },
  open_by_severity: { critical: 5, high: 20, medium: 50, low: 25 }, open_by_type: {}, overdue_end: 10, new: 20, resolved: 15,
  closed_other: 0, median_resolve_hours: 40, on_time: 12, on_time_pct: 80, kev_open_end: 3, sightings_new: 0, posture_score: 70, ...over,
})

test('week against week: the change, and whether it is better (fewer open, more resolved...)', () => {
  const c = Object.fromEntries(compareWeeks(week({ open_end: 90, resolved: 20, on_time_pct: 70, open_by_tier: { 1: 0, 2: 1, 3: 85, 4: 4 } }), week({})).map((x) => [x.key, x]))
  assert.deepEqual([c.open_end!.delta, c.open_end!.trend], [-10, 'better'])
  assert.deepEqual([c.resolved!.delta, c.resolved!.trend], [5, 'better'])
  assert.deepEqual([c.on_time_pct!.delta, c.on_time_pct!.trend], [-10, 'worse'])
  assert.deepEqual([c.tier12!.now, c.tier12!.then, c.tier12!.trend], [1, 3, 'better'])
  assert.equal(c.kev_open_end!.trend, 'same')
  // nothing to compare with: no change shown
  assert.equal(compareWeeks(week({}), null)[0]!.delta, null)
  // a missing value (no posture snapshot that week) is no change, not a drop to 0
  assert.equal(compareWeeks(week({ posture_score: null }), week({})).find((x) => x.key === 'posture_score')!.delta, null)
})

test('0045 adds the weekly table only, and changes no data', () => {
  const code = readFileSync(join(process.cwd(), 'drizzle/0045_weekly_history.sql'), 'utf8')
    .split('\n').filter((l) => !l.trim().startsWith('--')).join('\n')
  assert.match(code, /CREATE TABLE IF NOT EXISTS "weekly_snapshots"/)
  assert.doesNotMatch(code, /ALTER TABLE "tenants"/)
  assert.match(code, /CREATE UNIQUE INDEX IF NOT EXISTS "idx_weekly_tenant_week" ON "weekly_snapshots" USING btree \("tenant_id","week_start"\)/)
  assert.doesNotMatch(code, /^\s*(UPDATE|DELETE)\b/im)
})
