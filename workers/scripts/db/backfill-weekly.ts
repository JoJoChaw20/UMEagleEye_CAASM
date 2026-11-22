/**
 * backfill-weekly.ts — record every tenant's missing finished weeks now (services/weekly.ts recordWeeks),
 * as the nightly job does. For staging (no crons) and for a first fill on production. Dry run unless
 * --apply: then it prints one tenant's weeks as they would be saved.
 *
 *   npx esbuild scripts/db/backfill-weekly.ts --bundle --platform=node --format=esm --outfile=scripts/db/.backfill-weekly.mjs \
 *     "--banner:js=import { createRequire as __cr } from 'module'; const require = __cr(import.meta.url);"
 *   node scripts/db/.backfill-weekly.mjs <staging|production> [--apply] [--tenant <id>]
 */
import { getDb } from '../../src/db/client'
import { computeWeeks, recordWeeks, MAX_BACKFILL } from '../../src/services/weekly'
import { finishedWeeks, isoWeek } from '../../src/lib/weekly'
// @ts-expect-error plain .mjs helper
import { loadEnvFile, describe } from './lib.mjs'

const target = process.argv[2]
if (target !== 'staging' && target !== 'production') { console.error('usage: <staging|production> [--apply] [--tenant <id>]'); process.exit(1) }
const apply = process.argv.includes('--apply')
const ti = process.argv.indexOf('--tenant')
const { DATABASE_URL } = loadEnvFile(target)
const db = getDb(DATABASE_URL)
console.log(`Target: ${target} (${describe(DATABASE_URL)})${apply ? '' : '  [dry run]'}`)

if (!apply) {
  const tenantId = ti > 0 ? process.argv[ti + 1]! : null
  if (!tenantId) { console.log('Dry run needs --tenant <id> to show its weeks'); process.exit(0) }
  const t = Date.now()
  const weeks = await computeWeeks(db, tenantId, finishedWeeks(new Date(), MAX_BACKFILL))
  for (const [w, m] of weeks) {
    console.log(`${isoWeek(w)} ${w}: devices ${m.assets_total} (+${m.assets_added}) · open ${m.open_end} [t1 ${m.open_by_tier[1]} t2 ${m.open_by_tier[2]} t3 ${m.open_by_tier[3]} t4 ${m.open_by_tier[4]}] · new ${m.new} · resolved ${m.resolved} · on time ${m.on_time_pct ?? '-'}% · median ${m.median_resolve_hours ?? '-'} h · overdue ${m.overdue_end} · KEV ${m.kev_open_end} · sightings ${m.sightings_new} · posture ${m.posture_score ?? '-'}`)
  }
  console.log(`(${weeks.size} weeks in ${Date.now() - t} ms) Dry run: nothing written (add --apply)`)
} else {
  const r = await recordWeeks(db)
  console.log(`Recorded ${r.weeks} week(s) for ${r.tenants} tenant(s)`)
}
