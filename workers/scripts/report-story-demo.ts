/**
 * report-story-demo.ts — runs the report storyline queries (SELECT only) for one tenant on the
 * database in ../.env and writes the JSON, so the PDF layout can be checked on real data.
 * Run: npx esbuild scripts/report-story-demo.ts --bundle --platform=node --format=cjs --outfile=.s.cjs
 *      node --env-file=../.env .s.cjs <tenant_id> <out.json> [weekly|monthly|executive]
 */
import { writeFileSync } from 'node:fs'
import { getDb } from '../src/db/client'
import { buildReportStory } from '../src/services/reportStory'

const url = (process.env.DATABASE_URL ?? '').replace(/^postgresql\+asyncpg:\/\//, 'postgresql://').replace(/([?&])ssl=require/, '$1sslmode=require')
async function main() {
  const t0 = Date.now()
  const story = await buildReportStory(getDb(url), process.argv[2], process.argv[4] ?? 'weekly')
  writeFileSync(process.argv[3]!, JSON.stringify(story, null, 2))
  console.log(`ok in ${Date.now() - t0} ms: ${story.actions.length} actions, ${story.hotspots.length} hotspots, verdict ${story.verdict.level}`)
}
main().catch(e => { console.error('FAILED', e.message); process.exit(1) })
