/**
 * report-pdf-demo.ts — builds the queued report exactly as the Worker does (buildReportData,
 * then the shared layout) for one tenant on the database in ../.env (SELECT only), and writes
 * the PDF. Run: npx esbuild scripts/report-pdf-demo.ts --bundle --platform=node --format=cjs --outfile=.p.cjs
 *               node --env-file=../.env .p.cjs <tenant_id> <out.pdf> [weekly|monthly|executive]
 */
import { writeFileSync } from 'node:fs'
import { getDb } from '../src/db/client'
import { buildReportData } from '../src/services/reportData'
import { buildPdf } from '../../frontend/src/utils/reportPdf.js'

const url = (process.env.DATABASE_URL ?? '').replace(/^postgresql\+asyncpg:\/\//, 'postgresql://').replace(/([?&])ssl=require/, '$1sslmode=require')
async function main() {
  const type = process.argv[4] ?? 'weekly'
  const data = await buildReportData(getDb(url), process.argv[2], type)
  writeFileSync(process.argv[3]!, Buffer.from(buildPdf(data, type).output('arraybuffer')))
  console.log(`ok: score ${data.posture_score}, ${data.top_cves.length} CVEs, ${data.open_advisories.length} advisories, verdict ${data.story.verdict.level}`)
}
main().catch(e => { console.error('FAILED', e.message); process.exit(1) })
