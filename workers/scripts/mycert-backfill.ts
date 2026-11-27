/**
 * Load MyCERT's older advisories (its RSS feed holds only the newest 20) as platform threat-intel
 * events, the way the nightly 'mycert' step saves new ones (services/mycert.ts).
 *
 * Lists a year's advisories from MyCERT's monthly archive pages (10 a page), fetches each advisory's
 * page one at a time (a second apart: MyCERT is a public service), parses it (lib/mycert.ts) and
 * saves it. Advisories already stored are skipped unless --refresh. Afterwards the CVE alerts and
 * asset matches of every tenant are refreshed once. The agents' cached sightings lists pick the new
 * events up within the AgentHub's revalidation time (30 minutes).
 *
 * Run from workers/ (reads .env.<target>; DB_TARGET must match, as in scripts/db):
 *   npx esbuild scripts/mycert-backfill.ts --bundle --platform=node --format=cjs --outfile=.mycert-backfill.cjs
 *   node .mycert-backfill.cjs --target staging [--year 2026] [--dry-run] [--refresh]
 * --dry-run fetches and parses only, and prints what would be saved (no database).
 */
import { readFileSync, existsSync } from 'node:fs'
import path from 'node:path'
import { sql } from 'drizzle-orm'
import { getDb } from '../src/db/client'
import { MYCERT_ORIGIN, mycertAdvisoryUrl, parseMycertAdvisory } from '../src/lib/mycert'
import { fetchMycertDirect as fetchMycert, saveMycertAdvisory } from '../src/services/mycert'
import { refreshIntelAlerts } from '../src/services/iocMatch'

const ARCHIVE = 'https://www.mycert.org.my/portal/advisories?id=431fab9c-d24c-4a27-ba93-e92edafdefa5'
const PAUSE_MS = 1000

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`)
  return i > 0 ? process.argv[i + 1] : undefined
}
const flag = (name: string) => process.argv.includes(`--${name}`)
function die(msg: string): never { console.error(`\nERROR: ${msg}`); process.exit(1) }
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

const target = arg('target') ?? 'staging'
const year = Number(arg('year') ?? new Date().getFullYear())
const dryRun = flag('dry-run')
const refresh = flag('refresh')
if (!['staging', 'production'].includes(target)) die('--target must be staging or production')
if (!Number.isInteger(year) || year < 2014 || year > 2100) die('--year must be a year MyCERT has advisories for (2014 on)')

function databaseUrl(): string {
  const envFile = path.resolve(process.cwd(), `.env.${target}`)
  if (!existsSync(envFile)) die(`${envFile} not found (run from workers/)`)
  const vars: Record<string, string> = {}
  for (const raw of readFileSync(envFile, 'utf8').replace(/^﻿/, '').split(/\r?\n/)) {
    const line = raw.trim(); const eq = line.indexOf('=')
    if (line && !line.startsWith('#') && eq > 0) vars[line.slice(0, eq).trim()] = line.slice(eq + 1).trim().replace(/^(['"])(.*)\1$/, '$2')
  }
  if (vars['DB_TARGET'] !== target) die(`${path.basename(envFile)} has DB_TARGET="${vars['DB_TARGET'] ?? ''}", not "${target}"`)
  return vars['DATABASE_URL'] ?? die('DATABASE_URL missing')
}

/** The year's advisory numbers from the monthly archive pages, oldest first. */
async function listYear(): Promise<string[]> {
  const ids: string[] = []
  const suffix = String(year)
  const lastMonth = year === new Date().getFullYear() ? new Date().getMonth() + 1 : 12
  for (let m = 1; m <= lastMonth; m++) {
    const month = `${year}-${String(m).padStart(2, '0')}`
    for (let page = 1; page <= 20; page++) {
      const html = await fetchMycert(`${ARCHIVE}&month=${month}&page=${page}&per-page=10`)
      const found = [...html.matchAll(/advisory\?id=(MA-\d+\.\d{2}(\d{4}))/g)].filter((x) => x[2] === suffix).map((x) => x[1]!)
      const fresh = [...new Set(found)].filter((id) => !ids.includes(id))
      if (!fresh.length) break
      ids.push(...fresh)
      await sleep(PAUSE_MS)
    }
    console.log(`${month}: ${ids.length} so far`)
  }
  return ids.sort((a, b) => Number(a.split(/[-.]/)[1]) - Number(b.split(/[-.]/)[1]))
}

async function main() {
  const db = dryRun ? null : getDb(databaseUrl())
  console.log(`MyCERT ${year} -> ${dryRun ? 'dry run (no database)' : target}${refresh ? ', re-saving stored ones' : ''}`)
  const ids = await listYear()
  console.log(`${ids.length} advisories listed for ${year}`)

  const stored = new Set<string>()
  if (db && !refresh) {
    const res = await db.execute(sql`SELECT external_id FROM ti_events WHERE origin = ${MYCERT_ORIGIN}`)
    for (const r of res.rows as { external_id: string }[]) stored.add(r.external_id)
  }

  const totals = { saved: 0, skipped: 0, failed: 0, cves: 0, exploited: 0, iocs: 0 }
  for (const id of ids) {
    if (stored.has(id)) { totals.skipped++; continue }
    try {
      const adv = parseMycertAdvisory(await fetchMycert(mycertAdvisoryUrl(id)))
      if (!adv || adv.id !== id) throw new Error(`the page holds ${adv ? adv.id : 'no advisory'}`)
      if (db) await saveMycertAdvisory(db, adv, null)
      totals.saved++; totals.cves += adv.cves.length; totals.exploited += adv.exploitedCves.length; totals.iocs += adv.iocs.length
      console.log(`${id}: ${adv.cves.length} CVE(s), exploited [${adv.exploitedCves.join(', ')}], ${adv.iocs.length} indicator(s) - ${adv.headline.slice(0, 70)}`)
    } catch (err) {
      totals.failed++
      console.error(`${id} FAILED: ${err instanceof Error ? err.message : String(err)}`)
    }
    await sleep(PAUSE_MS)
  }
  console.log('\n', totals)

  if (db && totals.saved) {
    console.log('Refreshing CVE alerts and asset matches for every tenant...')
    console.log(await refreshIntelAlerts(db, { all: true }))
  }
}

main().catch((err) => die(err instanceof Error ? err.stack ?? err.message : String(err)))
