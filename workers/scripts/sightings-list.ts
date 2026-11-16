/**
 * Threat sightings: how big the agents' list is, and what a full sync costs.
 *
 * Pages through the feed entries exactly as GET /sightings/indicators does (same SQL, same
 * lib/sightings.ts listItems, LIST_PAGE rows a page), then reads one tenant's event part,
 * and reports pages, values (domains / IPs), bytes (raw and gzip) and database time per page.
 *
 * Run from workers/ (reads .env.<target>; DB_TARGET must match, as in scripts/db):
 *   npx esbuild scripts/sightings-list.ts --bundle --platform=node --format=cjs --outfile=.sightings-list.cjs
 *   node .sightings-list.cjs --target staging [--out <dir>]
 *
 * Only SELECTs. No indicator values are printed.
 */
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs'
import { gzipSync } from 'node:zlib'
import path from 'node:path'
import { neon } from '@neondatabase/serverless'
import { LIST_PAGE, decodeCursor, encodeCursor, listItems, type ListItem } from '../src/lib/sightings'

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`)
  return i > 0 ? process.argv[i + 1] : undefined
}
function die(msg: string): never { console.error(`\nERROR: ${msg}`); process.exit(1) }

const target = arg('target') ?? 'staging'
const outDir = arg('out')
if (!['staging', 'production'].includes(target)) die('--target must be staging or production')
const envFile = path.resolve(process.cwd(), `.env.${target}`)
if (!existsSync(envFile)) die(`${envFile} not found (run from workers/)`)
const vars: Record<string, string> = {}
for (const raw of readFileSync(envFile, 'utf8').replace(/^﻿/, '').split(/\r?\n/)) {
  const line = raw.trim(); const eq = line.indexOf('=')
  if (line && !line.startsWith('#') && eq > 0) vars[line.slice(0, eq).trim()] = line.slice(eq + 1).trim().replace(/^(['"])(.*)\1$/, '$2')
}
if (vars['DB_TARGET'] !== target) die(`${path.basename(envFile)} has DB_TARGET="${vars['DB_TARGET'] ?? ''}", not "${target}"`)
const sql = neon(vars['DATABASE_URL'] ?? die('DATABASE_URL missing'))

type Page = { type: string; value: string; seen: string; id: string }

async function main() {
  const all = new Map<string, ListItem>()
  const pageMs: number[] = []
  let cursor: string | null = null
  let rows = 0
  for (;;) {
    const after = decodeCursor(cursor)
    const t0 = performance.now()
    const page = (after
      ? await sql`
          SELECT c.indicator_type::text AS type, c.value, c.last_seen::text AS seen, c.indicator_id::text AS id
          FROM cti_indicators c
          WHERE c.ti_event_id IS NULL AND c.to_ids AND c.warning IS NULL AND c.indicator_type IN ('ip', 'domain', 'url')
            AND (c.last_seen, c.indicator_id) > (${after.seen}::timestamptz, ${after.id}::uuid)
          ORDER BY c.last_seen, c.indicator_id LIMIT ${LIST_PAGE}`
      : await sql`
          SELECT c.indicator_type::text AS type, c.value, c.last_seen::text AS seen, c.indicator_id::text AS id
          FROM cti_indicators c
          WHERE c.ti_event_id IS NULL AND c.to_ids AND c.warning IS NULL AND c.indicator_type IN ('ip', 'domain', 'url')
          ORDER BY c.last_seen, c.indicator_id LIMIT ${LIST_PAGE}`) as Page[]
    pageMs.push(performance.now() - t0)
    rows += page.length
    for (const it of listItems(page)) all.set(it.k + it.v, it)
    const last = page[page.length - 1]
    if (last) cursor = encodeCursor(last.seen, last.id)
    if (page.length < LIST_PAGE) break
  }
  const events = await sql`
    SELECT count(*)::int AS n FROM cti_indicators c JOIN ti_events te ON te.ti_event_id = c.ti_event_id
    WHERE c.indicator_type IN ('ip', 'domain', 'url') AND c.to_ids AND c.warning IS NULL AND te.status = 'published'`
  const delta = await sql`
    SELECT count(*)::int AS n FROM cti_indicators c
    WHERE c.ti_event_id IS NULL AND c.to_ids AND c.warning IS NULL AND c.indicator_type IN ('ip', 'domain', 'url')
      AND c.last_seen > now() - interval '1 day'`

  const items = [...all.values()]
  const body = JSON.stringify(items)
  const sorted = [...pageMs].sort((a, b) => a - b)
  const result = {
    target, measured_at: new Date().toISOString(), page_size: LIST_PAGE,
    full_sync: {
      pages: pageMs.length, rows, values: items.length,
      domains: items.filter(i => i.k === 'd').length, ips: items.filter(i => i.k === 'i').length,
      bytes_raw: Buffer.byteLength(body), bytes_gzip: gzipSync(body).length,
      db_ms_per_page: { median: Math.round(sorted[Math.floor(sorted.length / 2)] ?? 0), max: Math.round(sorted[sorted.length - 1] ?? 0) },
    },
    daily_delta_rows: (delta[0] as { n: number }).n,
    published_event_values_all_tenants: (events[0] as { n: number }).n,
  }
  console.log(JSON.stringify(result, null, 2))
  if (outDir) {
    mkdirSync(outDir, { recursive: true })
    writeFileSync(path.join(outDir, `sightings-list-${target}.json`), JSON.stringify(result, null, 2))
  }
}

main().catch(err => die(String(err?.stack ?? err)))
