/**
 * convert-package-alerts.ts — fold the old SBOM alerts (one per CVE) into one alert per
 * vulnerable package with its CVEs as findings (lib/packageAlerts.ts), for every asset that
 * still has open old-style alerts. Uses the same planner and writer as the CVE ingest, so a
 * converted alert is the same as one the next SBOM upload would make; that upload also
 * converts any asset this missed.
 *
 * Per package: the row with an advisory, else the one in progress or assigned, else the
 * oldest is kept (assignee, advisory, SLA age and history stay); the other rows are folded
 * into it (a live advisory moves over). A CVE someone closed as false positive / accepted
 * risk inside a package that is still open becomes a dismissed finding. Closed history of
 * packages that are gone is left as it is.
 *
 * Run from workers/ (reads .env.<target>; DB_TARGET must match, as in scripts/db). Dry run
 * unless --apply; production asks to type "production".
 *   npx esbuild scripts/convert-package-alerts.ts --bundle --platform=node --format=cjs --outfile=.convert-package-alerts.cjs
 *   node .convert-package-alerts.cjs --target staging [--apply]
 */
import { readFileSync, existsSync } from 'node:fs'
import path from 'node:path'
import readline from 'node:readline/promises'
import { sql } from 'drizzle-orm'
import { getDb } from '../src/db/client'
import {
  alertKey, findingKey, isPackageAlert, legacyFindings, planPackageAlerts, type Finding,
} from '../src/lib/packageAlerts'
import { loadAlerts, loadPresentFindings, planStatements, runBatches } from '../src/services/packageAlerts'
import { linkCveIndicators } from '../src/services/threatIntel'

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`)
  return i > 0 ? process.argv[i + 1] : undefined
}
function die(msg: string): never { console.error(`\nERROR: ${msg}`); process.exit(1) }

const target = arg('target') ?? 'staging'
const apply = process.argv.includes('--apply')
if (!['staging', 'production'].includes(target)) die('--target must be staging or production')
const envFile = path.resolve(process.cwd(), `.env.${target}`)
if (!existsSync(envFile)) die(`${envFile} not found (run from workers/)`)
const vars: Record<string, string> = {}
for (const raw of readFileSync(envFile, 'utf8').replace(/^﻿/, '').split(/\r?\n/)) {
  const line = raw.trim(); const eq = line.indexOf('=')
  if (line && !line.startsWith('#') && eq > 0) vars[line.slice(0, eq).trim()] = line.slice(eq + 1).trim().replace(/^(['"])(.*)\1$/, '$2')
}
if (vars['DB_TARGET'] !== target) die(`${path.basename(envFile)} has DB_TARGET="${vars['DB_TARGET'] ?? ''}", not "${target}"`)
const url = vars['DATABASE_URL'] ?? die('DATABASE_URL missing')

const ACTIVE = new Set(['open', 'in_progress'])
const JUDGED = new Set(['false_positive', 'accepted_risk'])

async function main() {
  if (apply && target === 'production') {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
    const answer = await rl.question('This writes to PRODUCTION. Type "production" to go on: ')
    rl.close()
    if (answer.trim() !== 'production') die('not confirmed')
  }
  const db = getDb(url)
  const assets = (await db.execute(sql`
    SELECT DISTINCT a.asset_id, COALESCE(a.hostname, a.ip_address) AS name, a.criticality_score AS crit
    FROM events e JOIN assets a ON a.asset_id = e.asset_id
    WHERE e.event_type = 'cve_detected' AND e.status IN ('open', 'in_progress')
      AND e.details->>'shape' IS DISTINCT FROM 'package'
    ORDER BY 2`)).rows as { asset_id: string; name: string; crit: number | null }[]
  console.log(`${target}: ${assets.length} asset(s) with open per-CVE alerts${apply ? '' : ' (dry run: nothing is written)'}\n`)

  const totals = { legacy: 0, packages: 0, created: 0, folded: 0, dismissed: 0, resolved: 0 }
  for (const a of assets) {
    const [existing, stored] = await Promise.all([loadAlerts(db, a.asset_id), loadPresentFindings(db, a.asset_id)])
    // the packages with an open per-CVE alert; their open and judged CVEs become findings
    const legacy = existing.filter((e) => !isPackageAlert(e.details))
    const activeKeys = new Set(legacy.filter((e) => ACTIVE.has(e.status)).map((e) => alertKey(e.details)).filter(Boolean))
    const byKey = new Map<string, Finding>(stored.map((f) => [findingKey(f), f]))
    for (const e of legacy) {
      if (!activeKeys.has(alertKey(e.details)) || !(ACTIVE.has(e.status) || JUDGED.has(e.status))) continue
      for (const f of legacyFindings(e.details, e.severity)) if (!byKey.has(findingKey(f))) byKey.set(findingKey(f), f)
    }
    const findings = [...byKey.values()]
    const plan = planPackageAlerts({ findings, existing, criticality: a.crit ?? 5, newId: () => crypto.randomUUID() })
    const created = plan.alerts.filter((x) => x.isNew).length
    totals.legacy += legacy.length; totals.packages += plan.alerts.length; totals.created += created
    totals.folded += plan.merge.length; totals.dismissed += plan.dismiss.size; totals.resolved += plan.resolve.length
    console.log(`${String(a.name).padEnd(28)} ${String(legacy.length).padStart(5)} per-CVE alert(s) -> ${plan.alerts.length} package alert(s)`
      + ` (${plan.merge.length} folded, ${created} new, ${plan.dismiss.size} dismissed CVE(s), ${plan.resolve.length} resolved)`)
    if (apply) {
      await runBatches(db, planStatements(db, a.asset_id, plan, findings, new Date()))
      await linkCveIndicators(db, { assetId: a.asset_id })
    }
  }
  console.log(`\nTotal: ${totals.legacy} per-CVE alerts -> ${totals.packages} package alerts; ${totals.folded} folded, `
    + `${totals.created} new, ${totals.dismissed} dismissed CVEs, ${totals.resolved} resolved${apply ? '' : ' (dry run)'}`)
}

main().catch((e) => die(e instanceof Error ? e.stack ?? e.message : String(e)))
