/**
 * Threat sightings evaluation (Objective 3): plant known indicators in a tenant, then measure
 * what the agents reported.
 *
 *   plant   a PUBLISHED threat-intel event in the tenant (threat level high) holding
 *           20 random, unregistered domains under .com (lookups get NXDOMAIN: harmless, still
 *           an answer the agent sees) and one public IP (info.cern.ch, a static page).
 *           Writes the planted values to <out>/sightings-planted.json for the VM scripts.
 *           Dry run unless --apply.
 *   measure the R7 alerts on the tenant's assets since the event was published: per planted
 *           value detected or not, per asset; alerts on anything not planted (false alerts);
 *           the time from the first contact (agent clock) to the alert (server clock).
 *   remove  unpublish and delete the planted event (its sightings stay as alerts to close).
 *
 * Run from workers/ (reads .env.<target>; DB_TARGET must match, as in scripts/db):
 *   npx esbuild scripts/sightings-eval.ts --bundle --platform=node --format=cjs --outfile=.sightings-eval.cjs
 *   node .sightings-eval.cjs plant   --tenant <uuid> --out <dir> [--apply]
 *   node .sightings-eval.cjs measure --tenant <uuid> --out <dir>
 *   node .sightings-eval.cjs remove  --tenant <uuid> [--apply]
 */
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import path from 'node:path'
import { neon } from '@neondatabase/serverless'

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`)
  return i > 0 ? process.argv[i + 1] : undefined
}
function die(msg: string): never { console.error(`\nERROR: ${msg}`); process.exit(1) }

const cmd = process.argv[2]
const target = arg('target') ?? 'staging'
const tenant = arg('tenant') ?? die('--tenant <uuid> is required')
const outDir = arg('out')
const apply = process.argv.includes('--apply')
if (!['plant', 'measure', 'remove'].includes(cmd ?? '')) die('usage: plant | measure | remove')
if (target !== 'staging') die('the evaluation runs on staging only')
if (!/^[0-9a-f-]{36}$/.test(tenant)) die('--tenant must be a uuid')
const envFile = path.resolve(process.cwd(), `.env.${target}`)
if (!existsSync(envFile)) die(`${envFile} not found (run from workers/)`)
const vars: Record<string, string> = {}
for (const raw of readFileSync(envFile, 'utf8').replace(/^﻿/, '').split(/\r?\n/)) {
  const line = raw.trim(); const eq = line.indexOf('=')
  if (line && !line.startsWith('#') && eq > 0) vars[line.slice(0, eq).trim()] = line.slice(eq + 1).trim().replace(/^(['"])(.*)\1$/, '$2')
}
if (vars['DB_TARGET'] !== target) die(`${path.basename(envFile)} has DB_TARGET="${vars['DB_TARGET'] ?? ''}", not "${target}"`)
const sql = neon(vars['DATABASE_URL'] ?? die('DATABASE_URL missing'))

const TITLE = 'Sightings evaluation (planted indicators)'
const PLANTED_IP = '188.184.67.127'          // info.cern.ch
const DOMAINS = 20

type Row = Record<string, unknown>

async function plant() {
  const existing = await sql`SELECT ti_event_id FROM ti_events WHERE tenant_id = ${tenant}::uuid AND title = ${TITLE}`
  if (existing.length) die('a planted event already exists in this tenant: run "remove" first')
  const domains = Array.from({ length: DOMAINS }, () => `ue-sight-${randomBytes(6).toString('hex')}.com`)
  const planted = { tenant, title: TITLE, domains, ip: PLANTED_IP, planted_at: new Date().toISOString() }
  console.log(JSON.stringify(planted, null, 2))
  if (!apply) { console.log('\nDry run: nothing written (add --apply)'); return }
  const [ev] = await sql`
    INSERT INTO ti_events (tenant_id, title, description, threat_level, status, distribution, published_at)
    VALUES (${tenant}::uuid, ${TITLE}, 'Random unregistered domains and one benign public IP, planted to measure threat sightings (scripts/sightings-eval.ts).',
            'high', 'published', 'organisation', now())
    RETURNING ti_event_id` as Row[]
  const id = String(ev!['ti_event_id'])
  for (const [type, value] of [...domains.map(d => ['domain', d]), ['ip', PLANTED_IP]] as [string, string][]) {
    await sql`
      INSERT INTO cti_indicators (source, indicator_type, value, tenant_id, ti_event_id, to_ids, first_seen, last_seen)
      VALUES (${`Event: ${TITLE}`.slice(0, 100)}, ${type}::indicator_type, ${value}, ${tenant}::uuid, ${id}::uuid, true, now(), now())`
  }
  if (outDir) {
    mkdirSync(outDir, { recursive: true })
    writeFileSync(path.join(outDir, 'sightings-planted.json'), JSON.stringify({ ...planted, ti_event_id: id }, null, 2))
    writeFileSync(path.join(outDir, 'planted-domains.txt'), domains.join('\n') + '\n')
  }
  console.log(`\nPlanted event ${id}: ${DOMAINS} domains and 1 IP (agents fetch it within 30 minutes, or at their next start)`)
}

async function measure() {
  const plantedFile = outDir ? path.join(outDir, 'sightings-planted.json') : null
  if (!plantedFile || !existsSync(plantedFile)) die('--out must hold sightings-planted.json from "plant"')
  const planted = JSON.parse(readFileSync(plantedFile, 'utf8')) as { domains: string[]; ip: string; planted_at: string }
  // --since <ISO time>: only alerts raised or updated since then (one test round)
  const since = arg('since') ?? planted.planted_at
  if (isNaN(Date.parse(since))) die('--since must be an ISO time')
  const rows = await sql`
    SELECT a.hostname, e.event_id, e.severity::text, e.status::text, e.timestamp AS created,
           e.details->>'indicator_value' AS listed, e.details->>'observed' AS observed,
           e.details->>'matched_on' AS matched_on, e.details->'seen_via' AS seen_via,
           (e.details->>'count')::int AS count, e.details->>'first_seen_at' AS first_contact,
           e.details->>'last_seen_at' AS last_contact, e.updated_at AS updated, e.details->>'process' AS process
    FROM events e JOIN assets a ON a.asset_id = e.asset_id
    WHERE a.tenant_id = ${tenant}::uuid AND e.event_type = 'cti_match' AND e.details->>'match_kind' = 'sighting'
      -- contacts in this round (not alerts a person edited: marking one false positive changes updated_at)
      AND (e.details->>'last_seen_at')::timestamptz >= ${since}::timestamptz
    ORDER BY a.hostname, e.timestamp` as Row[]
  const plantedSet = new Set([...planted.domains, planted.ip])
  const hosts = [...new Set(rows.map(r => String(r['hostname'])))]
  const perHost = hosts.map(host => {
    const mine = rows.filter(r => r['hostname'] === host)
    const found = new Set(mine.map(r => String(r['listed'])).filter(v => plantedSet.has(v)))
    // A new alert: created - first contact; one from an earlier round: its last update - last contact
    // (the contact's upload; nobody edits the planted alerts during a round).
    const delays = mine.filter(r => plantedSet.has(String(r['listed'])))
      .map(r => new Date(String(r['created'])) >= new Date(since)
        ? (new Date(String(r['created'])).getTime() - new Date(String(r['first_contact'])).getTime()) / 1000
        : (new Date(String(r['updated'])).getTime() - new Date(String(r['last_contact'])).getTime()) / 1000)
      .sort((a, b) => a - b)
    return {
      host,
      domains_detected: planted.domains.filter(d => found.has(d)).length, domains_planted: planted.domains.length,
      ip_detected: found.has(planted.ip),
      ip_via: mine.filter(r => r['listed'] === planted.ip).map(r => r['seen_via']),
      ip_process: mine.find(r => r['listed'] === planted.ip)?.['process'] ?? null,
      false_alerts: mine.filter(r => !plantedSet.has(String(r['listed']))).map(r => ({ listed: r['listed'], via: r['matched_on'] })),
      seconds_contact_to_alert: delays.length ? { median: delays[Math.floor(delays.length / 2)], max: delays[delays.length - 1] } : null,
      severities: [...new Set(mine.map(r => r['severity']))],
    }
  })
  const result = { measured_at: new Date().toISOString(), planted_at: planted.planted_at, since, hosts: perHost }
  console.log(JSON.stringify(result, null, 2))
  const label = arg('label')
  writeFileSync(path.join(outDir!, `sightings-measure${label ? `-${label}` : ''}.json`), JSON.stringify(result, null, 2))
}

async function remove() {
  const evs = await sql`SELECT ti_event_id FROM ti_events WHERE tenant_id = ${tenant}::uuid AND title = ${TITLE}` as Row[]
  console.log(`${evs.length} planted event(s)`)
  if (!apply) { console.log('Dry run: nothing deleted (add --apply)'); return }
  for (const ev of evs) await sql`DELETE FROM ti_events WHERE ti_event_id = ${String(ev['ti_event_id'])}::uuid`
  console.log('Deleted (their indicators go with them); the sighting alerts stay for people to close.')
}

(cmd === 'plant' ? plant() : cmd === 'measure' ? measure() : remove()).catch(err => die(String(err?.stack ?? err)))
