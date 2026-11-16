/**
 * ti-usefulness.ts — READ-ONLY evaluation of how useful the threat-intelligence page is to
 * a small team: does the intel ever touch the tenant's own assets, how accurate is it when
 * it does, does it change what is fixed first, and is anyone using it.
 *
 *  1. Knowledge base   indicators by source and type, how many can ever alert (to_ids, not
 *                      warninglisted, a type assets can match), families, ATT&CK, freshness
 *  2. Relevance        intel that reached an asset: indicator matches (R5/R6), KEV and
 *                      threat-intel-event CVE alerts, exploited Windows patches
 *  3. Accuracy         how analysts closed indicator matches (false positive vs fixed)
 *  4. Prioritisation   per tenant, how many of the top 10/20/50 alerts in the queue are there
 *                      because of threat intel (the +100/+200 boosts of lib/priority.ts)
 *  5. Events           MISP-style events written and the alerts they drive
 *  6. Use              audit-log actions on threat intel
 *
 * Run from workers/ (reads .env.<target>; DB_TARGET must match, as in scripts/db):
 *   npx esbuild scripts/ti-usefulness.ts --bundle --platform=node --format=cjs --outfile=.ti-usefulness.cjs
 *   node .ti-usefulness.cjs --target staging [--out <dir>]
 *
 * Only SELECTs. Tenants are reported as "tenant 1, 2..." and no indicator values, hostnames
 * or addresses are printed.
 */
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs'
import path from 'node:path'
import { neon } from '@neondatabase/serverless'

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
const url = vars['DATABASE_URL'] ?? die('DATABASE_URL missing')

type Row = Record<string, unknown>
const pct = (a: number, b: number) => (b ? `${(100 * a / b).toFixed(1)}%` : 'n/a')

// lib/priority.ts, in TypeScript: the same terms, so the queue order can be rebuilt with and without intel
const SEVERITY_FLOOR: Record<string, number> = { critical: 70, high: 50, medium: 30 }
function ctiBoost(r: Row): number {
  const d = (r['details'] ?? {}) as Record<string, unknown>
  if (r['event_type'] === 'os_patch_missing') return Number(d['exploited'] ?? 0) > 0 ? 100 : 0
  if (r['event_type'] === 'cti_match') return d['match_kind'] === 'watchlist' ? 100 : 200
  if (d['has_cti_match'] !== true) return 0
  return r['event_type'] === 'cve_detected' ? 100 : 200
}
function basePriority(r: Row): number {
  const base = r['score'] != null ? Number(r['score']) : SEVERITY_FLOOR[r['severity'] as string] ?? 10
  return base * (r['internet_facing'] ? 1.5 : 1) + Number(r['crit'] ?? 5) * 2
}

async function main() {
  const sql = neon(url)
  const report: Record<string, unknown> = { generated: new Date().toISOString(), target }

  // ── 1. Knowledge base ──
  const kb = await sql`
    SELECT source, count(*)::int AS n,
           count(*) FILTER (WHERE to_ids AND warning IS NULL AND indicator_type IN ('ip', 'domain', 'url', 'cve'))::int AS can_alert,
           count(*) FILTER (WHERE warning IS NOT NULL)::int AS warninglisted,
           count(*) FILTER (WHERE indicator_type = 'hash')::int AS hashes,
           count(malware_family)::int AS with_family,
           count(*) FILTER (WHERE attack_software IS NOT NULL OR attack_techniques IS NOT NULL)::int AS with_attack,
           count(*) FILTER (WHERE last_seen > now() - interval '7 days')::int AS seen_7d,
           to_char(max(last_seen), 'YYYY-MM-DD') AS newest
    FROM cti_indicators WHERE ti_event_id IS NULL GROUP BY source ORDER BY n DESC` as Row[]
  const byType = await sql`
    SELECT indicator_type AS type, count(*)::int AS n FROM cti_indicators WHERE ti_event_id IS NULL GROUP BY 1 ORDER BY 2 DESC` as Row[]
  report['knowledge_base'] = { by_source: kb, by_type: byType }
  console.log(`\n1. KNOWLEDGE BASE (${target})`)
  console.table(kb)
  console.log('By type:', byType.map((r) => `${r['type']} ${r['n']}`).join(', '))

  // ── 2. Relevance: intel that reached an asset ──
  const tenants = await sql`
    SELECT t.tenant_id, count(DISTINCT a.asset_id)::int AS assets
    FROM tenants t LEFT JOIN assets a ON a.tenant_id = t.tenant_id GROUP BY t.tenant_id ORDER BY 2 DESC` as Row[]
  const label = new Map(tenants.map((t, i) => [t['tenant_id'] as string, `tenant ${i + 1}`]))
  const matches = await sql`
    SELECT a.tenant_id, e.details->>'rule' AS rule, e.details->>'matched_on' AS matched_on, e.details->>'indicator_type' AS itype,
           e.status::text AS status, (e.resolved_by IS NOT NULL) AS by_person,
           jsonb_array_length(COALESCE(e.details->'ti_event_ids', '[]'::jsonb)) > 0 AS from_event, e.asset_id
    FROM events e JOIN assets a ON a.asset_id = e.asset_id WHERE e.event_type = 'cti_match'` as Row[]
  const cveIntel = await sql`
    SELECT a.tenant_id, e.status::text AS status, e.details->>'cve_id' AS cve,
           COALESCE((e.details->>'kev')::boolean, false) AS kev,
           COALESCE((e.details->>'has_cti_match')::boolean, false) AS cti,
           jsonb_array_length(COALESCE(e.details->'ti_event_titles', '[]'::jsonb)) > 0 AS from_event
    FROM events e JOIN assets a ON a.asset_id = e.asset_id WHERE e.event_type = 'cve_detected'` as Row[]
  const patches = await sql`
    SELECT count(*)::int AS n, count(*) FILTER (WHERE COALESCE((details->>'exploited')::int, 0) > 0)::int AS exploited
    FROM events WHERE event_type = 'os_patch_missing'` as Row[]

  const open = (s: unknown) => s === 'open' || s === 'in_progress'
  const cveOpen = cveIntel.filter((r) => open(r['status']))
  const relevance = {
    tenants: tenants.length,
    indicator_matches: {
      total: matches.length, open: matches.filter((m) => open(m['status'])).length,
      assets: new Set(matches.map((m) => m['asset_id'])).size,
      tenants_with_any: new Set(matches.map((m) => m['tenant_id'])).size,
      by_rule: Object.fromEntries(['R5', 'R6'].map((r) => [r, matches.filter((m) => m['rule'] === r).length])),
      by_matched_on: matches.reduce((acc, m) => ({ ...acc, [String(m['matched_on'])]: ((acc as Record<string, number>)[String(m['matched_on'])] ?? 0) + 1 }), {} as Record<string, number>),
      from_tenant_events: matches.filter((m) => m['from_event']).length,
    },
    cve_alerts: {
      total: cveIntel.length, open: cveOpen.length,
      open_kev: cveOpen.filter((r) => r['kev']).length,
      open_kev_cves: new Set(cveOpen.filter((r) => r['kev']).map((r) => r['cve'])).size,
      open_with_intel: cveOpen.filter((r) => r['cti']).length,
      open_from_tenant_events: cveOpen.filter((r) => r['from_event']).length,
      tenants_with_kev: new Set(cveOpen.filter((r) => r['kev']).map((r) => r['tenant_id'])).size,
    },
    windows_patch_alerts: patches[0],
  }
  report['relevance'] = relevance
  const im = relevance.indicator_matches, ca = relevance.cve_alerts
  console.log('\n2. RELEVANCE: intel that reached the tenants\' own assets')
  console.log(`  Indicator matches (R5 address/domain, R6 watched software): ${im.total} ever, ${im.open} open, on ${im.assets} assets in ${im.tenants_with_any}/${relevance.tenants} tenants`)
  console.log(`    by rule ${JSON.stringify(im.by_rule)}; matched on ${JSON.stringify(im.by_matched_on)}; from tenant events ${im.from_tenant_events}`)
  console.log(`  CVE alerts: ${ca.open} open, ${ca.open_with_intel} carry threat intel (${pct(ca.open_with_intel, ca.open)}): ${ca.open_kev} KEV (${ca.open_kev_cves} CVEs, ${ca.tenants_with_kev} tenants), ${ca.open_from_tenant_events} from tenant events`)
  console.log(`  Missing Windows patches: ${relevance.windows_patch_alerts?.['n']} alerts, ${relevance.windows_patch_alerts?.['exploited']} fix exploited CVEs (MSRC)`)

  // ── 3. Accuracy: how analysts closed indicator matches ──
  const closedByPerson = matches.filter((m) => !open(m['status']) && m['by_person'])
  const accuracy = {
    closed_by_person: closedByPerson.length,
    false_positive: closedByPerson.filter((m) => m['status'] === 'false_positive').length,
    resolved: closedByPerson.filter((m) => m['status'] === 'resolved').length,
    accepted_risk: closedByPerson.filter((m) => m['status'] === 'accepted_risk').length,
    closed_by_system: matches.filter((m) => !open(m['status']) && !m['by_person']).length,
  }
  report['accuracy'] = accuracy
  console.log('\n3. ACCURACY of indicator matches, from how people closed them')
  console.log(`  closed by a person: ${accuracy.closed_by_person} (false positive ${accuracy.false_positive}, fixed ${accuracy.resolved}, accepted risk ${accuracy.accepted_risk}); closed by the system (match no longer holds): ${accuracy.closed_by_system}`)

  // ── 4. Prioritisation: does intel change the top of each tenant's queue? ──
  const queue = await sql`
    SELECT a.tenant_id, e.event_type::text AS event_type, e.severity::text AS severity, e.details,
           e.composite_risk_score::float AS score, a.is_internet_facing AS internet_facing, a.criticality_score AS crit
    FROM events e JOIN assets a ON a.asset_id = e.asset_id
    WHERE e.status IN ('open', 'in_progress')` as Row[]
  const perTenant: Record<string, unknown>[] = []
  for (const [tid, name] of label) {
    const rows = queue.filter((r) => r['tenant_id'] === tid)
    if (!rows.length) continue
    const withIntel = [...rows].sort((a, b) => (basePriority(b) + ctiBoost(b)) - (basePriority(a) + ctiBoost(a)))
    const without = [...rows].sort((a, b) => basePriority(b) - basePriority(a))
    const t: Record<string, unknown> = { tenant: name, open_alerts: rows.length, boosted: rows.filter((r) => ctiBoost(r) > 0).length }
    for (const k of [10, 20, 50]) {
      const top = withIntel.slice(0, k), topWithout = new Set(without.slice(0, k))
      t[`top${k}_boosted`] = top.filter((r) => ctiBoost(r) > 0).length
      t[`top${k}_only_because_of_intel`] = top.filter((r) => !topWithout.has(r)).length
    }
    perTenant.push(t)
  }
  report['prioritisation'] = perTenant
  console.log('\n4. PRIORITISATION: alerts in each tenant\'s top N that are there because of threat intel')
  console.table(perTenant)

  // ── 5. Threat-intel events (MISP-style) ──
  const tiEv = await sql`
    SELECT te.tenant_id, te.status::text AS status, te.distribution::text AS distribution,
           (SELECT count(*)::int FROM cti_indicators c WHERE c.ti_event_id = te.ti_event_id) AS attributes
    FROM ti_events te` as Row[]
  report['ti_events'] = {
    total: tiEv.length, published: tiEv.filter((e) => e['status'] === 'published').length,
    tenants_authoring: new Set(tiEv.map((e) => e['tenant_id'] ?? 'platform')).size,
    attributes: tiEv.reduce((a, e) => a + Number(e['attributes']), 0),
    by_distribution: tiEv.reduce((acc, e) => ({ ...acc, [String(e['distribution'])]: ((acc as Record<string, number>)[String(e['distribution'])] ?? 0) + 1 }), {} as Record<string, number>),
  }
  console.log('\n5. THREAT-INTEL EVENTS:', JSON.stringify(report['ti_events']))

  // ── 6. Use: what people did with threat intel (audit log) ──
  const audit = await sql`
    SELECT action_type, count(*)::int AS n, count(DISTINCT user_id)::int AS users,
           to_char(min(timestamp), 'YYYY-MM-DD') AS first, to_char(max(timestamp), 'YYYY-MM-DD') AS last
    FROM audit_logs
    WHERE action_type ILIKE ANY (ARRAY['%cti%', '%ti_event%', '%threat%', '%indicator%', '%lookup%', '%ingest%'])
       OR target_entity ILIKE ANY (ARRAY['%cti%', '%ti_event%'])
    GROUP BY action_type ORDER BY n DESC` as Row[]
  const alertActions = await sql`
    SELECT e.event_type::text AS event_type, l.action_type, count(*)::int AS n
    FROM audit_logs l JOIN events e ON l.target_entity = e.event_id::text
    WHERE e.event_type = 'cti_match' AND l.user_id IS NOT NULL GROUP BY 1, 2 ORDER BY n DESC` as Row[]
  report['use'] = { audit_actions: audit, actions_on_indicator_matches: alertActions }
  console.log('\n6. USE (audit log)')
  console.table(audit)
  if (alertActions.length) console.table(alertActions)

  if (outDir) {
    mkdirSync(outDir, { recursive: true })
    const file = path.join(outDir, `ti-usefulness-${target}.json`)
    writeFileSync(file, JSON.stringify(report, null, 2))
    console.log(`\nWrote ${file}`)
  }
}

main().catch((e) => die(e instanceof Error ? e.message : String(e)))
