/**
 * ranking-eval.ts — READ-ONLY comparison of the old alert priority (before 22 Nov 2026) and the
 * tiered ranking (lib/alertRank.ts, lib/priority.ts) on the same open alerts, plus a parity check
 * that the SQL expressions agree with the pure functions on every alert.
 *
 * Per tenant: what the top 10 / 20 hold under each ranking (by tier and alert type), how many
 * informational changes (new devices, configuration changes) sit above a critical or exploited
 * vulnerability, and where exploited (KEV) and threat-intel alerts land.
 *
 * Run from workers/:
 *   npx esbuild scripts/ranking-eval.ts --bundle --platform=node --format=cjs --outfile=.ranking-eval.cjs
 *   node .ranking-eval.cjs --target staging [--out <dir>]
 * Only SELECTs. Tenants are reported as "tenant 1, 2...", no hostnames or addresses.
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { neon } from '@neondatabase/serverless'
import { drizzle } from 'drizzle-orm/neon-http'
import { and, eq, inArray, sql } from 'drizzle-orm'
import { assets, events } from '../src/db/schema'
import { priorityExpr, rankScoreExpr, tierExpr, dueStatusExpr, slaKeyExpr } from '../src/lib/priority'
import { priorityOf, rankScore, tierOf, slaKeyOf, type Severity } from '../src/lib/alertRank'
// @ts-expect-error plain .mjs helper shared by the db scripts
import { loadEnvFile } from './db/lib.mjs'

const arg = (n: string) => { const i = process.argv.indexOf(`--${n}`); return i > 0 ? process.argv[i + 1] : undefined }
const target = arg('target') ?? 'staging'
const out = arg('out')

// The priority as it was before the tiered ranking (lib/priority.ts at commit fbf72e8)
const oldPriority = sql<number>`round((
  COALESCE(${events.compositeRiskScore}::numeric, CASE ${events.severity} WHEN 'critical' THEN 70 WHEN 'high' THEN 50 WHEN 'medium' THEN 30 ELSE 10 END)
  * CASE WHEN ${events.eventType} = 'cve_detected' AND ${events.details}->>'shape' = 'package'
              AND COALESCE((${events.details}->>'fixable_count')::int, 1) = 0 AND (${events.details}->>'kev')::boolean IS NOT TRUE THEN 0.5 ELSE 1 END
  * CASE WHEN ${assets.isInternetFacing} THEN 1.5 ELSE 1 END + COALESCE(${assets.criticalityScore}, 5) * 2
  + CASE WHEN ${events.eventType} = 'os_patch_missing' THEN CASE WHEN COALESCE((${events.details}->>'exploited')::int, 0) > 0 THEN 100 ELSE 0 END
         WHEN ${events.eventType} = 'cti_match' AND ${events.details}->>'match_kind' = 'watchlist' THEN 100
         WHEN ${events.eventType} = 'cti_match' THEN 200
         WHEN (${events.details}->>'has_cti_match')::boolean IS NOT TRUE THEN 0
         WHEN ${events.eventType} = 'cve_detected' THEN 100 ELSE 200 END)::numeric, 1)::float`

type Row = {
  tenantId: string; type: string; severity: Severity; details: Record<string, unknown>; score: string | null
  internet: boolean | null; crit: number | null; oldP: number; newP: number; tier: number; rank: number; due: string; slaKey: string
}
const INFO = new Set(['new_device', 'config_change', 'version_downgrade'])
const isKev = (d: Record<string, unknown>) => d.kev === true || Number(d.kev_count ?? 0) > 0
const isSevereVuln = (r: Row) => ['cve_detected', 'vulnerable_service', 'os_patch_missing'].includes(r.type) && (r.severity === 'critical' || isKev(r.details))

function summary(rows: Row[], key: 'oldP' | 'newP', n: number) {
  const top = [...rows].sort((a, b) => b[key] - a[key]).slice(0, n)
  const byType: Record<string, number> = {}
  for (const r of top) byType[r.type] = (byType[r.type] ?? 0) + 1
  return {
    by_type: byType,
    informational: top.filter((r) => INFO.has(r.type)).length,
    kev: top.filter((r) => isKev(r.details)).length,
    threat_intel: top.filter((r) => r.type === 'cti_match' && r.details.match_kind !== 'watchlist').length,
  }
}

/** How many informational alerts rank above at least one critical or exploited vulnerability. */
function infoAboveSevere(rows: Row[], key: 'oldP' | 'newP'): number {
  const severe = rows.filter(isSevereVuln)
  if (!severe.length) return 0
  const lowest = Math.min(...severe.map((r) => r[key]))
  return rows.filter((r) => INFO.has(r.type) && r[key] > lowest).length
}

async function main() {
  const { DATABASE_URL } = loadEnvFile(target)
  const db = drizzle(neon(DATABASE_URL))
  const rows = await db.select({
    tenantId: assets.tenantId, type: events.eventType, severity: events.severity, details: events.details,
    score: events.compositeRiskScore, internet: assets.isInternetFacing, crit: assets.criticalityScore,
    oldP: oldPriority, newP: priorityExpr, tier: tierExpr, rank: rankScoreExpr, due: dueStatusExpr, slaKey: slaKeyExpr,
  }).from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
    .where(and(inArray(events.status, ['open', 'in_progress']), sql`${assets.tenantId} IS NOT NULL`)) as unknown as Row[]

  // Parity: the SQL against the pure functions, every alert
  const mismatches: unknown[] = []
  for (const r of rows) {
    const input = { type: r.type, severity: r.severity, details: (r.details ?? {}) as Record<string, unknown>,
      compositeRiskScore: r.score == null ? null : Number(r.score), internetFacing: !!r.internet, criticality: r.crit }
    const t = tierOf(input), s = rankScore(input)
    const k = slaKeyOf(t, r.severity, !!r.internet)
    if (t !== Number(r.tier) || Math.abs(s - Number(r.rank)) > 0.11 || Math.abs(priorityOf(input) - Number(r.newP)) > 0.11 || k !== r.slaKey) {
      mismatches.push({ type: r.type, severity: r.severity, sql: { tier: r.tier, rank: r.rank, key: r.slaKey }, pure: { tier: t, rank: s, key: k } })
    }
  }

  const tenants = [...new Set(rows.map((r) => r.tenantId))]
  const perTenant = tenants.map((tid, i) => {
    const rs = rows.filter((r) => r.tenantId === tid)
    const tiers: Record<string, number> = {}
    for (const r of rs) tiers[`tier ${r.tier}`] = (tiers[`tier ${r.tier}`] ?? 0) + 1
    const due: Record<string, number> = {}
    for (const r of rs) due[r.due] = (due[r.due] ?? 0) + 1
    return {
      tenant: `tenant ${i + 1}`, open_alerts: rs.length, tiers, due_status: due,
      top10: { old: summary(rs, 'oldP', 10), new: summary(rs, 'newP', 10) },
      top20: { old: summary(rs, 'oldP', 20), new: summary(rs, 'newP', 20) },
      informational_above_a_critical_or_exploited_vulnerability: { old: infoAboveSevere(rs, 'oldP'), new: infoAboveSevere(rs, 'newP') },
    }
  }).filter((t) => t.open_alerts > 0)

  const result = { generated: new Date().toISOString(), target, alerts: rows.length, parity_mismatches: mismatches.length, mismatch_examples: mismatches.slice(0, 10), tenants: perTenant }
  console.log(JSON.stringify(result, null, 1))
  if (out) {
    mkdirSync(out, { recursive: true })
    const file = path.join(out, `ranking-eval-${target}.json`)
    writeFileSync(file, JSON.stringify(result, null, 1))
    console.error(`Wrote ${file}`)
  }
}

main().catch((e) => { console.error(e); process.exit(1) })
