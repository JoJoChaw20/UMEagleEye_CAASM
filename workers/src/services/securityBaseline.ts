import { and, desc, eq, inArray, isNotNull } from 'drizzle-orm'
import type { DB } from '../db/client'
import { assets, events, tenants } from '../db/schema'
import { OPEN_STATUSES } from '../lib/eventStatus'
import { baselineColumns, DEFAULT_TARGET, planBaselineAlert, type StoredBaseline } from '../lib/baseline'
import { sameJson } from '../lib/rescore'

// Security baseline (lib/baseline.ts): the score is stored on each computer from its inventory
// (routes/agents.ts), and one security_baseline alert is kept per computer under its tenant's target.
// The alerts follow the stored scores: after an inventory (that computer), after the target changes
// (the whole tenant), and nightly (refreshTenantBaselines: "OS still supported" depends on the date,
// and a rule change applies without new agent runs).

const CHUNK = 200

export async function tenantTarget(db: DB, tenantId: string): Promise<number> {
  const [t] = await db.select({ target: tenants.securityBaselineTarget }).from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
  return t?.target ?? DEFAULT_TARGET
}

export interface BaselineAlertCounts { opened: number; updated: number; resolved: number; suppressed: number }

/** Open, update or resolve the Below baseline alerts of a tenant's computers (all, or `assetIds`). */
export async function syncBaselineAlerts(db: DB, tenantId: string, assetIds?: string[], now = new Date()): Promise<BaselineAlertCounts> {
  const counts: BaselineAlertCounts = { opened: 0, updated: 0, resolved: 0, suppressed: 0 }
  const target = await tenantTarget(db, tenantId)
  const scope = assetIds?.length ? inArray(assets.assetId, assetIds) : undefined
  const rows = await db.select({ assetId: assets.assetId, stored: assets.securityBaseline })
    .from(assets)
    .where(and(eq(assets.tenantId, tenantId), isNotNull(assets.securityBaseline), scope))
  const stmts: unknown[] = []
  for (let i = 0; i < rows.length; i += CHUNK) {
    const slice = rows.slice(i, i + CHUNK)
    const alerts = await db.select({ eventId: events.eventId, assetId: events.assetId, status: events.status, details: events.details })
      .from(events)
      .where(and(eq(events.eventType, 'security_baseline'), inArray(events.assetId, slice.map(r => r.assetId))))
      .orderBy(desc(events.updatedAt))
    for (const row of slice) {
      const mine = alerts.filter(a => a.assetId === row.assetId)
      const open = mine.filter(a => OPEN_STATUSES.includes(a.status))
      if (open.length > 1) {                                  // two open copies (assets merged): keep the newest
        stmts.push(db.update(events)
          .set({ status: 'resolved', resolvedAt: now, updatedAt: now, resolutionNote: 'Merged into an identical open alert on the same asset' })
          .where(inArray(events.eventId, open.slice(1).map(a => a.eventId))))
      }
      const plan = planBaselineAlert(row.stored as StoredBaseline | null, target, open[0] ?? null, open.length ? null : mine[0] ?? null)
      if (plan.kind === 'open') {
        stmts.push(db.insert(events).values({
          assetId: row.assetId, eventType: 'security_baseline', severity: plan.severity, details: plan.details, firstSeen: now, lastSeen: now,
        }))
        counts.opened++
      } else if (plan.kind === 'update') {
        stmts.push(db.update(events).set({ severity: plan.severity, details: plan.details, lastSeen: now, updatedAt: now })
          .where(eq(events.eventId, plan.eventId)))
        counts.updated++
      } else if (plan.kind === 'resolve') {
        stmts.push(db.update(events).set({ status: 'resolved', resolvedAt: now, updatedAt: now, resolutionNote: plan.note })
          .where(eq(events.eventId, plan.eventId)))
        counts.resolved++
      } else if (plan.kind === 'suppressed') {
        counts.suppressed++
      }
    }
  }
  for (let i = 0; i < stmts.length; i += 100) {
    await db.batch(stmts.slice(i, i + 100) as unknown as Parameters<typeof db.batch>[0])
  }
  return counts
}

export interface BaselineSummary {
  /** The tenant's target; null across tenants (superadmin without a tenant: each uses its own). */
  target: number | null
  /** Computers with a baseline result, and those with enough readable checks to be scored. */
  computers: number
  assessed: number
  at_target: number
  /** All passed checks / all judged checks of the assessed computers (one bad server is not averaged away). */
  percent: number | null
  by_os: Record<string, { assessed: number; at_target: number; percent: number | null }>
  lowest: { asset_id: string; hostname: string | null; os: string; percent: number; target: number }[]
}

/** The organisation's figure for the dashboard and reports. */
export async function baselineSummary(db: DB, tenantId: string | undefined): Promise<BaselineSummary> {
  const rows = await db.select({
    assetId: assets.assetId, hostname: assets.hostname, stored: assets.securityBaseline, target: tenants.securityBaselineTarget,
  }).from(assets)
    .innerJoin(tenants, eq(tenants.tenantId, assets.tenantId))
    .where(and(isNotNull(assets.securityBaseline), tenantId ? eq(assets.tenantId, tenantId) : undefined))
  const pct = (p: number, j: number) => (j ? Math.floor((1000 * p) / j) / 10 : null)
  const scored = rows.map(r => ({ ...r, b: r.stored as StoredBaseline })).filter(r => r.b?.assessed && r.b.percent != null)
  const byOs: BaselineSummary['by_os'] = {}
  for (const os of new Set(scored.map(r => r.b.os))) {
    const mine = scored.filter(r => r.b.os === os)
    byOs[os] = {
      assessed: mine.length, at_target: mine.filter(r => r.b.percent! >= r.target).length,
      percent: pct(mine.reduce((n, r) => n + r.b.passed, 0), mine.reduce((n, r) => n + r.b.judged, 0)),
    }
  }
  return {
    target: tenantId ? rows[0]?.target ?? await tenantTarget(db, tenantId) : null,
    computers: rows.length,
    assessed: scored.length,
    at_target: scored.filter(r => r.b.percent! >= r.target).length,
    percent: pct(scored.reduce((n, r) => n + r.b.passed, 0), scored.reduce((n, r) => n + r.b.judged, 0)),
    by_os: byOs,
    lowest: scored.sort((a, b) => a.b.percent! - b.b.percent!).slice(0, 5)
      .map(r => ({ asset_id: r.assetId, hostname: r.hostname, os: r.b.os, percent: r.b.percent!, target: r.target })),
  }
}

/** Nightly: re-judge every computer's stored inventory (dates, rule changes), then its alerts. */
export async function refreshTenantBaselines(db: DB, tenantId: string, now = new Date()): Promise<{ changed: number } & BaselineAlertCounts> {
  const rows = await db.select({
    assetId: assets.assetId, inventory: assets.endpointInventory, collectedAt: assets.inventoryCollectedAt, stored: assets.securityBaseline,
  }).from(assets).where(and(eq(assets.tenantId, tenantId), isNotNull(assets.endpointInventory)))
  const stmts: unknown[] = []
  for (const r of rows) {
    const cols = baselineColumns(r.inventory, r.collectedAt, now)
    if (!sameJson(cols.securityBaseline, r.stored ?? null)) {
      stmts.push(db.update(assets).set(cols).where(eq(assets.assetId, r.assetId)))
    }
  }
  for (let i = 0; i < stmts.length; i += 100) {
    await db.batch(stmts.slice(i, i + 100) as unknown as Parameters<typeof db.batch>[0])
  }
  return { changed: stmts.length, ...(await syncBaselineAlerts(db, tenantId, undefined, now)) }
}
