// The database side of the exposure rules (lib/exposureRules.ts): after an ACTIVE scan upload, each
// scanned device's exposures are raised, refreshed, reopened or closed. One read and one batch for the
// whole upload (the Workers free plan counts every query as a subrequest).
import { and, eq, inArray, sql } from 'drizzle-orm'
import type { DB } from '../db/client'
import { assets, events } from '../db/schema'
import { exposuresOf, planExposure, type ExposureFinding, type OpenExposure } from '../lib/exposureRules'

export interface ExposureResult { created: number; refreshed: number; reopened: number; resolved: number }

const detailsOf = (f: ExposureFinding) => ({ rule: f.rule, port: f.port, title: f.title, fix: f.fix, evidence: f.evidence })

export async function applyExposures(db: DB, assetIds: string[], scannedPorts: number[] | null,
  now = new Date()): Promise<ExposureResult> {
  const result: ExposureResult = { created: 0, refreshed: 0, reopened: 0, resolved: 0 }
  const ids = [...new Set(assetIds)]
  if (!ids.length) return result
  const [devices, existing] = await Promise.all([
    db.select({ assetId: assets.assetId, osInfo: assets.osInfo, internetFacing: assets.isInternetFacing,
      criticality: assets.criticalityScore, deviceType: assets.deviceType })
      .from(assets).where(inArray(assets.assetId, ids)),
    db.select({ eventId: events.eventId, assetId: events.assetId, status: events.status, details: events.details })
      .from(events).where(and(eq(events.eventType, 'exposure'), inArray(events.assetId, ids))),
  ])
  const byAsset = new Map<string, OpenExposure[]>()
  for (const e of existing) {
    const d = (e.details ?? {}) as { rule?: string; port?: number }
    if (!d.rule || !Number.isInteger(d.port)) continue
    const list = byAsset.get(e.assetId) ?? []
    list.push({ eventId: e.eventId, status: e.status, rule: d.rule, port: d.port! })
    byAsset.set(e.assetId, list)
  }
  const checked = scannedPorts?.length ? new Set(scannedPorts) : null
  const stmts: unknown[] = []
  for (const d of devices) {
    const os = (d.osInfo ?? {}) as { services?: unknown; name?: string; os_name?: string }
    const findings = exposuresOf(os.services, {
      internetFacing: !!d.internetFacing, criticality: d.criticality ?? null, deviceType: d.deviceType ?? null,
      osName: os.name ?? os.os_name ?? null, now,
    })
    const plan = planExposure(findings, byAsset.get(d.assetId) ?? [], checked)
    for (const f of plan.create) {
      stmts.push(db.insert(events).values({ assetId: d.assetId, eventType: 'exposure', severity: f.severity,
        details: detailsOf(f), firstSeen: now, lastSeen: now }))
    }
    for (const r of plan.refresh) {
      stmts.push(db.update(events).set({
        severity: r.finding.severity, details: detailsOf(r.finding), lastSeen: now, updatedAt: now,
        occurrences: sql`${events.occurrences} + 1`,
        ...(r.reopen ? { status: 'open' as const, resolvedAt: null, resolvedBy: null, resolutionNote: null } : {}),
      }).where(eq(events.eventId, r.eventId)))
    }
    if (plan.resolve.length) {
      stmts.push(db.update(events).set({ status: 'resolved', resolvedAt: now, updatedAt: now,
        resolutionNote: 'No longer seen: an active scan checked the port and the problem is gone.' })
        .where(inArray(events.eventId, plan.resolve)))
    }
    result.created += plan.create.length
    result.refreshed += plan.refresh.length
    result.reopened += plan.refresh.filter((r) => r.reopen).length
    result.resolved += plan.resolve.length
  }
  for (let i = 0; i < stmts.length; i += 200) {
    const part = stmts.slice(i, i + 200)
    if (part.length) await db.batch(part as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
  }
  return result
}
