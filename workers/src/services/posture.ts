import type { DB } from '../db/client'
import { assets, events, advisories, postureMetrics } from '../db/schema'
import { eq, and, inArray, sql } from 'drizzle-orm'
import { isOpenEvent, postureScore } from '../lib/eventStatus'

interface PostureResult {
  overallScore: number
  totalAssets: number
  totalCriticalAssets: number
  openCriticalEvents: number
  topRisks: Array<{ asset_id: string; ip: string; hostname: string | null; risk: string }>
}

export async function computePosture(db: DB, tenantId?: string): Promise<PostureResult> {
  // Fetch asset counts
  const assetFilter = tenantId ? eq(assets.tenantId, tenantId) : undefined
  const allAssets = await db
    .select({ assetId: assets.assetId, ipAddress: assets.ipAddress, hostname: assets.hostname,
               criticalityScore: assets.criticalityScore, tenantId: assets.tenantId })
    .from(assets)
    .where(assetFilter)

  const totalAssets = allAssets.length
  const criticalAssets = allAssets.filter(a => (a.criticalityScore ?? 0) >= 8)
  const totalCriticalAssets = criticalAssets.length

  // Open critical/high alerts — same definition as /posture/current
  const sevRows = await db
    .select({ severity: events.severity, count: sql<number>`count(*)::int` })
    .from(events)
    .innerJoin(assets, eq(events.assetId, assets.assetId))
    .where(and(assetFilter, isOpenEvent(), inArray(events.severity, ['critical', 'high'])))
    .groupBy(events.severity)
  const openCriticalEvents = sevRows.find(r => r.severity === 'critical')?.count ?? 0
  const openHighEvents     = sevRows.find(r => r.severity === 'high')?.count ?? 0

  const score = postureScore(openCriticalEvents, openHighEvents, totalAssets, totalCriticalAssets)

  // Top risks: assets with most recent critical events
  const topRisks = criticalAssets.slice(0, 5).map(a => ({
    asset_id: a.assetId,
    ip: a.ipAddress,
    hostname: a.hostname ?? null,
    risk: 'High criticality asset',
  }))

  return {
    overallScore: score,
    totalAssets,
    totalCriticalAssets,
    openCriticalEvents,
    topRisks,
  }
}

export async function savePostureSnapshot(db: DB, tenantId?: string): Promise<void> {
  const result = await computePosture(db, tenantId)
  await db.insert(postureMetrics).values({
    tenantId: tenantId ?? null,
    overallScore: result.overallScore,
    totalAssets: result.totalAssets,
    totalCriticalAssets: result.totalCriticalAssets,
    openCriticalEvents: result.openCriticalEvents,
    topRisks: result.topRisks,
  })
}
