import type { DB } from '../db/client'
import { assets, events, advisories, postureMetrics } from '../db/schema'
import { eq, and, gte, count, sql } from 'drizzle-orm'

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

  // Open critical events in last 7 days
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
  const criticalEventRows = await db
    .select({ eventId: events.eventId, assetId: events.assetId })
    .from(events)
    .where(and(
      eq(events.severity, 'critical'),
      gte(events.timestamp, sevenDaysAgo)
    ))

  // Filter to this tenant's assets
  const tenantAssetIds = new Set(allAssets.map(a => a.assetId))
  const openCritical = criticalEventRows.filter(e => tenantAssetIds.has(e.assetId))
  const openCriticalEvents = openCritical.length

  // High events in last 7 days
  const highEventRows = await db
    .select({ eventId: events.eventId })
    .from(events)
    .where(and(eq(events.severity, 'high'), gte(events.timestamp, sevenDaysAgo)))

  const openHighEvents = highEventRows.filter(e =>
    'assetId' in e ? tenantAssetIds.has((e as { assetId: string }).assetId) : false
  ).length

  // Score calculation
  let score = 100
  score -= Math.min(openCriticalEvents * 5, 40)   // -5 per critical, max -40
  score -= Math.min(openHighEvents * 2, 20)         // -2 per high, max -20
  if (totalAssets > 0 && totalCriticalAssets / totalAssets > 0.2) {
    score -= 10  // >20% assets are high-criticality
  }
  score = Math.max(0, Math.min(100, score))

  // Top risks: assets with most recent critical events
  const topRisks = criticalAssets.slice(0, 5).map(a => ({
    asset_id: a.assetId,
    ip: a.ipAddress,
    hostname: a.hostname ?? null,
    risk: 'High criticality asset',
  }))

  return {
    overallScore: Math.round(score),
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
