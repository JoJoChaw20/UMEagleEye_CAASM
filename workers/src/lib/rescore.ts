/**
 * Bulk criticality rescoring.
 * Fetches topology layer for each asset (if available) then calls
 * computeCriticality and writes the updated score back to the DB.
 */
import { eq, inArray } from 'drizzle-orm'
import { getDb } from '../db/client'
import { assets, topologyNodes } from '../db/schema'
import { computeCriticality } from './criticality'

type DbClient = ReturnType<typeof getDb>

/**
 * Rescore a set of assets (by ID) within a tenant.
 * If assetIds is empty, rescores ALL assets for the tenant.
 * Returns the number of assets updated.
 */
export async function rescoreAssets(
  db: DbClient,
  tenantId: string | null,
  assetIds?: string[],
): Promise<number> {
  // Fetch asset rows
  let rows: (typeof assets.$inferSelect)[]
  if (assetIds && assetIds.length > 0) {
    rows = await db.select().from(assets).where(inArray(assets.assetId, assetIds))
  } else if (tenantId) {
    rows = await db.select().from(assets).where(eq(assets.tenantId, tenantId))
  } else {
    return 0
  }
  if (rows.length === 0) return 0

  // Build assetId → topology layer map
  const topoRows = tenantId
    ? await db
        .select({ assetId: topologyNodes.assetId, layer: topologyNodes.layer })
        .from(topologyNodes)
        .where(eq(topologyNodes.tenantId, tenantId))
    : []

  const layerMap = new Map<string, number>()
  for (const t of topoRows) {
    if (t.assetId) layerMap.set(t.assetId, t.layer)
  }

  // Score each asset and batch-update
  let updated = 0
  for (const asset of rows) {
    const result = computeCriticality({
      deviceType: asset.deviceType,
      isInternetFacing: asset.isInternetFacing,
      hostname: asset.hostname,
      osInfo: (asset.osInfo ?? {}) as Record<string, unknown>,
      topologyLayer: layerMap.get(asset.assetId) ?? null,
    })

    await db
      .update(assets)
      .set({ criticalityScore: result.score, updatedAt: new Date() })
      .where(eq(assets.assetId, asset.assetId))

    updated++
  }

  return updated
}
