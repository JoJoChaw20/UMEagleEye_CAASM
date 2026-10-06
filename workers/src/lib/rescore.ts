/**
 * Bulk criticality rescoring.
 *
 * Prefetches the tenant's assets + topology layers in a constant number of
 * queries, recomputes every score IN MEMORY with the existing scoring function
 * (logic unchanged), and writes back only the assets whose score changed, via
 * db.batch in ~100-statement chunks. This keeps Cloudflare subrequests constant
 * instead of one UPDATE per asset (which blew the Free-plan 50/request limit).
 */
import { eq, inArray, and } from 'drizzle-orm'
import { getDb } from '../db/client'
import { assets, topologyNodes } from '../db/schema'
import { computeCriticality } from './criticality'

type DbClient = ReturnType<typeof getDb>

export interface RescoreChange { assetId: string; score: number }
export interface RescorePlan { scanned: number; changes: RescoreChange[] }

export interface ScoreInput {
  deviceType: string
  isInternetFacing: boolean
  hostname: string | null | undefined
  osInfo: Record<string, unknown> | null | undefined
  topologyLayer: number | null
  owner: string | null | undefined
}

/**
 * PURE single-asset scorer — the ONE entry point for criticality used by bulk
 * rescore, the per-asset rescore endpoint, PATCH recompute, and POST create, so
 * they can never disagree. Passes device type, exposure, hostname, ports (via
 * osInfo), the topology layer AND the owner, so an owned asset no longer gets the
 * "unowned" penalty on a bulk run. Formula itself is unchanged.
 */
export function scoreAsset(input: ScoreInput): number {
  return computeCriticality({
    deviceType: input.deviceType,
    isInternetFacing: input.isInternetFacing,
    hostname: input.hostname,
    osInfo: (input.osInfo ?? {}) as Record<string, unknown>,
    topologyLayer: input.topologyLayer,
    owner: input.owner,
  }).score
}

/**
 * PURE: recompute scores in memory and return only the assets whose score
 * differs from the stored value. No DB access — unit-testable (see rescore-demo).
 */
export function planRescore(
  rows: Pick<typeof assets.$inferSelect, 'assetId' | 'deviceType' | 'isInternetFacing' | 'hostname' | 'osInfo' | 'criticalityScore' | 'owner'>[],
  layerMap: Map<string, number>,
): RescorePlan {
  const changes: RescoreChange[] = []
  for (const asset of rows) {
    const score = scoreAsset({
      deviceType: asset.deviceType,
      isInternetFacing: asset.isInternetFacing,
      hostname: asset.hostname,
      osInfo: asset.osInfo as Record<string, unknown> | null,
      topologyLayer: layerMap.get(asset.assetId) ?? null,
      owner: asset.owner,
    })
    if (score !== asset.criticalityScore) changes.push({ assetId: asset.assetId, score })
  }
  return { scanned: rows.length, changes }
}

/**
 * Rescore a set of assets (by ID) within a tenant. If assetIds is empty,
 * rescores ALL assets for the tenant.
 *
 * Subrequests: 1 (assets) + 1 (topology, tenant-wide) + ceil(changed / 100) batch
 * writes — constant regardless of asset count.
 */
export async function rescoreAssets(
  db: DbClient,
  tenantId: string | null,
  assetIds?: string[],
  opts?: { myAssetsOnly?: boolean },
): Promise<RescorePlan> {
  // Fetch asset rows (1 query). scope=my_assets adds in_my_assets=true to the
  // tenant prefetch only — the topology-layer read below stays tenant-wide (it
  // only holds My Assets nodes anyway), so the query count is unchanged.
  let rows: (typeof assets.$inferSelect)[]
  if (assetIds && assetIds.length > 0) {
    rows = await db.select().from(assets).where(inArray(assets.assetId, assetIds))
  } else if (tenantId) {
    rows = await db.select().from(assets).where(
      opts?.myAssetsOnly ? and(eq(assets.tenantId, tenantId), eq(assets.inMyAssets, true)) : eq(assets.tenantId, tenantId),
    )
  } else {
    return { scanned: 0, changes: [] }
  }
  if (rows.length === 0) return { scanned: 0, changes: [] }

  // Topology layers for the tenant (1 query).
  const topoRows = tenantId
    ? await db.select({ assetId: topologyNodes.assetId, layer: topologyNodes.layer })
        .from(topologyNodes).where(eq(topologyNodes.tenantId, tenantId))
    : []
  const layerMap = new Map<string, number>()
  for (const t of topoRows) { if (t.assetId) layerMap.set(t.assetId, t.layer) }

  const plan = planRescore(rows, layerMap)

  // Write only changed assets, in ~100-statement batches (one batch = one subrequest).
  const now = new Date()
  for (let i = 0; i < plan.changes.length; i += 100) {
    const slice = plan.changes.slice(i, i + 100)
    if (slice.length === 0) continue
    const stmts = slice.map(ch => db.update(assets).set({ criticalityScore: ch.score, updatedAt: now }).where(eq(assets.assetId, ch.assetId)))
    await db.batch(stmts as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
  }

  return plan
}
