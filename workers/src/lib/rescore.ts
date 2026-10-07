/**
 * Bulk criticality rescoring.
 *
 * Prefetches the tenant's assets in a constant number of queries, recomputes every
 * score IN MEMORY from each asset's own facts (the scoring function is unchanged
 * except that it no longer reads topology), and writes back only the assets whose
 * score changed, via db.batch in ~100-statement chunks. This keeps Cloudflare
 * subrequests constant instead of one UPDATE per asset (which blew the Free-plan
 * 50/request limit).
 */
import { eq, inArray, and } from 'drizzle-orm'
import { getDb } from '../db/client'
import { assets } from '../db/schema'
import { computeCriticality } from './criticality'

type DbClient = ReturnType<typeof getDb>

export interface RescoreChange { assetId: string; score: number }
export interface RescorePlan { scanned: number; changes: RescoreChange[] }

export interface ScoreInput {
  deviceType: string
  isInternetFacing: boolean
  hostname: string | null | undefined
  osInfo: Record<string, unknown> | null | undefined
  owner: string | null | undefined
}

/**
 * PURE single-asset scorer — the ONE entry point for criticality used by bulk
 * rescore, the per-asset rescore endpoint, PATCH recompute, and POST create, so
 * they can never disagree. Derives the score from the asset's own facts only
 * (device type, exposure, hostname, ports via osInfo, owner). It does NOT take any
 * topology input — criticality must never depend on the graph.
 */
export function scoreAsset(input: ScoreInput): number {
  return computeCriticality({
    deviceType: input.deviceType,
    isInternetFacing: input.isInternetFacing,
    hostname: input.hostname,
    osInfo: (input.osInfo ?? {}) as Record<string, unknown>,
    owner: input.owner,
  }).score
}

/**
 * PURE: recompute scores in memory and return only the assets whose score
 * differs from the stored value. No DB access — unit-testable (see rescore-demo).
 */
export function planRescore(
  rows: Pick<typeof assets.$inferSelect, 'assetId' | 'deviceType' | 'isInternetFacing' | 'hostname' | 'osInfo' | 'criticalityScore' | 'owner'>[],
): RescorePlan {
  const changes: RescoreChange[] = []
  for (const asset of rows) {
    const score = scoreAsset({
      deviceType: asset.deviceType,
      isInternetFacing: asset.isInternetFacing,
      hostname: asset.hostname,
      osInfo: asset.osInfo as Record<string, unknown> | null,
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
 * Subrequests: 1 (assets) + ceil(changed / 100) batch writes — constant regardless
 * of asset count. (No topology read: criticality no longer depends on the graph.)
 */
export async function rescoreAssets(
  db: DbClient,
  tenantId: string | null,
  assetIds?: string[],
  opts?: { myAssetsOnly?: boolean },
): Promise<RescorePlan> {
  // Fetch asset rows (1 query). scope=my_assets adds in_my_assets=true to the
  // tenant prefetch.
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

  const plan = planRescore(rows)

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
