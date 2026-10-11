/**
 * Criticality scoring entry point + bulk rescoring.
 *
 * Two formulas exist: v1 (lib/criticality.ts, the original) and v2
 * (lib/criticalityV2.ts, importance only, with sources). A tenant uses one of them
 * (tenants.criticality_model); every writer scores through scoreAsset(input, model)
 * so ingest, inventory, create/PATCH and rescore can never disagree. Each asset
 * records which model produced its score (assets.criticality_model).
 *
 * Bulk rescoring prefetches the tenant's assets in a constant number of queries,
 * recomputes every score IN MEMORY from each asset's own facts, and writes back only
 * the assets whose score, model or posture changed, via db.batch in ~100-statement
 * chunks. This keeps Cloudflare subrequests constant instead of one UPDATE per asset
 * (which blew the Free-plan 50/request limit). Posture is refreshed from the stored
 * inventory at the same time, so a posture rule change applies without new agent runs.
 */
import { eq, inArray, and } from 'drizzle-orm'
import { getDb } from '../db/client'
import { assets, tenants } from '../db/schema'
import { computeCriticality, type ScoringResult } from './criticality'
import { computeCriticalityV2, type ScoringResultV2 } from './criticalityV2'
import { POSTURE_MODEL, evaluatePosture } from './endpointPosture'
import { applyHint, deviceTypeHint, type DeviceTypeHint } from './deviceHints'

type DbClient = ReturnType<typeof getDb>

export type CriticalityModel = 1 | 2
export const CRITICALITY_MODELS: CriticalityModel[] = [1, 2]
export const asModel = (v: unknown): CriticalityModel => (Number(v) === 2 ? 2 : 1)

export interface RescoreChange {
  assetId: string
  score: number
  model: CriticalityModel
  /** Classifier v2: refreshed hint, and the type when a high-confidence hint filled an unknown one. */
  hint?: DeviceTypeHint | null
  deviceType?: string
  deviceTypeSource?: string
  baselineState?: unknown
  posture?: { postureScore: number | null; postureModel: number; postureChecks: unknown; postureAssessedAt: Date | null }
}
export interface RescorePlan { scanned: number; changes: RescoreChange[] }

export interface ScoreInput {
  deviceType: string
  isInternetFacing: boolean
  hostname: string | null | undefined
  osInfo: Record<string, unknown> | null | undefined
  owner: string | null | undefined
  // v2 inputs (ignored by v1)
  deviceTypeSource?: string | null
  internetFacingOverride?: boolean | null
  /** OS role the machine's agent reported (endpoint_inventory.os.role). */
  agentRole?: string | null
  /** Classifier v2 hint stored on the asset (assets.device_type_hint). */
  deviceTypeHint?: DeviceTypeHint | null
}

/** The OS role an agent reported, from a stored endpoint inventory. */
export function agentRoleOf(endpointInventory: unknown): string | null {
  const os = (endpointInventory as { os?: { role?: unknown } } | null)?.os
  return typeof os?.role === 'string' ? os.role : null
}

/** Full result (score, factors, breakdown) for the given model. */
export function scoreDetail(input: ScoreInput, model: CriticalityModel): ScoringResult | ScoringResultV2 {
  const osInfo = (input.osInfo ?? {}) as Record<string, unknown>
  if (model === 2) {
    return computeCriticalityV2({
      deviceType: input.deviceType, deviceTypeSource: input.deviceTypeSource,
      isInternetFacing: input.isInternetFacing, internetFacingOverride: input.internetFacingOverride,
      hostname: input.hostname, osInfo, agentRole: input.agentRole, deviceTypeHint: input.deviceTypeHint,
    })
  }
  return computeCriticality({
    deviceType: input.deviceType, isInternetFacing: input.isInternetFacing,
    hostname: input.hostname, osInfo, owner: input.owner,
  })
}

/**
 * PURE single-asset scorer — the ONE entry point for criticality used by bulk
 * rescore, the per-asset rescore endpoint, PATCH recompute, POST create, scan ingest
 * and agent inventory. Derives the score from the asset's own facts only. It does NOT
 * take any topology input — criticality must never depend on the graph.
 */
export function scoreAsset(input: ScoreInput, model: CriticalityModel = 1): number {
  return scoreDetail(input, model).score
}

/** Scoring inputs from a full assets row. */
export function scoreInputOf(row: Pick<typeof assets.$inferSelect,
  'deviceType' | 'deviceTypeSource' | 'isInternetFacing' | 'internetFacingOverride' | 'hostname' | 'osInfo' | 'owner' | 'endpointInventory'>
  & Partial<Pick<typeof assets.$inferSelect, 'deviceTypeHint'>>): ScoreInput {
  return {
    deviceType: row.deviceType, deviceTypeSource: row.deviceTypeSource,
    isInternetFacing: row.isInternetFacing, internetFacingOverride: row.internetFacingOverride,
    hostname: row.hostname, osInfo: row.osInfo as Record<string, unknown> | null, owner: row.owner,
    agentRole: agentRoleOf(row.endpointInventory), deviceTypeHint: (row.deviceTypeHint as DeviceTypeHint | null) ?? null,
  }
}

/** The criticality model a tenant uses (1 when unknown). One query. */
export async function tenantCriticalityModel(db: DbClient, tenantId: string | null | undefined): Promise<CriticalityModel> {
  if (!tenantId) return 1
  const [t] = await db.select({ model: tenants.criticalityModel }).from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
  return asModel(t?.model)
}

type RescoreRow = Pick<typeof assets.$inferSelect,
  'assetId' | 'deviceType' | 'isInternetFacing' | 'hostname' | 'osInfo' | 'criticalityScore' | 'owner'>
  & Partial<Pick<typeof assets.$inferSelect,
    'deviceTypeSource' | 'internetFacingOverride' | 'endpointInventory' | 'inventoryCollectedAt' | 'criticalityModel' | 'postureModel' | 'postureScore'
    | 'macAddress' | 'hardwareVendor' | 'deviceTypeHint' | 'baselineState'>>

/**
 * PURE: recompute scores in memory and return only the assets whose score or model
 * differs from the stored value, plus agent assets whose posture is missing or from
 * an older posture model, plus assets whose classifier v2 hint changed (a
 * high-confidence hint also fills an unknown type). No DB access — unit-testable
 * (see rescore-demo, device-hints-demo).
 */
export function planRescore(rows: RescoreRow[], model: CriticalityModel = 1): RescorePlan {
  const changes: RescoreChange[] = []
  for (const asset of rows) {
    const osInfo = asset.osInfo as Record<string, unknown> | null
    const hint = deviceTypeHint({ hostname: asset.hostname, mac: asset.macAddress, vendor: asset.hardwareVendor, osInfo })
    const typed = applyHint({ deviceType: asset.deviceType, deviceTypeSource: asset.deviceTypeSource ?? null }, hint)
    // Rows read without the hint column (older callers) never count as a hint change.
    const hintChanged = 'deviceTypeHint' in asset && JSON.stringify(hint) !== JSON.stringify(asset.deviceTypeHint ?? null)
    const score = scoreAsset({
      deviceType: typed.deviceType,
      deviceTypeSource: typed.deviceTypeSource,
      isInternetFacing: asset.isInternetFacing,
      internetFacingOverride: asset.internetFacingOverride ?? null,
      hostname: asset.hostname,
      osInfo,
      owner: asset.owner,
      agentRole: agentRoleOf(asset.endpointInventory),
      deviceTypeHint: hint,
    }, model)
    const storedModel = asset.criticalityModel ?? 1
    let posture: RescoreChange['posture']
    if (asset.endpointInventory != null && asset.postureModel !== POSTURE_MODEL) {
      const r = evaluatePosture(asset.endpointInventory)
      // Assessed = when the agent collected the facts, not when they were scored.
      posture = { postureScore: r.score, postureModel: r.model, postureChecks: r.checks, postureAssessedAt: asset.inventoryCollectedAt ?? null }
    }
    let typeChange: Pick<RescoreChange, 'deviceType' | 'deviceTypeSource' | 'baselineState'> = {}
    if (typed.changed) {
      typeChange = { deviceType: typed.deviceType, deviceTypeSource: typed.deviceTypeSource }
      // Filling an unknown type is classification, not drift: move an automatic baseline with it.
      const b = asset.baselineState as Record<string, unknown> | null | undefined
      if (b && b['auto_set'] === true && b['device_type'] === asset.deviceType) typeChange.baselineState = { ...b, device_type: typed.deviceType }
    }
    if (score !== asset.criticalityScore || storedModel !== model || posture || hintChanged || typed.changed) {
      changes.push({
        assetId: asset.assetId, score, model, ...(posture ? { posture } : {}),
        ...(hintChanged || typed.changed ? { hint } : {}), ...typeChange,
      })
    }
  }
  return { scanned: rows.length, changes }
}

/**
 * Rescore a set of assets (by ID) within a tenant with the tenant's model (or the
 * model given). If assetIds is empty, rescores ALL assets for the tenant.
 *
 * Subrequests: 1 (tenant model, unless given) + 1 (assets) + ceil(changed / 100)
 * batch writes — constant regardless of asset count. (No topology read.)
 */
export async function rescoreAssets(
  db: DbClient,
  tenantId: string | null,
  assetIds?: string[],
  opts?: { myAssetsOnly?: boolean; discoveredOnly?: boolean; model?: CriticalityModel },
): Promise<RescorePlan & { model: CriticalityModel }> {
  const model = opts?.model ?? await tenantCriticalityModel(db, tenantId)
  // Fetch asset rows (1 query). scope=my_assets adds in_my_assets=true to the
  // tenant prefetch; scope=discovered adds in_my_assets=false.
  let rows: (typeof assets.$inferSelect)[]
  if (assetIds && assetIds.length > 0) {
    rows = await db.select().from(assets).where(inArray(assets.assetId, assetIds))
  } else if (tenantId) {
    const membership = opts?.myAssetsOnly ? eq(assets.inMyAssets, true)
      : opts?.discoveredOnly ? eq(assets.inMyAssets, false)
      : undefined
    rows = await db.select().from(assets).where(
      membership ? and(eq(assets.tenantId, tenantId), membership) : eq(assets.tenantId, tenantId),
    )
  } else {
    return { scanned: 0, changes: [], model }
  }
  if (rows.length === 0) return { scanned: 0, changes: [], model }

  const plan = planRescore(rows, model)

  // Write only changed assets, in ~100-statement batches (one batch = one subrequest).
  const now = new Date()
  for (let i = 0; i < plan.changes.length; i += 100) {
    const slice = plan.changes.slice(i, i + 100)
    if (slice.length === 0) continue
    const stmts = slice.map(ch => db.update(assets).set({
      criticalityScore: ch.score, criticalityModel: ch.model, updatedAt: now,
      ...(ch.posture ?? {}),
      ...('hint' in ch ? { deviceTypeHint: ch.hint ?? null } : {}),
      ...(ch.deviceType ? { deviceType: ch.deviceType as typeof assets.$inferInsert['deviceType'], deviceTypeSource: ch.deviceTypeSource } : {}),
      ...(ch.baselineState ? { baselineState: ch.baselineState } : {}),
    }).where(eq(assets.assetId, ch.assetId)))
    await db.batch(stmts as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
  }

  return { ...plan, model }
}
