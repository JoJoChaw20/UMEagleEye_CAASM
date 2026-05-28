/**
 * UMEagleEye Workers — SBOM routes
 * Serves SBOM list, stats, single record, and dependency data from Neon DB.
 */

import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, desc, ilike, sql, count } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { sboms, dependencies, assets, scanResults, agents } from '../db/schema'

const app = new Hono<{ Bindings: Env }>()

const READ_ROLES = ['ops_lead', 'security_engineer', 'mssp_analyst', 'business_owner', 'superadmin']

// ── GET /stats/summary ───────────────────────────────────────────
// Must be defined BEFORE /:sbomId to avoid being swallowed by the param route
app.get('/stats/summary', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)

    const [totalSboms, totalDeps, assetsWithSbom, latestRow, pmRows] = await Promise.all([
      db.select({ n: count() }).from(sboms),
      db.select({ n: count() }).from(dependencies),
      db.select({ n: sql<number>`count(distinct ${sboms.assetId})::int` }).from(sboms),
      db.select({ t: sboms.generatedAt }).from(sboms).orderBy(desc(sboms.generatedAt)).limit(1),
      db
        .select({ pm: dependencies.packageManager, n: count() })
        .from(dependencies)
        .groupBy(dependencies.packageManager),
    ])

    const byPm: Record<string, number> = {}
    for (const row of pmRows) byPm[row.pm ?? 'system'] = Number(row.n)

    return c.json({
      total_sboms: Number(totalSboms[0]?.n ?? 0),
      total_dependencies: Number(totalDeps[0]?.n ?? 0),
      assets_scanned: Number(assetsWithSbom[0]?.n ?? 0),
      by_package_manager: byPm,
      latest_scan: latestRow[0]?.t ?? null,
    })
  } catch (err) {
    console.error('sbom stats error:', err)
    return c.json({ detail: 'Failed to fetch SBOM stats' }, 500)
  }
})

// ── GET / ────────────────────────────────────────────────────────
app.get('/', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const page = Math.max(1, parseInt(c.req.query('page') ?? '1'))
    const pageSize = Math.min(100, Math.max(1, parseInt(c.req.query('page_size') ?? '15')))
    const offset = (page - 1) * pageSize
    const assetIdFilter = c.req.query('asset_id')

    // Build conditions: if not superadmin, scope to tenant via asset join
    const conditions = []
    if (assetIdFilter) conditions.push(eq(sboms.assetId, assetIdFilter))

    // For tenant scoping we join assets
    let rows: typeof sboms.$inferSelect[]
    let total = 0

    if (user.role !== 'superadmin' && user.tenantId) {
      // Join with assets to scope by tenant
      const tenantAssets = await db
        .select({ assetId: assets.assetId })
        .from(assets)
        .where(eq(assets.tenantId, user.tenantId))
      const assetIds = tenantAssets.map(a => a.assetId)
      if (assetIds.length === 0) {
        return c.json({ items: [], total: 0, page, page_size: pageSize })
      }
      const scopedConditions = [...conditions, sql`${sboms.assetId} = ANY(${assetIds})`]
      const [data, cnt] = await Promise.all([
        db.select().from(sboms).where(and(...scopedConditions)).orderBy(desc(sboms.generatedAt)).limit(pageSize).offset(offset),
        db.select({ n: count() }).from(sboms).where(and(...scopedConditions)),
      ])
      rows = data
      total = Number(cnt[0]?.n ?? 0)
    } else {
      const whereClause = conditions.length > 0 ? and(...conditions) : undefined
      const [data, cnt] = await Promise.all([
        db.select().from(sboms).where(whereClause).orderBy(desc(sboms.generatedAt)).limit(pageSize).offset(offset),
        db.select({ n: count() }).from(sboms).where(whereClause),
      ])
      rows = data
      total = Number(cnt[0]?.n ?? 0)
    }

    const items = rows.map(s => {
      const raw = (s.rawData ?? {}) as Record<string, unknown>
      const componentCount = typeof raw.component_count === 'number'
        ? raw.component_count
        : Array.isArray(raw.components) ? (raw.components as unknown[]).length : null
      return {
        sbom_id: s.sbomId,
        asset_id: s.assetId,
        format: s.format,
        format_version: s.formatVersion,
        tool_used: s.toolUsed,
        gcs_path: s.r2Path ?? null,
        generated_at: s.generatedAt,
        component_count: componentCount,
      }
    })

    return c.json({ items, total, page, page_size: pageSize })
  } catch (err) {
    console.error('sbom list error:', err)
    return c.json({ detail: 'Failed to fetch SBOMs' }, 500)
  }
})

// ── GET /:sbomId ─────────────────────────────────────────────────
app.get('/:sbomId', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const { sbomId } = c.req.param()

    const [sbom] = await db.select().from(sboms).where(eq(sboms.sbomId, sbomId)).limit(1)
    if (!sbom) return c.json({ detail: 'SBOM not found' }, 404)

    const raw = (sbom.rawData ?? {}) as Record<string, unknown>
    const componentCount = typeof raw.component_count === 'number'
      ? raw.component_count
      : Array.isArray(raw.components) ? (raw.components as unknown[]).length : null

    return c.json({
      sbom_id: sbom.sbomId,
      asset_id: sbom.assetId,
      format: sbom.format,
      format_version: sbom.formatVersion,
      raw_data: sbom.rawData,
      tool_used: sbom.toolUsed,
      gcs_path: sbom.r2Path ?? null,
      generated_at: sbom.generatedAt,
      component_count: componentCount,
    })
  } catch (err) {
    console.error('sbom get error:', err)
    return c.json({ detail: 'Failed to fetch SBOM' }, 500)
  }
})

// ── GET /:sbomId/dependencies ────────────────────────────────────
app.get('/:sbomId/dependencies', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const { sbomId } = c.req.param()
    const limit = Math.min(1000, Math.max(1, parseInt(c.req.query('limit') ?? '500')))
    const search = c.req.query('search')
    const pm = c.req.query('package_manager')

    const conditions = [eq(dependencies.sbomId, sbomId)]
    if (pm) conditions.push(eq(dependencies.packageManager, pm))
    if (search) conditions.push(ilike(dependencies.name, `%${search}%`))

    const [rows, cnt] = await Promise.all([
      db.select().from(dependencies).where(and(...conditions)).limit(limit),
      db.select({ n: count() }).from(dependencies).where(and(...conditions)),
    ])

    const items = rows.map(d => ({
      dependency_id: d.dependencyId,
      sbom_id: d.sbomId,
      asset_id: d.assetId,
      name: d.name,
      version: d.version,
      package_manager: d.packageManager,
      purl: d.purl,
      licenses: d.licenses,
    }))

    return c.json({ items, total: Number(cnt[0]?.n ?? 0) })
  } catch (err) {
    console.error('sbom deps error:', err)
    return c.json({ detail: 'Failed to fetch dependencies' }, 500)
  }
})

// ── DELETE /by-asset/:assetId ─── superadmin cleans up stale SBOM records ────
app.delete('/by-asset/:assetId', authMiddleware, requireRoles('superadmin'), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()
    // CASCADE on sbomId FK deletes dependencies automatically
    const deleted = await db.delete(sboms).where(eq(sboms.assetId, assetId)).returning({ sbomId: sboms.sbomId })
    return c.json({ deleted: deleted.length })
  } catch (err) {
    console.error('sbom delete error:', err)
    return c.json({ detail: 'Failed to delete SBOM records' }, 500)
  }
})

// ── POST /ingest ─── agent submits CycloneDX SBOM after syft scan ────────────
function extractPackageManager(purl?: string | null): string | null {
  if (!purl) return null
  const m = purl.match(/^pkg:([^/]+)\//)
  return m ? (m[1] ?? null) : null
}

const sbomIngestSchema = z.object({
  agent_id: z.string().uuid(),
  scan_id:  z.string().uuid(),
  sbom:     z.record(z.unknown()),
})

app.post('/ingest', zValidator('json', sbomIngestSchema), async (c) => {
  try {
    // Agent auth — same Bearer + X-Agent-ID pattern as /scans/pending
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ detail: 'Missing or invalid Authorization header' }, 401)
    }
    const incomingKey = authHeader.slice(7)
    const enc = new TextEncoder()
    const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(incomingKey))
    const incomingKeyHash = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0')).join('')

    const agentId = c.req.header('X-Agent-ID')
    if (!agentId) return c.json({ detail: 'X-Agent-ID header required' }, 400)

    const db = getDb(c.env.DATABASE_URL)
    const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!agent || incomingKeyHash !== agent.apiKeyHash) {
      return c.json({ detail: 'Invalid agent credentials' }, 401)
    }

    const { scan_id, sbom: sbomJson } = c.req.valid('json')

    // Fetch the pending SBOM scan — subnet field carries the assetId
    const [scanRow] = await db
      .select()
      .from(scanResults)
      .where(and(eq(scanResults.scanId, scan_id), eq(scanResults.scanType, 'sbom')))
      .limit(1)
    if (!scanRow) return c.json({ detail: 'Scan not found' }, 404)

    const assetId = scanRow.subnet
    if (!assetId) return c.json({ detail: 'Scan has no associated asset' }, 400)

    // Verify asset exists
    const [asset] = await db
      .select({ assetId: assets.assetId })
      .from(assets)
      .where(eq(assets.assetId, assetId))
      .limit(1)
    if (!asset) return c.json({ detail: 'Asset not found' }, 404)

    const formatVersion = String((sbomJson as Record<string, unknown>).specVersion ?? '1.5')

    // Replace any existing SBOMs for this asset — cascade deletes old dependencies
    await db.delete(sboms).where(eq(sboms.assetId, assetId))

    // Insert fresh SBOM record
    const [sbomRow] = await db.insert(sboms).values({
      assetId,
      format:        'cyclonedx',
      formatVersion,
      rawData:       sbomJson,
      toolUsed:      'syft',
    }).returning({ sbomId: sboms.sbomId })

    if (!sbomRow) return c.json({ detail: 'Failed to insert SBOM' }, 500)

    // Batch-insert dependencies from CycloneDX components (100 per INSERT)
    const components = Array.isArray((sbomJson as Record<string, unknown>).components)
      ? (sbomJson as Record<string, unknown>).components as Record<string, unknown>[]
      : []

    const depRows = components
      .filter(comp => comp.name && comp.version)
      .map(comp => ({
        assetId,
        sbomId:         sbomRow.sbomId,
        name:           String(comp.name).slice(0, 255),
        version:        String(comp.version).slice(0, 100),
        packageManager: extractPackageManager(comp.purl as string | null | undefined),
        purl:           comp.purl ? String(comp.purl).slice(0, 500) : null,
        licenses:       (comp.licenses as Record<string, unknown>[] | null | undefined) ?? null,
      }))

    const BATCH = 100
    for (let i = 0; i < depRows.length; i += BATCH) {
      await db.insert(dependencies).values(depRows.slice(i, i + BATCH))
    }

    // Mark scan completed
    await db.update(scanResults)
      .set({ status: 'completed', hostsDiscovered: depRows.length })
      .where(eq(scanResults.scanId, scan_id))

    return c.json({ sbom_id: sbomRow.sbomId, dependencies_inserted: depRows.length }, 201)
  } catch (err) {
    console.error('sbom ingest error:', err)
    return c.json({ detail: 'Failed to ingest SBOM' }, 500)
  }
})

export default app
