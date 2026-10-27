/**
 * UMEagleEye Workers — SBOM routes
 * Serves SBOM list, stats, single record, and dependency data from Neon DB.
 */

import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, desc, ilike, isNull, sql, count, inArray } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { sboms, dependencies, assets, scanResults, agents, events, ctiIndicators } from '../db/schema'
import { buildPackageMap, planPackageBaselineCompletion, type AssetBaseline } from '../services/drift'
import { cveIntelFor, linkCveIndicators, type CveIntel } from '../services/threatIntel'
import { matchIocs } from '../services/iocMatch'
import { isStoredInR2, licenseNames, sbomObjectKey, sbomSummary } from '../lib/sbomStore'

const app = new Hono<{ Bindings: Env }>()

const READ_ROLES = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner']

type User = { role: string; tenantId?: string | null }

/** The SBOM if this user may see it (its asset is in their tenant; superadmins see all). */
async function visibleSbom(db: ReturnType<typeof getDb>, user: User, sbomId: string) {
  const [row] = await db.select({ sbom: sboms, tenantId: assets.tenantId })
    .from(sboms).innerJoin(assets, eq(assets.assetId, sboms.assetId))
    .where(eq(sboms.sbomId, sbomId)).limit(1)
  if (!row) return null
  if (user.role !== 'superadmin' && row.tenantId !== user.tenantId) return null
  return row.sbom
}

function componentCountOf(raw: Record<string, unknown>): number | null {
  return typeof raw.component_count === 'number'
    ? raw.component_count
    : Array.isArray(raw.components) ? (raw.components as unknown[]).length : null
}

// ── GET /stats/summary ───────────────────────────────────────────
// Must be defined BEFORE /:sbomId to avoid being swallowed by the param route
app.get('/stats/summary', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const tenantIdParam = c.req.query('tenant_id')
    const effectiveTenantId = user.role === 'superadmin'
      ? (tenantIdParam ?? undefined)
      : (user.tenantId ?? undefined)

    // If tenant-scoped, get allowed asset IDs first
    let assetIdFilter: string[] | undefined
    if (effectiveTenantId) {
      const tenantAssets = await db
        .select({ assetId: assets.assetId })
        .from(assets)
        .where(eq(assets.tenantId, effectiveTenantId))
      assetIdFilter = tenantAssets.map(a => a.assetId)
      if (assetIdFilter.length === 0) {
        return c.json({ total_sboms: 0, total_dependencies: 0, assets_scanned: 0, by_package_manager: {}, latest_scan: null })
      }
    }

    const sbomWhere = assetIdFilter ? inArray(sboms.assetId, assetIdFilter) : undefined
    const depJoinFilter = assetIdFilter
      ? and(eq(dependencies.sbomId, sboms.sbomId), inArray(sboms.assetId, assetIdFilter))
      : eq(dependencies.sbomId, sboms.sbomId)

    const [totalSboms, totalDeps, assetsWithSbom, latestRow, pmRows] = await Promise.all([
      sbomWhere
        ? db.select({ n: count() }).from(sboms).where(sbomWhere)
        : db.select({ n: count() }).from(sboms),
      assetIdFilter
        ? db.select({ n: count() }).from(dependencies).innerJoin(sboms, depJoinFilter)
        : db.select({ n: count() }).from(dependencies),
      sbomWhere
        ? db.select({ n: sql<number>`count(distinct ${sboms.assetId})::int` }).from(sboms).where(sbomWhere)
        : db.select({ n: sql<number>`count(distinct ${sboms.assetId})::int` }).from(sboms),
      sbomWhere
        ? db.select({ t: sboms.generatedAt }).from(sboms).where(sbomWhere).orderBy(desc(sboms.generatedAt)).limit(1)
        : db.select({ t: sboms.generatedAt }).from(sboms).orderBy(desc(sboms.generatedAt)).limit(1),
      assetIdFilter
        ? db.select({ pm: dependencies.packageManager, n: count() }).from(dependencies).innerJoin(sboms, depJoinFilter).groupBy(dependencies.packageManager)
        : db.select({ pm: dependencies.packageManager, n: count() }).from(dependencies).groupBy(dependencies.packageManager),
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

// ── GET /scans/active ───────────────────────────────────────────
// Restores visible progress after navigation or a browser refresh.
// Must remain above /:sbomId so "scans" is not treated as an SBOM UUID.
app.get('/scans/active', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const tenantIdParam = c.req.query('tenant_id')
    const effectiveTenantId = user.role === 'superadmin'
      ? (tenantIdParam ?? undefined)
      : (user.tenantId ?? undefined)

    const conditions = [
      eq(scanResults.scanType, 'sbom'),
      inArray(scanResults.status, ['pending', 'running']),
    ]
    if (effectiveTenantId) conditions.push(eq(scanResults.tenantId, effectiveTenantId))

    const rows = await db
      .select({
        scanId: scanResults.scanId,
        assetId: scanResults.subnet,
        status: scanResults.status,
        startedAt: scanResults.startedAt,
        completedAt: scanResults.completedAt,
        failureReason: scanResults.failureReason,
      })
      .from(scanResults)
      .where(and(...conditions))
      .orderBy(desc(scanResults.startedAt))
      .limit(100)

    return c.json({
      items: rows.map(row => ({
        scan_id: row.scanId,
        asset_id: row.assetId,
        status: row.status,
        started_at: row.startedAt,
        completed_at: row.completedAt,
        failure_reason: row.failureReason,
      })),
    })
  } catch (err) {
    console.error('active SBOM scans error:', err)
    return c.json({ detail: 'Failed to fetch active SBOM scans' }, 500)
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

    const tenantIdParam = c.req.query('tenant_id')
    const effectiveTenantId = user.role === 'superadmin'
      ? (tenantIdParam ?? undefined)
      : (user.tenantId ?? undefined)

    if (effectiveTenantId) {
      // Join with assets to scope by tenant
      const tenantAssets = await db
        .select({ assetId: assets.assetId })
        .from(assets)
        .where(eq(assets.tenantId, effectiveTenantId))
      const assetIds = tenantAssets.map(a => a.assetId)
      if (assetIds.length === 0) {
        return c.json({ items: [], total: 0, page, page_size: pageSize })
      }
      const scopedConditions = [...conditions, inArray(sboms.assetId, assetIds)]
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

    // The computer each SBOM belongs to, for the table (one query for the page).
    const pageAssetIds = [...new Set(rows.map(r => r.assetId))]
    const assetRows = pageAssetIds.length
      ? await db.select({ assetId: assets.assetId, hostname: assets.hostname, ip: assets.ipAddress })
          .from(assets).where(inArray(assets.assetId, pageAssetIds))
      : []
    const assetById = new Map(assetRows.map(a => [a.assetId, a]))

    const items = rows.map(s => {
      const raw = (s.rawData ?? {}) as Record<string, unknown>
      const asset = assetById.get(s.assetId)
      return {
        sbom_id: s.sbomId,
        asset_id: s.assetId,
        asset_hostname: asset?.hostname ?? null,
        asset_ip: asset?.ip ?? null,
        format: s.format,
        format_version: s.formatVersion,
        tool_used: s.toolUsed,
        generated_by: raw.generated_by ?? null,
        stored_in_r2: isStoredInR2(raw),
        scope: Array.isArray(raw.scope) ? raw.scope : [],
        run: raw.run ?? null,          // how the agent built it (2.2.6+), see sbomSummary
        generated_at: s.generatedAt,
        component_count: componentCountOf(raw),
      }
    })

    return c.json({ items, total, page, page_size: pageSize })
  } catch (err) {
    console.error('sbom list error:', err)
    return c.json({ detail: 'Failed to fetch SBOMs' }, 500)
  }
})

// ── GET /:sbomId ─────────────────────────────────────────────────
// Metadata only; the document itself comes from GET /:sbomId/download.
app.get('/:sbomId', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const sbom = await visibleSbom(db, c.get('user'), c.req.param('sbomId'))
    if (!sbom) return c.json({ detail: 'SBOM not found' }, 404)
    const raw = (sbom.rawData ?? {}) as Record<string, unknown>

    return c.json({
      sbom_id: sbom.sbomId,
      asset_id: sbom.assetId,
      format: sbom.format,
      format_version: sbom.formatVersion,
      tool_used: sbom.toolUsed,
      generated_by: raw.generated_by ?? null,
      stored_in_r2: isStoredInR2(raw),
      scope: Array.isArray(raw.scope) ? raw.scope : [],
      run: raw.run ?? null,
      generated_at: sbom.generatedAt,
      component_count: componentCountOf(raw),
    })
  } catch (err) {
    console.error('sbom get error:', err)
    return c.json({ detail: 'Failed to fetch SBOM' }, 500)
  }
})

// ── GET /:sbomId/download ─── the CycloneDX document (R2, or the database for old SBOMs) ──
app.get('/:sbomId/download', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const sbom = await visibleSbom(db, c.get('user'), c.req.param('sbomId'))
    if (!sbom) return c.json({ detail: 'SBOM not found' }, 404)
    const filename = `sbom-${sbom.assetId}.cdx.json`
    const headers = {
      'Content-Type': 'application/vnd.cyclonedx+json',
      'Content-Disposition': `attachment; filename="${filename}"`,
    }
    if (!isStoredInR2(sbom.rawData)) return new Response(JSON.stringify(sbom.rawData ?? {}, null, 2), { headers })
    const obj = await c.env.REPORTS_BUCKET.get(sbom.r2Path ?? sbomObjectKey(sbom.assetId))
    if (!obj) return c.json({ detail: 'The SBOM file is no longer stored' }, 404)
    return new Response(obj.body, { headers })
  } catch (err) {
    console.error('sbom download error:', err)
    return c.json({ detail: 'Failed to download SBOM' }, 500)
  }
})

// ── GET /:sbomId/dependencies ────────────────────────────────────
app.get('/:sbomId/dependencies', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const { sbomId } = c.req.param()
    if (!await visibleSbom(db, c.get('user'), sbomId)) return c.json({ detail: 'SBOM not found' }, 404)
    const limit = Math.min(1000, Math.max(1, parseInt(c.req.query('limit') ?? '500')))
    const search = c.req.query('search')
    const pm = c.req.query('package_manager')

    const conditions = [eq(dependencies.sbomId, sbomId)]
    // 'system' = packages with no package manager (the UI's label for them)
    if (pm) conditions.push(pm === 'system' ? isNull(dependencies.packageManager) : eq(dependencies.packageManager, pm))
    if (search) conditions.push(ilike(dependencies.name, `%${search}%`))

    const [rows, cnt, pmRows] = await Promise.all([
      db.select().from(dependencies).where(and(...conditions)).orderBy(dependencies.name).limit(limit),
      db.select({ n: count() }).from(dependencies).where(and(...conditions)),
      // Every package manager in this SBOM (not just the loaded page), for the filter
      db.select({ pm: dependencies.packageManager, n: count() }).from(dependencies)
        .where(eq(dependencies.sbomId, sbomId)).groupBy(dependencies.packageManager),
    ])

    const items = rows.map(d => ({
      dependency_id: d.dependencyId,
      sbom_id: d.sbomId,
      asset_id: d.assetId,
      name: d.name,
      version: d.version,
      package_manager: d.packageManager,
      purl: d.purl,
      // Older SBOMs stored raw CycloneDX licence objects; newer ones store names.
      licenses: Array.isArray(d.licenses) && d.licenses.some(l => typeof l !== 'string') ? licenseNames(d.licenses) : d.licenses,
    }))

    const package_managers = pmRows
      .map(r => ({ package_manager: r.pm ?? 'system', count: Number(r.n) }))
      .sort((a, b) => b.count - a.count)
    return c.json({ items, total: Number(cnt[0]?.n ?? 0), package_managers })
  } catch (err) {
    console.error('sbom deps error:', err)
    return c.json({ detail: 'Failed to fetch dependencies' }, 500)
  }
})

// ── DELETE /by-asset/:assetId ─── tenant admins clean up their tenant's SBOMs ──
app.delete('/by-asset/:assetId', authMiddleware,
  requireRoles('tenant_superadmin', 'tenant_admin'), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()

    // Authorize against the asset tenant before deleting any SBOM data.
    const [asset] = await db
      .select({ tenantId: assets.tenantId })
      .from(assets)
      .where(eq(assets.assetId, assetId))
      .limit(1)
    if (!asset || !user.tenantId || asset.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    // CASCADE on sbomId FK deletes dependencies automatically
    const deleted = await db.delete(sboms).where(eq(sboms.assetId, assetId)).returning({ sbomId: sboms.sbomId })
    await c.env.REPORTS_BUCKET.delete(sbomObjectKey(assetId)).catch(() => {})
    return c.json({ deleted: deleted.length })
  } catch (err) {
    console.error('sbom delete error:', err)
    return c.json({ detail: 'Failed to delete SBOM records' }, 500)
  }
})

// ── Agent endpoints ─────────────────────────────────────────────────────────
// An SBOM always describes the computer the agent runs on: its host asset
// (agents.host_asset_id, bound by the agent's inventory). The scan record's subnet
// column carries that assetId, and every agent endpoint checks the two still agree.

type AgentRow = typeof agents.$inferSelect
type ScanRow = typeof scanResults.$inferSelect

async function authenticateAgent(c: { req: { header(name: string): string | undefined } }, db: ReturnType<typeof getDb>): Promise<AgentRow | null> {
  const authHeader = c.req.header('Authorization')
  const agentId = c.req.header('X-Agent-ID')
  if (!authHeader?.startsWith('Bearer ') || !agentId) return null
  const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(authHeader.slice(7)))
  const incomingKeyHash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('')
  const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
  return agent && incomingKeyHash === agent.apiKeyHash ? agent : null
}

const NOT_BOUND = "This computer's inventory has not reached the server yet, so its SBOM cannot be linked "
  + 'to an asset. Collect the inventory first (Status > Collect inventory now).'

/** The SBOM scan record `scanId` of this agent, if it belongs to the agent's own host. */
async function hostScan(db: ReturnType<typeof getDb>, agent: AgentRow, scanId: string): Promise<{ scan?: ScanRow; error?: [string, 404 | 409] }> {
  const [scan] = await db.select().from(scanResults)
    .where(and(eq(scanResults.scanId, scanId), eq(scanResults.scanType, 'sbom'), eq(scanResults.agentId, agent.agentId)))
    .limit(1)
  if (!scan) return { error: ['SBOM scan not found for this agent', 404] }
  if (!agent.hostAssetId || scan.subnet !== agent.hostAssetId) {
    return { error: ['This SBOM job is for a different device than the one this agent runs on', 409] }
  }
  return { scan }
}

// ── POST /agent-start ─── the agent starts an SBOM run ──────────────────────
// For its daily schedule (no scan_id: a new record is created) and for a job the
// dashboard queued (scan_id: that pending record is marked running). `mode` (agent 2.2.6+):
// a full run lists every folder; a quick (daily) run only the folders that changed. It is
// kept in the record's network_info (unused by SBOM records otherwise) so "Run SBOM" on the
// dashboard can say which kind of run is busy.
const agentStartSchema = z.object({
  trigger: z.enum(['schedule', 'manual', 'dashboard']),
  scan_id: z.string().uuid().optional(),
  mode:    z.enum(['full', 'quick']).default('full'),
})

app.post('/agent-start', zValidator('json', agentStartSchema), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const agent = await authenticateAgent(c, db)
    if (!agent) return c.json({ detail: 'Invalid agent credentials' }, 401)
    if (!agent.hostAssetId) return c.json({ detail: NOT_BOUND }, 409)
    const { trigger, scan_id, mode } = c.req.valid('json')
    const now = new Date()
    const networkInfo = { sbom_mode: mode }

    if (scan_id) {
      const { scan, error } = await hostScan(db, agent, scan_id)
      if (error) {
        if (error[1] === 409) {
          await db.update(scanResults).set({ status: 'failed', completedAt: now, failureReason: error[0] })
            .where(eq(scanResults.scanId, scan_id))
        }
        return c.json({ detail: error[0] }, error[1])
      }
      if (scan!.status !== 'pending') return c.json({ detail: `This SBOM job is already ${scan!.status}` }, 409)
      await db.update(scanResults).set({ status: 'running', startedAt: now, networkInfo }).where(eq(scanResults.scanId, scan_id))
      return c.json({ scan_id, status: 'running' })
    }

    // A full run of its own answers any job still queued for this computer. A quick run
    // does not (it lists only changed folders), so the job waits and runs after it.
    if (mode === 'full') {
      await db.update(scanResults).set({ status: 'cancelled', completedAt: now, failureReason: 'Replaced by a scheduled full SBOM run' })
        .where(and(eq(scanResults.subnet, agent.hostAssetId), eq(scanResults.scanType, 'sbom'), eq(scanResults.status, 'pending')))
    }
    const [scan] = await db.insert(scanResults).values({
      agentId: agent.agentId,
      tenantId: agent.tenantId ?? null,
      scanType: 'sbom',
      subnet: agent.hostAssetId,
      status: 'running',
      rawResults: [],
      networkInfo,
    }).returning({ scanId: scanResults.scanId })
    if (!scan) return c.json({ detail: 'Failed to create scan record' }, 500)
    console.log(`agent ${agent.agentId} started SBOM ${scan.scanId} (${trigger}, ${mode})`)
    return c.json({ scan_id: scan.scanId, status: 'running' }, 201)
  } catch (err) {
    console.error('sbom agent-start error:', err)
    return c.json({ detail: 'Failed to start SBOM scan' }, 500)
  }
})

// ── GET /agent-status/:scanId ─── lets the agent stop a run cancelled on the dashboard ──
app.get('/agent-status/:scanId', async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const agent = await authenticateAgent(c, db)
    if (!agent) return c.json({ detail: 'Invalid agent credentials' }, 401)
    const [scan] = await db.select({ status: scanResults.status }).from(scanResults)
      .where(and(eq(scanResults.scanId, c.req.param('scanId')), eq(scanResults.agentId, agent.agentId), eq(scanResults.scanType, 'sbom')))
      .limit(1)
    if (!scan) return c.json({ detail: 'SBOM scan not found for this agent' }, 404)
    return c.json({ status: scan.status })
  } catch (err) {
    console.error('sbom agent-status error:', err)
    return c.json({ detail: 'Failed to read SBOM scan status' }, 500)
  }
})

// ── POST /ingest ─── agent submits the CycloneDX SBOM of its own machine ─────
function extractPackageManager(purl?: string | null): string | null {
  if (!purl) return null
  const m = purl.match(/^pkg:([^/]+)\//)
  return m ? (m[1] ?? null) : null
}

const sbomIngestSchema = z.object({
  agent_id: z.string().uuid(),
  scan_id:  z.string().uuid(),
  sbom:     z.record(z.unknown()),
  scope:    z.array(z.string().max(300)).max(50).optional(),   // folders Syft scanned
  // How the agent built it (2.2.6+): full or quick, and the folders whose packages are
  // older than this run (kept from their last listing) or missing (never listed).
  run:      z.object({
    mode:      z.enum(['full', 'quick']),
    seconds:   z.number().int().nonnegative(),
    folders:   z.number().int().nonnegative(),
    listed:    z.number().int().nonnegative(),
    unchanged: z.number().int().nonnegative(),
    kept:      z.array(z.object({ folder: z.string().max(300), listed_at: z.string().max(40).nullable(), reason: z.string().max(300) })).max(50),
    missing:   z.array(z.object({ folder: z.string().max(300), reason: z.string().max(300) })).max(50),
  }).optional(),
})

app.post('/ingest', zValidator('json', sbomIngestSchema), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const agent = await authenticateAgent(c, db)
    if (!agent) return c.json({ detail: 'Invalid agent credentials' }, 401)

    const { scan_id, sbom: sbomJson, scope, run } = c.req.valid('json')
    const { scan: scanRow, error } = await hostScan(db, agent, scan_id)
    if (error) return c.json({ detail: error[0] }, error[1])
    if (scanRow!.status === 'cancelled') {
      return c.json({ detail: 'Scan was cancelled; SBOM output was discarded' }, 409)
    }
    const assetId = agent.hostAssetId!

    // Verify asset exists. Also pull its baseline so the first real SBOM can
    // complete the (unknown) package baseline in the same write — no extra query.
    const [asset] = await db
      .select({ assetId: assets.assetId, baselineState: assets.baselineState })
      .from(assets)
      .where(eq(assets.assetId, assetId))
      .limit(1)
    if (!asset) return c.json({ detail: 'Asset not found' }, 404)

    const formatVersion = String((sbomJson as Record<string, unknown>).specVersion ?? '1.5')
    const components = Array.isArray((sbomJson as Record<string, unknown>).components)
      ? (sbomJson as Record<string, unknown>).components as Record<string, unknown>[]
      : []

    // The document goes to R2 (overwriting this asset's previous one); the database keeps
    // a summary. If R2 is unavailable the document is kept in the database as before.
    const r2Key = sbomObjectKey(assetId)
    let storedInR2 = false
    try {
      await c.env.REPORTS_BUCKET.put(r2Key, JSON.stringify(sbomJson), {
        httpMetadata: { contentType: 'application/vnd.cyclonedx+json' },
        customMetadata: { assetId, scanId: scan_id },
      })
      storedInR2 = true
    } catch (e) {
      console.error('sbom ingest: R2 put failed, keeping the document in the database:', e)
    }

    // Everything below is written in ONE db.batch: one subrequest (the Workers free plan
    // allows 50 per request, and a PC can have thousands of packages) and one transaction,
    // so a failure never leaves a half-stored SBOM. The id is made here so the
    // dependency rows can reference it inside the same batch.
    const sbomId = crypto.randomUUID()
    const depRows = components
      .filter(comp => comp.name && comp.version && comp.type !== 'operating-system' && comp.type !== 'file')
      .map(comp => ({
        assetId,
        sbomId,
        name:           String(comp.name).slice(0, 255),
        version:        String(comp.version).slice(0, 100),
        packageManager: extractPackageManager(comp.purl as string | null | undefined),
        purl:           comp.purl ? String(comp.purl).slice(0, 500) : null,
        licenses:       licenseNames(comp.licenses),
      }))

    // First real SBOM for an asset whose baseline packages are still unknown →
    // complete baseline_state.packages (+ packages_known) from this scan, so the
    // drift audit has a package baseline to compare against instead of treating
    // every package as new. Partial jsonb merge (|| patch) leaves ports/hostname/
    // os_version/etc. untouched; skipped when baseline is null, already known, or
    // this SBOM carried no packages. Same batch as the scan-complete update, so the
    // drift cron can never observe one without the other.
    const pkgMap = buildPackageMap((sbomJson as Record<string, unknown>).components)
    const completion = planPackageBaselineCompletion(asset.baselineState as AssetBaseline | null, pkgMap)

    const DEP_BATCH = 500   // rows per INSERT: 7 params each, well under Postgres' 65k limit
    const stmts: unknown[] = [
      // Replace any existing SBOMs for this asset — cascade deletes old dependencies
      db.delete(sboms).where(eq(sboms.assetId, assetId)),
      db.insert(sboms).values({
        sbomId,
        assetId,
        format:        'cyclonedx',
        formatVersion,
        rawData:       storedInR2 ? sbomSummary(sbomJson, components.length, scope, run) : sbomJson,
        toolUsed:      'syft',
        r2Path:        storedInR2 ? r2Key : null,
      }),
    ]
    for (let i = 0; i < depRows.length; i += DEP_BATCH) {
      stmts.push(db.insert(dependencies).values(depRows.slice(i, i + DEP_BATCH)))
    }
    // A record the 90-minute window already failed still completes when its SBOM arrives.
    stmts.push(db.update(scanResults)
      .set({ status: 'completed', completedAt: new Date(), failureReason: null, hostsDiscovered: depRows.length })
      .where(eq(scanResults.scanId, scan_id)))
    if (completion) {
      stmts.push(db.update(assets)
        .set({ baselineState: sql`${assets.baselineState} || ${JSON.stringify(completion)}::jsonb`, updatedAt: new Date() })
        .where(eq(assets.assetId, assetId)))
    }
    await db.batch(stmts as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
    const sbomRow = { sbomId }
    // Its packages may now be on a watchlist (R6).
    try {
      await matchIocs(db, { assetId })
    } catch (err) {
      console.error('sbom ingest: threat-intel matching failed:', err)
    }

    return c.json({
      sbom_id: sbomRow.sbomId, dependencies_inserted: depRows.length, stored_in_r2: storedInR2,
      baseline_packages_completed: completion ? Object.keys(pkgMap).length : 0,
    }, 201)
  } catch (err) {
    console.error('sbom ingest error:', err)
    return c.json({ detail: 'Failed to ingest SBOM' }, 500)
  }
})

// ── POST /ingest-cve ── agent submits Grype findings after SBOM scan ──────────
// One finding per (CVE, package). cve_id is the CVE when Grype knows one (the agent
// takes it from Grype's related vulnerabilities when the match is a GHSA advisory),
// so EPSS and CISA KEV can match it. epss is Grype's own EPSS value when it has one.

const cveIngestSchema = z.object({
  agent_id: z.string().uuid(),
  scan_id:  z.string().uuid(),
  findings: z.array(z.object({
    cve_id:          z.string(),
    advisory_id:     z.string().max(64).nullish(),
    severity:        z.string().default('Unknown'),
    description:     z.string().default(''),
    cvss_base_score: z.number().default(0),
    epss:            z.number().min(0).max(1).nullish(),
    package_name:    z.string(),
    package_version: z.string().default(''),
    package_type:    z.string().max(40).nullish(),
    fix_versions:    z.array(z.string()).default([]),
    cwe_ids:         z.array(z.string()).default([]),
  })).max(5000),
  // Every "cve_id::package_name" Grype reported, when the agent sent only the top findings:
  // a CVE left out of `findings` is still present, so its alert must not be auto-resolved.
  present_keys:   z.array(z.string().max(400)).max(100000).optional(),
  total_findings: z.number().int().nonnegative().optional(),
})

// At most this many findings become alerts per scan (KEV first, then EPSS, then CVSS).
// Keeps one PC from flooding the queue, and keeps the ingest within the Workers free
// plan's 50 subrequests (the writes go in db.batch chunks of WRITE_BATCH statements).
export const MAX_CVE_ALERTS = 1500
const WRITE_BATCH = 300
const MAX_EPSS_LOOKUPS = 300      // FIRST.org calls are 30 CVEs each: at most 10 subrequests

function mapSeverity(cvss: number, grypeSev: string): 'critical' | 'high' | 'medium' | 'low' {
  if (cvss >= 9.0) return 'critical'
  if (cvss >= 7.0) return 'high'
  if (cvss >= 4.0) return 'medium'
  if (cvss === 0) {
    const s = grypeSev.toLowerCase()
    if (s === 'critical') return 'critical'
    if (s === 'high') return 'high'
    if (s === 'medium') return 'medium'
  }
  return 'low'
}

function computeRiskScore(cvss: number, epss: number, criticality: number, ctiMatch: boolean): number {
  // Normalise all components to 0-100 scale before weighting:
  // CVSS (0-10) → *10 → 0-100, weight 40%
  // EPSS (0-1)  → *100 → 0-100, weight 35%
  // Criticality (1-10) → *10 → 0-100, weight 15%
  // CTI match flat 10 pts
  const score = (cvss * 10 * 0.40) + (epss * 100 * 0.35) + (Math.max(criticality, 1) * 10 * 0.15) + (ctiMatch ? 10 : 0)
  return Math.round(Math.min(score, 100) * 100) / 100
}

async function fetchEpssScores(cveIds: string[]): Promise<Map<string, number>> {
  const scores = new Map<string, number>()
  const filtered = cveIds.filter(id => id.startsWith('CVE-'))
  if (filtered.length === 0) return scores

  const chunkSize = 30
  for (let i = 0; i < filtered.length; i += chunkSize) {
    const chunk = filtered.slice(i, i + chunkSize)
    try {
      const resp = await fetch(`https://api.first.org/data/v1/epss?cve=${chunk.join(',')}`)
      if (resp.ok) {
        const data = await resp.json() as { data?: Array<{ cve: string; epss: string }> }
        for (const entry of data.data ?? []) {
          scores.set(entry.cve, parseFloat(entry.epss) || 0)
        }
      }
    } catch {
      // EPSS is best-effort — non-fatal
    }
  }
  return scores
}

app.post('/ingest-cve', zValidator('json', cveIngestSchema), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const agent = await authenticateAgent(c, db)
    if (!agent) return c.json({ detail: 'Invalid agent credentials' }, 401)

    const { scan_id, findings: allFindings, present_keys, total_findings } = c.req.valid('json')
    const { error } = await hostScan(db, agent, scan_id)
    if (error) return c.json({ detail: error[0] }, error[1])
    const assetId = agent.hostAssetId!

    // Fetch asset for criticality score
    const [asset] = await db
      .select({ criticalityScore: assets.criticalityScore })
      .from(assets)
      .where(eq(assets.assetId, assetId))
      .limit(1)
    const criticality = asset?.criticalityScore ?? 5

    // Threat-intel match: CVE IDs named by intel this tenant may use (global feeds such as
    // CISA KEV, its own published events, shared and platform events; services/threatIntel).
    const cvePrefixedIds = [...new Set(allFindings.map(f => f.cve_id).filter(id => id?.startsWith('CVE-')))]
    let intel = new Map<string, CveIntel>()
    try {
      intel = await cveIntelFor(db, agent.tenantId ?? null, cvePrefixedIds)
    } catch (e) {
      console.error('cve ingest: threat-intel lookup failed (alerts stored without it):', e)
    }
    const ctiMatches = new Set(intel.keys())
    const kevMatches = new Set([...intel].filter(([, v]) => v.kev).map(([id]) => id))

    // Keep the findings that matter most: on KEV, named by any feed, likely exploited, severe.
    const rank = (f: typeof allFindings[number]): number[] =>
      [kevMatches.has(f.cve_id) ? 1 : 0, ctiMatches.has(f.cve_id) ? 1 : 0, f.epss ?? 0, f.cvss_base_score]
    const findings = [...allFindings].sort((x, y) => {
      const a = rank(x), b = rank(y)
      for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return b[i]! - a[i]!
      return 0
    }).slice(0, MAX_CVE_ALERTS)
    const totalFindings = Math.max(total_findings ?? 0, allFindings.length)

    // EPSS: Grype's own value when it sent one, otherwise FIRST's API (CVE IDs only).
    const missingEpss = [...new Set(findings.filter(f => f.epss == null).map(f => f.cve_id))].slice(0, MAX_EPSS_LOOKUPS)
    const epssMap = await fetchEpssScores(missingEpss)
    for (const f of findings) if (f.epss != null) epssMap.set(f.cve_id, f.epss)

    // Fetch all existing cve_detected events for this asset in ONE query for dedup
    const existingRows = await db
      .select({ eventId: events.eventId, details: events.details, status: events.status })
      .from(events)
      .where(and(
        eq(events.assetId, assetId),
        eq(events.eventType, 'cve_detected'),
      ))

    // Build dedup map: "cve_id::package_name" → { eventId, details, status }
    type ExistingEvent = { eventId: string; details: Record<string, unknown>; status: string }
    const existingMap = new Map<string, ExistingEvent>()
    for (const row of existingRows) {
      const d = (row.details ?? {}) as Record<string, unknown>
      const key = `${d.cve_id}::${d.package_name}`
      existingMap.set(key, { eventId: row.eventId, details: d, status: row.status })
    }
    const seenKeys = new Set<string>()
    // Everything still present on the machine, including findings past the cap.
    const presentKeys = new Set<string>([...(present_keys ?? []), ...allFindings.map(f => `${f.cve_id}::${f.package_name}`)])
    const now = new Date()

    const toInsert: (typeof events.$inferInsert)[] = []
    const stmts: unknown[] = []   // every write, run in db.batch chunks (one subrequest each)
    let eventsUpdated = 0

    for (const finding of findings) {
      const { cve_id, cvss_base_score, severity: grypeSev, package_name,
              package_version, fix_versions, description, cwe_ids } = finding
      if (!cve_id || !package_name) continue
      const dedupKey  = `${cve_id}::${package_name}`
      if (seenKeys.has(dedupKey)) continue    // same CVE reported for two copies of a package
      seenKeys.add(dedupKey)

      const epss      = epssMap.get(cve_id) ?? 0
      const ctiMatch  = ctiMatches.has(cve_id)
      const severity  = mapSeverity(cvss_base_score, grypeSev)
      const riskScore = computeRiskScore(cvss_base_score, epss, criticality, ctiMatch)
      const existing  = existingMap.get(dedupKey)
      const fresh = {
        cvss_base_score,
        epss_score:      epss,
        has_cti_match:   ctiMatch,
        kev:             kevMatches.has(cve_id),
        ti_event_titles: intel.get(cve_id)?.titles ?? [],
        advisory_id:     finding.advisory_id ?? null,
        package_type:    finding.package_type ?? null,
        fix_versions,
        description:     description.slice(0, 500),
        cwe_ids,
      }

      if (existing) {
        // Refresh all scored fields plus the freshest data from this scan
        const mergedDetails = { ...existing.details, ...fresh, package_version }
        // Still vulnerable after being marked resolved: the fix did not take, so
        // reopen. False positives and accepted risks stay closed.
        const reopen = existing.status === 'resolved'
        eventsUpdated++
        stmts.push(
          db.update(events)
            .set({
              lastSeen:           now,
              occurrences:        sql`${events.occurrences} + 1`,
              severity,
              compositeRiskScore: String(riskScore),
              details:            mergedDetails,
              updatedAt:          now,
              ...(reopen ? { status: 'open' as const, resolvedAt: null, resolvedBy: null,
                             resolutionNote: 'Reopened: CVE still present in latest SBOM scan' } : {}),
            })
            .where(eq(events.eventId, existing.eventId))
        )
      } else {
        toInsert.push({
          assetId,
          eventType:          'cve_detected',
          severity,
          compositeRiskScore: String(riskScore),
          details: { cve_id, package_name, package_version, ...fresh },
        })
      }
    }

    // New events, 50 rows per INSERT statement
    for (let i = 0; i < toInsert.length; i += 50) {
      stmts.push(db.insert(events).values(toInsert.slice(i, i + 50)))
    }

    // CVEs the latest scan no longer reports were patched or the package was
    // removed — close their open alerts so the queue reflects reality. A scan with
    // no findings at all closes every open one.
    const fixedIds = [...existingMap.entries()]
      .filter(([key, e]) => !presentKeys.has(key) && (e.status === 'open' || e.status === 'in_progress'))
      .map(([, e]) => e.eventId)
    if (fixedIds.length > 0) {
      stmts.push(db.update(events)
        .set({ status: 'resolved', resolvedAt: now, updatedAt: now,
               resolutionNote: 'Auto-resolved: CVE no longer present in latest SBOM scan' })
        .where(inArray(events.eventId, fixedIds)))
    }

    for (let i = 0; i < stmts.length; i += WRITE_BATCH) {
      await db.batch(stmts.slice(i, i + WRITE_BATCH) as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
    }
    const eventsCreated = toInsert.length

    // Link each matched alert to the feed entry naming its CVE (shown on the alert).
    await linkCveIndicators(db, { assetId })

    return c.json({
      events_created: eventsCreated, events_updated: eventsUpdated, events_resolved: fixedIds.length,
      // One alert per (CVE, package): copies and versions of a package share it. Only
      // distinct ones past MAX_CVE_ALERTS count as dropped.
      kev_matches: kevMatches.size, findings_total: totalFindings, findings_stored: seenKeys.size,
      findings_dropped: Math.max(0, presentKeys.size - seenKeys.size),
    }, 201)
  } catch (err) {
    console.error('cve ingest error:', err)
    return c.json({ detail: 'Failed to ingest CVE findings' }, 500)
  }
})

export default app
