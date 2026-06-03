import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, gte, sql, or, desc } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { assets, events, postureMetrics, advisories, ctiIndicators, scanResults, sboms } from '../db/schema'

const app = new Hono<{ Bindings: Env }>()

const GENERATE_ROLES = ['ops_lead', 'business_owner', 'superadmin']
const SNAPSHOT_ROLES = ['ops_lead', 'superadmin']

// ── GET /data — synchronous report data for browser-side PDF ─────
app.get('/data', authMiddleware, requireRoles(...GENERATE_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db   = getDb(c.env.DATABASE_URL)
    const af   = user.role !== 'superadmin' && user.tenantId ? eq(assets.tenantId,       user.tenantId) : undefined
    const pmf  = user.role !== 'superadmin' && user.tenantId ? eq(postureMetrics.tenantId, user.tenantId) : undefined
    const sf   = user.role !== 'superadmin' && user.tenantId ? eq(scanResults.tenantId,   user.tenantId) : undefined
    const now  = new Date()
    const slaThreshold = new Date(now.getTime() - 72 * 60 * 60 * 1000)

    // Fetch all data in parallel
    const [
      postureRows, prevPostureRows,
      assetRows, assetByType, internetFacingRows,
      critRows, highRows, medRows,
      eventByType,
      openAdvRows, slaBreachRows,
      topAssetRows,
      topCveRows,
      ctiRows,
      sbomRows,
      lastScanRows,
    ] = await Promise.all([
      // Posture: latest + previous for trend
      db.select().from(postureMetrics).where(pmf).orderBy(desc(postureMetrics.timestamp)).limit(1),
      db.select().from(postureMetrics).where(pmf).orderBy(desc(postureMetrics.timestamp)).limit(2),
      // Asset counts
      db.select({ count: sql<number>`count(*)::int` }).from(assets).where(af),
      db.select({ deviceType: assets.deviceType, count: sql<number>`count(*)::int` })
        .from(assets).where(af).groupBy(assets.deviceType),
      db.select({ count: sql<number>`count(*)::int` })
        .from(assets).where(af ? and(af, eq(assets.isInternetFacing, true)) : eq(assets.isInternetFacing, true)),
      // Event severity counts
      db.select({ count: sql<number>`count(*)::int` }).from(events).where(eq(events.severity, 'critical')),
      db.select({ count: sql<number>`count(*)::int` }).from(events).where(eq(events.severity, 'high')),
      db.select({ count: sql<number>`count(*)::int` }).from(events).where(eq(events.severity, 'medium')),
      // Event type breakdown (top 6)
      db.select({ eventType: events.eventType, count: sql<number>`count(*)::int` })
        .from(events).groupBy(events.eventType).orderBy(desc(sql`count(*)`)).limit(6),
      // Advisories
      db.select({ advisoryId: advisories.advisoryId, summary: advisories.summary,
        recommendedAction: advisories.recommendedAction, status: advisories.status, createdAt: advisories.createdAt })
        .from(advisories)
        .where(or(eq(advisories.status, 'open'), eq(advisories.status, 'acknowledged')))
        .orderBy(desc(advisories.createdAt)).limit(15),
      // SLA breaches (open > 72h)
      db.select({ count: sql<number>`count(*)::int` }).from(advisories)
        .where(and(eq(advisories.status, 'open'), sql`${advisories.createdAt} < ${slaThreshold}`)),
      // Top assets by criticality
      db.select({ hostname: assets.hostname, ipAddress: assets.ipAddress,
        deviceType: assets.deviceType, criticalityScore: assets.criticalityScore,
        isInternetFacing: assets.isInternetFacing, owner: assets.owner })
        .from(assets).where(af).orderBy(desc(assets.criticalityScore)).limit(10),
      // Top CVE events by risk score
      db.select({ eventId: events.eventId, details: events.details,
        compositeRiskScore: events.compositeRiskScore, timestamp: events.timestamp })
        .from(events).where(eq(events.eventType, 'cve_detected'))
        .orderBy(desc(events.compositeRiskScore)).limit(8),
      // CTI summary
      db.select({ source: ctiIndicators.source, count: sql<number>`count(*)::int` })
        .from(ctiIndicators).groupBy(ctiIndicators.source),
      // SBOM count
      db.select({ count: sql<number>`count(*)::int` }).from(sboms),
      // Last scan
      db.select({ startedAt: scanResults.startedAt, scanType: scanResults.scanType,
        hostsDiscovered: scanResults.hostsDiscovered })
        .from(scanResults).where(sf).orderBy(desc(scanResults.startedAt)).limit(1),
    ])

    const posture    = postureRows[0]
    const prevScore  = prevPostureRows[1]?.overallScore ?? null
    const scoreTrend = prevScore !== null ? (posture?.overallScore ?? 0) - prevScore : null

    return c.json({
      generated_at:      now.toISOString(),
      report_type:       c.req.query('type') ?? 'executive',
      posture_score:     posture?.overallScore ?? 0,
      score_trend:       scoreTrend,
      total_assets:      assetRows[0]?.count ?? 0,
      critical_assets:   posture?.totalCriticalAssets ?? 0,
      internet_facing:   internetFacingRows[0]?.count ?? 0,
      asset_by_type:     assetByType,
      critical_events:   critRows[0]?.count ?? 0,
      high_events:       highRows[0]?.count ?? 0,
      medium_events:     medRows[0]?.count ?? 0,
      event_by_type:     eventByType,
      open_advisories:   openAdvRows,
      sla_breaches:      slaBreachRows[0]?.count ?? 0,
      top_assets:        topAssetRows,
      top_cves:          topCveRows,
      cti_summary:       ctiRows,
      sbom_count:        sbomRows[0]?.count ?? 0,
      last_scan:         lastScanRows[0] ?? null,
    })
  } catch (err) {
    console.error('reports GET /data error:', err)
    return c.json({ detail: 'Failed to fetch report data' }, 500)
  }
})

// ── POST /generate ───────────────────────────────────────────────
const generateSchema = z.object({
  report_type: z.enum(['weekly', 'monthly', 'executive']),
})

app.post('/generate', authMiddleware, requireRoles(...GENERATE_ROLES), zValidator('json', generateSchema), async (c) => {
  try {
    const user = c.get('user')
    const { report_type } = c.req.valid('json')

    const filename = `report_${report_type}_${Date.now()}.pdf`  // consumer honours this filename
    const r2Key = `reports/${user.tenantId ?? 'global'}/${filename}`

    // Queue report generation
    await c.env.REPORT_QUEUE.send({
      type:        'report',
      reportType:  report_type,
      filename,
      r2Key,
      tenantId:    user.tenantId ?? undefined,
      requestedBy: user.userId,
    })

    // Store metadata in KV for listing
    const meta = {
      filename,
      report_type,
      created_at: new Date().toISOString(),
      r2_key: r2Key,
      tenant_id: user.tenantId ?? null,
      requested_by: user.userId,
      status: 'queued',
    }
    await c.env.KV_CACHE.put(`report:${filename}`, JSON.stringify(meta), { expirationTtl: 60 * 60 * 24 * 90 }) // 90 days

    return c.json({ message: 'Report generation queued', filename, report_type, r2_key: r2Key }, 202)
  } catch (err) {
    console.error('reports POST /generate error:', err)
    return c.json({ detail: 'Failed to queue report generation' }, 500)
  }
})

// ── POST /upload — receive PDF blob from browser, store in R2 ────
app.post('/upload', authMiddleware, requireRoles(...GENERATE_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const formData = await c.req.formData()
    const file = formData.get('pdf') as File | null
    const reportType = (formData.get('report_type') as string | null) ?? 'executive'

    if (!file || file.size === 0) {
      return c.json({ detail: 'No PDF file provided' }, 400)
    }

    const filename = `report_${reportType}_${Date.now()}.pdf`
    const r2Key = `reports/${user.tenantId ?? 'global'}/${filename}`

    const buffer = await file.arrayBuffer()
    await c.env.REPORTS_BUCKET.put(r2Key, buffer, {
      httpMetadata: { contentType: 'application/pdf' },
    })

    const meta = {
      filename,
      report_type: reportType,
      created_at: new Date().toISOString(),
      r2_key: r2Key,
      tenant_id: user.tenantId ?? null,
      requested_by: user.userId,
      status: 'completed',
    }
    await c.env.KV_CACHE.put(`report:${filename}`, JSON.stringify(meta), {
      expirationTtl: 90 * 24 * 3600,
    })

    return c.json({ filename, r2_key: r2Key }, 201)
  } catch (err) {
    console.error('reports POST /upload error:', err)
    return c.json({ detail: 'Failed to upload report' }, 500)
  }
})

// ── GET /list ────────────────────────────────────────────────────
app.get('/list', authMiddleware, async (c) => {
  try {
    const user = c.get('user')

    // List keys with prefix 'report:' from KV
    const list = await c.env.KV_CACHE.list({ prefix: 'report:' })

    const reportMetas: Array<{
      filename: string
      report_type: string
      created_at: string
      r2_key: string
      tenant_id: string | null
      status: string
    }> = []

    for (const key of list.keys) {
      const raw = await c.env.KV_CACHE.get(key.name)
      if (!raw) continue

      try {
        const meta = JSON.parse(raw) as {
          filename: string
          report_type: string
          created_at: string
          r2_key: string
          tenant_id: string | null
          status: string
        }

        // Only show PDF reports
        if (!meta.filename?.endsWith('.pdf')) continue

        // Filter by tenant unless superadmin
        if (user.role !== 'superadmin' && user.tenantId) {
          if (meta.tenant_id !== user.tenantId) continue
        }

        reportMetas.push(meta)
      } catch {
        // Skip malformed entries
      }
    }

    // Sort by created_at descending
    reportMetas.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())

    return c.json({ total: reportMetas.length, reports: reportMetas })
  } catch (err) {
    console.error('reports GET /list error:', err)
    return c.json({ detail: 'Failed to list reports' }, 500)
  }
})

// ── GET /download/:filename ──────────────────────────────────────
app.get('/download/:filename', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { filename } = c.req.param()

    // Look up metadata from KV
    const raw = await c.env.KV_CACHE.get(`report:${filename}`)
    if (!raw) {
      return c.json({ detail: 'Report not found' }, 404)
    }

    const meta = JSON.parse(raw) as { r2_key: string; tenant_id: string | null }

    // Tenant check
    if (user.role !== 'superadmin' && user.tenantId && meta.tenant_id !== user.tenantId) {
      return c.json({ detail: 'Report not found' }, 404)
    }

    // Fetch from R2
    const obj = await c.env.REPORTS_BUCKET.get(meta.r2_key)
    if (!obj) {
      return c.json({ detail: 'Report file not yet available or still processing — try again in a few seconds.' }, 404)
    }

    const buffer = await obj.arrayBuffer()
    return c.newResponse(buffer, 200, {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': String(buffer.byteLength),
    })
  } catch (err) {
    console.error('reports GET /download error:', err)
    return c.json({ detail: 'Failed to download report' }, 500)
  }
})

// ── DELETE /delete/:filename ─────────────────────────────────────
app.delete('/delete/:filename', authMiddleware, requireRoles(...GENERATE_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const { filename } = c.req.param()

    const raw = await c.env.KV_CACHE.get(`report:${filename}`)
    if (!raw) {
      return c.json({ detail: 'Report not found' }, 404)
    }

    const meta = JSON.parse(raw) as { r2_key: string; tenant_id: string | null }

    if (user.role !== 'superadmin' && user.tenantId && meta.tenant_id !== user.tenantId) {
      return c.json({ detail: 'Report not found' }, 404)
    }

    await Promise.all([
      c.env.REPORTS_BUCKET.delete(meta.r2_key),
      c.env.KV_CACHE.delete(`report:${filename}`),
    ])

    return c.json({ message: 'Report deleted' })
  } catch (err) {
    console.error('reports DELETE /delete error:', err)
    return c.json({ detail: 'Failed to delete report' }, 500)
  }
})

// ── POST /snapshot ───────────────────────────────────────────────
app.post('/snapshot', authMiddleware, requireRoles(...SNAPSHOT_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const tenantCondition =
      user.role !== 'superadmin' && user.tenantId ? eq(assets.tenantId, user.tenantId) : undefined

    const assetRows = await db
      .select({ assetId: assets.assetId, criticalityScore: assets.criticalityScore })
      .from(assets)
      .where(tenantCondition)

    const total_assets = assetRows.length
    const total_critical_assets = assetRows.filter((a) => (a.criticalityScore ?? 0) >= 8).length
    const highCriticalityPercent = total_assets > 0 ? total_critical_assets / total_assets : 0

    const assetIds = assetRows.map((a) => a.assetId)

    let criticalCount = 0
    let highCount = 0
    let topRisks: unknown[] = []

    if (assetIds.length > 0) {
      const assetFilter = sql`${events.assetId} = ANY(ARRAY[${sql.join(assetIds.map(id => sql`${id}::uuid`), sql`, `)}])`

      const [critResult, highResult, topRiskRows] = await Promise.all([
        db
          .select({ count: sql<number>`count(*)::int` })
          .from(events)
          .where(and(assetFilter, eq(events.severity, 'critical'))),
        db
          .select({ count: sql<number>`count(*)::int` })
          .from(events)
          .where(and(assetFilter, eq(events.severity, 'high'))),
        db
          .select({
            eventId: events.eventId,
            severity: events.severity,
            eventType: events.eventType,
            assetId: events.assetId,
          })
          .from(events)
          .where(and(assetFilter, eq(events.severity, 'critical')))
          .limit(5),
      ])

      criticalCount = critResult[0]?.count ?? 0
      highCount = highResult[0]?.count ?? 0
      topRisks = topRiskRows
    }

    // Score algorithm
    let score = 100
    score -= Math.min(criticalCount * 5, 40)
    score -= Math.min(highCount * 2, 20)
    if (highCriticalityPercent > 0.2) score -= 10
    score = Math.max(0, Math.min(100, score))

    const [snapshot] = await db
      .insert(postureMetrics)
      .values({
        tenantId: user.tenantId ?? null,
        overallScore: score,
        totalAssets: total_assets,
        totalCriticalAssets: total_critical_assets,
        openCriticalEvents: criticalCount,
        topRisks,
      })
      .returning()

    return c.json({ message: 'Snapshot saved', snapshot }, 201)
  } catch (err) {
    console.error('reports POST /snapshot error:', err)
    return c.json({ detail: 'Failed to save posture snapshot' }, 500)
  }
})

export default app
