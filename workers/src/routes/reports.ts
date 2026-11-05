import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, gte, sql, or, desc } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { isOpenEvent } from '../lib/eventStatus'
import { assets, events, postureMetrics, advisories, ctiIndicators, scanResults, sboms } from '../db/schema'
import { buildReportData } from '../services/reportData'

const app = new Hono<{ Bindings: Env }>()

const READ_ROLES     = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner']
const GENERATE_ROLES = ['tenant_superadmin', 'tenant_admin']
const SNAPSHOT_ROLES = ['tenant_superadmin']

// ── GET /data — synchronous report data for browser-side PDF ─────
app.get('/data', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user')
    if (user.role !== 'superadmin' && !user.tenantId) return c.json({ detail: 'Your account is not part of an organisation' }, 403)
    const db   = getDb(c.env.DATABASE_URL)
    const tenantId = user.role !== 'superadmin' ? (user.tenantId ?? undefined) : undefined
    return c.json(await buildReportData(db, tenantId, c.req.query('type') ?? 'executive'))
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

        // Skip reports not associated with any tenant
        if (!meta.tenant_id) continue

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
          .where(and(assetFilter, isOpenEvent(), eq(events.severity, 'critical'))),
        db
          .select({ count: sql<number>`count(*)::int` })
          .from(events)
          .where(and(assetFilter, isOpenEvent(), eq(events.severity, 'high'))),
        db
          .select({
            eventId: events.eventId,
            severity: events.severity,
            eventType: events.eventType,
            assetId: events.assetId,
          })
          .from(events)
          .where(and(assetFilter, isOpenEvent(), eq(events.severity, 'critical')))
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
