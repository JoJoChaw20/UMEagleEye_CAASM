/**
 * UMEagleEye Workers — CTI routes
 * Returns snake_case field names to match frontend expectations.
 */

import { Hono } from 'hono'
import { eq, and, desc, gte, ilike, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { ctiIndicators, assets } from '../db/schema'

const app = new Hono<{ Bindings: Env }>()

const INGEST_ROLES = ['ops_lead', 'security_engineer', 'superadmin']

// ── Helper: transform a Drizzle CTI row → snake_case ─────────────
function toSnake(row: typeof ctiIndicators.$inferSelect) {
  return {
    indicator_id:       row.indicatorId,
    source:             row.source,
    indicator_type:     row.indicatorType,
    value:              row.value,
    confidence_score:   row.confidenceScore != null ? Number(row.confidenceScore) : null,
    attack_tactic:      row.attackTactic,
    attack_technique:   row.attackTechnique,
    first_seen:         row.firstSeen,
    last_seen:          row.lastSeen,
  }
}

// ── GET /indicators ──────────────────────────────────────────────
app.get('/indicators', authMiddleware, async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)

    const page     = Math.max(1, parseInt(c.req.query('page')  ?? '1'))
    const limit    = Math.min(500, Math.max(1, parseInt(c.req.query('limit') ?? '100')))
    const offset   = (page - 1) * limit
    const type     = c.req.query('indicator_type') ?? c.req.query('type')
    const source   = c.req.query('source')
    const search   = c.req.query('search')

    const conditions = []
    if (type)   conditions.push(eq(ctiIndicators.indicatorType, type as 'ip' | 'domain' | 'hash' | 'url' | 'email'))
    if (source) conditions.push(ilike(ctiIndicators.source, `%${source}%`))
    if (search) conditions.push(ilike(ctiIndicators.value, `%${search}%`))

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined

    const [rows, countRows] = await Promise.all([
      db.select().from(ctiIndicators).where(whereClause).orderBy(desc(ctiIndicators.lastSeen)).limit(limit).offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(ctiIndicators).where(whereClause),
    ])

    return c.json({
      total:  countRows[0]?.count ?? 0,
      page,
      limit,
      items:  rows.map(toSnake),
    })
  } catch (err) {
    console.error('cti GET /indicators error:', err)
    return c.json({ detail: 'Failed to fetch CTI indicators' }, 500)
  }
})

// ── GET /stats ───────────────────────────────────────────────────
app.get('/stats', authMiddleware, async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)

    const [totalResult, bySource, byType, recent7d] = await Promise.all([
      db.select({ count: sql<number>`count(*)::int` }).from(ctiIndicators),
      db
        .select({ source: ctiIndicators.source, count: sql<number>`count(*)::int` })
        .from(ctiIndicators)
        .groupBy(ctiIndicators.source)
        .orderBy(desc(sql`count(*)`)),
      db
        .select({ indicator_type: ctiIndicators.indicatorType, count: sql<number>`count(*)::int` })
        .from(ctiIndicators)
        .groupBy(ctiIndicators.indicatorType)
        .orderBy(desc(sql`count(*)`)),
      db
        .select({ count: sql<number>`count(*)::int` })
        .from(ctiIndicators)
        .where(gte(ctiIndicators.firstSeen, sevenDaysAgo)),
    ])

    const by_source: Record<string, number> = {}
    for (const row of bySource) by_source[row.source] = row.count

    const by_type: Record<string, number> = {}
    for (const row of byType) by_type[row.indicator_type] = row.count

    return c.json({
      total_indicators: totalResult[0]?.count ?? 0,  // snake_case for frontend
      by_source,
      by_type,
      recent_7d: recent7d[0]?.count ?? 0,
    })
  } catch (err) {
    console.error('cti GET /stats error:', err)
    return c.json({ detail: 'Failed to fetch CTI stats' }, 500)
  }
})

// ── GET /matrix ──────────────────────────────────────────────────
// Returns { matrix: { "Tactic Name": [{technique_id, count}] } }
app.get('/matrix', authMiddleware, async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)

    const rows = await db
      .select({
        attack_tactic:    ctiIndicators.attackTactic,
        attack_technique: ctiIndicators.attackTechnique,
        count:            sql<number>`count(*)::int`,
      })
      .from(ctiIndicators)
      .where(sql`${ctiIndicators.attackTactic} IS NOT NULL`)
      .groupBy(ctiIndicators.attackTactic, ctiIndicators.attackTechnique)
      .orderBy(ctiIndicators.attackTactic, desc(sql`count(*)`))

    // Build { tactic → [{technique_id, count}] } structure
    const matrix: Record<string, Array<{ technique_id: string; count: number }>> = {}
    for (const row of rows) {
      const tactic = row.attack_tactic!
      if (!matrix[tactic]) matrix[tactic] = []
      matrix[tactic].push({
        technique_id: row.attack_technique || 'Unknown',
        count: row.count,
      })
    }

    return c.json({ matrix, total_indicators: rows.reduce((s, r) => s + r.count, 0) })
  } catch (err) {
    console.error('cti GET /matrix error:', err)
    return c.json({ detail: 'Failed to fetch MITRE ATT&CK matrix' }, 500)
  }
})

// ── GET /lookup ──────────────────────────────────────────────────
app.get('/lookup', authMiddleware, async (c) => {
  try {
    const db    = getDb(c.env.DATABASE_URL)
    const value = c.req.query('value')?.trim()
    if (!value) return c.json({ detail: 'value query param required' }, 422)

    // Find indicator
    const [indicator] = await db
      .select()
      .from(ctiIndicators)
      .where(eq(ctiIndicators.value, value))
      .limit(1)

    // Cross-reference against internal assets (IP match only)
    let matched_internal_asset = null
    try {
      const [asset] = await db
        .select({
          assetId:         assets.assetId,
          hostname:        assets.hostname,
          ipAddress:       assets.ipAddress,
          criticalityScore: assets.criticalityScore,
          isInternetFacing: assets.isInternetFacing,
        })
        .from(assets)
        .where(eq(assets.ipAddress, value))
        .limit(1)

      if (asset) {
        matched_internal_asset = {
          asset_id:         asset.assetId,
          hostname:         asset.hostname,
          ip_address:       asset.ipAddress,
          criticality_score: asset.criticalityScore,
          is_internet_facing: asset.isInternetFacing,
        }
      }
    } catch {
      // Non-IP values will not match asset IPs — expected
    }

    if (indicator) {
      return c.json({
        found: true,
        indicator: toSnake(indicator),
        matched_internal_asset,
      })
    }

    return c.json({ found: false, value, matched_internal_asset })
  } catch (err) {
    console.error('cti GET /lookup error:', err)
    return c.json({ detail: 'Lookup failed' }, 500)
  }
})

// ── GET /debug ───────────────────────────────────────────────────
// Live reachability test — accessible to any authenticated user.
app.get('/debug', authMiddleware, async (c) => {
  const results: Record<string, unknown> = {}

  // ── OTX ──
  try {
    const key = c.env.OTX_API_KEY
    results.otx_key_set    = !!key
    results.otx_key_length = key?.length ?? 0
    const res = await fetch(
      'https://otx.alienvault.com/api/v1/pulses/activity?limit=3&page=1',
      { headers: key ? { 'X-OTX-API-KEY': key } : {} },
    )
    results.otx_http_status = res.status
    results.otx_ok = res.ok
    if (res.ok) {
      const d = await res.json() as { count?: number; results?: Array<{ name: string; indicators: unknown[] }> }
      results.otx_total_pulses_available = d.count
      results.otx_pulses_in_response     = d.results?.length ?? 0
      results.otx_first_pulse_name       = d.results?.[0]?.name ?? null
      results.otx_first_pulse_indicators = d.results?.[0]?.indicators?.length ?? 0
    } else {
      results.otx_error_body = await res.text().catch(() => '(unreadable)')
    }
  } catch (e) {
    results.otx_fetch_exception = String(e)
  }

  // ── ThreatFox ──
  try {
    const key = c.env.THREATFOX_API_KEY
    results.threatfox_key_set    = !!key
    results.threatfox_key_length = key?.length ?? 0
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (key) headers['Auth-Key'] = key

    const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers,
      body: JSON.stringify({ query: 'get_iocs', days: 1 }),
    })
    results.threatfox_http_status = res.status
    results.threatfox_ok = res.ok
    const rawText = await res.text()
    results.threatfox_raw_response_snippet = rawText.slice(0, 300)
    if (res.ok) {
      try {
        const d = JSON.parse(rawText) as { query_status?: string; data?: unknown[] }
        results.threatfox_query_status  = d.query_status
        results.threatfox_ioc_count     = Array.isArray(d.data) ? d.data.length : `data is ${typeof d.data}`
        results.threatfox_sample_ioc    = Array.isArray(d.data) ? d.data[0] : d.data
      } catch { results.threatfox_parse_error = 'JSON.parse failed' }
    }
  } catch (e) {
    results.threatfox_fetch_exception = String(e)
  }

  return c.json(results)
})

// ── POST /ingest ─────────────────────────────────────────────────
app.post('/ingest', authMiddleware, requireRoles(...INGEST_ROLES), async (c) => {
  try {
    const lockKey  = 'cti_ingest_lock'
    const existing = await c.env.KV_CACHE.get(lockKey)
    if (existing) {
      return c.json({ message: 'CTI ingestion already running or recently completed', queued: false })
    }

    await c.env.KV_CACHE.put(lockKey, '1', { expirationTtl: 3600 })
    await c.env.ADVISORY_QUEUE.send({ type: 'cti_ingest', triggeredBy: c.get('user').userId })

    return c.json({ message: 'CTI ingestion queued successfully', queued: true })
  } catch (err) {
    console.error('cti POST /ingest error:', err)
    return c.json({ detail: 'Failed to queue CTI ingestion' }, 500)
  }
})

export default app
