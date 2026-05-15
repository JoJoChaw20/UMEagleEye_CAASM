import { Hono } from 'hono'
import { eq, and, desc, gte, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { ctiIndicators } from '../db/schema'

const app = new Hono<{ Bindings: Env }>()

const INGEST_ROLES = ['ops_lead', 'security_engineer', 'superadmin']

// ── GET /indicators ──────────────────────────────────────────────
app.get('/indicators', authMiddleware, async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)

    const page = Math.max(1, parseInt(c.req.query('page') ?? '1'))
    const limit = Math.min(200, Math.max(1, parseInt(c.req.query('limit') ?? '50')))
    const offset = (page - 1) * limit
    const type = c.req.query('type')
    const source = c.req.query('source')

    const conditions = []
    if (type) {
      conditions.push(eq(ctiIndicators.indicatorType, type as 'ip' | 'domain' | 'hash' | 'url' | 'email'))
    }
    if (source) {
      conditions.push(eq(ctiIndicators.source, source))
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined

    const [rows, countRows] = await Promise.all([
      db
        .select()
        .from(ctiIndicators)
        .where(whereClause)
        .orderBy(desc(ctiIndicators.lastSeen))
        .limit(limit)
        .offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(ctiIndicators).where(whereClause),
    ])

    return c.json({ total: countRows[0]?.count ?? 0, page, limit, items: rows })
  } catch (err) {
    console.error('cti GET /indicators error:', err)
    return c.json({ detail: 'Failed to fetch CTI indicators' }, 500)
  }
})

// ── GET /matrix ──────────────────────────────────────────────────
app.get('/matrix', authMiddleware, async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)

    const rows = await db
      .select({
        attack_tactic: ctiIndicators.attackTactic,
        count: sql<number>`count(*)::int`,
      })
      .from(ctiIndicators)
      .where(sql`${ctiIndicators.attackTactic} IS NOT NULL`)
      .groupBy(ctiIndicators.attackTactic)
      .orderBy(desc(sql`count(*)`))

    const matrix: Record<string, number> = {}
    for (const row of rows) {
      if (row.attack_tactic) {
        matrix[row.attack_tactic] = row.count
      }
    }

    return c.json({ matrix, total_tactics: rows.length })
  } catch (err) {
    console.error('cti GET /matrix error:', err)
    return c.json({ detail: 'Failed to fetch MITRE ATT&CK matrix' }, 500)
  }
})

// ── POST /ingest ─────────────────────────────────────────────────
app.post('/ingest', authMiddleware, requireRoles(...INGEST_ROLES), async (c) => {
  try {
    // KV lock check — prevent duplicate runs within 1 hour
    const lockKey = 'cti_ingest_lock'
    const existing = await c.env.KV_CACHE.get(lockKey)

    if (existing) {
      return c.json({ message: 'CTI ingestion already running or recently completed', queued: false })
    }

    // Set lock with 1 hour TTL
    await c.env.KV_CACHE.put(lockKey, '1', { expirationTtl: 3600 })

    // Queue the ingestion job via ADVISORY_QUEUE (reusing available queue)
    await c.env.ADVISORY_QUEUE.send({ type: 'cti_ingest', triggeredBy: c.get('user').userId })

    return c.json({ message: 'CTI ingestion queued successfully', queued: true })
  } catch (err) {
    console.error('cti POST /ingest error:', err)
    return c.json({ detail: 'Failed to queue CTI ingestion' }, 500)
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
    for (const row of bySource) {
      by_source[row.source] = row.count
    }

    const by_type: Record<string, number> = {}
    for (const row of byType) {
      by_type[row.indicator_type] = row.count
    }

    return c.json({
      total: totalResult[0]?.count ?? 0,
      by_source,
      by_type,
      recent_7d: recent7d[0]?.count ?? 0,
    })
  } catch (err) {
    console.error('cti GET /stats error:', err)
    return c.json({ detail: 'Failed to fetch CTI stats' }, 500)
  }
})

export default app
