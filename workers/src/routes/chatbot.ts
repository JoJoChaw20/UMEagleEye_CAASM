import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { desc, eq, and, or, sql, inArray } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb } from '../db/client'
import { assets, events, advisories, postureMetrics } from '../db/schema'

const app = new Hono<{ Bindings: Env }>()

// ── Intent detection ──────────────────────────────────────────────
function detectIntent(raw: string): { intent: string; query: string } {
  const m = raw.toLowerCase().trim()

  if (/^\/?(help)$/.test(m)) return { intent: 'help', query: '' }
  if (/^\/status$/.test(m) || /\b(status|health|how are|overview)\b/.test(m))
    return { intent: 'status', query: '' }
  if (/^\/assets$/.test(m) || /\b(asset|device|server|host|workstation)\b/.test(m))
    return { intent: 'assets', query: '' }
  if (/^\/alerts$/.test(m) || /\b(alert|threat|critical event|attack|incident)\b/.test(m))
    return { intent: 'alerts', query: '' }
  if (/^\/advisories$/.test(m) || /\b(advisor|remediat|action item|pending fix|resolve)\b/.test(m))
    return { intent: 'advisories', query: '' }
  if (/^\/posture$/.test(m) || /\b(posture|score|risk level|security score)\b/.test(m))
    return { intent: 'posture', query: '' }
  if (/^\/ask\s+/.test(m))
    return { intent: 'ai', query: raw.slice(4).trim() }
  if (/\b(how (to|do|can|should)|what is|explain|why|prevent|mitigat|harden|block|stop|fix)\b/.test(m))
    return { intent: 'ai', query: raw }

  // Default: AI
  return { intent: 'ai', query: raw }
}

function helpText(role: string): string {
  const lines = [
    '**Available commands:**',
    '',
    '`status` — System health overview',
    '`posture` — Security posture score',
  ]
  if (role !== 'business_owner') {
    lines.push(
      '`assets` — Top assets by criticality',
      '`alerts` — Recent critical & high alerts',
      '`advisories` — Open advisories',
      '`ask <question>` — AI security assistant',
    )
  }
  lines.push('', 'You can also type naturally — I\'ll understand!')
  return lines.join('\n')
}

// ── DB helpers ────────────────────────────────────────────────────
async function queryStatus(db: ReturnType<typeof getDb>, tenantId?: string) {
  const af = tenantId ? eq(assets.tenantId, tenantId) : undefined
  const [assetCnt, advisoryCnt] = await Promise.all([
    db.select({ count: sql<number>`count(*)::int` }).from(assets).where(af),
    db.select({ count: sql<number>`count(*)::int` }).from(advisories)
      .where(or(eq(advisories.status, 'open'), eq(advisories.status, 'acknowledged'))),
  ])

  // Critical events scoped by asset tenant
  let critCount = 0
  if (!tenantId) {
    const [r] = await db.select({ count: sql<number>`count(*)::int` }).from(events)
      .where(eq(events.severity, 'critical'))
    critCount = r?.count ?? 0
  } else {
    const assetIds = (await db.select({ assetId: assets.assetId }).from(assets).where(af))
      .map(a => a.assetId)
    if (assetIds.length > 0) {
      const [r] = await db.select({ count: sql<number>`count(*)::int` }).from(events)
        .where(and(inArray(events.assetId, assetIds), eq(events.severity, 'critical')))
      critCount = r?.count ?? 0
    }
  }

  return [
    { label: 'Total Assets',     value: assetCnt[0]?.count ?? 0 },
    { label: 'Open Advisories',  value: advisoryCnt[0]?.count ?? 0 },
    { label: 'Critical Events',  value: critCount },
  ]
}

async function queryAssets(db: ReturnType<typeof getDb>, tenantId?: string) {
  const af = tenantId ? eq(assets.tenantId, tenantId) : undefined
  return db.select({
    hostname:        assets.hostname,
    ipAddress:       assets.ipAddress,
    deviceType:      assets.deviceType,
    criticalityScore: assets.criticalityScore,
  })
    .from(assets)
    .where(af)
    .orderBy(desc(assets.criticalityScore))
    .limit(10)
}

async function queryAlerts(db: ReturnType<typeof getDb>, tenantId?: string) {
  let assetIds: string[] | undefined
  if (tenantId) {
    assetIds = (await db.select({ assetId: assets.assetId }).from(assets)
      .where(eq(assets.tenantId, tenantId))).map(a => a.assetId)
    if (assetIds.length === 0) return []
  }

  const severityFilter = or(eq(events.severity, 'critical'), eq(events.severity, 'high'))
  const where = assetIds ? and(inArray(events.assetId, assetIds), severityFilter) : severityFilter

  return db.select({
    eventId:   events.eventId,
    eventType: events.eventType,
    severity:  events.severity,
    timestamp: events.timestamp,
  })
    .from(events)
    .where(where)
    .orderBy(desc(events.timestamp))
    .limit(10)
}

async function queryAdvisories(db: ReturnType<typeof getDb>) {
  return db.select({
    advisoryId: advisories.advisoryId,
    summary:    advisories.summary,
    status:     advisories.status,
    createdAt:  advisories.createdAt,
  })
    .from(advisories)
    .where(or(eq(advisories.status, 'open'), eq(advisories.status, 'acknowledged')))
    .orderBy(desc(advisories.createdAt))
    .limit(10)
}

async function queryPosture(db: ReturnType<typeof getDb>, tenantId?: string) {
  // Try latest posture snapshot first
  const snapshotFilter = tenantId ? eq(postureMetrics.tenantId, tenantId) : undefined
  const [snap] = await db.select()
    .from(postureMetrics)
    .where(snapshotFilter)
    .orderBy(desc(postureMetrics.timestamp))
    .limit(1)

  if (snap) {
    return {
      score:    snap.overallScore,
      total:    snap.totalAssets,
      critical: snap.totalCriticalAssets,
      openCrit: snap.openCriticalEvents,
    }
  }

  // Fallback: compute live from assets
  const af = tenantId ? eq(assets.tenantId, tenantId) : undefined
  const rows = await db.select({ criticalityScore: assets.criticalityScore }).from(assets).where(af)
  const total = rows.length
  if (total === 0) return { score: 0, total: 0, critical: 0, openCrit: 0 }
  const critical = rows.filter(r => (r.criticalityScore ?? 0) >= 8).length
  const avg = rows.reduce((s, r) => s + (r.criticalityScore ?? 5), 0) / total
  const score = Math.max(0, Math.min(100, Math.round(100 - avg * 8)))
  return { score, total, critical, openCrit: 0 }
}

async function askAI(env: Env, question: string): Promise<string> {
  // Prefer DeepSeek direct API if key is available, fall back to OpenRouter
  const useDeepSeek = !!env.DEEPSEEK_API_KEY
  const apiKey = useDeepSeek ? env.DEEPSEEK_API_KEY : env.OPENROUTER_API_KEY
  const baseUrl = useDeepSeek
    ? 'https://api.deepseek.com/chat/completions'
    : 'https://openrouter.ai/api/v1/chat/completions'
  const model = useDeepSeek ? 'deepseek-chat' : (env.OPENROUTER_MODEL ?? 'deepseek/deepseek-chat')

  const res = await fetch(baseUrl, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model,
      messages: [
        {
          role: 'system',
          content:
            'You are a cybersecurity assistant for the UMEagleEye CAASM platform. ' +
            'Give concise, actionable security advice. Keep responses under 300 words. ' +
            'Use bullet points for steps. Focus on practical remediation.',
        },
        { role: 'user', content: question },
      ],
      max_tokens: 450,
    }),
  })
  if (!res.ok) throw new Error(`AI API error: ${res.status}`)
  const data = await res.json() as { choices?: { message?: { content?: string } }[] }
  return data.choices?.[0]?.message?.content ?? 'No response from AI.'
}

// ── Route ─────────────────────────────────────────────────────────
app.post(
  '/',
  authMiddleware,
  zValidator('json', z.object({ message: z.string().min(1).max(1000) })),
  async (c) => {
    const { message } = c.req.valid('json')
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const tenantId = user.role !== 'superadmin' ? user.tenantId : undefined
    const restricted = user.role === 'business_owner'

    const { intent, query } = detectIntent(message)

    if (restricted && !['help', 'status', 'posture'].includes(intent)) {
      return c.json({
        type: 'text',
        content: 'Your role only has access to `status` and `posture` queries.',
      })
    }

    try {
      switch (intent) {
        case 'help':
          return c.json({ type: 'text', content: helpText(user.role) })

        case 'status': {
          const items = await queryStatus(db, tenantId)
          return c.json({ type: 'stats', content: 'System Status', items })
        }

        case 'assets': {
          const items = await queryAssets(db, tenantId)
          return c.json({ type: 'assets', content: 'Top Assets by Criticality', items })
        }

        case 'alerts': {
          const items = await queryAlerts(db, tenantId)
          return c.json({ type: 'alerts', content: 'Recent Critical & High Alerts', items })
        }

        case 'advisories': {
          const items = await queryAdvisories(db)
          return c.json({ type: 'advisories', content: 'Open Advisories', items })
        }

        case 'posture': {
          const data = await queryPosture(db, tenantId)
          return c.json({ type: 'posture', content: 'Security Posture', data })
        }

        case 'ai': {
          if (!c.env.DEEPSEEK_API_KEY && !c.env.OPENROUTER_API_KEY) {
            return c.json({ type: 'text', content: 'AI assistant is not configured on this instance.' })
          }
          const answer = await askAI(c.env, query || message)
          return c.json({ type: 'ai', content: answer })
        }

        default:
          return c.json({ type: 'text', content: helpText(user.role) })
      }
    } catch (err) {
      console.error('[chatbot]', err)
      return c.json({ type: 'text', content: 'Something went wrong. Please try again.' }, 500)
    }
  },
)

export default app
