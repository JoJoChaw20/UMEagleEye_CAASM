import { Hono } from 'hono'
import { eq, and, lt, desc } from 'drizzle-orm'
import { sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb } from '../db/client'
import { advisories, agents } from '../db/schema'

const app = new Hono<{ Bindings: Env }>()

type Severity = 'info' | 'warning' | 'critical'
type NotifType = 'advisory_generated' | 'advisory_resolved' | 'sla_breach' | 'agent_offline' | 'agent_degraded'

interface Notification {
  id: string
  type: NotifType
  title: string
  message: string
  timestamp: string
  severity: Severity
  metadata: Record<string, unknown>
}

function agentStatus(lastHeartbeat: Date | null): 'online' | 'degraded' | 'offline' {
  if (!lastHeartbeat) return 'offline'
  const min = (Date.now() - new Date(lastHeartbeat).getTime()) / 60_000
  if (min < 2) return 'online'
  if (min < 10) return 'degraded'
  return 'offline'
}

// ── GET / — aggregated notification feed ─────────────────────────
app.get('/', authMiddleware, async (c) => {
  const user = c.get('user')
  const db = getDb(c.env.DATABASE_URL)
  const items: Notification[] = []

  try {
    // 1. Recent advisories (last 20)
    const recentAdvisories = await db
      .select({
        advisoryId: advisories.advisoryId,
        summary: advisories.summary,
        status: advisories.status,
        createdAt: advisories.createdAt,
        resolvedAt: advisories.resolvedAt,
      })
      .from(advisories)
      .orderBy(desc(advisories.createdAt))
      .limit(20)

    for (const a of recentAdvisories) {
      const summary = (a.summary ?? '').slice(0, 120) + ((a.summary?.length ?? 0) > 120 ? '...' : '')
      if (a.status === 'resolved' && a.resolvedAt) {
        items.push({
          id: `advisory-resolved-${a.advisoryId}`,
          type: 'advisory_resolved',
          title: '✅ Advisory Resolved',
          message: summary,
          timestamp: a.resolvedAt.toISOString(),
          severity: 'info',
          metadata: { advisory_id: a.advisoryId, status: a.status },
        })
      } else {
        items.push({
          id: `advisory-${a.advisoryId}`,
          type: 'advisory_generated',
          title: '🤖 AI Advisory Generated',
          message: summary,
          timestamp: a.createdAt!.toISOString(),
          severity: a.status === 'open' ? 'warning' : 'info',
          metadata: { advisory_id: a.advisoryId, status: a.status },
        })
      }
    }

    // 2. SLA breach: advisories open > 72 hours
    const cutoff = new Date(Date.now() - 72 * 60 * 60 * 1000)
    const [breachRow] = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(advisories)
      .where(and(eq(advisories.status, 'open'), lt(advisories.createdAt, cutoff)))

    const breachCount = breachRow?.count ?? 0
    if (breachCount > 0) {
      items.push({
        id: 'sla-breach-current',
        type: 'sla_breach',
        title: '⚠️ SLA Breach Alert',
        message: `${breachCount} ${breachCount === 1 ? 'advisory has' : 'advisories have'} been open for more than 72 hours.`,
        timestamp: new Date().toISOString(),
        severity: 'critical',
        metadata: { breach_count: breachCount },
      })
    }

    // 3. Agent status alerts (tenant-scoped)
    const agentRows = user.role === 'superadmin'
      ? await db.select().from(agents)
      : user.tenantId
        ? await db.select().from(agents).where(eq(agents.tenantId, user.tenantId))
        : []

    for (const a of agentRows) {
      const status = agentStatus(a.lastHeartbeat)
      if (status === 'offline') {
        items.push({
          id: `agent-offline-${a.agentId}`,
          type: 'agent_offline',
          title: '📡 Agent Offline',
          message: `Agent "${a.name}" is offline.${a.lastHeartbeat ? ` Last seen: ${new Date(a.lastHeartbeat).toLocaleString()}` : ' Never connected.'}`,
          timestamp: a.lastHeartbeat?.toISOString() ?? a.createdAt!.toISOString(),
          severity: 'warning',
          metadata: { agent_id: a.agentId, agent_name: a.name },
        })
      } else if (status === 'degraded') {
        items.push({
          id: `agent-degraded-${a.agentId}`,
          type: 'agent_degraded',
          title: '⚡ Agent Degraded',
          message: `Agent "${a.name}" has not sent a heartbeat in the last 10 minutes.`,
          timestamp: a.lastHeartbeat?.toISOString() ?? a.createdAt!.toISOString(),
          severity: 'warning',
          metadata: { agent_id: a.agentId, agent_name: a.name },
        })
      }
    }

    items.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())

    return c.json({ items: items.slice(0, 50) })
  } catch (err) {
    console.error('notifications GET error:', err)
    return c.json({ detail: 'Failed to fetch notifications' }, 500)
  }
})

// ── POST /test — send test Telegram message ───────────────────────
app.post('/test', authMiddleware, async (c) => {
  const user = c.get('user')
  if (!['ops_lead', 'superadmin'].includes(user.role)) {
    return c.json({ detail: 'Forbidden' }, 403)
  }

  const { TELEGRAM_BOT_TOKEN: token, TELEGRAM_CHAT_ID: chatId } = c.env
  if (!token || !chatId) {
    return c.json({ detail: 'Telegram not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.' }, 400)
  }

  try {
    const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: `*Test Notification — UMEagleEye*\nSent by *${user.username}* via dashboard\n${new Date().toLocaleString('en-MY', { timeZone: 'Asia/Kuala_Lumpur' })} MYT`,
        parse_mode: 'Markdown',
      }),
    })
    if (!res.ok) return c.json({ detail: 'Telegram API rejected the request. Check bot token and chat ID.' }, 502)
    return c.json({ ok: true })
  } catch {
    return c.json({ detail: 'Failed to reach Telegram API' }, 500)
  }
})

export default app
