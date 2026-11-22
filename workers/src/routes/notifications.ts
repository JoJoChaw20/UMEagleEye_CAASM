import { Hono } from 'hono'
import { eq, and, desc, inArray, isNull } from 'drizzle-orm'
import { sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireAction } from '../middleware/auth'
import { getDb } from '../db/client'
import { advisories, agents, assets, events } from '../db/schema'
import { dueAtExpr } from '../lib/priority'
import { advisoryScope } from '../lib/advisoryScope'
import { agentLiveness, livenessMinutes } from '../lib/agentLiveness'

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

const agentStatus = (lastHeartbeat: Date | null, kind: string | null) => agentLiveness(lastHeartbeat, kind)

/** Open alerts past their fix-time target, in the user's tenant (the platform superadmin: all). */
function overdueAlerts(db: ReturnType<typeof getDb>, user: { role: string; tenantId?: string | null }) {
  return db.select({ count: sql<number>`count(*)::int` })
    .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
    .where(and(
      inArray(events.status, ['open', 'in_progress']), sql`now() > ${dueAtExpr}`,
      user.role === 'superadmin' ? undefined : eq(assets.tenantId, user.tenantId ?? '00000000-0000-0000-0000-000000000000'),
    ))
}

// ── GET / — aggregated notification feed ─────────────────────────
app.get('/', authMiddleware, requireAction('dashboard.view'), async (c) => {
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
      .where(advisoryScope(db, user))
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

    // 2. SLA breach: open alerts past their fix-time target (lib/alertRank.ts, the same rule as
    //    the Alerts page and the report)
    const [breachRow] = await overdueAlerts(db, user)

    const breachCount = breachRow?.count ?? 0
    if (breachCount > 0) {
      items.push({
        id: 'sla-breach-current',
        type: 'sla_breach',
        title: '⚠️ Alerts past their fix-time target',
        message: `${breachCount} ${breachCount === 1 ? 'alert is' : 'alerts are'} past the fix-time target. Filter Alerts by "Overdue" to see them.`,
        timestamp: new Date().toISOString(),
        severity: 'critical',
        metadata: { breach_count: breachCount },
      })
    }

    // 3. Agent status alerts (tenant-scoped). Retired agents can never connect again,
    //    so they never raise an offline alert.
    const agentRows = user.role === 'superadmin'
      ? await db.select().from(agents).where(isNull(agents.retiredAt))
      : user.tenantId
        ? await db.select().from(agents).where(and(eq(agents.tenantId, user.tenantId), isNull(agents.retiredAt)))
        : []

    for (const a of agentRows) {
      const status = agentStatus(a.lastHeartbeat, a.kind)
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
          message: `Agent "${a.name}" has not sent a heartbeat in the last ${livenessMinutes(a.kind).online} minutes.`,
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

// ── GET /count — lightweight unread count for header polling ──────
app.get('/count', authMiddleware, requireAction('dashboard.view'), async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const scope = advisoryScope(db, c.get('user'))
  try {
    const [recent, breach] = await Promise.all([
      db.select({ count: sql<number>`count(*)::int` })
        .from(advisories)
        .where(and(sql`${advisories.createdAt} > now() - interval '7 days'`, scope)),
      overdueAlerts(db, c.get('user')),
    ])
    return c.json({
      recent_advisories: recent[0]?.count ?? 0,
      sla_breaches: breach[0]?.count ?? 0,
    })
  } catch (err) {
    console.error('notifications GET /count error:', err)
    return c.json({ detail: 'Failed to fetch count' }, 500)
  }
})

export default app
