// The database side of scan routing and network coverage (lib/agentRouting.ts): a
// tenant's agents as the routing rules see them.

import { and, eq, inArray, isNull, sql } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { agents, scanResults } from '../db/schema'
import type { RouteAgent } from '../lib/agentRouting'
import { policyOf, reportedOf, tenantPolicies } from './agentPolicy'

type Db = ReturnType<typeof getDb>
const ONLINE_MS = 2 * 60_000

export async function routeAgents(db: Db, tenantId: string): Promise<RouteAgent[]> {
  const rows = await db.select().from(agents).where(and(eq(agents.tenantId, tenantId), isNull(agents.retiredAt)))
  if (!rows.length) return []
  const tenant = (await tenantPolicies(db, [tenantId])).get(tenantId) ?? null
  const queued = await db.select({ agentId: scanResults.agentId })
    .from(scanResults)
    .where(and(
      inArray(scanResults.agentId, rows.map((r) => r.agentId)),
      eq(scanResults.scanType, 'active'),
      inArray(scanResults.status, ['pending', 'running']),
    ))
    .groupBy(scanResults.agentId)
  const busy = new Set(queued.map((q) => q.agentId))
  const now = Date.now()
  return rows.map((a) => {
    const effective = policyOf(a, tenant).effective
    const reported = reportedOf(a) as { networks?: unknown }
    return {
      agent_id: a.agentId,
      name: a.name,
      online: !!a.lastHeartbeat && now - new Date(a.lastHeartbeat).getTime() < ONLINE_MS,
      scanner: typeof effective.scanner === 'boolean' ? effective.scanner : null,
      passive: typeof effective.passive === 'boolean' ? effective.passive : null,
      networks: Array.isArray(reported.networks) ? reported.networks.filter((n): n is string => typeof n === 'string') : [],
      local_ip: a.gatewayIp,                 // the column has always held the agent's own address
      busy: busy.has(a.agentId),
      last_heartbeat: a.lastHeartbeat ? new Date(a.lastHeartbeat).toISOString() : null,
    }
  })
}

/** PCs and servers in this tenant with no agent of their own (their addresses). */
export async function unmanagedHostIps(db: Db, tenantId: string): Promise<string[]> {
  const rows = await db.execute(sql`
    SELECT a.ip_address AS ip FROM assets a
    WHERE a.tenant_id = ${tenantId} AND a.device_type IN ('server', 'workstation')
      AND a.inventory_collected_at IS NULL
      AND NOT EXISTS (SELECT 1 FROM agents g WHERE g.host_asset_id = a.asset_id AND g.retired_at IS NULL)`)
  return (rows.rows as { ip: string | null }[]).map((r) => r.ip).filter((ip): ip is string => !!ip)
}
