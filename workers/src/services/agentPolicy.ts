// The database side of agent policy (lib/agentPolicy.ts has the rules): an agent's
// resolved policy from its overrides and its tenant's defaults.

import { eq, inArray } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { agents, tenants } from '../db/schema'
import { resolvePolicy, type ResolvedPolicy } from '../lib/agentPolicy'

type Db = ReturnType<typeof getDb>
type AgentRow = typeof agents.$inferSelect
export type TenantPolicyRow = { agentPolicy: unknown; allowLocalScans: boolean }

export function reportedOf(agent: Pick<AgentRow, 'reported'>): {
  settings?: unknown; capabilities?: Record<string, unknown>; policy_version?: string; reported_at?: string
} {
  const r = agent.reported
  return r && typeof r === 'object' && !Array.isArray(r) ? (r as Record<string, never>) : {}
}

export function policyOf(agent: Pick<AgentRow, 'kind' | 'policy' | 'reported'>, tenant: TenantPolicyRow | null): ResolvedPolicy {
  return resolvePolicy({ kind: agent.kind, overrides: agent.policy, tenantDefaults: tenant?.agentPolicy })
}

export async function tenantPolicies(db: Db, tenantIds: (string | null)[]): Promise<Map<string, TenantPolicyRow>> {
  const ids = [...new Set(tenantIds.filter((t): t is string => !!t))]
  if (!ids.length) return new Map()
  const rows = await db.select({ tenantId: tenants.tenantId, agentPolicy: tenants.agentPolicy, allowLocalScans: tenants.allowLocalScans })
    .from(tenants).where(inArray(tenants.tenantId, ids))
  return new Map(rows.map((r) => [r.tenantId, { agentPolicy: r.agentPolicy, allowLocalScans: r.allowLocalScans }]))
}

/** The agent and its resolved policy, or null when there is no such agent. */
export async function agentPolicy(db: Db, agentId: string): Promise<{ agent: AgentRow; resolved: ResolvedPolicy } | null> {
  const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
  if (!agent) return null
  const tenant = (await tenantPolicies(db, [agent.tenantId])).get(agent.tenantId ?? '') ?? null
  return { agent, resolved: policyOf(agent, tenant) }
}
