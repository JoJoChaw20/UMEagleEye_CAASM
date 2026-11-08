// The database side of lib/scanTarget.ts: the networks a tenant's agents report they are on, and
// the checks of a settings change that names routers or ranges for a network agent.
import type { DB } from '../db/client'
import { networkTargetRefusal } from '../lib/scanTarget'
import { routeAgents } from './agentRouting'

export async function knownNetworks(db: DB, tenantId: string | null): Promise<string[]> {
  if (!tenantId) return []
  return [...new Set((await routeAgents(db, tenantId)).flatMap((a) => a.networks))]
}

/** Problems with the network agent's starting points and ranges in a settings change (null values clear). */
export async function networkTargetErrors(db: DB, tenantId: string | null, change: Record<string, unknown>): Promise<string[]> {
  const values = ['network_seeds', 'network_ranges']
    .flatMap((key) => (Array.isArray(change[key]) ? (change[key] as unknown[]).map((v) => [key, String(v)] as const) : []))
  if (!values.length) return []
  const known = await knownNetworks(db, tenantId)
  return values.flatMap(([key, v]) => {
    const why = networkTargetRefusal(v, known)
    return why ? [`${key}: ${why}`] : []
  })
}
