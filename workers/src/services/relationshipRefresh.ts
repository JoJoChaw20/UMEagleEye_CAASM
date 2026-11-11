// Keeps a tenant's relationships current (Blast radius, an asset's Connected list): its topology and
// the relationships between its devices are built again in the background when devices come or go
// (a scan or inventory that created devices, a network agent's crawl, an asset added, deleted or
// merged), every night, and when someone presses "Update relationships" on the Network page.
// One rebuild per tenant at a time: a change during a rebuild has it run once more when it ends.

import type { Env } from '../types'
import { getDb } from '../db/client'
import { rebuildTopology } from '../routes/topology'
import { inferRelationshipsForTenant } from '../routes/relationships'

const LOCK_TTL = 300                     // seconds; a rebuild that died frees its tenant after this
const ROUNDS = 3                         // at most this many rebuilds in a row while changes keep coming
const lockKey = (tenantId: string) => `relationships:rebuilding:${tenantId}`
const againKey = (tenantId: string) => `relationships:again:${tenantId}`

/** Rebuild now; null when a rebuild of this tenant is already running (it will run once more). */
export async function refreshRelationships(env: Env, tenantId: string): Promise<{ nodes: number; relationships: number } | null> {
  if (await env.KV_CACHE.get(lockKey(tenantId))) {
    await env.KV_CACHE.put(againKey(tenantId), '1', { expirationTtl: LOCK_TTL })
    return null
  }
  await env.KV_CACHE.put(lockKey(tenantId), '1', { expirationTtl: LOCK_TTL })
  try {
    const db = getDb(env.DATABASE_URL)
    let result = { nodes: 0, relationships: 0 }
    for (let round = 0; round < ROUNDS; round++) {
      const nodes = await rebuildTopology(db, tenantId)
      result = { nodes, relationships: await inferRelationshipsForTenant(db, tenantId) }
      if (!(await env.KV_CACHE.get(againKey(tenantId)))) break
      await env.KV_CACHE.delete(againKey(tenantId))
    }
    return result
  } finally {
    await env.KV_CACHE.delete(lockKey(tenantId))
  }
}

/** Rebuild after the response has gone (a request's or a queue's execution context). */
export function refreshRelationshipsLater(
  c: { env: Env; executionCtx: { waitUntil(p: Promise<unknown>): void } }, tenantId: string | null | undefined,
): void {
  if (!tenantId) return
  const job = refreshRelationships(c.env, tenantId).catch((err) => console.error('relationships refresh failed:', err))
  try { c.executionCtx.waitUntil(job) } catch { /* no execution context (a test): it still runs */ }
}
