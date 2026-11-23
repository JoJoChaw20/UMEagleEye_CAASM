// The Worker's side of the AgentHub Durable Object (durable/agentHub.ts): reaching it, writing the agents'
// last-seen times before something reads them, and dropping cached check-in answers after a change.
// Every call is best effort: without the binding (tests, local runs) or when the hub fails, check-ins
// take the database path as before. docs/plans/2026-11-23-quiet-database.md
import type { Env } from '../types'
import type { HubSelector } from '../lib/agentHub'

// Last-seen times are written before a signed-in request at most this often per Worker instance.
const SYNC_MS = 60_000
let lastSync = 0

export function hubOf(env: Env) {
  const ns = env.AGENT_HUB
  return ns ? ns.get(ns.idFromName('agents')) : null
}

/** Write the buffered last-seen times now (signed-in requests, scheduled jobs, queue batches), so what
 *  is read next shows which agents are online. `force` skips the per-instance minute. */
export async function syncAgentHub(env: Env, force = false): Promise<void> {
  const now = Date.now()
  if (!force && now - lastSync < SYNC_MS) return
  lastSync = now
  const hub = hubOf(env)
  if (!hub) return
  try {
    await hub.flush()
  } catch (err) {
    console.error('agent hub: flush failed:', err)
  }
}

/** Drop cached check-in answers: the agents' next check-in reads settings and jobs from the database. */
export async function invalidateAgentHub(env: Env, sel: HubSelector): Promise<void> {
  const hub = hubOf(env)
  if (!hub) return
  try {
    await hub.invalidate(sel)
  } catch (err) {
    console.error('agent hub: invalidate failed:', err)
  }
}
