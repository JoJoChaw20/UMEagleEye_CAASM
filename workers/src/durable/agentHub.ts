// The AgentHub Durable Object: answers routine agent check-ins without the database and writes their
// last-seen times in one batch (lib/agentHub.ts HubState; docs/plans/2026-11-23-quiet-database.md).
// One instance for the platform (services/agentHub.ts hubOf). State is in memory only: after a restart
// every agent's next check-in simply takes the slow path.
import { DurableObject } from 'cloudflare:workers'
import { sql } from 'drizzle-orm'
import type { Env } from '../types'
import { getDb } from '../db/client'
import { FLUSH_MS, HubState, type HubCheck, type HubRemember, type HubSelector } from '../lib/agentHub'

const CHUNK = 500

export class AgentHub extends DurableObject<Env> {
  private hub = new HubState()
  private alarmAt: number | null = null

  async check(agentId: string, keyHash: string, report: string, publicIp: string | null): Promise<HubCheck> {
    const res = this.hub.check(agentId, keyHash, report, publicIp, Date.now())
    if (res.hit) await this.armAlarm()
    return res
  }

  async remember(agentId: string, r: HubRemember): Promise<void> {
    this.hub.remember(agentId, r, Date.now())
  }

  async invalidate(sel: HubSelector): Promise<number> {
    return this.hub.invalidate(sel)
  }

  /** Writes the unsaved last-seen times to the database; returns how many. On failure they stay unsaved. */
  async flush(): Promise<number> {
    const rows = this.hub.takeDirty()
    if (!rows.length) return 0
    try {
      const db = getDb(this.env.DATABASE_URL)
      for (let i = 0; i < rows.length; i += CHUNK) {
        const values = sql.join(rows.slice(i, i + CHUNK).map((r) =>
          sql`(${r.agentId}::uuid, ${new Date(r.lastSeen).toISOString()}::timestamptz)`), sql`, `)
        await db.execute(sql`
          UPDATE agents a SET last_heartbeat = v.seen, status = 'online'
          FROM (VALUES ${values}) AS v(agent_id, seen)
          WHERE a.agent_id = v.agent_id AND (a.last_heartbeat IS NULL OR a.last_heartbeat < v.seen)`)
      }
    } catch (err) {
      this.hub.restore(rows)
      throw err
    }
    return rows.length
  }

  async alarm(): Promise<void> {
    this.alarmAt = null
    try {
      await this.flush()
    } catch (err) {
      console.error('agent hub: writing last-seen times failed (kept for the next try):', err)
    }
    if (this.hub.hasDirty()) await this.armAlarm()
  }

  private async armAlarm(): Promise<void> {
    if (this.alarmAt !== null) return
    const existing = await this.ctx.storage.getAlarm()
    if (existing !== null) {
      this.alarmAt = existing
      return
    }
    const at = Date.now() + FLUSH_MS
    await this.ctx.storage.setAlarm(at)
    this.alarmAt = at
  }
}
