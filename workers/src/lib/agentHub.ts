// What the AgentHub Durable Object (durable/agentHub.ts) keeps in memory so a routine check-in needs no
// database: per agent, its key hash, what it last reported, the answer it was given and when it was last
// seen (written to the database in one batch: flush). Pure; docs/plans/2026-11-23-quiet-database.md.

// A cached answer is rebuilt from the database at least this often, plus up to SPREAD_MS per agent so
// agents do not all take the slow path in the same minute.
export const REVALIDATE_MS = 6 * 3600_000
export const SPREAD_MS = 30 * 60_000
// "Last seen" reaches the database at least this often (the hub's alarm), and sooner whenever a signed-in
// request, a scheduled job or a queue batch asks for it.
export const FLUSH_MS = 60 * 60_000

export interface HubAnswer { ok: true; policy: unknown }

export interface HubRemember {
  tenantId: string | null
  keyHash: string
  report: string             // reportKey() of the check-in
  publicIp: string | null
  answer: HubAnswer
  jobsWaiting: boolean       // jobs still queued for it (also ones not due yet): keep taking the slow path
}

interface Entry extends HubRemember { cachedAt: number; lastSeen: number; dirty: boolean }

export type HubCheck = { hit: true; answer: HubAnswer } | { hit: false }
export type HubSelector = { agentIds: string[] } | { tenantId: string } | { all: true }

/** A stable string of what a check-in reports, so an unchanged report can be told from a changed one. */
export function reportKey(fields: Record<string, unknown>): string {
  return stable(fields)
}

function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(',')}]`
  if (v && typeof v === 'object') {
    return `{${Object.keys(v).sort().filter((k) => (v as Record<string, unknown>)[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${stable((v as Record<string, unknown>)[k])}`).join(',')}}`
  }
  return JSON.stringify(v ?? null)
}

/** A per-agent offset in [0, SPREAD_MS) from its id. */
export function spreadOf(agentId: string): number {
  let h = 0
  for (let i = 0; i < agentId.length; i++) h = (h * 31 + agentId.charCodeAt(i)) >>> 0
  return h % SPREAD_MS
}

export class HubState {
  private entries = new Map<string, Entry>()

  /** The cached answer when nothing needs the database; records the check-in either way it hits. */
  check(agentId: string, keyHash: string, report: string, publicIp: string | null, now: number): HubCheck {
    const e = this.entries.get(agentId)
    if (!e || e.keyHash !== keyHash || e.report !== report || e.publicIp !== publicIp || e.jobsWaiting) return { hit: false }
    if (now - e.cachedAt >= REVALIDATE_MS + spreadOf(agentId)) return { hit: false }
    e.lastSeen = now
    e.dirty = true
    return { hit: true, answer: e.answer }
  }

  /** After a slow-path check-in, which wrote its last-seen time to the database itself. */
  remember(agentId: string, r: HubRemember, now: number): void {
    this.entries.set(agentId, { ...r, cachedAt: now, lastSeen: now, dirty: false })
  }

  /** Drop cached answers (the next check-in takes the slow path); unsaved last-seen times are kept. */
  invalidate(sel: HubSelector): number {
    let n = 0
    for (const [id, e] of this.entries) {
      const hit = 'all' in sel || ('tenantId' in sel ? e.tenantId === sel.tenantId : sel.agentIds.includes(id))
      if (!hit) continue
      n++
      if (e.dirty) this.entries.set(id, { ...e, keyHash: '', cachedAt: -Infinity })   // keep lastSeen for the flush
      else this.entries.delete(id)
    }
    return n
  }

  hasDirty(): boolean {
    for (const e of this.entries.values()) if (e.dirty) return true
    return false
  }

  /** The last-seen times not yet in the database; they count as saved until restore() puts them back. */
  takeDirty(): { agentId: string; lastSeen: number }[] {
    const out: { agentId: string; lastSeen: number }[] = []
    for (const [agentId, e] of this.entries) {
      if (!e.dirty) continue
      out.push({ agentId, lastSeen: e.lastSeen })
      e.dirty = false
    }
    return out
  }

  /** A flush failed: mark them unsaved again (unless a newer check-in already did). */
  restore(rows: { agentId: string; lastSeen: number }[]): void {
    for (const r of rows) {
      const e = this.entries.get(r.agentId)
      if (e && e.lastSeen <= r.lastSeen) e.dirty = true
    }
  }

  get size(): number { return this.entries.size }
}
