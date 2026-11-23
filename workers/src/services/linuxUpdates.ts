import { and, desc, eq, inArray } from 'drizzle-orm'
import type { DB } from '../db/client'
import { events } from '../db/schema'
import { OPEN_STATUSES } from '../lib/eventStatus'
import { linuxUpdateFacts, planLinuxUpdateAlert } from '../lib/linuxUpdates'

// Linux security updates waiting (lib/linuxUpdates.ts): the Linux os_patch_missing alert, checked on
// every agent inventory like services/windowsPatch.ts, so a machine that installs them has its alert
// closed by its next inventory. High: a security update is waiting, but no CVE detail from the channel.
export async function checkLinuxUpdates(db: DB, assetId: string, inventory: unknown, now = new Date()): Promise<string> {
  const facts = linuxUpdateFacts(inventory)
  if (!facts || facts.status === 'unknown') return 'none'
  const rows = await db.select({ eventId: events.eventId, status: events.status, details: events.details })
    .from(events)
    .where(and(eq(events.assetId, assetId), eq(events.eventType, 'os_patch_missing')))
    .orderBy(desc(events.updatedAt))
  const open = rows.filter(r => OPEN_STATUSES.includes(r.status))
  const stmts: unknown[] = []
  if (open.length > 1) {
    stmts.push(db.update(events)
      .set({ status: 'resolved', resolvedAt: now, updatedAt: now, resolutionNote: 'Merged into an identical open alert on the same asset' })
      .where(inArray(events.eventId, open.slice(1).map(r => r.eventId))))
  }
  const plan = planLinuxUpdateAlert(facts, open[0] ?? null, open.length ? null : rows[0] ?? null)
  if (plan.kind === 'open') {
    stmts.push(db.insert(events).values({ assetId, eventType: 'os_patch_missing', severity: 'high', details: plan.details, firstSeen: now, lastSeen: now }))
  } else if (plan.kind === 'update') {
    stmts.push(db.update(events).set({ details: plan.details, severity: 'high', lastSeen: now, updatedAt: now }).where(eq(events.eventId, plan.eventId)))
  } else if (plan.kind === 'resolve') {
    stmts.push(db.update(events).set({ status: 'resolved', resolvedAt: now, updatedAt: now, resolutionNote: plan.note }).where(eq(events.eventId, plan.eventId)))
  }
  if (stmts.length) await db.batch(stmts as unknown as Parameters<typeof db.batch>[0])
  console.log(`linux updates: asset=${assetId} ${facts.status} (${facts.updates}) -> ${plan.kind}`)
  return plan.kind
}
