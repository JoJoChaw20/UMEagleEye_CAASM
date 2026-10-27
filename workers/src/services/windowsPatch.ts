import { and, desc, eq, inArray } from 'drizzle-orm'
import type { DB } from '../db/client'
import { events } from '../db/schema'
import { OPEN_STATUSES } from '../lib/eventStatus'
import { assessPatch, patchSeverity, windowsOs, type MsrcIndex } from '../lib/windowsPatch'

// Windows patch alerts: one os_patch_missing alert per Windows machine whose build is missing
// fixes Microsoft has released (lib/windowsPatch.ts). Checked on every agent inventory, so a
// machine that installs the update has its alert closed by its next inventory (6-hourly).
//
// The reference data is in R2 (REPORTS_BUCKET), uploaded by scripts/msrc/build-msrc.mjs:
//   msrc/index.json          Windows versions -> month -> fixed builds, KB, counts
//   msrc/cves/<month>.json   that month's CVEs per Windows version (the alert's CVE list)

export const MSRC_PREFIX = 'msrc/'
const CACHE_MS = 60 * 60 * 1000

// Per isolate: the index is small (a few KB gzipped) and changes monthly.
let cached: { at: number; index: MsrcIndex | null } | null = null

export async function loadMsrcIndex(bucket: R2Bucket): Promise<MsrcIndex | null> {
  if (cached && Date.now() - cached.at < CACHE_MS) return cached.index
  let index: MsrcIndex | null = null
  try {
    const obj = await bucket.get(`${MSRC_PREFIX}index.json`)
    index = obj ? await obj.json<MsrcIndex>() : null
    if (!index) console.warn('windows patch: no msrc/index.json in R2; run scripts/msrc/build-msrc.mjs and upload it')
  } catch (err) {
    console.error('windows patch: reading msrc/index.json failed:', err)
  }
  cached = { at: Date.now(), index }
  return index
}

export type MsrcMonth = {
  month: string
  /** CVE -> [title, severity, exploited] */
  cves: Record<string, [string, string | null, boolean]>
  /** Windows version -> fixed build -> CVEs */
  products: Record<string, Record<string, string[]>>
}

export async function loadMsrcMonth(bucket: R2Bucket, month: string): Promise<MsrcMonth | null> {
  if (!/^\d{4}-[A-Z][a-z]{2}$/.test(month)) return null
  const obj = await bucket.get(`${MSRC_PREFIX}cves/${month}.json`)
  return obj ? obj.json<MsrcMonth>() : null
}

/** Opens, refreshes or closes the asset's Windows patch alert from its inventory.
 *  Returns what it did, for logs and tests. */
export async function checkWindowsPatch(
  db: DB, bucket: R2Bucket, assetId: string, inventory: unknown, now = new Date(),
): Promise<'opened' | 'updated' | 'resolved' | 'suppressed' | 'none'> {
  const os = windowsOs(inventory)
  if (!os) return 'none'
  const index = await loadMsrcIndex(bucket)
  const a = assessPatch(os, index, now)
  if (a.status === 'unknown') return 'none'   // no data, or a version we cannot place: leave alerts as they are

  const rows = await db.select({ eventId: events.eventId, status: events.status, details: events.details })
    .from(events)
    .where(and(eq(events.assetId, assetId), eq(events.eventType, 'os_patch_missing')))
    .orderBy(desc(events.updatedAt))
  const open = rows.filter(r => OPEN_STATUSES.includes(r.status))
  const stmts: unknown[] = []
  // Two open copies (assets merged): keep the newest
  if (open.length > 1) {
    stmts.push(db.update(events)
      .set({ status: 'resolved', resolvedAt: now, updatedAt: now, resolutionNote: 'Merged into an identical open alert on the same asset' })
      .where(inArray(events.eventId, open.slice(1).map(r => r.eventId))))
  }
  let result: 'opened' | 'updated' | 'resolved' | 'suppressed' | 'none' = 'none'

  if (a.status === 'current') {
    if (open.length) {
      stmts.push(db.update(events)
        .set({ status: 'resolved', resolvedAt: now, updatedAt: now,
               resolutionNote: `Auto-resolved: Windows is up to date (build ${a.build})` })
        .where(eq(events.eventId, open[0]!.eventId)))
      result = 'resolved'
    }
  } else {
    const details = {
      patch_status: a.status,
      product: a.product,
      build: a.build,
      cves: a.cves,
      critical: a.critical,
      exploited: a.exploited,
      latest_build: a.latest?.fixed_build ?? null,
      kb: a.latest?.kb ?? null,
      behind_since: a.missing[0]?.released ?? null,
      missing: a.missing,
      reason: a.reason,
    }
    const severity = patchSeverity(a)
    if (open.length) {
      stmts.push(db.update(events)
        .set({ details, severity, lastSeen: now, updatedAt: now })
        .where(eq(events.eventId, open[0]!.eventId)))
      result = 'updated'
    } else {
      // Marked false positive / accepted risk for this same build and the same newest fix:
      // stay quiet until the machine changes build or Microsoft releases a newer fix.
      const last = rows[0]
      const ld = (last?.details ?? {}) as Record<string, unknown>
      if (last && (last.status === 'false_positive' || last.status === 'accepted_risk')
          && ld['build'] === details.build && ld['latest_build'] === details.latest_build) {
        result = 'suppressed'
      } else {
        stmts.push(db.insert(events).values({
          assetId, eventType: 'os_patch_missing', severity, details, firstSeen: now, lastSeen: now,
        }))
        result = 'opened'
      }
    }
  }
  if (stmts.length) await db.batch(stmts as unknown as Parameters<typeof db.batch>[0])
  return result
}
