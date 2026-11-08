import type { Env } from '../types'
import { getDb } from '../db/client'
import { runDriftAudit } from '../services/drift'
import { savePostureSnapshot } from '../services/posture'
import { purgeOldData } from '../services/retention'
import { CTI_INGEST_LOCK } from '../services/cti'
import { runAlertHygiene } from '../services/alertHygiene'
import { rescoreAssets } from '../lib/rescore'
import { tenants } from '../db/schema'

// Maps cron expression to handler name for logging
function getCronName(cron: string): string {
  const names: Record<string, string> = {
    '0 */6 * * *':  'drift-audit',
    '0 22 * * *':   'cti-ingestion',
    '0 16 * * *':   'posture-snapshot',
  }
  return names[cron] ?? cron
}

// One nightly step: its own failure no longer stops the steps after it (they all sat in one try,
// so a failed snapshot silently skipped cleanup and alert tidy-up every night). Each step's last
// result is kept in KV (cron:last:<step>, 30 days) for whoever needs to know it ran.
async function step(env: Env, name: string, run: () => Promise<string>): Promise<void> {
  const at = new Date().toISOString()
  try {
    const summary = await run()
    console.log(`[${name}] ${summary}`)
    await env.KV_CACHE.put(`cron:last:${name}`, JSON.stringify({ ok: true, at, summary }), { expirationTtl: 30 * 86400 }).catch(() => {})
  } catch (err) {
    console.error(`[${name}] failed:`, err)
    await env.KV_CACHE.put(`cron:last:${name}`, JSON.stringify({ ok: false, at, error: String(err).slice(0, 500) }), { expirationTtl: 30 * 86400 }).catch(() => {})
  }
}

export async function handleCron(controller: ScheduledController, env: Env): Promise<void> {
  const db = getDb(env.DATABASE_URL)
  const name = getCronName(controller.cron)
  console.log(`[cron] Running: ${name} (${controller.cron})`)

  try {
    switch (name) {
      case 'drift-audit': {
        const count = await runDriftAudit(db)
        console.log(`[drift-audit] Generated ${count} drift events`)
        break
      }

      case 'cti-ingestion': {
        // Queued like "Update feeds now": one feed per queue job (services/cti.ts
        // runIngestStep), since all of them in this run exceed the CPU limit.
        await env.KV_CACHE.put(CTI_INGEST_LOCK, '1', { expirationTtl: 3600 })
        await env.ADVISORY_QUEUE.send({ type: 'cti_ingest', triggeredBy: 'schedule' })
        console.log('[cti-ingestion] CTI feed ingestion queued')
        break
      }

      case 'posture-snapshot': {
        const tenantIds = (await db.select({ tenantId: tenants.tenantId }).from(tenants)).map((t) => t.tenantId)
        // The platform-wide snapshot, and one per tenant: tenant reports read their own trend,
        // which only the manual "Save snapshot" wrote before.
        await step(env, 'posture-snapshot', async () => {
          await savePostureSnapshot(db)
          for (const id of tenantIds) await savePostureSnapshot(db, id)
          return `Posture snapshot saved (platform and ${tenantIds.length} tenant(s))`
        })
        await step(env, 'retention', async () => {
          const purged = await purgeOldData(db)
          return `Purged ${purged.cti} stale CTI indicators, ${purged.events} closed events, ${purged.scans} old scan records`
        })
        await step(env, 'alert-hygiene', async () => {
          const closed = await runAlertHygiene(db)
          return `Closed ${closed.cve} CVE alerts without an SBOM, ${closed.newDevices} reviewed or stale new-device alerts; resolved ${closed.advisories} advisories of closed alerts`
        })
        // Criticality is recomputed on every scan, inventory and edit; this applies a
        // scoring-rule change to assets nothing has touched since (manual ones, say).
        // One read per tenant, writes only for scores that moved.
        await step(env, 'rescore', async () => {
          let changed = 0
          for (const id of tenantIds) changed += (await rescoreAssets(db, id)).scoresChanged
          return `${changed} criticality score(s) changed`
        })
        break
      }

    }
  } catch (err) {
    console.error(`[cron] ${name} failed:`, err)
  }
}
