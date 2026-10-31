import type { Env } from '../types'
import { getDb } from '../db/client'
import { runDriftAudit } from '../services/drift'
import { savePostureSnapshot } from '../services/posture'
import { purgeOldData } from '../services/retention'
import { CTI_INGEST_LOCK } from '../services/cti'
import { runAlertHygiene } from '../services/alertHygiene'

// Maps cron expression to handler name for logging
function getCronName(cron: string): string {
  const names: Record<string, string> = {
    '0 */6 * * *':  'drift-audit',
    '0 22 * * *':   'cti-ingestion',
    '0 16 * * *':   'posture-snapshot',
  }
  return names[cron] ?? cron
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
        await savePostureSnapshot(db)
        console.log('[posture-snapshot] Posture snapshot saved')
        const purged = await purgeOldData(db)
        console.log(`[retention] Purged ${purged.cti} stale CTI indicators, ${purged.events} closed events`)
        const closed = await runAlertHygiene(db)
        console.log(`[alert-hygiene] Closed ${closed.cve} CVE alerts without an SBOM, ${closed.newDevices} reviewed or stale new-device alerts`)
        break
      }

    }
  } catch (err) {
    console.error(`[cron] ${name} failed:`, err)
  }
}
