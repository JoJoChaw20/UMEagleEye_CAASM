import type { Env } from '../types'
import { getDb } from '../db/client'
import { runDriftAudit } from '../services/drift'
import { savePostureSnapshot } from '../services/posture'
import { purgeOldData } from '../services/retention'
import { ingestAllFeeds } from '../services/cti'
import { enrichMissingCwe } from '../services/nvd'

// Maps cron expression to handler name for logging
function getCronName(cron: string): string {
  const names: Record<string, string> = {
    '0 */6 * * *':  'drift-audit',
    '0 22 * * *':   'cti-ingestion',
    '0 23 * * *':   'nvd-update',
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
        await ingestAllFeeds(db, env.OTX_API_KEY, env.THREATFOX_API_KEY)
        console.log('[cti-ingestion] CTI feeds ingested')
        break
      }

      case 'posture-snapshot': {
        await savePostureSnapshot(db)
        console.log('[posture-snapshot] Posture snapshot saved')
        const purged = await purgeOldData(db)
        console.log(`[retention] Purged ${purged.cti} stale CTI indicators, ${purged.events} closed events`)
        break
      }

      case 'nvd-update': {
        const enriched = await enrichMissingCwe(db, env.NVD_API_KEY)
        console.log(`[nvd-update] Enriched ${enriched} CVE events with CWE data`)
        break
      }
    }
  } catch (err) {
    console.error(`[cron] ${name} failed:`, err)
  }
}
