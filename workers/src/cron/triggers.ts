import type { Env } from '../types'
import { getDb } from '../db/client'
import { runDriftAudit } from '../services/drift'
import { savePostureSnapshot } from '../services/posture'
import { ingestAllFeeds } from '../services/cti'
import { enrichMissingCwe } from '../services/nvd'
import { advisories } from '../db/schema'
import { eq, and, lt } from 'drizzle-orm'

// Maps cron expression to handler name for logging
function getCronName(cron: string): string {
  const names: Record<string, string> = {
    '*/15 * * * *': 'drift-audit',
    '*/30 * * * *': 'sla-monitor',
    '0 22 * * *':   'cti-ingestion',
    '0 23 * * *':   'nvd-update',
    '0 16 * * *':   'posture-snapshot',
  }
  return names[cron] ?? cron
}

async function checkSlaBreaches(db: ReturnType<typeof getDb>): Promise<void> {
  // Advisories open > 72 hours → SLA breach (surfaced in the in-app notification feed)
  const cutoff = new Date(Date.now() - 72 * 60 * 60 * 1000)
  const breaches = await db
    .select({ advisoryId: advisories.advisoryId })
    .from(advisories)
    .where(and(eq(advisories.status, 'open'), lt(advisories.createdAt, cutoff)))

  if (breaches.length > 0) {
    console.log(`[sla-monitor] ${breaches.length} SLA breach(es) detected — visible in Notification Centre`)
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

      case 'sla-monitor': {
        await checkSlaBreaches(db)
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
