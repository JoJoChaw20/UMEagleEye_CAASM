import { buildPdf } from '../../../frontend/src/utils/reportPdf.js'
import { buildReportData } from '../services/reportData'
import type { Env } from '../types'
import { getDb } from '../db/client'
import { isOpenEvent } from '../lib/eventStatus'
import { generateAdvisory } from '../services/advisory'
import { savePostureSnapshot } from '../services/posture'
import { CTI_INGEST_LOCK, runIngestStep, type CtiStep } from '../services/cti'
import { runDriftAudit } from '../services/drift'
import { runServiceCves, type ServiceCveJob } from '../services/serviceCves'
import { postureMetrics, assets, events, advisories } from '../db/schema'
import { and, desc, eq, inArray, sql } from 'drizzle-orm'
import { runKgSyncJob, signalKgSyncSafe } from '../kg/sync'
import { ACTIVE_ADVISORY_STATUSES, advisoryInTenant } from '../lib/advisoryScope'

interface AdvisoryJob {
  type: 'advisory'
  eventId: string
  userId: string
}

interface ReportJob {
  type: 'report'
  reportType: 'weekly' | 'monthly' | 'executive'
  filename?: string
  r2Key?: string
  requestedBy: string
  tenantId?: string
}

interface CtiIngestJob {
  type: 'cti_ingest'
  triggeredBy?: string
  /** One feed per job (services/cti.ts runIngestStep); none = the first */
  step?: CtiStep
}

interface DriftCheckJob {
  type: 'drift_check'
  assetId: string
  scanId?: string
  agentId?: string
}

// Applies the graph's outstanding changes (kg/sync.ts); sent by signalKgSync and by itself while work remains
interface KgSyncJob {
  type: 'kg_sync'
}

type Job = AdvisoryJob | ReportJob | CtiIngestJob | ServiceCveJob | KgSyncJob

// The same report as the dashboard's download: same data (services/reportData.ts), same
// layout (frontend/src/utils/reportPdf.js). A queued report is always a tenant's (only tenant
// admins can queue one), or every tenant's when no tenant is given.
async function buildReportPdf(db: ReturnType<typeof getDb>, reportType: string, tenantId?: string): Promise<ArrayBuffer> {
  const data = await buildReportData(db, tenantId, reportType)
  return buildPdf(data, reportType).output('arraybuffer')
}

export async function handleQueue(batch: MessageBatch<unknown>, env: Env): Promise<void> {
  const db = getDb(env.DATABASE_URL)

  // Drift checks queued by scan ingest: run them together right away so a new
  // risky port or MAC change becomes an alert minutes after the scan, not at
  // the next 15-minute cron.
  const driftMsgs = batch.messages.filter(m => (m.body as { type?: string })?.type === 'drift_check')
  if (driftMsgs.length > 0) {
    const ids = [...new Set(driftMsgs.map(m => (m.body as DriftCheckJob).assetId).filter(Boolean))]
    try {
      const created = await runDriftAudit(db, null, ids)
      console.log(`[drift_check] ${ids.length} asset(s) checked, ${created} new alert(s)`)
      if (created > 0) await signalKgSyncSafe(env)
      for (const m of driftMsgs) m.ack()
    } catch (err) {
      console.error('[drift_check] failed:', err)
      for (const m of driftMsgs) m.retry()
    }
  }

  // Set when a job wrote tables the graph reads; one signal after the batch (never for kg_sync itself).
  let wrote = false

  for (const message of batch.messages) {
    const job = message.body as Job
    if ((job as { type?: string })?.type === 'drift_check') continue

    try {
      if (job.type === 'advisory') {
        const advisory = await generateAdvisory(
          db, job.eventId,
          env.OPENROUTER_API_KEY, env.OPENROUTER_MODEL, env.DEEPSEEK_API_KEY,
          { kv: env.KV_CACHE, nvdKey: env.NVD_API_KEY },
        )
        if (advisory) {
          console.log(`[advisory] Generated ${advisory.advisoryId} for ${advisory.assetLabel} (${advisory.severity} ${advisory.eventType})`)
          wrote = true
        }
        message.ack()
      } else if (job.type === 'report') {
        const filename = job.filename ?? `report_${job.reportType}_${Date.now()}.pdf`
        const r2Key    = job.r2Key    ?? filename
        try {
          const pdfBytes = await buildReportPdf(db, job.reportType ?? 'executive', job.tenantId)

          await env.REPORTS_BUCKET.put(r2Key, pdfBytes, {
            httpMetadata: { contentType: 'application/pdf' },
          })

          const meta = {
            filename,
            report_type: job.reportType,
            created_at:  new Date().toISOString(),
            r2_key:      r2Key,
            tenant_id:   job.tenantId ?? null,
            status:      'completed',
          }
          await env.KV_CACHE.put(`report:${filename}`, JSON.stringify(meta), { expirationTtl: 90 * 24 * 3600 })
        } catch (pdfErr) {
          console.error('[report] PDF generation failed:', pdfErr)
          // Mark as failed so the UI shows an error instead of spinning forever
          const failedMeta = {
            filename,
            report_type: job.reportType,
            created_at:  new Date().toISOString(),
            r2_key:      r2Key,
            tenant_id:   job.tenantId ?? null,
            status:      'failed',
          }
          await env.KV_CACHE.put(`report:${filename}`, JSON.stringify(failedMeta), { expirationTtl: 24 * 3600 })
        }
        message.ack()
      } else if (job.type === 'service_cves') {
        const r = await runServiceCves(db, env.KV_CACHE, env.NVD_API_KEY, job)
        console.log(`[service_cves] ${r.devices} device(s): ${r.created} new, ${r.refreshed} still vulnerable, ${r.resolved} closed; `
          + `${r.nvdCalls} NVD lookup(s)${r.deferred.length ? `, ${r.deferred.length} device(s) deferred` : ''}`)
        // NVD's budget per job ran out: the rest in a minute (cached lookups are free then)
        if (r.deferred.length) await env.ADVISORY_QUEUE.send({ ...job, assetIds: r.deferred }, { delaySeconds: 60 })
        message.ack()
      } else if (job.type === 'cti_ingest') {
        const next = await runIngestStep(db, env.KV_CACHE, { otx: env.OTX_API_KEY, threatFox: env.THREATFOX_API_KEY }, job.step ?? 'kev')
        if (next) {
          await env.ADVISORY_QUEUE.send({ type: 'cti_ingest', step: next, triggeredBy: job.triggeredBy })
        } else {
          console.log(`[cti_ingest] Feeds ingested (triggered by: ${job.triggeredBy ?? 'system'})`)
          // Release the lock so re-ingestion can be triggered again
          await env.KV_CACHE.delete(CTI_INGEST_LOCK)
        }
        wrote = true
        message.ack()
      } else if (job.type === 'kg_sync') {
        await runKgSyncJob(env)
        message.ack()
      } else {
        message.ack()
      }
    } catch (err) {
      console.error('Queue job failed:', err)
      message.retry()
    }
  }

  if (wrote) await signalKgSyncSafe(env)
}
