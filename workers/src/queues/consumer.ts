import type { Env } from '../types'
import { getDb } from '../db/client'
import { generateAdvisory } from '../services/advisory'
import { savePostureSnapshot } from '../services/posture'
import { ingestAllFeeds } from '../services/cti'
import { postureMetrics } from '../db/schema'
import { desc, eq } from 'drizzle-orm'

interface AdvisoryJob {
  type: 'advisory'
  eventId: string
  userId: string
}

interface ReportJob {
  type: 'report'
  reportType: 'weekly' | 'monthly' | 'executive'
  requestedBy: string
  tenantId?: string
}

interface CtiIngestJob {
  type: 'cti_ingest'
  triggeredBy?: string
}

type Job = AdvisoryJob | ReportJob | CtiIngestJob

async function sendTelegramMessage(botToken: string, chatId: string, text: string): Promise<void> {
  if (!botToken || !chatId) return
  await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' }),
  }).catch(() => undefined)
}

async function buildReportJson(db: ReturnType<typeof getDb>, tenantId?: string): Promise<Record<string, unknown>> {
  const posture = await db
    .select()
    .from(postureMetrics)
    .where(tenantId ? eq(postureMetrics.tenantId, tenantId) : undefined)
    .orderBy(desc(postureMetrics.timestamp))
    .limit(1)

  return {
    generated_at: new Date().toISOString(),
    tenant_id: tenantId ?? null,
    posture: posture[0] ?? null,
  }
}

export async function handleQueue(batch: MessageBatch<unknown>, env: Env): Promise<void> {
  const db = getDb(env.DATABASE_URL)

  for (const message of batch.messages) {
    const job = message.body as Job

    try {
      if (job.type === 'advisory') {
        await generateAdvisory(db, job.eventId, env.OPENROUTER_API_KEY, env.OPENROUTER_MODEL)
        await sendTelegramMessage(
          env.TELEGRAM_BOT_TOKEN,
          env.TELEGRAM_CHAT_ID,
          `*Advisory Generated*\nEvent \`${job.eventId.slice(0, 8)}...\` has a new AI advisory. Check the dashboard.`
        )
        message.ack()
      } else if (job.type === 'report') {
        const reportData = await buildReportJson(db, job.tenantId)
        const filename = `report_${job.reportType}_${Date.now()}.json`
        const body = JSON.stringify(reportData, null, 2)

        await env.REPORTS_BUCKET.put(filename, body, {
          httpMetadata: { contentType: 'application/json' },
        })

        // Store metadata in KV
        const meta = { filename, report_type: job.reportType, created_at: new Date().toISOString(), r2_key: filename }
        await env.KV_CACHE.put(`report:${filename}`, JSON.stringify(meta), { expirationTtl: 90 * 24 * 3600 })

        message.ack()
      } else if (job.type === 'cti_ingest') {
        await ingestAllFeeds(db, env.OTX_API_KEY, env.THREATFOX_API_KEY)
        console.log(`[cti_ingest] Feeds ingested (triggered by: ${job.triggeredBy ?? 'system'})`)
        // Release the lock so re-ingestion can be triggered again
        await env.KV_CACHE.delete('cti_ingest_lock')
        message.ack()
      } else {
        message.ack()
      }
    } catch (err) {
      console.error('Queue job failed:', err)
      message.retry()
    }
  }
}
