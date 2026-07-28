import { PDFDocument, rgb, StandardFonts } from 'pdf-lib'
import type { Env } from '../types'
import { getDb } from '../db/client'
import { generateAdvisory } from '../services/advisory'
import { savePostureSnapshot } from '../services/posture'
import { ingestAllFeeds } from '../services/cti'
import { postureMetrics, assets, events, advisories } from '../db/schema'
import { desc, eq, or, sql } from 'drizzle-orm'

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
}

type Job = AdvisoryJob | ReportJob | CtiIngestJob

async function buildReportPdf(
  db: ReturnType<typeof getDb>,
  reportType: string,
  tenantId?: string,
): Promise<Uint8Array> {
  // ── Fetch data ─────────────────────────────────────────────────
  const tenantFilter = tenantId ? eq(postureMetrics.tenantId, tenantId) : undefined
  const assetFilter  = tenantId ? eq(assets.tenantId, tenantId) : undefined

  const [postureRows, assetRows, critEventRows, openAdvRows] = await Promise.all([
    db.select().from(postureMetrics).where(tenantFilter).orderBy(desc(postureMetrics.timestamp)).limit(1),
    db.select({ count: sql<number>`count(*)::int` }).from(assets).where(assetFilter),
    db.select({ count: sql<number>`count(*)::int` }).from(events).where(eq(events.severity, 'critical')),
    db.select({ summary: advisories.summary, status: advisories.status, createdAt: advisories.createdAt })
      .from(advisories)
      .where(or(eq(advisories.status, 'open'), eq(advisories.status, 'acknowledged')))
      .orderBy(desc(advisories.createdAt))
      .limit(5),
  ])

  // Strip non-WinAnsi characters — pdf-lib StandardFonts only support Latin-1
  const safe = (s: string | null | undefined): string =>
    (s ?? '').replace(/[^\x20-\x7E\xA0-\xFF]/g, ' ').trim()

  const posture       = postureRows[0]
  const totalAssets   = assetRows[0]?.count ?? 0
  const critEvents    = critEventRows[0]?.count ?? 0
  const postureScore  = posture?.overallScore ?? 0
  const critAssets    = posture?.totalCriticalAssets ?? 0
  const now           = new Date()

  // ── Build PDF ──────────────────────────────────────────────────
  const doc  = await PDFDocument.create()
  const bold = await doc.embedFont(StandardFonts.HelveticaBold)
  const reg  = await doc.embedFont(StandardFonts.Helvetica)

  const W = 595, H = 842  // A4 points
  const margin = 50
  const col = W - margin * 2

  const page = doc.addPage([W, H])

  const NAVY  = rgb(0.04, 0.09, 0.18)
  const BLUE  = rgb(0.20, 0.58, 1.00)
  const WHITE = rgb(1, 1, 1)
  const GRAY  = rgb(0.40, 0.44, 0.52)
  const RED   = rgb(0.86, 0.20, 0.20)
  const AMBER = rgb(0.96, 0.62, 0.10)
  const GREEN = rgb(0.13, 0.77, 0.37)
  const DARK  = rgb(0.10, 0.13, 0.20)

  // Header banner
  page.drawRectangle({ x: 0, y: H - 90, width: W, height: 90, color: NAVY })
  page.drawText('UMEagleEye CAASM', { x: margin, y: H - 38, font: bold, size: 20, color: WHITE })
  page.drawText(safe(`${reportType.charAt(0).toUpperCase() + reportType.slice(1)} Security Posture Report`), {
    x: margin, y: H - 58, font: reg, size: 11, color: rgb(0.6, 0.75, 1),
  })
  page.drawText(safe(`Generated: ${now.toLocaleString('en-US', { timeZone: 'Asia/Kuala_Lumpur' })} MYT`), {
    x: margin, y: H - 76, font: reg, size: 9, color: rgb(0.5, 0.6, 0.8),
  })

  let y = H - 115

  // ── Posture score ────────────────────────────────────────────────
  const scoreColor = postureScore >= 70 ? GREEN : postureScore >= 40 ? AMBER : RED
  const scoreLabel = postureScore >= 70 ? 'GOOD' : postureScore >= 40 ? 'FAIR' : 'CRITICAL'

  page.drawRectangle({ x: margin, y: y - 70, width: col, height: 80, color: DARK, borderColor: BLUE, borderWidth: 1 })
  page.drawText('SECURITY POSTURE SCORE', { x: margin + 14, y: y - 14, font: bold, size: 8, color: GRAY })
  page.drawText(`${postureScore}`, { x: margin + 14, y: y - 48, font: bold, size: 36, color: scoreColor })
  page.drawText('/ 100', { x: margin + 70, y: y - 48, font: reg, size: 14, color: GRAY })
  page.drawText(scoreLabel, { x: margin + 130, y: y - 40, font: bold, size: 13, color: scoreColor })
  y -= 85

  // ── Stats row ───────────────────────────────────────────────────
  y -= 16
  page.drawText('KEY METRICS', { x: margin, y, font: bold, size: 8, color: GRAY })
  y -= 12

  const stats = [
    { label: 'Total Assets',    value: String(totalAssets),  color: BLUE },
    { label: 'Critical Assets', value: String(critAssets),   color: RED  },
    { label: 'Critical Events', value: String(critEvents),   color: AMBER },
    { label: 'Open Advisories', value: String(openAdvRows.length), color: AMBER },
  ]
  const boxW = (col - 12) / 4
  stats.forEach((s, i) => {
    const bx = margin + i * (boxW + 4)
    page.drawRectangle({ x: bx, y: y - 48, width: boxW, height: 56, color: DARK, borderColor: rgb(0.2,0.25,0.35), borderWidth: 1 })
    page.drawText(s.value, { x: bx + 10, y: y - 22, font: bold, size: 20, color: s.color })
    page.drawText(s.label, { x: bx + 10, y: y - 40, font: reg, size: 7.5, color: GRAY })
  })
  y -= 68

  // ── Open advisories ─────────────────────────────────────────────
  if (openAdvRows.length > 0) {
    y -= 16
    page.drawText('OPEN ADVISORIES', { x: margin, y, font: bold, size: 8, color: GRAY })
    y -= 4
    page.drawLine({ start: { x: margin, y }, end: { x: margin + col, y }, thickness: 0.5, color: rgb(0.2,0.25,0.35) })
    y -= 14

    for (const adv of openAdvRows) {
      if (y < 80) break
      const statusColor = adv.status === 'open' ? RED : AMBER
      page.drawText('*', { x: margin, y, font: bold, size: 8, color: statusColor })
      page.drawText(safe(adv.status?.toUpperCase() ?? ''), { x: margin + 12, y, font: bold, size: 7, color: statusColor })
      page.drawText(safe(new Date(adv.createdAt).toLocaleDateString('en-US')), { x: margin + col - 55, y, font: reg, size: 7, color: GRAY })

      const summary = safe(adv.summary ?? '').slice(0, 95)
      y -= 12
      page.drawText(summary + (safe(adv.summary ?? '').length > 95 ? '...' : ''), { x: margin + 12, y, font: reg, size: 8, color: WHITE })
      y -= 16
    }
  }

  // ── Footer ──────────────────────────────────────────────────────
  page.drawLine({ start: { x: margin, y: 36 }, end: { x: W - margin, y: 36 }, thickness: 0.5, color: rgb(0.2,0.25,0.35) })
  page.drawText('UMEagleEye CAASM - Confidential - University of Malaya', {
    x: margin, y: 22, font: reg, size: 7.5, color: GRAY,
  })
  page.drawText('Page 1', { x: W - margin - 25, y: 22, font: reg, size: 7.5, color: GRAY })

  return doc.save()
}

export async function handleQueue(batch: MessageBatch<unknown>, env: Env): Promise<void> {
  const db = getDb(env.DATABASE_URL)

  for (const message of batch.messages) {
    const job = message.body as Job

    try {
      if (job.type === 'advisory') {
        const advisory = await generateAdvisory(
          db, job.eventId,
          env.OPENROUTER_API_KEY, env.OPENROUTER_MODEL, env.DEEPSEEK_API_KEY,
        )
        if (advisory) {
          console.log(`[advisory] Generated ${advisory.advisoryId} for ${advisory.assetLabel} (${advisory.severity} ${advisory.eventType})`)
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
