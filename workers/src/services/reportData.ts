/**
 * services/reportData.ts — everything the security posture report shows, for one tenant
 * (or every tenant: the platform superadmin). Used by GET /reports/data (the browser builds
 * the PDF) and by the report queue (the Worker builds it), so both PDFs are the same.
 * The layout is frontend/src/utils/reportPdf.js, shared by both.
 */
import { eq, and, sql, or, desc, inArray, isNull } from 'drizzle-orm'
import { ACTIVE_ADVISORY_STATUSES } from '../lib/advisoryScope'
import type { DB } from '../db/client'
import { isOpenEvent } from '../lib/eventStatus'
import { assets, events, postureMetrics, advisories, ctiIndicators, scanResults, sboms } from '../db/schema'
import { buildReportStory } from './reportStory'
import { computePosture } from './posture'
import { fixTimeSummary } from './fixTime'
import { baselineSummary } from './securityBaseline'
import { weeklyView } from './weekly'
import { compareWeeks, isoWeek } from '../lib/weekly'

export async function buildReportData(db: DB, tenantId: string | undefined, reportType: string) {
  const af   = tenantId ? eq(assets.tenantId, tenantId) : undefined
  const pmf  = tenantId ? eq(postureMetrics.tenantId, tenantId) : isNull(postureMetrics.tenantId)   // platform-wide: the platform snapshots only
  const sf   = tenantId ? eq(scanResults.tenantId, tenantId) : undefined
  const now  = new Date()
  const slaThreshold = new Date(now.getTime() - 72 * 60 * 60 * 1000)

  // Fetch all data in parallel
  const [
    postureRows, prevPostureRows,
    assetRows, assetByType, internetFacingRows,
    critRows, highRows, medRows,
    eventByType,
    openAdvRows, slaBreachRows,
    topAssetRows,
    topCveRows,
    ctiRows,
    sbomRows,
    lastScanRows,
  ] = await Promise.all([
    // Posture: latest + previous for trend
    db.select().from(postureMetrics).where(pmf).orderBy(desc(postureMetrics.timestamp)).limit(1),
    db.select().from(postureMetrics).where(pmf).orderBy(desc(postureMetrics.timestamp)).limit(2),
    // Asset counts
    db.select({ count: sql<number>`count(*)::int` }).from(assets).where(af),
    db.select({ deviceType: assets.deviceType, count: sql<number>`count(*)::int` })
      .from(assets).where(af).groupBy(assets.deviceType),
    db.select({ count: sql<number>`count(*)::int` })
      .from(assets).where(af ? and(af, eq(assets.isInternetFacing, true)) : eq(assets.isInternetFacing, true)),
    // Event severity counts (join assets for tenant isolation)
    db.select({ count: sql<number>`count(*)::int` }).from(events)
      .innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(af ? and(af, isOpenEvent(), eq(events.severity, 'critical')) : and(isOpenEvent(), eq(events.severity, 'critical'))),
    db.select({ count: sql<number>`count(*)::int` }).from(events)
      .innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(af ? and(af, isOpenEvent(), eq(events.severity, 'high')) : and(isOpenEvent(), eq(events.severity, 'high'))),
    db.select({ count: sql<number>`count(*)::int` }).from(events)
      .innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(af ? and(af, isOpenEvent(), eq(events.severity, 'medium')) : and(isOpenEvent(), eq(events.severity, 'medium'))),
    // Event type breakdown (top 6, tenant-scoped)
    db.select({ eventType: events.eventType, count: sql<number>`count(*)::int` })
      .from(events)
      .innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(af).groupBy(events.eventType).orderBy(desc(sql`count(*)`)).limit(6),
    // Advisories (tenant-scoped via advisories→events→assets join)
    db.select({ advisoryId: advisories.advisoryId, summary: advisories.summary,
      recommendedAction: advisories.recommendedAction, status: advisories.status, createdAt: advisories.createdAt })
      .from(advisories)
      .innerJoin(events, eq(advisories.eventId, events.eventId))
      .innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(af
        ? and(af, inArray(advisories.status, [...ACTIVE_ADVISORY_STATUSES]))
        : inArray(advisories.status, [...ACTIVE_ADVISORY_STATUSES]))
      .orderBy(desc(advisories.createdAt)).limit(15),
    // SLA breaches (open > 72h, tenant-scoped via join)
    db.select({ count: sql<number>`count(*)::int` }).from(advisories)
      .innerJoin(events, eq(advisories.eventId, events.eventId))
      .innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(af
        ? and(af, eq(advisories.status, 'open'), sql`${advisories.createdAt} < ${slaThreshold}`)
        : and(eq(advisories.status, 'open'), sql`${advisories.createdAt} < ${slaThreshold}`)),
    // Top assets by criticality
    db.select({ hostname: assets.hostname, ipAddress: assets.ipAddress,
      deviceType: assets.deviceType, criticalityScore: assets.criticalityScore,
      isInternetFacing: assets.isInternetFacing, owner: assets.owner })
      .from(assets).where(af).orderBy(desc(assets.criticalityScore)).limit(10),
    // Top CVE events by risk score (tenant-scoped via asset join)
    db.select({ eventId: events.eventId, details: events.details,
      compositeRiskScore: events.compositeRiskScore, timestamp: events.timestamp })
      .from(events)
      .innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(af ? and(af, isOpenEvent(), eq(events.eventType, 'cve_detected')) : and(isOpenEvent(), eq(events.eventType, 'cve_detected')))
      .orderBy(desc(events.compositeRiskScore)).limit(8),
    // CTI summary (global — intentional)
    db.select({ source: ctiIndicators.source, count: sql<number>`count(*)::int` })
      .from(ctiIndicators).groupBy(ctiIndicators.source),
    // SBOM count (tenant-scoped via asset join)
    db.select({ count: sql<number>`count(*)::int` }).from(sboms)
      .innerJoin(assets, eq(sboms.assetId, assets.assetId))
      .where(af),
    // Last scan
    db.select({ startedAt: scanResults.startedAt, scanType: scanResults.scanType,
      hostsDiscovered: scanResults.hostsDiscovered })
      .from(scanResults).where(sf).orderBy(desc(scanResults.startedAt)).limit(1),
  ])

  // The report's storyline (verdict, first actions, hotspots, changes, progress, coverage), and the
  // fix-time figures for management (services/fixTime.ts, the same as the Dashboard)
  const [story, fixTime, weekly, securityBaseline] = await Promise.all([
    buildReportStory(db, tenantId, reportType), fixTimeSummary(db, tenantId),
    // a tenant's weekly report: last finished week against the week before (services/weekly.ts)
    reportType === 'weekly' && tenantId ? weeklyView(db, tenantId, 2) : Promise.resolve(null),
    baselineSummary(db, tenantId),     // the security baseline (services/securityBaseline.ts, as on the Dashboard)
  ])
  const lastWeek = weekly?.weeks[0] ?? null
  const weekOverWeek = weekly && lastWeek ? {
    week_start: lastWeek.week_start, iso_week: isoWeek(lastWeek.week_start), backfilled: lastWeek.backfilled,
    vs_last_week: compareWeeks(lastWeek.metrics, weekly.weeks[1]?.metrics ?? null),
  } : null

  const posture    = postureRows[0]
  // No snapshot yet (a new tenant, or staging, which has no nightly job): compute it now,
  // with the same formula, rather than print 0/100.
  const live       = posture ? null : await computePosture(db, tenantId)
  const score      = posture?.overallScore ?? live?.overallScore ?? 0
  const prevScore  = posture ? (prevPostureRows[1]?.overallScore ?? null) : null
  const scoreTrend = prevScore !== null ? score - prevScore : null

  return {
    generated_at:      now.toISOString(),
    report_type:       reportType,
    posture_score:     score,
    score_trend:       scoreTrend,
    total_assets:      assetRows[0]?.count ?? 0,
    critical_assets:   posture?.totalCriticalAssets ?? live?.totalCriticalAssets ?? 0,
    internet_facing:   internetFacingRows[0]?.count ?? 0,
    asset_by_type:     assetByType,
    critical_events:   critRows[0]?.count ?? 0,
    high_events:       highRows[0]?.count ?? 0,
    medium_events:     medRows[0]?.count ?? 0,
    event_by_type:     eventByType,
    open_advisories:   openAdvRows,
    // same rule as the storyline: live advisories (open, acknowledged, in progress) older than 72 hours
    sla_breaches:      story.progress.sla_total,
    top_assets:        topAssetRows,
    top_cves:          topCveRows,
    cti_summary:       ctiRows,
    sbom_count:        sbomRows[0]?.count ?? 0,
    last_scan:         lastScanRows[0] ?? null,
    story,
    fix_time:          fixTime,
    security_baseline: securityBaseline,
    week_over_week:    weekOverWeek,
  }
}
