/**
 * UMEagleEye Workers — Events / Alerts routes
 * Returns snake_case + joined asset context for the AlertsPage triage queue.
 *
 * Alerts are never deleted by analysts: they move through a status lifecycle
 * (open → in_progress → resolved | false_positive | accepted_risk) and every
 * change is written to audit_logs.
 */

import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, or, desc, sql, gte, inArray, isNull, ilike, ne } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireAction } from '../middleware/auth'
import { assignableUsers, canBeAssignedAlerts } from '../lib/accountRows'
import { getDb, type DB } from '../db/client'
import {
  events, assets, advisories, users, auditLogs, tenants,
  assetRelationships, eventCtiIndicators, ctiIndicators, tiEvents, cveFindings,
} from '../db/schema'
import { buildBaseline, baselinePackagesKnown, extractPorts, type AssetBaseline } from '../services/drift'
import { OPEN_STATUSES, CLOSED_STATUSES, isOpenEvent, type EventStatus } from '../lib/eventStatus'
import { dueAtExpr, dueStatusExpr, priorityExpr, rankScoreExpr, slaHoursExpr, tierExpr } from '../lib/priority'
import { slaPolicy } from '../lib/alertRank'
import { softwareName, techniqueName, techniquesFor } from '../lib/attack'
import { kevTechniques } from '../lib/kevAttack'

/** The exploited (KEV) CVEs an alert names, with how they are exploited and what they lead to; null if none is mapped. */
function kevAttackOf(d: Record<string, unknown> | null) {
  if (!d) return null
  const list = (v: unknown) => (Array.isArray(v) ? v as Array<Record<string, unknown>> : [])
  const ids = [
    ...list(d.top_cves).filter((c) => c.kev).map((c) => String(c.id)),          // an SBOM package alert
    ...list(d.cves).filter((c) => c.kev).map((c) => String(c.id)),              // a vulnerable service
    ...(d.kev === true && typeof d.cve_id === 'string' ? [d.cve_id] : []),      // a single-CVE alert
  ]
  const mapped = [...new Set(ids)].map((id) => ({ id, t: kevTechniques(id) })).filter((c) => c.t.all.length)
  if (!mapped.length) return null
  const named = (ids: string[]) => [...new Set(ids)].map((id) => ({ id, name: techniqueName(id) }))
  return {
    cves: mapped.map((c) => c.id),
    exploit: named(mapped.flatMap((c) => c.t.exploit)),
    impact: named(mapped.flatMap((c) => [...c.t.primary, ...c.t.secondary])),
    source: 'MITRE Center for Threat-Informed Defense, KEV mappings',
  }
}
import { cweList } from '../lib/cwe'
import { concernCondition, concernCountColumns, isConcernId } from '../lib/concerns'
import { loadMsrcMonth } from '../services/windowsPatch'
import { UNSEEN_NOTE } from '../services/alertHygiene'
import { resolveAdvisoriesOfClosedEvents } from '../lib/advisoryScope'

const app = new Hono<{ Bindings: Env }>()

const STATUS_VALUES = ['open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk'] as const
const SEVERITY_VALUES = ['low', 'medium', 'high', 'critical'] as const
const EVENT_TYPE_VALUES = [
  'port_opened', 'port_closed', 'version_downgrade', 'version_upgrade',
  'cve_detected', 'new_device', 'config_change', 'new_package',
  'removed_package', 'cti_match', 'os_patch_missing', 'exposure', 'vulnerable_service',
] as const
// Filter-only types: a kind of alert inside an event type. cti_sighting = the cti_match alerts an
// agent saw its own computer make (rule R7, routes/sightings.ts).
const FILTER_TYPE_VALUES = [...EVENT_TYPE_VALUES, 'cti_sighting'] as const
const isSighting = sql`(${events.eventType} = 'cti_match' AND ${events.details}->>'match_kind' = 'sighting')`

function typeCondition(raw: string | undefined) {
  const list = csv(raw, FILTER_TYPE_VALUES)
  if (list.length === 0) return undefined
  const real = list.filter((t): t is typeof EVENT_TYPE_VALUES[number] => t !== 'cti_sighting')
  return or(real.length ? inArray(events.eventType, real) : undefined, list.includes('cti_sighting') ? isSighting : undefined)
}
const DRIFT_TYPES = new Set([
  'port_opened', 'port_closed', 'version_downgrade', 'version_upgrade',
  'config_change', 'new_package', 'removed_package',
])

// How long an alert has been open, by first_seen. Fix-time targets (when an alert is due) are
// per tier and severity and a tenant may change them: lib/alertRank.ts, lib/priority.ts.
const AGE_BUCKETS = [
  { id: 'lt1d',  minH: 0,   maxH: 24 },
  { id: 'd1_3',  minH: 24,  maxH: 72 },
  { id: 'd3_7',  minH: 72,  maxH: 168 },
  { id: 'd7_30', minH: 168, maxH: 720 },
  { id: 'gt30',  minH: 720, maxH: null },
] as const

function ageCondition(id: string | undefined, now: number) {
  const b = AGE_BUCKETS.find(x => x.id === id)
  if (!b) return undefined
  return and(
    sql`${events.firstSeen} <= ${new Date(now - b.minH * 3600000)}`,
    b.maxH != null ? sql`${events.firstSeen} > ${new Date(now - b.maxH * 3600000)}` : undefined,
  )
}

// Past its fix-time target (needs assets joined; callers also require the alert to be open)
function overdueCondition() {
  return sql`now() > ${dueAtExpr}`
}

type User = { userId: string; role: string; tenantId?: string }

function scopeTenant(user: User, tenantIdParam: string | undefined): string | undefined {
  return user.role === 'superadmin' ? (tenantIdParam || undefined) : (user.tenantId ?? undefined)
}

function csv<T extends string>(raw: string | undefined, allowed: readonly T[]): T[] {
  if (!raw) return []
  return raw.split(',').map(s => s.trim()).filter((s): s is T => (allowed as readonly string[]).includes(s))
}

// status=open → open + in_progress; status=closed → the three closed states;
// otherwise a comma list of exact statuses. Omitted = every status.
function statusCondition(raw: string | undefined) {
  if (!raw || raw === 'all') return undefined
  if (raw === 'open') return inArray(events.status, OPEN_STATUSES)
  if (raw === 'closed') return inArray(events.status, CLOSED_STATUSES)
  const list = csv(raw, STATUS_VALUES)
  return list.length > 0 ? inArray(events.status, list) : undefined
}

// ── GET / ────────────────────────────────────────────────────────
// Query: page, page_size, status, severity (csv), event_type, asset_id,
//        assigned_to (me|unassigned|<uuid>), internet_facing=true,
//        device_type, q (host/IP/CVE/package), since (ISO), sort (priority|time),
//        concern (see lib/concerns), age (lt1d|d1_3|d3_7|d7_30|gt30), overdue=true,
//        package (exact CVE package name), closed=unreviewed (closed because the device
//        was not seen, without anyone looking at it)
/** The list filters (query string → WHERE), shared by GET / and GET /cve-groups.
 *  Requires `assets` joined on events.asset_id. */
export function listConditions(user: User, q: (k: string) => string | undefined) {
    const tenantId   = scopeTenant(user, q('tenant_id'))
    const severities = csv(q('severity'), SEVERITY_VALUES)
    const assignedTo = q('assigned_to')
    const search     = q('q')?.trim()
    const since      = q('since') ? new Date(q('since')!) : null
    const concern    = q('concern')
    const now        = Date.now()

    const conditions = [
      tenantId ? eq(assets.tenantId, tenantId) : undefined,
      statusCondition(q('status')),
      severities.length ? inArray(events.severity, severities) : undefined,
      typeCondition(q('event_type') ?? q('type')),
      q('asset_id') && z.string().uuid().safeParse(q('asset_id')).success ? eq(events.assetId, q('asset_id')!) : undefined,
      q('internet_facing') === 'true' ? eq(assets.isInternetFacing, true) : undefined,
      q('device_type') ? eq(assets.deviceType, q('device_type') as typeof assets.$inferSelect['deviceType']) : undefined,
      since && !isNaN(since.getTime()) ? gte(events.firstSeen, since) : undefined,
      isConcernId(concern) ? concernCondition(concern) : undefined,
      q('package') ? sql`${events.details}->>'package_name' = ${q('package')}` : undefined,
      ageCondition(q('age'), now),
      q('closed') === 'unreviewed' ? eq(events.resolutionNote, UNSEEN_NOTE) : undefined,
      q('overdue') === 'true' ? and(isOpenEvent(), overdueCondition()) : undefined,
      // tier=1..4 (lib/alertRank.ts): Compromise, Exploited, Fix, Review
      /^[1-4]$/.test(q('tier') ?? '') ? sql`${tierExpr} = ${Number(q('tier'))}` : undefined,
      q('due') === 'soon' ? and(isOpenEvent(), sql`${dueStatusExpr} = 'due_soon'`) : undefined,
      assignedTo === 'me' ? eq(events.assignedTo, user.userId)
        : assignedTo === 'unassigned' ? isNull(events.assignedTo)
        : assignedTo && z.string().uuid().safeParse(assignedTo).success ? eq(events.assignedTo, assignedTo)
        : undefined,
      search ? or(
        ilike(assets.hostname, `%${search}%`),
        ilike(assets.ipAddress, `%${search}%`),
        sql`${events.details}->>'cve_id' ILIKE ${'%' + search + '%'}`,
        // a package alert holds its CVEs as findings
        sql`EXISTS (SELECT 1 FROM cve_findings f WHERE f.event_id = ${events.eventId} AND f.fixed_at IS NULL AND f.cve_id ILIKE ${'%' + search + '%'})`,
        sql`${events.details}->>'package_name' ILIKE ${'%' + search + '%'}`,
        sql`${events.details}->>'package' ILIKE ${'%' + search + '%'}`,
      ) : undefined,
    ]
    return conditions
}

app.get('/', authMiddleware, requireAction('alert.view'), async (c) => {
  try {
    const user = c.get('user') as User
    const db   = getDb(c.env.DATABASE_URL)
    const q    = (k: string) => c.req.query(k)

    const page     = Math.max(1, parseInt(q('page') ?? '1'))
    const pageSize = Math.min(200, Math.max(1, parseInt(q('page_size') ?? q('limit') ?? '50')))
    const offset   = (page - 1) * pageSize
    const whereClause = and(...listConditions(user, q))

    const order = q('sort') === 'priority'
      ? [desc(priorityExpr), desc(events.lastSeen)]
      : [desc(events.lastSeen)]

    const [rows, countRows] = await Promise.all([
      db
        .select({
          eventId:            events.eventId,
          assetId:            events.assetId,
          eventType:          events.eventType,
          severity:           events.severity,
          details:            events.details,
          compositeRiskScore: events.compositeRiskScore,
          timestamp:          events.timestamp,
          status:             events.status,
          assignedTo:         events.assignedTo,
          assigneeName:       users.username,
          firstSeen:          events.firstSeen,
          lastSeen:           events.lastSeen,
          occurrences:        events.occurrences,
          resolvedAt:         events.resolvedAt,
          resolutionNote:     events.resolutionNote,
          assetHostname:      assets.hostname,
          assetIp:            assets.ipAddress,
          assetDeviceType:    assets.deviceType,
          assetCriticality:   assets.criticalityScore,
          assetInternetFacing: assets.isInternetFacing,
          priority:           priorityExpr,
          tier:               tierExpr,
          rankScore:          rankScoreExpr,
          dueAt:              dueAtExpr,
          dueStatus:          dueStatusExpr,
          slaHours:           slaHoursExpr,
          reopenedAt:         events.reopenedAt,
          reopenCount:        events.reopenCount,
        })
        .from(events)
        .innerJoin(assets, eq(events.assetId, assets.assetId))
        .leftJoin(users, eq(events.assignedTo, users.userId))
        .where(whereClause)
        .orderBy(...order)
        .limit(pageSize)
        .offset(offset),
      db.select({ count: sql<number>`count(*)::int` })
        .from(events)
        .innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(whereClause),
    ])

    // Advisory state for the returned page
    const pageEventIds = rows.map(r => r.eventId)
    const advisoryByEvent = new Map<string, { advisoryId: string; status: string }>()
    if (pageEventIds.length > 0) {
      const advRows = await db
        .select({ eventId: advisories.eventId, advisoryId: advisories.advisoryId, status: advisories.status })
        .from(advisories)
        .where(inArray(advisories.eventId, pageEventIds))
        .orderBy(desc(advisories.createdAt))
      for (const a of advRows) if (!advisoryByEvent.has(a.eventId)) advisoryByEvent.set(a.eventId, a)
    }

    return c.json({
      total:     countRows[0]?.count ?? 0,
      page,
      page_size: pageSize,
      items:     rows.map(row => serializeEvent(row, advisoryByEvent.get(row.eventId))),
    })
  } catch (err) {
    console.error('events GET / error:', err)
    return c.json({ detail: 'Failed to fetch events' }, 500)
  }
})

function serializeEvent(
  row: {
    eventId: string; assetId: string; eventType: string; severity: string; details: unknown
    compositeRiskScore: string | null; timestamp: Date; status: string; assignedTo: string | null
    assigneeName: string | null; firstSeen: Date; lastSeen: Date; occurrences: number
    resolvedAt: Date | null; resolutionNote: string | null; assetHostname: string | null
    assetIp: string | null; assetDeviceType: string | null; assetCriticality: number | null
    assetInternetFacing: boolean | null; priority: number | null
    tier?: number | null; rankScore?: number | null; dueAt?: string | Date | null; dueStatus?: string | null
    slaHours?: number | null; reopenedAt?: Date | null; reopenCount?: number | null
  },
  advisory?: { advisoryId: string; status: string },
) {
  const open = row.status === 'open' || row.status === 'in_progress'
  return {
    event_id:              row.eventId,
    asset_id:              row.assetId,
    event_type:            row.eventType,
    severity:              row.severity,
    details:               row.details,
    composite_risk_score:  row.compositeRiskScore != null ? Number(row.compositeRiskScore) : null,
    timestamp:             row.timestamp,
    status:                row.status,
    assigned_to:           row.assignedTo,
    assignee_name:         row.assigneeName,
    first_seen:            row.firstSeen,
    last_seen:             row.lastSeen,
    occurrences:           row.occurrences,
    resolved_at:           row.resolvedAt,
    resolution_note:       row.resolutionNote,
    asset_hostname:        row.assetHostname ?? null,
    asset_ip:              row.assetIp ?? null,
    asset_device_type:     row.assetDeviceType,
    asset_criticality:     row.assetCriticality,
    asset_internet_facing: row.assetInternetFacing ?? false,
    priority_score:        row.priority != null ? Number(row.priority) : null,
    // tier 1 Compromise / 2 Exploited / 3 Fix / 4 Review, the 0-100 score within it, and the
    // fix-time target (due only while the alert is open)
    tier:                  row.tier != null ? Number(row.tier) : null,
    rank_score:            row.rankScore != null ? Number(row.rankScore) : null,
    due_at:                open && row.dueAt ? new Date(row.dueAt).toISOString() : null,
    due_status:            open ? row.dueStatus ?? null : null,
    sla_hours:             row.slaHours != null ? Number(row.slaHours) : null,
    reopened_at:           row.reopenedAt ?? null,
    reopen_count:          row.reopenCount ?? 0,
    has_advisory:          !!advisory,
    advisory_id:           advisory?.advisoryId ?? null,
    advisory_status:       advisory?.status ?? null,
  }
}

// ── GET /stats/summary ───────────────────────────────────────────
// Must be before /:eventId. All headline counts are OPEN alerts only.
app.get('/stats/summary', authMiddleware, requireAction('alert.view'), async (c) => {
  try {
    const user = c.get('user') as User
    const db   = getDb(c.env.DATABASE_URL)

    const tenantId   = scopeTenant(user, c.req.query('tenant_id'))
    const tenantCond = tenantId ? eq(assets.tenantId, tenantId) : undefined
    const base = () => db.select({ count: sql<number>`count(*)::int` })
      .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))

    const now     = Date.now()
    const days7   = new Date(now - 7 * 86400000)
    const days30  = new Date(now - 30 * 86400000)
    const ageCase = sql.join([
      sql`CASE`,
      ...AGE_BUCKETS.filter(b => b.maxH != null).map(b =>
        sql`WHEN ${events.firstSeen} > ${new Date(now - b.maxH! * 3600000)} THEN ${b.id}`),
      sql`ELSE 'gt30' END`,
    ], sql` `)

    const [
      byStatus, bySeverity, byType, avgRisk, newCount, resolvedCount,
      mttr, recent30, slaBreaches, dailyNew, dailyResolved, agingRows, concernRows, policyRow,
    ] = await Promise.all([
      db.select({ status: events.status, count: sql<number>`count(*)::int` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(tenantCond).groupBy(events.status),
      db.select({ severity: events.severity, count: sql<number>`count(*)::int` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(tenantCond, isOpenEvent())).groupBy(events.severity),
      // cti_sighting (a filter-only type) is counted inside cti_match too
      db.select({ event_type: sql<string>`CASE WHEN ${isSighting} THEN 'cti_sighting' ELSE ${events.eventType}::text END`, count: sql<number>`count(*)::int` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(tenantCond, isOpenEvent())).groupBy(sql`1`),
      db.select({ avg: sql<number>`round(avg(${events.compositeRiskScore})::numeric, 1)::float` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(tenantCond, isOpenEvent(), sql`${events.compositeRiskScore} IS NOT NULL`)),
      base().where(and(tenantCond, gte(events.firstSeen, days7))),
      base().where(and(tenantCond, inArray(events.status, CLOSED_STATUSES), gte(events.resolvedAt, days7))),
      db.select({ hours: sql<number>`round((avg(extract(epoch from (${events.resolvedAt} - ${events.firstSeen}))) / 3600)::numeric, 1)::float` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(tenantCond, eq(events.status, 'resolved'), gte(events.resolvedAt, days30))),
      db.select({
          total:  sql<number>`count(*)::int`,
          closed: sql<number>`count(*) filter (where ${events.status} in ('resolved','false_positive','accepted_risk'))::int`,
        })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(tenantCond, gte(events.firstSeen, days30))),
      base().where(and(tenantCond, isOpenEvent(), overdueCondition())),
      db.select({ day: sql<string>`date_trunc('day', ${events.firstSeen})::date::text`, count: sql<number>`count(*)::int` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(tenantCond, gte(events.firstSeen, days7)))
        .groupBy(sql`date_trunc('day', ${events.firstSeen})`),
      db.select({ day: sql<string>`date_trunc('day', ${events.resolvedAt})::date::text`, count: sql<number>`count(*)::int` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(tenantCond, inArray(events.status, CLOSED_STATUSES), gte(events.resolvedAt, days7)))
        .groupBy(sql`date_trunc('day', ${events.resolvedAt})`),
      db.select({ severity: events.severity, bucket: sql<string>`${ageCase}`, count: sql<number>`count(*)::int` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(tenantCond, isOpenEvent()))
        .groupBy(events.severity, sql`2`),
      db.select(concernCountColumns)
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(tenantCond, isOpenEvent())),
      // the tenant's own fix-time targets (none for the platform view: the defaults)
      tenantId
        ? db.select({ policy: tenants.slaPolicy }).from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
        : Promise.resolve([] as { policy: unknown }[]),
    ])

    const by_status: Record<string, number> = { open: 0, in_progress: 0, resolved: 0, false_positive: 0, accepted_risk: 0 }
    for (const r of byStatus) by_status[r.status] = r.count
    const by_severity: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 }
    for (const r of bySeverity) by_severity[r.severity] = r.count
    const by_type: Record<string, number> = {}
    for (const r of byType) by_type[r.event_type] = r.count
    if (by_type['cti_sighting']) by_type['cti_match'] = (by_type['cti_match'] ?? 0) + by_type['cti_sighting']

    const newMap: Record<string, number> = {}
    for (const r of dailyNew) newMap[r.day] = r.count
    const resMap: Record<string, number> = {}
    for (const r of dailyResolved) resMap[r.day] = r.count
    const daily_trend = []
    for (let i = 6; i >= 0; i--) {
      const key = new Date(now - i * 86400000).toISOString().slice(0, 10)
      daily_trend.push({ date: key.slice(5), count: newMap[key] ?? 0, new: newMap[key] ?? 0, resolved: resMap[key] ?? 0 })
    }

    // aging[severity][bucket] = open alerts of that severity first seen in that window
    const aging: Record<string, Record<string, number>> = {}
    for (const sev of SEVERITY_VALUES) aging[sev] = Object.fromEntries(AGE_BUCKETS.map(b => [b.id, 0]))
    for (const r of agingRows) aging[r.severity]![r.bucket] = r.count

    const total30  = recent30[0]?.total ?? 0
    const closed30 = recent30[0]?.closed ?? 0
    const open_total = by_status.open! + by_status.in_progress!

    return c.json({
      total_alerts:     open_total,          // open + in_progress
      open_total,
      by_status,
      by_severity,                           // open only
      by_type,                               // open only
      total_critical:   by_severity.critical,
      avg_risk_score:   avgRisk[0]?.avg ?? 0,
      new_7d:           newCount[0]?.count ?? 0,
      resolved_7d:      resolvedCount[0]?.count ?? 0,
      mttr_hours:       mttr[0]?.hours ?? null,
      sla_breaches:     slaBreaches[0]?.count ?? 0,     // open alerts past their fix-time target
      sla_policy:       slaPolicy(policyRow[0]?.policy),  // the targets in force, hours
      resolution_rate:  total30 > 0 ? Math.round((closed30 / total30) * 100) : 100,
      daily_trend,
      aging,
      age_buckets:      AGE_BUCKETS,
      concerns:         concernRows[0] ?? null,
    })
  } catch (err) {
    console.error('events GET stats/summary error:', err)
    return c.json({ detail: 'Failed to fetch event stats' }, 500)
  }
})

// ── GET /assignees ───────────────────────────────────────────────
// Analysts in scope who can be assigned alerts. Must be before /:eventId.
app.get('/assignees', authMiddleware, requireAction('alert.manage', 'advisory.update'), async (c) => {
  try {
    const user = c.get('user') as User
    const db   = getDb(c.env.DATABASE_URL)
    const tenantId = scopeTenant(user, c.req.query('tenant_id'))
    if (!tenantId) return c.json({ items: [] })

    const rows = await db
      .select({ userId: users.userId, username: users.username, role: users.role, actions: users.actions })
      .from(users)
      .where(and(
        eq(users.tenantId, tenantId),
        eq(users.isActive, true),
        sql`(${users.scheduledDeactivationAt} is null or ${users.scheduledDeactivationAt} > now())`,
        // Any tenant member.
        ne(users.role, 'superadmin'),
      ))
      .orderBy(users.username)

    return c.json({ items: assignableUsers(rows, tenantId) })
  } catch (err) {
    console.error('events GET assignees error:', err)
    return c.json({ detail: 'Failed to fetch assignees' }, 500)
  }
})

// ── Shared: load an event the caller is allowed to see ───────────
async function loadScopedEvent(db: DB, user: User, eventId: string) {
  if (!z.string().uuid().safeParse(eventId).success) return null
  const [row] = await db
    .select({ event: events, asset: assets })
    .from(events)
    .innerJoin(assets, eq(events.assetId, assets.assetId))
    .where(eq(events.eventId, eventId))
    .limit(1)
  if (!row) return null
  if (user.role !== 'superadmin' && user.tenantId && row.asset.tenantId !== user.tenantId) return null
  return row
}

// ── GET /:eventId — full triage context for the detail panel ─────
app.get('/:eventId', authMiddleware, requireAction('alert.view'), async (c) => {
  try {
    const user = c.get('user') as User
    const db   = getDb(c.env.DATABASE_URL)
    const row  = await loadScopedEvent(db, user, c.req.param('eventId'))
    if (!row) return c.json({ detail: 'Event not found' }, 404)
    const { event, asset } = row

    const [assignee, advisoryRows, relOut, relIn, cti, history] = await Promise.all([
      event.assignedTo
        ? db.select({ username: users.username }).from(users).where(eq(users.userId, event.assignedTo)).limit(1)
        : Promise.resolve([]),
      db.select().from(advisories).where(eq(advisories.eventId, event.eventId))
        .orderBy(desc(advisories.createdAt)).limit(1),
      db.select({ type: assetRelationships.relationshipType, assetId: assets.assetId, hostname: assets.hostname, ip: assets.ipAddress, deviceType: assets.deviceType })
        .from(assetRelationships)
        .innerJoin(assets, eq(assetRelationships.targetAssetId, assets.assetId))
        .where(eq(assetRelationships.sourceAssetId, asset.assetId)).limit(15),
      db.select({ type: assetRelationships.relationshipType, assetId: assets.assetId, hostname: assets.hostname, ip: assets.ipAddress, deviceType: assets.deviceType })
        .from(assetRelationships)
        .innerJoin(assets, eq(assetRelationships.sourceAssetId, assets.assetId))
        .where(eq(assetRelationships.targetAssetId, asset.assetId)).limit(15),
      db.select({
          value: ctiIndicators.value, type: ctiIndicators.indicatorType, source: ctiIndicators.source,
          family: ctiIndicators.malwareFamily, attack_software: ctiIndicators.attackSoftware,
          named_techniques: ctiIndicators.attackTechniques,
          confidence: ctiIndicators.confidenceScore,
          event_id: tiEvents.tiEventId, event_title: tiEvents.title, event_level: tiEvents.threatLevel,
          // another tenant's shared event that this tenant opted into
          shared_by: sql<string | null>`CASE WHEN ${tiEvents.tenantId} IS NOT NULL AND ${tiEvents.tenantId} IS DISTINCT FROM ${asset.tenantId}
            THEN (SELECT name FROM tenants tn WHERE tn.tenant_id = ${tiEvents.tenantId}) END`,
        })
        .from(eventCtiIndicators)
        .innerJoin(ctiIndicators, eq(eventCtiIndicators.indicatorId, ctiIndicators.indicatorId))
        .leftJoin(tiEvents, eq(tiEvents.tiEventId, ctiIndicators.tiEventId))
        .where(eq(eventCtiIndicators.eventId, event.eventId)),
      db.select({ action: auditLogs.actionType, prev: auditLogs.previousState, next: auditLogs.newState, at: auditLogs.timestamp, username: users.username, actorUsername: auditLogs.actorUsername })
        .from(auditLogs)
        .leftJoin(users, eq(auditLogs.userId, users.userId))
        .where(eq(auditLogs.targetEntity, event.eventId))
        .orderBy(desc(auditLogs.timestamp)).limit(20),
    ])

    const osInfo = (asset.osInfo ?? {}) as Record<string, unknown>
    const advisory = advisoryRows[0]
    // its tier, score and fix-time target, as the queue shows them (lib/priority.ts)
    const [rank] = await db.select({
      priority: priorityExpr, tier: tierExpr, rankScore: rankScoreExpr, dueAt: dueAtExpr, dueStatus: dueStatusExpr, slaHours: slaHoursExpr,
    }).from(events).innerJoin(assets, eq(events.assetId, assets.assetId)).where(eq(events.eventId, event.eventId)).limit(1)
    const open = event.status === 'open' || event.status === 'in_progress'

    return c.json({
      priority_score:       rank ? Number(rank.priority) : null,
      tier:                 rank ? Number(rank.tier) : null,
      rank_score:           rank ? Number(rank.rankScore) : null,
      due_at:               open && rank?.dueAt ? new Date(rank.dueAt).toISOString() : null,
      due_status:           open ? rank?.dueStatus ?? null : null,
      sla_hours:            rank ? Number(rank.slaHours) : null,
      reopened_at:          event.reopenedAt,
      reopen_count:         event.reopenCount,
      event_id:             event.eventId,
      asset_id:             event.assetId,
      event_type:           event.eventType,
      severity:             event.severity,
      details:              event.details,
      cwes:                 cweList((event.details as Record<string, unknown> | null)?.cwe_ids),
      composite_risk_score: event.compositeRiskScore != null ? Number(event.compositeRiskScore) : null,
      timestamp:            event.timestamp,
      status:               event.status,
      assigned_to:          event.assignedTo,
      assignee_name:        assignee[0]?.username ?? null,
      first_seen:           event.firstSeen,
      last_seen:            event.lastSeen,
      occurrences:          event.occurrences,
      resolved_at:          event.resolvedAt,
      resolution_note:      event.resolutionNote,
      asset_hostname:       asset.hostname,
      asset_ip:             asset.ipAddress,
      asset: {
        asset_id:           asset.assetId,
        hostname:           asset.hostname,
        ip_address:         asset.ipAddress,
        mac_address:        asset.macAddress,
        hardware_vendor:    asset.hardwareVendor,
        device_type:        asset.deviceType,
        owner:              asset.owner,
        criticality_score:  asset.criticalityScore,
        is_internet_facing: asset.isInternetFacing,
        internet_facing_confirmed: asset.internetFacingOverride !== null,
        last_scanned:       asset.lastScanned,
        source:             asset.source,
        os_name:            (osInfo.name ?? osInfo.os_name ?? null),
        os_version:         (osInfo.os_version ?? osInfo.version ?? null),
        ports:              extractPorts(osInfo),
        services:           Array.isArray(osInfo.services) ? osInfo.services : [],
        snmp_sysdescr:      osInfo.snmp_sysdescr ?? null,
        snmp_interfaces:    Array.isArray(osInfo.snmp_interfaces) ? (osInfo.snmp_interfaces as unknown[]).length : 0,
      },
      advisory: advisory ? {
        advisory_id:        advisory.advisoryId,
        summary:            advisory.summary,
        recommended_action: advisory.recommendedAction,
        status:             advisory.status,
        created_at:         advisory.createdAt,
      } : null,
      related_assets: [
        ...relOut.map(r => ({ direction: 'outbound', ...r })),
        ...relIn.map(r => ({ direction: 'inbound', ...r })),
      ].map(r => ({
        direction: r.direction, relationship: r.type, asset_id: r.assetId,
        hostname: r.hostname, ip: r.ip, device_type: r.deviceType,
      })),
      cti_indicators: cti.map(({ named_techniques, ...i }) => {
        // documented: ATT&CK's own entry for the family; inferred: from the malware's kind or the
        // indicator's role (lib/malwareKind.ts), or named by the feed
        const documented = new Set(techniquesFor(i.attack_software, []))
        const all = techniquesFor(i.attack_software, named_techniques)
        return {
          ...i,
          confidence: i.confidence != null ? Number(i.confidence) : null,
          attack_software_name: softwareName(i.attack_software),
          technique_count: all.length,
          techniques: all.slice(0, 12).map((id) => ({ id, name: techniqueName(id), how: documented.has(id) ? 'documented' : 'inferred' })),
        }
      }),
      // An exploited CVE: how attackers exploit it and what it leads to (MITRE CTID's KEV mappings)
      attack_kev: kevAttackOf(event.details as Record<string, unknown> | null),
      // by: the user's current username; null when the system acted or the user was deleted.
      // actor_username: kept from a deleted user (the page shows "<name> (deleted)").
      history: history.map(h => ({ action: h.action, previous: h.prev, next: h.next, at: h.at, by: h.username, actor_username: h.actorUsername })),
    })
  } catch (err) {
    console.error('events GET /:eventId error:', err)
    return c.json({ detail: 'Failed to fetch event' }, 500)
  }
})

// ── Accept one drift change into the baseline ────────────────────
// Only the field this alert is about is re-baselined, so accepting "port 22
// opened" does not silently accept an unrelated port or MAC change as well.
async function acceptIntoBaseline(db: DB, event: typeof events.$inferSelect, asset: typeof assets.$inferSelect) {
  const osInfo = (asset.osInfo ?? {}) as Record<string, unknown>
  const baseline: AssetBaseline = asset.baselineState
    ? { ...(asset.baselineState as AssetBaseline) }
    : buildBaseline({
        ports: extractPorts(osInfo), osInfo, hostname: asset.hostname, macAddress: asset.macAddress,
        isInternetFacing: asset.isInternetFacing, deviceType: asset.deviceType,
      })
  const d = (event.details ?? {}) as Record<string, unknown>
  const ports = new Set(baseline.ports ?? [])
  const packages = { ...(baseline.packages ?? {}) }
  // Accepting a single package change into an UNKNOWN package baseline would turn it
  // into a one-entry "known" map, so the next audit would flag every other installed
  // package as new. Leave packages unknown and just let the caller close the event —
  // the first full SBOM is what completes the package baseline.
  const pkgKnown = baselinePackagesKnown(baseline)

  switch (event.eventType) {
    case 'port_opened': ports.add(Number(d.port)); break
    case 'port_closed': ports.delete(Number(d.port)); break
    case 'new_package': if (!pkgKnown) return; if (d.package) packages[String(d.package)] = String(d.version ?? ''); break
    case 'removed_package': if (!pkgKnown) return; if (d.package) delete packages[String(d.package)]; break
    case 'version_upgrade':
    case 'version_downgrade':
      if (d.package) { if (!pkgKnown) return; packages[String(d.package)] = String(d.to ?? '') }
      else baseline.os_version = d.to != null ? String(d.to) : baseline.os_version
      break
    case 'config_change':
      switch (d.changed_attribute) {
        case 'hostname':        baseline.hostname = (d.to as string | null) ?? null; break
        case 'mac_address':     baseline.mac_address = (d.to as string | null) ?? null; break
        case 'internet_facing': baseline.is_internet_facing = Boolean(d.to); break
        case 'device_type':     baseline.device_type = String(d.to); break
        // details.to is truncated for display; baseline the full current value
        case 'firmware':        baseline.snmp_sysdescr = (osInfo.snmp_sysdescr as string | undefined) ?? null; break
      }
      break
    default:
      return
  }

  baseline.ports = [...ports].filter(p => !isNaN(p)).sort((a, b) => a - b)
  // Only write packages back when they are (or just became) known, so accepting a
  // non-package change never stamps an empty `packages:{}` onto an unknown baseline.
  if (pkgKnown) baseline.packages = packages
  baseline.captured_at = new Date().toISOString()
  baseline.auto_set = false
  await db.update(assets).set({ baselineState: baseline, updatedAt: new Date() }).where(eq(assets.assetId, asset.assetId))
}

// ── Apply a triage update to one event (shared by PATCH and bulk) ─
const updateSchema = z.object({
  status:      z.enum(STATUS_VALUES).optional(),
  assigned_to: z.string().uuid().nullable().optional(),
  note:        z.string().trim().max(1000).optional(),
}).refine(b => b.status !== undefined || b.assigned_to !== undefined || !!b.note, {
  message: 'Provide status, assigned_to or note',
})
type UpdateBody = z.infer<typeof updateSchema>

async function applyUpdate(
  db: DB, user: User,
  row: { event: typeof events.$inferSelect; asset: typeof assets.$inferSelect },
  body: UpdateBody,
): Promise<{ error?: string }> {
  const { event, asset } = row
  const now = new Date()
  const closing = body.status !== undefined && (CLOSED_STATUSES as string[]).includes(body.status)

  if (closing && (!body.note || body.note.length < 3)) {
    return { error: 'A note (min 3 characters) is required to close an alert' }
  }

  let assignedTo = event.assignedTo
  if (body.assigned_to !== undefined) {
    if (body.assigned_to !== null) {
      const [assignee] = await db.select({ tenantId: users.tenantId, role: users.role, actions: users.actions })
        .from(users).where(eq(users.userId, body.assigned_to)).limit(1)
      if (!assignee || !canBeAssignedAlerts(assignee)
          || (asset.tenantId && assignee.tenantId !== asset.tenantId)) {
        return { error: 'Assignee must be able to manage alerts in the asset\'s tenant' }
      }
    }
    assignedTo = body.assigned_to
  }
  // Starting work on an unowned alert takes ownership of it
  if (body.status === 'in_progress' && !assignedTo) assignedTo = user.userId

  if (body.status === 'accepted_risk' && DRIFT_TYPES.has(event.eventType)) {
    await acceptIntoBaseline(db, event, asset)
  }

  const set: Partial<typeof events.$inferInsert> = { assignedTo, updatedAt: now }
  if (body.status !== undefined) {
    set.status = body.status as EventStatus
    if (closing) {
      set.resolvedAt = now
      set.resolvedBy = user.userId
    } else {
      set.resolvedAt = null
      set.resolvedBy = null
    }
  }
  if (body.note) set.resolutionNote = body.note

  await db.update(events).set(set).where(eq(events.eventId, event.eventId))
  await db.insert(auditLogs).values({
    userId:        user.userId,
    tenantId:      asset.tenantId ?? user.tenantId ?? null,
    actionType:    'alert_update',
    targetEntity:  event.eventId,
    previousState: { status: event.status, assigned_to: event.assignedTo },
    newState:      { status: set.status ?? event.status, assigned_to: assignedTo, note: body.note ?? null },
  })
  // A closed alert needs no remediation: its advisory is resolved with it.
  if (closing) await resolveAdvisoriesOfClosedEvents(db, { eventIds: [event.eventId] })
  return {}
}

// Same update applied to many alerts with a constant number of statements (one UPDATE
// and the audit rows per 500 alerts), so it fits the Workers free plan's 50-subrequest
// budget whatever the count. Drift alerts accepted as risk move their baseline one by one
// (only drift alerts do; GET /bulk caps those at 200).
export async function applyUpdateMany(
  db: DB, user: User,
  rows: Array<{ event: typeof events.$inferSelect; asset: typeof assets.$inferSelect }>,
  body: UpdateBody,
): Promise<{ updated: number; error?: string }> {
  if (rows.length === 0) return { updated: 0 }
  const now = new Date()
  const closing = body.status !== undefined && (CLOSED_STATUSES as string[]).includes(body.status)
  if (closing && (!body.note || body.note.length < 3)) {
    return { updated: 0, error: 'A note (min 3 characters) is required to close an alert' }
  }
  if (body.assigned_to) {
    const [assignee] = await db.select({ tenantId: users.tenantId, role: users.role, actions: users.actions })
      .from(users).where(eq(users.userId, body.assigned_to)).limit(1)
    if (!assignee || !canBeAssignedAlerts(assignee)
        || rows.some(r => r.asset.tenantId && assignee.tenantId !== r.asset.tenantId)) {
      return { updated: 0, error: 'Assignee must be able to manage alerts in the asset\'s tenant' }
    }
  }
  if (body.status === 'accepted_risk') {
    for (const r of rows) if (DRIFT_TYPES.has(r.event.eventType)) await acceptIntoBaseline(db, r.event, r.asset)
  }

  const assigneeOf = (current: string | null) =>
    body.assigned_to !== undefined ? body.assigned_to
      : body.status === 'in_progress' && !current ? user.userId   // starting work takes ownership
      : current
  const set: Record<string, unknown> = { updatedAt: now }
  if (body.assigned_to !== undefined) set.assignedTo = body.assigned_to
  else if (body.status === 'in_progress') set.assignedTo = sql`COALESCE(${events.assignedTo}, ${user.userId}::uuid)`
  if (body.status !== undefined) {
    set.status = body.status
    set.resolvedAt = closing ? now : null
    set.resolvedBy = closing ? user.userId : null
  }
  if (body.note) set.resolutionNote = body.note

  const stmts: unknown[] = []
  for (let i = 0; i < rows.length; i += 500) {
    const chunk = rows.slice(i, i + 500)
    stmts.push(db.update(events).set(set as Partial<typeof events.$inferInsert>)
      .where(inArray(events.eventId, chunk.map(r => r.event.eventId))))
    stmts.push(db.insert(auditLogs).values(chunk.map(r => ({
      userId:        user.userId,
      tenantId:      r.asset.tenantId ?? user.tenantId ?? null,
      actionType:    'alert_update',
      targetEntity:  r.event.eventId,
      previousState: { status: r.event.status, assigned_to: r.event.assignedTo },
      newState:      { status: body.status ?? r.event.status, assigned_to: assigneeOf(r.event.assignedTo), note: body.note ?? null },
    }))))
  }
  await db.batch(stmts as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
  if (closing) {
    for (let i = 0; i < rows.length; i += 500) {
      await resolveAdvisoriesOfClosedEvents(db, { eventIds: rows.slice(i, i + 500).map(r => r.event.eventId) })
    }
  }
  return { updated: rows.length }
}

// ── PATCH /:eventId — change status / assignee / note ────────────
// ── GET /:eventId/windows-cves — the CVEs behind a Windows patch alert ──
// The alert stores counts only; the list comes from Microsoft's data in R2, per missing
// fix (month + fixed build) of the alert's Windows version.
app.get('/:eventId/windows-cves', authMiddleware, requireAction('alert.view'), async (c) => {
  try {
    const user = c.get('user') as User
    const db   = getDb(c.env.DATABASE_URL)
    const row  = await loadScopedEvent(db, user, c.req.param('eventId'))
    if (!row) return c.json({ detail: 'Event not found' }, 404)
    if (row.event.eventType !== 'os_patch_missing') return c.json({ detail: 'Not a Windows patch alert' }, 400)
    const d = (row.event.details ?? {}) as { product?: string; missing?: { month: string; fixed_build: string; kb: string | null }[] }
    const missing = Array.isArray(d.missing) ? d.missing : []
    const months = [...new Set(missing.map(m => m.month))]
    const docs = new Map(await Promise.all(months.map(async m => [m, await loadMsrcMonth(c.env.REPORTS_BUCKET, m)] as const)))
    const seen = new Set<string>()
    const cves: { cve: string; title: string; severity: string | null; exploited: boolean; month: string; kb: string | null; fixed_build: string }[] = []
    for (const m of missing) {
      const doc = docs.get(m.month)
      for (const id of (d.product && doc?.products[d.product]?.[m.fixed_build]) || []) {
        if (seen.has(id)) continue
        seen.add(id)
        const [title, severity, exploited] = doc!.cves[id] ?? ['', null, false]
        cves.push({ cve: id, title, severity, exploited, month: m.month, kb: m.kb, fixed_build: m.fixed_build })
      }
    }
    const rank: Record<string, number> = { Critical: 0, Important: 1, Moderate: 2, Low: 3 }
    cves.sort((a, b) => Number(b.exploited) - Number(a.exploited) || (rank[a.severity ?? ''] ?? 9) - (rank[b.severity ?? ''] ?? 9) || b.cve.localeCompare(a.cve))
    return c.json({ product: d.product ?? null, cves, unavailable: months.filter(m => !docs.get(m)) })
  } catch (err) {
    console.error('events GET /:eventId/windows-cves error:', err)
    return c.json({ detail: 'Failed to load the CVE list' }, 500)
  }
})

// ── GET /:eventId/cves ─── the CVEs of an SBOM package alert ──────
// Its present findings (cve_findings), KEV first, then the most likely to be exploited
// and the most severe; ?q= filters by CVE id, ?fixed=true lists the ones fixed since.
// Paged like the other long lists (page_size ≤ 100).
app.get('/:eventId/cves', authMiddleware, requireAction('alert.view'), async (c) => {
  try {
    const user = c.get('user') as User
    const db   = getDb(c.env.DATABASE_URL)
    const row  = await loadScopedEvent(db, user, c.req.param('eventId'))
    if (!row) return c.json({ detail: 'Event not found' }, 404)
    if (row.event.eventType !== 'cve_detected') return c.json({ detail: 'Not an SBOM vulnerability alert' }, 400)
    const page     = Math.max(1, parseInt(c.req.query('page') ?? '1') || 1)
    const pageSize = Math.min(100, Math.max(1, parseInt(c.req.query('page_size') ?? '50') || 50))
    const search   = (c.req.query('q') ?? '').trim()
    const fixed    = c.req.query('fixed') === 'true'
    const where = and(
      eq(cveFindings.eventId, row.event.eventId),
      fixed ? sql`${cveFindings.fixedAt} IS NOT NULL` : sql`${cveFindings.fixedAt} IS NULL`,
      search ? ilike(cveFindings.cveId, `%${search}%`) : undefined,
    )
    const [items, [total]] = await Promise.all([
      db.select({
          cve_id: cveFindings.cveId, advisory_id: cveFindings.advisoryId, package_version: cveFindings.packageVersion,
          severity: cveFindings.severity, cvss: cveFindings.cvss, epss: cveFindings.epss, kev: cveFindings.kev,
          threat_intel: cveFindings.hasCtiMatch, ti_event_titles: cveFindings.tiEventTitles, fix_versions: cveFindings.fixVersions,
          cwe_ids: cveFindings.cweIds, description: cveFindings.description, dismissed: cveFindings.dismissed,
          first_seen: cveFindings.firstSeen, fixed_at: cveFindings.fixedAt,
        })
        .from(cveFindings).where(where)
        .orderBy(desc(cveFindings.kev), sql`${cveFindings.epss} DESC NULLS LAST`, desc(cveFindings.cvss), cveFindings.cveId, cveFindings.packageVersion)
        .limit(pageSize).offset((page - 1) * pageSize),
      db.select({ n: sql<number>`count(*)::int` }).from(cveFindings).where(where),
    ])
    return c.json({
      total: total?.n ?? 0, page, page_size: pageSize,
      items: items.map((f) => ({ ...f, cvss: Number(f.cvss), epss: f.epss == null ? null : Number(f.epss), cwes: cweList(f.cwe_ids) })),
    })
  } catch (err) {
    console.error('events GET /:eventId/cves error:', err)
    return c.json({ detail: 'Failed to load the CVE list' }, 500)
  }
})

app.patch('/:eventId', authMiddleware, requireAction('alert.manage'), zValidator('json', updateSchema), async (c) => {
  try {
    const user = c.get('user') as User
    const db   = getDb(c.env.DATABASE_URL)
    const row  = await loadScopedEvent(db, user, c.req.param('eventId'))
    if (!row) return c.json({ detail: 'Event not found' }, 404)

    const result = await applyUpdate(db, user, row, c.req.valid('json'))
    if (result.error) return c.json({ detail: result.error }, 400)
    return c.json({ message: 'Alert updated' })
  } catch (err) {
    console.error('events PATCH error:', err)
    return c.json({ detail: 'Failed to update alert' }, 500)
  }
})

// ── POST /bulk — same update applied to many alerts ──────────────
const bulkSchema = z.object({
  event_ids:   z.array(z.string().uuid()).min(1).max(200),
  status:      z.enum(STATUS_VALUES).optional(),
  assigned_to: z.string().uuid().nullable().optional(),
  note:        z.string().trim().max(1000).optional(),
})

app.post('/bulk', authMiddleware, requireAction('alert.bulk_update'), zValidator('json', bulkSchema), async (c) => {
  try {
    const user = c.get('user') as User
    const db   = getDb(c.env.DATABASE_URL)
    const { event_ids, ...rest } = c.req.valid('json')
    const body = updateSchema.safeParse(rest)
    if (!body.success) return c.json({ detail: 'Provide status, assigned_to or note' }, 400)

    const rows = await db
      .select({ event: events, asset: assets })
      .from(events)
      .innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(and(
        inArray(events.eventId, event_ids),
        user.role !== 'superadmin' && user.tenantId ? eq(assets.tenantId, user.tenantId) : undefined,
      ))

    const result = await applyUpdateMany(db, user, rows, body.data)
    if (result.error) return c.json({ detail: result.error }, 400)
    return c.json({ updated: result.updated, skipped: event_ids.length - result.updated })
  } catch (err) {
    console.error('events POST bulk error:', err)
    return c.json({ detail: 'Failed to update alerts' }, 500)
  }
})

// ── POST /:eventId/acknowledge ───────────────────────────────────
// Kept for older clients: accepts a drift change as intentional. The alert is
// closed as accepted_risk (not deleted) and the decision is audit-logged.
app.post('/:eventId/acknowledge', authMiddleware, requireAction('alert.manage'), async (c) => {
  try {
    const user = c.get('user') as User
    const db   = getDb(c.env.DATABASE_URL)
    const row  = await loadScopedEvent(db, user, c.req.param('eventId'))
    if (!row) return c.json({ detail: 'Event not found' }, 404)

    const result = await applyUpdate(db, user, row, { status: 'accepted_risk', note: 'Accepted as an intended change' })
    if (result.error) return c.json({ detail: result.error }, 400)
    return c.json({ message: 'Event accepted and baseline updated' })
  } catch (err) {
    console.error('events POST acknowledge error:', err)
    return c.json({ detail: 'Failed to acknowledge event' }, 500)
  }
})

// ── POST /:eventId/advisory ──────────────────────────────────────
app.post('/:eventId/advisory', authMiddleware, requireAction('advisory.generate'), async (c) => {
  try {
    const user = c.get('user') as User
    const db   = getDb(c.env.DATABASE_URL)
    const row  = await loadScopedEvent(db, user, c.req.param('eventId'))
    if (!row) return c.json({ detail: 'Event not found' }, 404)

    await c.env.ADVISORY_QUEUE.send({ type: 'advisory', eventId: row.event.eventId, userId: user.userId })

    return c.json({ message: 'Advisory generation queued', task_queued: true })
  } catch (err) {
    console.error('events POST advisory error:', err)
    return c.json({ detail: 'Failed to queue advisory generation' }, 500)
  }
})

export default app
