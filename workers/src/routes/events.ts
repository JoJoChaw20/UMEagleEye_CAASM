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
import { eq, and, or, desc, sql, gte, inArray, isNull, ilike } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb, type DB } from '../db/client'
import {
  events, assets, advisories, users, auditLogs,
  assetRelationships, eventCtiIndicators, ctiIndicators,
} from '../db/schema'
import { buildBaseline, extractPorts, type AssetBaseline } from '../services/drift'
import { OPEN_STATUSES, CLOSED_STATUSES, isOpenEvent, type EventStatus } from '../lib/eventStatus'
import { priorityExpr } from '../lib/priority'

const app = new Hono<{ Bindings: Env }>()

const ACTION_ROLES = ['tenant_superadmin', 'tenant_admin']
const STATUS_VALUES = ['open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk'] as const
const SEVERITY_VALUES = ['low', 'medium', 'high', 'critical'] as const
const EVENT_TYPE_VALUES = [
  'port_opened', 'port_closed', 'version_downgrade', 'version_upgrade',
  'cve_detected', 'new_device', 'config_change', 'new_package',
  'removed_package', 'cti_match',
] as const
const DRIFT_TYPES = new Set([
  'port_opened', 'port_closed', 'version_downgrade', 'version_upgrade',
  'config_change', 'new_package', 'removed_package',
])

// Response-time targets for open alerts, by severity (hours).
const SLA_HOURS = { critical: 72, high: 168 } as const

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
//        device_type, q (host/IP/CVE/package), since (ISO), sort (priority|time)
app.get('/', authMiddleware, async (c) => {
  try {
    const user = c.get('user') as User
    const db   = getDb(c.env.DATABASE_URL)
    const q    = (k: string) => c.req.query(k)

    const page     = Math.max(1, parseInt(q('page') ?? '1'))
    const pageSize = Math.min(200, Math.max(1, parseInt(q('page_size') ?? q('limit') ?? '50')))
    const offset   = (page - 1) * pageSize

    const tenantId   = scopeTenant(user, q('tenant_id'))
    const severities = csv(q('severity'), SEVERITY_VALUES)
    const eventType  = csv(q('event_type') ?? q('type'), EVENT_TYPE_VALUES)
    const assignedTo = q('assigned_to')
    const search     = q('q')?.trim()
    const since      = q('since') ? new Date(q('since')!) : null

    const conditions = [
      tenantId ? eq(assets.tenantId, tenantId) : undefined,
      statusCondition(q('status')),
      severities.length ? inArray(events.severity, severities) : undefined,
      eventType.length ? inArray(events.eventType, eventType) : undefined,
      q('asset_id') ? eq(events.assetId, q('asset_id')!) : undefined,
      q('internet_facing') === 'true' ? eq(assets.isInternetFacing, true) : undefined,
      q('device_type') ? eq(assets.deviceType, q('device_type') as typeof assets.$inferSelect['deviceType']) : undefined,
      since && !isNaN(since.getTime()) ? gte(events.firstSeen, since) : undefined,
      assignedTo === 'me' ? eq(events.assignedTo, user.userId)
        : assignedTo === 'unassigned' ? isNull(events.assignedTo)
        : assignedTo && z.string().uuid().safeParse(assignedTo).success ? eq(events.assignedTo, assignedTo)
        : undefined,
      search ? or(
        ilike(assets.hostname, `%${search}%`),
        ilike(assets.ipAddress, `%${search}%`),
        sql`${events.details}->>'cve_id' ILIKE ${'%' + search + '%'}`,
        sql`${events.details}->>'package_name' ILIKE ${'%' + search + '%'}`,
        sql`${events.details}->>'package' ILIKE ${'%' + search + '%'}`,
      ) : undefined,
    ]
    const whereClause = and(...conditions)

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
  },
  advisory?: { advisoryId: string; status: string },
) {
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
    has_advisory:          !!advisory,
    advisory_id:           advisory?.advisoryId ?? null,
    advisory_status:       advisory?.status ?? null,
  }
}

// ── GET /stats/summary ───────────────────────────────────────────
// Must be before /:eventId. All headline counts are OPEN alerts only.
app.get('/stats/summary', authMiddleware, async (c) => {
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
    const critSla = new Date(now - SLA_HOURS.critical * 3600000)
    const highSla = new Date(now - SLA_HOURS.high * 3600000)

    const [
      byStatus, bySeverity, byType, avgRisk, newCount, resolvedCount,
      mttr, recent30, slaBreaches, dailyNew, dailyResolved,
    ] = await Promise.all([
      db.select({ status: events.status, count: sql<number>`count(*)::int` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(tenantCond).groupBy(events.status),
      db.select({ severity: events.severity, count: sql<number>`count(*)::int` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(tenantCond, isOpenEvent())).groupBy(events.severity),
      db.select({ event_type: events.eventType, count: sql<number>`count(*)::int` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(tenantCond, isOpenEvent())).groupBy(events.eventType),
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
      base().where(and(tenantCond, isOpenEvent(), or(
        and(eq(events.severity, 'critical'), sql`${events.firstSeen} < ${critSla}`),
        and(eq(events.severity, 'high'), sql`${events.firstSeen} < ${highSla}`),
      ))),
      db.select({ day: sql<string>`date_trunc('day', ${events.firstSeen})::date::text`, count: sql<number>`count(*)::int` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(tenantCond, gte(events.firstSeen, days7)))
        .groupBy(sql`date_trunc('day', ${events.firstSeen})`),
      db.select({ day: sql<string>`date_trunc('day', ${events.resolvedAt})::date::text`, count: sql<number>`count(*)::int` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(tenantCond, inArray(events.status, CLOSED_STATUSES), gte(events.resolvedAt, days7)))
        .groupBy(sql`date_trunc('day', ${events.resolvedAt})`),
    ])

    const by_status: Record<string, number> = { open: 0, in_progress: 0, resolved: 0, false_positive: 0, accepted_risk: 0 }
    for (const r of byStatus) by_status[r.status] = r.count
    const by_severity: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 }
    for (const r of bySeverity) by_severity[r.severity] = r.count
    const by_type: Record<string, number> = {}
    for (const r of byType) by_type[r.event_type] = r.count

    const newMap: Record<string, number> = {}
    for (const r of dailyNew) newMap[r.day] = r.count
    const resMap: Record<string, number> = {}
    for (const r of dailyResolved) resMap[r.day] = r.count
    const daily_trend = []
    for (let i = 6; i >= 0; i--) {
      const key = new Date(now - i * 86400000).toISOString().slice(0, 10)
      daily_trend.push({ date: key.slice(5), count: newMap[key] ?? 0, new: newMap[key] ?? 0, resolved: resMap[key] ?? 0 })
    }

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
      sla_breaches:     slaBreaches[0]?.count ?? 0,
      sla_hours:        SLA_HOURS,
      resolution_rate:  total30 > 0 ? Math.round((closed30 / total30) * 100) : 100,
      daily_trend,
    })
  } catch (err) {
    console.error('events GET stats/summary error:', err)
    return c.json({ detail: 'Failed to fetch event stats' }, 500)
  }
})

// ── GET /assignees ───────────────────────────────────────────────
// Analysts in scope who can be assigned alerts. Must be before /:eventId.
app.get('/assignees', authMiddleware, async (c) => {
  try {
    const user = c.get('user') as User
    const db   = getDb(c.env.DATABASE_URL)
    const tenantId = scopeTenant(user, c.req.query('tenant_id'))
    if (!tenantId) return c.json({ items: [] })

    const rows = await db
      .select({ userId: users.userId, username: users.username, role: users.role })
      .from(users)
      .where(and(
        eq(users.tenantId, tenantId),
        eq(users.isActive, true),
        inArray(users.role, ['tenant_superadmin', 'tenant_admin']),
      ))
      .orderBy(users.username)

    return c.json({ items: rows.map(u => ({ user_id: u.userId, username: u.username, role: u.role })) })
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
app.get('/:eventId', authMiddleware, async (c) => {
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
          tactic: ctiIndicators.attackTactic, technique: ctiIndicators.attackTechnique,
          confidence: ctiIndicators.confidenceScore,
        })
        .from(eventCtiIndicators)
        .innerJoin(ctiIndicators, eq(eventCtiIndicators.indicatorId, ctiIndicators.indicatorId))
        .where(eq(eventCtiIndicators.eventId, event.eventId)),
      db.select({ action: auditLogs.actionType, prev: auditLogs.previousState, next: auditLogs.newState, at: auditLogs.timestamp, username: users.username })
        .from(auditLogs)
        .leftJoin(users, eq(auditLogs.userId, users.userId))
        .where(eq(auditLogs.targetEntity, event.eventId))
        .orderBy(desc(auditLogs.timestamp)).limit(20),
    ])

    const osInfo = (asset.osInfo ?? {}) as Record<string, unknown>
    const advisory = advisoryRows[0]

    return c.json({
      event_id:             event.eventId,
      asset_id:             event.assetId,
      event_type:           event.eventType,
      severity:             event.severity,
      details:              event.details,
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
      cti_indicators: cti.map(i => ({ ...i, confidence: i.confidence != null ? Number(i.confidence) : null })),
      history: history.map(h => ({ action: h.action, previous: h.prev, next: h.next, at: h.at, by: h.username })),
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

  switch (event.eventType) {
    case 'port_opened': ports.add(Number(d.port)); break
    case 'port_closed': ports.delete(Number(d.port)); break
    case 'new_package': if (d.package) packages[String(d.package)] = String(d.version ?? ''); break
    case 'removed_package': if (d.package) delete packages[String(d.package)]; break
    case 'version_upgrade':
    case 'version_downgrade':
      if (d.package) packages[String(d.package)] = String(d.to ?? '')
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
  baseline.packages = packages
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
      const [assignee] = await db.select({ tenantId: users.tenantId, role: users.role })
        .from(users).where(eq(users.userId, body.assigned_to)).limit(1)
      if (!assignee || !ACTION_ROLES.includes(assignee.role)
          || (asset.tenantId && assignee.tenantId !== asset.tenantId)) {
        return { error: 'Assignee must be an admin analyst in the asset\'s tenant' }
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
  return {}
}

// ── PATCH /:eventId — change status / assignee / note ────────────
app.patch('/:eventId', authMiddleware, requireRoles(...ACTION_ROLES), zValidator('json', updateSchema), async (c) => {
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

app.post('/bulk', authMiddleware, requireRoles(...ACTION_ROLES), zValidator('json', bulkSchema), async (c) => {
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

    let updated = 0
    const errors: string[] = []
    for (const row of rows) {
      const r = await applyUpdate(db, user, row, body.data)
      if (r.error) { errors.push(r.error); break }  // same body → same error for every row
      updated++
    }
    if (errors.length > 0 && updated === 0) return c.json({ detail: errors[0] }, 400)
    return c.json({ updated, skipped: event_ids.length - updated })
  } catch (err) {
    console.error('events POST bulk error:', err)
    return c.json({ detail: 'Failed to update alerts' }, 500)
  }
})

// ── POST /:eventId/acknowledge ───────────────────────────────────
// Kept for older clients: accepts a drift change as intentional. The alert is
// closed as accepted_risk (not deleted) and the decision is audit-logged.
app.post('/:eventId/acknowledge', authMiddleware, requireRoles(...ACTION_ROLES), async (c) => {
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
app.post('/:eventId/advisory', authMiddleware, requireRoles(...ACTION_ROLES), async (c) => {
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
