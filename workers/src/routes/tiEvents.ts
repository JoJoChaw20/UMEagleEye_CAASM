/**
 * UMEagleEye Workers — threat-intel events (MISP-style), mounted at /cti/events.
 *
 * An event groups indicators (attributes) an analyst wants to track: a phishing
 * campaign's domains, a malware family's hashes, the CVEs an advisory warns about.
 *
 * Who sees what:
 *   - a tenant sees its own events (drafts too) and published events shared with all
 *     tenants or published at platform level; superadmins see every event;
 *   - tenant superadmins and tenant admins write their tenant's events; superadmins
 *     write platform events (no tenant, visible to everyone); business owners read.
 *
 * Effect on alerts (services/threatIntel.ts): attributes of a PUBLISHED event count for
 * the tenants that can see it, except ones marked to_ids=false or on the warninglist.
 * CVE attributes flag CVE alerts (services/threatIntel.ts); IP, domain, URL and
 * software attributes are matched against assets (services/iocMatch.ts). Hashes and
 * emails are kept for reference: no agent data can match them yet.
 */

import { Hono, type Context } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { and, asc, desc, eq, inArray, or, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { auditLogs, ctiIndicators, tenants, tiEvents, users } from '../db/schema'
import { IOC_TYPES, parseIocs, type IocType } from '../lib/iocParse'
import { WARNINGLIST_LABELS, warninglistOf } from '../lib/warninglist'
import { refreshCveIntel, scopeForEvent } from '../services/threatIntel'
import { matchIocs } from '../services/iocMatch'
import { resolveSoftware, softwareName, techniqueIds, techniqueName } from '../lib/attack'

const app = new Hono<{ Bindings: Env }>()

const READ_ROLES  = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner']
const WRITE_ROLES = ['superadmin', 'tenant_superadmin', 'tenant_admin']
const MAX_ATTRIBUTES_PER_ADD = 2000
const MAX_ATTRIBUTES_PER_EVENT = 10000

type DB = ReturnType<typeof getDb>
type User = { userId: string; role: string; tenantId?: string | null }
type EventRow = typeof tiEvents.$inferSelect

const isShared = (d: string) => d === 'all_tenants' || d === 'platform'

function canView(user: User, ev: EventRow): boolean {
  if (user.role === 'superadmin') return true
  if (ev.tenantId && ev.tenantId === user.tenantId) return true
  return ev.status === 'published' && isShared(ev.distribution)
}

/** Tenant writers edit their tenant's events; superadmins edit platform events. */
function canEdit(user: User, ev: EventRow): boolean {
  if (user.role === 'superadmin') return ev.tenantId === null
  if (!['tenant_superadmin', 'tenant_admin'].includes(user.role)) return false
  return !!ev.tenantId && ev.tenantId === user.tenantId
}

/** SQL: the events this user may see. */
function visibleWhere(user: User) {
  if (user.role === 'superadmin') return undefined
  return or(
    eq(tiEvents.tenantId, user.tenantId ?? '00000000-0000-0000-0000-000000000000'),
    and(eq(tiEvents.status, 'published'), inArray(tiEvents.distribution, ['all_tenants', 'platform'])),
  )
}

async function loadEvent(db: DB, id: string): Promise<EventRow | undefined> {
  if (!/^[0-9a-f-]{36}$/i.test(id)) return undefined
  const [ev] = await db.select().from(tiEvents).where(eq(tiEvents.tiEventId, id)).limit(1)
  return ev
}

function eventOut(ev: EventRow, user: User, extra: Record<string, unknown> = {}) {
  return {
    event_id: ev.tiEventId,
    tenant_id: ev.tenantId,
    title: ev.title,
    description: ev.description,
    threat_level: ev.threatLevel,
    status: ev.status,
    distribution: ev.distribution,
    tags: ev.tags,
    malware_family: ev.malwareFamily,
    attack_software: ev.attackSoftware,
    attack_software_name: softwareName(ev.attackSoftware),
    attack_techniques: (ev.attackTechniques ?? []).map((id) => ({ id, name: techniqueName(id) })),
    created_by: ev.createdBy,
    created_at: ev.createdAt,
    updated_at: ev.updatedAt,
    published_at: ev.publishedAt,
    can_edit: canEdit(user, ev),
    ...extra,
  }
}

function attributeOut(a: typeof ctiIndicators.$inferSelect) {
  return {
    attribute_id: a.indicatorId,
    type: a.indicatorType,
    value: a.value,
    to_ids: a.toIds,
    comment: a.comment,
    warning: a.warning,
    warning_label: a.warning ? WARNINGLIST_LABELS[a.warning] ?? a.warning : null,
    first_seen: a.firstSeen,
  }
}

function audit(db: DB, user: User, ev: EventRow, actionType: string, newState: unknown, previousState: unknown = null) {
  return db.insert(auditLogs).values({
    userId: user.userId, tenantId: ev.tenantId, actionType, targetEntity: ev.tiEventId,
    previousState: previousState as Record<string, unknown> | null, newState: newState as Record<string, unknown>,
  })
}

/** After a change that can affect alerts: refresh the CVE alerts and re-match the assets
 *  of whoever can see the event. Returns how many alerts changed. */
async function refreshAfter(db: DB, ev: EventRow, previousDistribution?: string): Promise<number> {
  const scope = scopeForEvent(ev, previousDistribution)
  let changed = 0
  try {
    changed += await refreshCveIntel(db, scope)
  } catch (err) {
    console.error('ti event: refreshing CVE alerts failed:', err)
  }
  try {
    const m = await matchIocs(db, scope)
    changed += m.created + m.reopened + m.resolved
  } catch (err) {
    console.error('ti event: matching assets failed:', err)
  }
  return changed
}

const eventBody = z.object({
  title: z.string().trim().min(3).max(200),
  description: z.string().max(5000).nullish(),
  threat_level: z.enum(['low', 'medium', 'high']).optional(),
  distribution: z.enum(['organisation', 'all_tenants', 'platform']).optional(),
  tags: z.array(z.string().trim().min(1).max(50)).max(20).optional(),
  malware_family: z.string().trim().max(120).nullish(),
  attack_techniques: z.array(z.string().trim().max(20)).max(100).optional(),
})

/** The event's ATT&CK columns from a request body (undefined = not in the body). */
export function attackFields(body: { malware_family?: string | null; attack_techniques?: string[] }) {
  const out: Partial<Pick<EventRow, 'malwareFamily' | 'attackSoftware' | 'attackTechniques'>> = {}
  if (body.malware_family !== undefined) {
    const family = body.malware_family?.trim() || null
    out.malwareFamily = family
    out.attackSoftware = family ? resolveSoftware([family]) : null
  }
  if (body.attack_techniques !== undefined) {
    const ids = techniqueIds(body.attack_techniques)      // ids ATT&CK does not have are dropped
    out.attackTechniques = ids.length ? ids : null
  }
  return out
}

/** Attribute rows carry their event's ATT&CK fields (the feeds' columns), for lookups and alerts. */
const attackOfEvent = (ev: EventRow) => ({
  malwareFamily: ev.malwareFamily, attackSoftware: ev.attackSoftware, attackTechniques: ev.attackTechniques,
})

function badRequest(result: { success: boolean; error?: z.ZodError }, c: { json: (b: unknown, s: 400) => Response }) {
  if (!result.success) return c.json({ detail: result.error?.issues[0]?.message ?? 'Invalid request body' }, 400)
}

/** The distribution a user may set, or an error message. */
function allowedDistribution(user: User, wanted: string | undefined): { value?: 'organisation' | 'all_tenants' | 'platform'; error?: string } {
  if (user.role === 'superadmin') {
    if (wanted && wanted !== 'platform') return { error: 'Superadmins publish platform events (shared with every tenant)' }
    return { value: 'platform' }
  }
  if (wanted === 'platform') return { error: 'Only a superadmin can create platform events' }
  return { value: (wanted as 'organisation' | 'all_tenants' | undefined) ?? 'organisation' }
}

// ── GET / ─── events this user may see ─────────────────────────
app.get('/', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user') as User
    const db = getDb(c.env.DATABASE_URL)
    const status = c.req.query('status')
    const conditions = [visibleWhere(user)]
    if (status === 'draft' || status === 'published') conditions.push(eq(tiEvents.status, status))

    const rows = await db
      .select({
        ev: tiEvents,
        tenantName: tenants.name,
        author: users.username,
        attributes: sql<number>`(SELECT count(*)::int FROM cti_indicators c WHERE c.ti_event_id = ${tiEvents.tiEventId})`,
        cves: sql<number>`(SELECT count(*)::int FROM cti_indicators c WHERE c.ti_event_id = ${tiEvents.tiEventId} AND c.indicator_type = 'cve')`,
      })
      .from(tiEvents)
      .leftJoin(tenants, eq(tenants.tenantId, tiEvents.tenantId))
      .leftJoin(users, eq(users.userId, tiEvents.createdBy))
      .where(and(...conditions))
      .orderBy(desc(tiEvents.updatedAt))
      .limit(200)

    return c.json({
      items: rows.map(r => eventOut(r.ev, user, {
        tenant_name: r.ev.tenantId ? r.tenantName : null,
        own: !!r.ev.tenantId && r.ev.tenantId === user.tenantId,
        author: r.author, attribute_count: r.attributes, cve_count: r.cves,
      })),
    })
  } catch (err) {
    console.error('ti events list error:', err)
    return c.json({ detail: 'Failed to fetch threat-intel events' }, 500)
  }
})

// ── POST / ─── create a draft event ────────────────────────────
app.post('/', authMiddleware, requireRoles(...WRITE_ROLES), zValidator('json', eventBody, badRequest), async (c) => {
  try {
    const user = c.get('user') as User
    const db = getDb(c.env.DATABASE_URL)
    const body = c.req.valid('json')
    const dist = allowedDistribution(user, body.distribution)
    if (dist.error) return c.json({ detail: dist.error }, 403)
    if (user.role !== 'superadmin' && !user.tenantId) return c.json({ detail: 'Your account has no tenant' }, 403)

    const [ev] = await db.insert(tiEvents).values({
      tenantId: user.role === 'superadmin' ? null : user.tenantId!,
      title: body.title,
      description: body.description ?? null,
      threatLevel: body.threat_level ?? 'medium',
      distribution: dist.value!,
      tags: body.tags ?? [],
      ...attackFields(body),
      createdBy: user.userId,
    }).returning()
    if (!ev) return c.json({ detail: 'Failed to create event' }, 500)
    await audit(db, user, ev, 'ti_event.create', { title: ev.title, distribution: ev.distribution })
    return c.json(eventOut(ev, user, { attribute_count: 0, cve_count: 0, own: !!ev.tenantId }), 201)
  } catch (err) {
    console.error('ti event create error:', err)
    return c.json({ detail: 'Failed to create event' }, 500)
  }
})

// ── GET /:id ─── one event with its attributes ─────────────────
app.get('/:id', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user') as User
    const db = getDb(c.env.DATABASE_URL)
    const ev = await loadEvent(db, c.req.param('id'))
    if (!ev || !canView(user, ev)) return c.json({ detail: 'Event not found' }, 404)
    // Open alerts this event drives now (in the viewer's own tenant; superadmins: all).
    const viewerTenant = user.role === 'superadmin' ? sql`true` : sql`a.tenant_id = ${user.tenantId ?? null}`
    const [attrs, matches] = await Promise.all([
      db.select().from(ctiIndicators)
        .where(eq(ctiIndicators.tiEventId, ev.tiEventId))
        .orderBy(asc(ctiIndicators.indicatorType), asc(ctiIndicators.value))
        .limit(MAX_ATTRIBUTES_PER_EVENT),
      db.execute(sql`
        SELECT DISTINCT e.event_id, e.event_type, e.severity, e.details->>'indicator_value' AS indicator_value,
               e.details->>'cve_id' AS cve_id, e.details->>'observed' AS observed, e.details->>'match_kind' AS match_kind,
               a.asset_id, COALESCE(a.hostname, a.ip_address) AS asset_name
        FROM event_cti_indicators l
        JOIN cti_indicators c ON c.indicator_id = l.indicator_id AND c.ti_event_id = ${ev.tiEventId}
        JOIN events e ON e.event_id = l.event_id AND e.status IN ('open', 'in_progress')
        JOIN assets a ON a.asset_id = e.asset_id
        WHERE ${viewerTenant}
        LIMIT 50
      `),
    ])
    return c.json(eventOut(ev, user, {
      own: !!ev.tenantId && ev.tenantId === user.tenantId,
      attribute_count: attrs.length,
      attributes: attrs.map(attributeOut),
      matching_alerts: matches.rows,
    }))
  } catch (err) {
    console.error('ti event get error:', err)
    return c.json({ detail: 'Failed to fetch event' }, 500)
  }
})

// ── PATCH /:id ─── edit title, description, level, sharing, tags ──
app.patch('/:id', authMiddleware, requireRoles(...WRITE_ROLES), zValidator('json', eventBody.partial(), badRequest), async (c) => {
  try {
    const user = c.get('user') as User
    const db = getDb(c.env.DATABASE_URL)
    const ev = await loadEvent(db, c.req.param('id'))
    if (!ev || !canView(user, ev)) return c.json({ detail: 'Event not found' }, 404)
    if (!canEdit(user, ev)) return c.json({ detail: 'You cannot edit this event' }, 403)
    const body = c.req.valid('json')
    let distribution = ev.distribution
    if (body.distribution !== undefined) {
      const dist = allowedDistribution(user, body.distribution)
      if (dist.error) return c.json({ detail: dist.error }, 403)
      distribution = dist.value!
    }
    const [updated] = await db.update(tiEvents).set({
      ...(body.title !== undefined ? { title: body.title } : {}),
      ...(body.description !== undefined ? { description: body.description ?? null } : {}),
      ...(body.threat_level !== undefined ? { threatLevel: body.threat_level } : {}),
      ...(body.tags !== undefined ? { tags: body.tags } : {}),
      ...attackFields(body),
      distribution,
      updatedAt: new Date(),
    }).where(eq(tiEvents.tiEventId, ev.tiEventId)).returning()
    if (!updated) return c.json({ detail: 'Event not found' }, 404)
    // Attribute rows carry the event's name as their source.
    const attackChanged = body.malware_family !== undefined || body.attack_techniques !== undefined
    if ((body.title !== undefined && body.title !== ev.title) || attackChanged) {
      await db.update(ctiIndicators).set({ source: eventSource(updated.title), ...attackOfEvent(updated) })
        .where(eq(ctiIndicators.tiEventId, ev.tiEventId))
    }
    await audit(db, user, updated, 'ti_event.update', body, { title: ev.title, distribution: ev.distribution })
    // Sharing or the title (shown on alerts) changed on a published event: refresh alerts.
    const changed = updated.status === 'published' && (distribution !== ev.distribution || updated.title !== ev.title)
    const alerts = changed ? await refreshAfter(db, updated, ev.distribution) : 0
    return c.json(eventOut(updated, user, { alerts_updated: alerts }))
  } catch (err) {
    console.error('ti event update error:', err)
    return c.json({ detail: 'Failed to update event' }, 500)
  }
})

// ── DELETE /:id ─── delete an event and its attributes ─────────
app.delete('/:id', authMiddleware, requireRoles(...WRITE_ROLES), async (c) => {
  try {
    const user = c.get('user') as User
    const db = getDb(c.env.DATABASE_URL)
    const ev = await loadEvent(db, c.req.param('id'))
    if (!ev || !canView(user, ev)) return c.json({ detail: 'Event not found' }, 404)
    if (!canEdit(user, ev)) return c.json({ detail: 'You cannot delete this event' }, 403)
    await db.batch([
      db.delete(tiEvents).where(eq(tiEvents.tiEventId, ev.tiEventId)),   // attributes and their alert links cascade
      audit(db, user, ev, 'ti_event.delete', null, { title: ev.title, status: ev.status, distribution: ev.distribution }),
    ])
    const alerts = ev.status === 'published' ? await refreshAfter(db, ev) : 0
    return c.json({ deleted: true, alerts_updated: alerts })
  } catch (err) {
    console.error('ti event delete error:', err)
    return c.json({ detail: 'Failed to delete event' }, 500)
  }
})

// ── POST /:id/publish · /:id/unpublish ────────────────────────
async function setStatus(c: Context<{ Bindings: Env }>, status: 'draft' | 'published') {
  const user = c.get('user') as User
  const db = getDb(c.env.DATABASE_URL)
  const ev = await loadEvent(db, c.req.param('id') ?? '')
  if (!ev || !canView(user, ev)) return c.json({ detail: 'Event not found' }, 404)
  if (!canEdit(user, ev)) return c.json({ detail: 'You cannot change this event' }, 403)
  if (ev.status === status) return c.json(eventOut(ev, user, { alerts_updated: 0 }))
  const now = new Date()
  const [updated] = await db.update(tiEvents)
    .set({ status, updatedAt: now, ...(status === 'published' ? { publishedAt: now } : {}) })
    .where(eq(tiEvents.tiEventId, ev.tiEventId)).returning()
  if (!updated) return c.json({ detail: 'Event not found' }, 404)
  await audit(db, user, updated, status === 'published' ? 'ti_event.publish' : 'ti_event.unpublish', { status }, { status: ev.status })
  const alerts = await refreshAfter(db, updated)
  return c.json(eventOut(updated, user, { alerts_updated: alerts }))
}

app.post('/:id/publish', authMiddleware, requireRoles(...WRITE_ROLES), async (c) => {
  try { return await setStatus(c, 'published') } catch (err) {
    console.error('ti event publish error:', err)
    return c.json({ detail: 'Failed to publish event' }, 500)
  }
})

app.post('/:id/unpublish', authMiddleware, requireRoles(...WRITE_ROLES), async (c) => {
  try { return await setStatus(c, 'draft') } catch (err) {
    console.error('ti event unpublish error:', err)
    return c.json({ detail: 'Failed to unpublish event' }, 500)
  }
})

// ── POST /:id/attributes ─── paste values (one per line) ──────
const eventSource = (title: string) => `Event: ${title}`.slice(0, 100)

const addBody = z.object({
  text: z.string().min(1).max(500_000),
  type: z.enum(IOC_TYPES).optional(),          // forces one type for every value
  to_ids: z.boolean().optional(),
  comment: z.string().max(1000).nullish(),
})

app.post('/:id/attributes', authMiddleware, requireRoles(...WRITE_ROLES), zValidator('json', addBody, badRequest), async (c) => {
  try {
    const user = c.get('user') as User
    const db = getDb(c.env.DATABASE_URL)
    const ev = await loadEvent(db, c.req.param('id'))
    if (!ev || !canView(user, ev)) return c.json({ detail: 'Event not found' }, 404)
    if (!canEdit(user, ev)) return c.json({ detail: 'You cannot change this event' }, 403)
    const body = c.req.valid('json')
    const { parsed, rejected } = parseIocs(body.text, body.type as IocType | undefined)
    if (parsed.length > MAX_ATTRIBUTES_PER_ADD) {
      return c.json({ detail: `At most ${MAX_ATTRIBUTES_PER_ADD} values at a time (got ${parsed.length})` }, 400)
    }
    const [{ n: existing } = { n: 0 }] = await db.select({ n: sql<number>`count(*)::int` })
      .from(ctiIndicators).where(eq(ctiIndicators.tiEventId, ev.tiEventId))
    if (existing + parsed.length > MAX_ATTRIBUTES_PER_EVENT) {
      return c.json({ detail: `An event holds at most ${MAX_ATTRIBUTES_PER_EVENT} attributes` }, 400)
    }

    const now = new Date()
    const rows = parsed.map(p => {
      const warning = warninglistOf(p.type, p.value)
      return {
        source: eventSource(ev.title),
        indicatorType: p.type,
        value: p.value,
        tenantId: ev.tenantId,
        tiEventId: ev.tiEventId,
        toIds: body.to_ids ?? true,
        comment: body.comment ?? null,
        warning,
        ...attackOfEvent(ev),
        firstSeen: now,
        lastSeen: now,
      }
    })
    let added = 0
    if (rows.length) {
      // One db.batch (one subrequest); values already in the event are skipped.
      const stmts = []
      for (let i = 0; i < rows.length; i += 500) {
        stmts.push(db.insert(ctiIndicators).values(rows.slice(i, i + 500))
          .onConflictDoNothing({ target: [ctiIndicators.tiEventId, ctiIndicators.value], where: sql`ti_event_id IS NOT NULL` })
          .returning({ id: ctiIndicators.indicatorId }))
      }
      const results = await db.batch(stmts as [typeof stmts[number], ...typeof stmts])
      added = (results as Array<unknown[]>).reduce((n, r) => n + r.length, 0)
      await db.batch([
        db.update(tiEvents).set({ updatedAt: now }).where(eq(tiEvents.tiEventId, ev.tiEventId)),
        audit(db, user, ev, 'ti_event.attributes_add', { added, rejected: rejected.length }),
      ])
    }
    const touchesAlerts = ev.status === 'published' && added > 0
    const alerts = touchesAlerts ? await refreshAfter(db, ev) : 0
    return c.json({
      added,
      already_present: rows.length - added,
      on_warninglist: rows.filter(r => r.warning).length,
      rejected: rejected.slice(0, 50),
      rejected_count: rejected.length,
      alerts_updated: alerts,
    }, 201)
  } catch (err) {
    console.error('ti event add attributes error:', err)
    return c.json({ detail: 'Failed to add attributes' }, 500)
  }
})

// ── PATCH /:id/attributes/:attrId ─── to_ids, comment ─────────
const attrPatch = z.object({ to_ids: z.boolean().optional(), comment: z.string().max(1000).nullish() })

app.patch('/:id/attributes/:attrId', authMiddleware, requireRoles(...WRITE_ROLES), zValidator('json', attrPatch, badRequest), async (c) => {
  try {
    const user = c.get('user') as User
    const db = getDb(c.env.DATABASE_URL)
    const ev = await loadEvent(db, c.req.param('id'))
    if (!ev || !canView(user, ev)) return c.json({ detail: 'Event not found' }, 404)
    if (!canEdit(user, ev)) return c.json({ detail: 'You cannot change this event' }, 403)
    const body = c.req.valid('json')
    const [attr] = await db.update(ctiIndicators).set({
      ...(body.to_ids !== undefined ? { toIds: body.to_ids } : {}),
      ...(body.comment !== undefined ? { comment: body.comment ?? null } : {}),
    }).where(and(eq(ctiIndicators.indicatorId, c.req.param('attrId')), eq(ctiIndicators.tiEventId, ev.tiEventId))).returning()
    if (!attr) return c.json({ detail: 'Attribute not found' }, 404)
    const alerts = ev.status === 'published' && body.to_ids !== undefined ? await refreshAfter(db, ev) : 0
    return c.json({ ...attributeOut(attr), alerts_updated: alerts })
  } catch (err) {
    console.error('ti event update attribute error:', err)
    return c.json({ detail: 'Failed to update attribute' }, 500)
  }
})

// ── DELETE /:id/attributes/:attrId ───────────────────────────
app.delete('/:id/attributes/:attrId', authMiddleware, requireRoles(...WRITE_ROLES), async (c) => {
  try {
    const user = c.get('user') as User
    const db = getDb(c.env.DATABASE_URL)
    const ev = await loadEvent(db, c.req.param('id'))
    if (!ev || !canView(user, ev)) return c.json({ detail: 'Event not found' }, 404)
    if (!canEdit(user, ev)) return c.json({ detail: 'You cannot change this event' }, 403)
    const [attr] = await db.delete(ctiIndicators)
      .where(and(eq(ctiIndicators.indicatorId, c.req.param('attrId')), eq(ctiIndicators.tiEventId, ev.tiEventId)))
      .returning()
    if (!attr) return c.json({ detail: 'Attribute not found' }, 404)
    await audit(db, user, ev, 'ti_event.attribute_delete', null, { type: attr.indicatorType, value: attr.value })
    const alerts = ev.status === 'published' ? await refreshAfter(db, ev) : 0
    return c.json({ deleted: true, alerts_updated: alerts })
  } catch (err) {
    console.error('ti event delete attribute error:', err)
    return c.json({ detail: 'Failed to delete attribute' }, 500)
  }
})

export default app
