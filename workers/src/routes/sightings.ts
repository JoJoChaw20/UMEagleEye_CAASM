// Threat sightings (rule R7, lib/sightings.ts): the host agent's side.
//
//   GET  /sightings/indicators?part=feeds&after=<cursor>&limit=2000
//        the tenant's matchable feed domains and IPs, paged by (last_seen, indicator_id); the
//        agent keeps the last `next` and asks again for what changed since (a weekly full
//        resync starts without a cursor and replaces its list, dropping removed entries)
//   GET  /sightings/indicators?part=events
//        the domains and IPs of the published threat-intel events its tenant may match, whole
//        (small; fetched more often, so an analyst's new event reaches the agents quickly)
//   POST /sightings  {hits: [...]}
//        what this computer looked up or connected to that is on the list; re-checked here,
//        then one cti_match alert per (asset, listed value), match_kind 'sighting'
//
// Agent auth: X-Agent-ID + Bearer key (as routes/network.ts). Matching happens on the
// computer; lookups and connections that match nothing never leave it.

import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { and, eq, sql, type SQL } from 'drizzle-orm'
import type { Env } from '../types'
import { getDb } from '../db/client'
import { agents, auditLogs, eventCtiIndicators, events } from '../db/schema'
import { FEED_FRESH, matchableSql, sharedBySql } from '../services/threatIntel'
import {
  LIST_PAGE, LIST_RULES, cleanHits, decodeCursor, encodeCursor, listItems, lookupValues, matchHits, planSightings,
  type ExistingSighting, type IndicatorRow,
} from '../lib/sightings'

const app = new Hono<{ Bindings: Env }>()
type Db = ReturnType<typeof getDb>

// Event indicators sent whole; beyond this the agent gets the first ones and `truncated`.
const MAX_EVENT_VALUES = 20_000

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function sameHash(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

async function authenticateAgent(c: { req: { header(name: string): string | undefined } }, db: Db) {
  const auth = c.req.header('Authorization')
  const agentId = c.req.header('X-Agent-ID')
  if (!auth?.startsWith('Bearer ') || !agentId || !z.string().uuid().safeParse(agentId).success) return null
  const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
  return agent && !agent.retiredAt && sameHash(await sha256Hex(auth.slice(7)), agent.apiKeyHash) ? agent : null
}

const inList = (column: SQL, values: string[]): SQL =>
  values.length ? sql`${column} IN (${sql.join(values.map(v => sql`${v}`), sql`, `)})` : sql`false`

// The host of a URL indicator, as lib/sightings.ts listItem reads it; only an IPv4 host counts.
const URL_HOST = sql.raw(`lower(substring(c.value from '^[A-Za-z][A-Za-z0-9+.-]*://(?:[^/?#@]*@)?([^]/?#:[]+)'))`)

app.get('/indicators', async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const agent = await authenticateAgent(c, db)
  if (!agent) return c.json({ detail: 'Invalid credentials' }, 401)
  if (agent.kind !== 'host' || !agent.tenantId) return c.json({ detail: 'Sightings are for a computer\'s own agent' }, 403)
  const tenant = sql`${agent.tenantId}::uuid`

  if (c.req.query('part') === 'events') {
    const res = await db.execute(sql`
      SELECT c.indicator_type::text AS type, c.value
      FROM cti_indicators c JOIN ti_events te ON te.ti_event_id = c.ti_event_id
      WHERE c.indicator_type IN ('ip', 'domain', 'url') AND ${matchableSql(tenant)}
      ORDER BY c.indicator_id
      LIMIT ${MAX_EVENT_VALUES + 1}
    `)
    const rows = res.rows as { type: string; value: string }[]
    return c.json({ items: listItems(rows.slice(0, MAX_EVENT_VALUES)), truncated: rows.length > MAX_EVENT_VALUES, rules: LIST_RULES })
  }

  const rawAfter = c.req.query('after')
  const after = decodeCursor(rawAfter)
  if (rawAfter && !after) return c.json({ detail: 'Invalid cursor' }, 400)
  const limit = Math.min(Math.max(Number(c.req.query('limit')) || LIST_PAGE, 100), LIST_PAGE)
  // Feed entries only (ti_event_id NULL): matchable when to_ids, not on a warninglist, and still
  // listed by a feed recently (services/threatIntel.ts FEED_FRESH).
  const res = await db.execute(sql`
    SELECT c.indicator_type::text AS type, c.value, c.last_seen::text AS seen, c.indicator_id::text AS id
    FROM cti_indicators c
    WHERE c.ti_event_id IS NULL AND c.to_ids AND c.warning IS NULL AND c.indicator_type IN ('ip', 'domain', 'url') AND ${FEED_FRESH}
      ${after ? sql`AND (c.last_seen, c.indicator_id) > (${after.seen}::timestamptz, ${after.id}::uuid)` : sql``}
    ORDER BY c.last_seen, c.indicator_id
    LIMIT ${limit}
  `)
  const rows = res.rows as { type: string; value: string; seen: string; id: string }[]
  const last = rows[rows.length - 1]
  return c.json({
    items: listItems(rows),
    next: last ? encodeCursor(last.seen, last.id) : (rawAfter ?? null),
    done: rows.length < limit,
    rules: LIST_RULES,
  })
})

app.post('/', zValidator('json', z.object({ hits: z.array(z.unknown()).max(1000) })), async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const agent = await authenticateAgent(c, db)
  if (!agent) return c.json({ detail: 'Invalid credentials' }, 401)
  if (agent.kind !== 'host' || !agent.tenantId) return c.json({ detail: 'Sightings are for a computer\'s own agent' }, 403)
  const assetId = agent.hostAssetId
  if (!assetId) return c.json({ detail: 'This agent has not sent its inventory yet, so its computer is not known' }, 409)

  const now = new Date()
  const { hits, rejected } = cleanHits(c.req.valid('json').hits, now)
  if (hits.length === 0) return c.json({ accepted: 0, dropped: 0, rejected, created: 0, updated: 0, reopened: 0 })

  // The re-check: only what the tenant's matchable indicators list now counts.
  const { ips, names } = lookupValues(hits)
  const res = await db.execute(sql`
    SELECT c.indicator_id::text AS "indicatorId", c.indicator_type::text AS type, c.value, c.source,
           c.ti_event_id::text AS "tiEventId", te.title, te.threat_level::text AS level,
           c.confidence_score::float AS confidence, ${sharedBySql(sql`${agent.tenantId}::uuid`)} AS "sharedBy"
    FROM cti_indicators c LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
    WHERE ${matchableSql(sql`${agent.tenantId}::uuid`)} AND (
      (c.indicator_type = 'ip' AND ${inList(sql`c.value`, ips)})
      OR (c.indicator_type = 'domain' AND ${inList(sql`c.value`, names)})
      OR (c.indicator_type = 'url' AND ${inList(URL_HOST, ips)})
    )
    LIMIT 1000
  `)
  const { matched, dropped } = matchHits(hits, res.rows as unknown as IndicatorRow[])
  if (matched.length === 0) {
    return c.json({ accepted: 0, dropped: dropped.length, rejected, created: 0, updated: 0, reopened: 0 })
  }

  const existingRows = await db.select({
    eventId: events.eventId, status: events.status, resolvedAt: events.resolvedAt, details: events.details,
  }).from(events).where(and(
    eq(events.assetId, assetId), eq(events.eventType, 'cti_match'),
    sql`${events.details}->>'match_kind' = 'sighting'`,
    inList(sql`${events.details}->>'indicator_value'`, matched.map(m => m.listed)),
  ))
  const plan = planSightings({
    matched, existing: existingRows as unknown as ExistingSighting[], newId: () => crypto.randomUUID(),
  })

  const statements: unknown[] = []
  for (const w of plan.insert) {
    statements.push(db.insert(events).values({
      eventId: w.eventId, assetId, eventType: 'cti_match', severity: w.severity, details: w.details,
      firstSeen: w.firstSeen, lastSeen: w.lastSeen, timestamp: now, updatedAt: now,
    }))
  }
  for (const u of plan.update) {
    statements.push(db.update(events).set({
      details: u.details, severity: u.severity, lastSeen: u.lastSeen, updatedAt: now,
      ...(u.reopen ? {
        status: 'open' as const, resolvedAt: null, resolvedBy: null,
        resolutionNote: 'Reopened: this computer contacted the listed domain or IP again',
        occurrences: sql`${events.occurrences} + 1`,
      } : {}),
    }).where(eq(events.eventId, u.eventId)))
    if (u.reopen) {
      statements.push(db.insert(auditLogs).values({
        userId: null, tenantId: agent.tenantId, actionType: 'alert_auto', targetEntity: u.eventId,
        previousState: { status: u.prevStatus },
        newState: { status: 'open', note: 'this computer contacted the listed domain or IP again' },
      }))
    }
  }
  const links = [...plan.insert, ...plan.update].flatMap(w => w.indicatorIds.map(indicatorId => ({ eventId: w.eventId, indicatorId })))
  if (links.length) statements.push(db.insert(eventCtiIndicators).values(links).onConflictDoNothing())
  await db.batch(statements as unknown as Parameters<typeof db.batch>[0])

  return c.json({
    accepted: hits.length - dropped.length, dropped: dropped.length, rejected,
    created: plan.insert.length, updated: plan.update.length, reopened: plan.update.filter(u => u.reopen).length,
  })
})

export default app
