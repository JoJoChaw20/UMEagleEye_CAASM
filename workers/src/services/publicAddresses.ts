// The database side of the organisation's public addresses (lib/publicAddress.ts, D4): recording them,
// listing them, the blocklist check (rule R11) and Spamhaus DROP.
import { and, eq, inArray, sql, type SQL } from 'drizzle-orm'
import type { DB } from '../db/client'
import { auditLogs, events, publicAddresses } from '../db/schema'
import { matchableSql } from './threatIntel'
import { parseDrop, rangesContaining, type DropRange } from '../lib/ipRanges'
import {
  listKindOf, planR11, r11Details, r11Severity, isPublicAddressStatus,
  type Listing, type R11Have, type R11Want,
} from '../lib/publicAddress'

// ── Spamhaus DROP ("Don't Route Or Peer"): network ranges hijacked or run by criminals. Free with
// attribution; fetched at most once a day (the nightly CTI chain), kept in KV (not a table: ~1,800
// ranges, matched in code against a handful of addresses).
export const DROP_SOURCE = 'Spamhaus DROP'
export const DROP_KV_KEY = 'blocklist:spamhaus-drop'
const DROP_URLS = ['https://www.spamhaus.org/drop/drop_v4.json', 'https://www.spamhaus.org/drop/drop_v6.json']

interface StoredDrop { fetched_at: string; timestamp: number | null; copyright: string | null; ranges: DropRange[] }

/** Load DROP (IPv4 and IPv6) into KV; returns how many ranges. Throws when it could not be read, so the
 *  feed-health line says so; the copy from the last good run stays in KV. */
export async function ingestSpamhausDrop(kv: KVNamespace): Promise<number> {
  const ranges: DropRange[] = []
  let timestamp: number | null = null
  let copyright: string | null = null
  for (const url of DROP_URLS) {
    const res = await fetch(url, { headers: { 'User-Agent': 'UMEagleEye (public address check)' } })
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`)
    const list = parseDrop(await res.text())
    ranges.push(...list.ranges)
    timestamp = list.timestamp ?? timestamp
    copyright = list.copyright ?? copyright
  }
  if (ranges.length === 0) throw new Error('Spamhaus DROP was empty')
  const stored: StoredDrop = { fetched_at: new Date().toISOString(), timestamp, copyright, ranges }
  await kv.put(DROP_KV_KEY, JSON.stringify(stored))
  return ranges.length
}

async function dropRanges(kv: KVNamespace | null): Promise<DropRange[] | null> {
  if (!kv) return null
  try {
    return (await kv.get<StoredDrop>(DROP_KV_KEY, 'json'))?.ranges ?? null
  } catch {
    return null
  }
}

export type AddressScope = { tenantId: string } | { all: true }

export interface AddressWithAsset {
  public_address_id: string; tenant_id: string; ip: string; status: string; blocklists: unknown; asset_id: string | null
}

/** The addresses matching `where` (on alias p), each with the asset its alerts go on: the network's
 *  gateway when the agent that last reported the address named one and it is in the inventory, else
 *  that agent's own computer, else an asset holding the address itself; null when none. */
export async function addressesWithAsset(db: DB, where: SQL): Promise<AddressWithAsset[]> {
  const res = await db.execute(sql`
    SELECT p.public_address_id, p.tenant_id, p.ip, p.status, p.blocklists,
      COALESCE(
        (SELECT ad.asset_id FROM asset_addresses ad JOIN assets s ON s.asset_id = ad.asset_id
          WHERE s.tenant_id = p.tenant_id AND ad.ended_at IS NULL AND ad.ip_address = la.config->>'default_gateway'
          ORDER BY (ad.network_key = regexp_replace(la.config->>'default_gateway', '[.][0-9]+$', '.0') || '/24') DESC
          LIMIT 1),
        la.host_asset_id,
        (SELECT s.asset_id FROM assets s WHERE s.tenant_id = p.tenant_id AND s.ip_address = p.ip LIMIT 1)
      ) AS asset_id
    FROM public_addresses p
    LEFT JOIN agents la ON la.agent_id = p.last_agent_id AND la.tenant_id = p.tenant_id
    WHERE ${where}`)
  return res.rows as unknown as AddressWithAsset[]
}

export interface CheckResult { addresses: number; listed: number; created: number; updated: number; reopened: number; resolved: number }

/**
 * R11: the tenant's public addresses against the blocklists (the feeds' IPs and URL hosts the tenant may
 * match, published events, Spamhaus DROP). Stores what each list says on the address, then raises,
 * updates, reopens or resolves one threat-intel alert per (asset, address): on the network's gateway when
 * an agent reported it and it is in the inventory, else on the agent's own computer, else on an asset
 * with that address. An address with none of these is listed on the Network page only.
 * `kv` null (no DROP copy at hand) keeps the DROP listings stored last time.
 */
export async function checkPublicAddresses(db: DB, kv: KVNamespace | null, scope: AddressScope): Promise<CheckResult> {
  const out: CheckResult = { addresses: 0, listed: 0, created: 0, updated: 0, reopened: 0, resolved: 0 }
  const where: SQL = 'tenantId' in scope ? sql`p.tenant_id = ${scope.tenantId}::uuid` : sql`true`
  const addrs = await addressesWithAsset(db, where)
  out.addresses = addrs.length

  const listings = new Map<string, Listing[]>(addrs.map((a) => [a.public_address_id, []]))
  if (addrs.length) {
    const visible = matchableSql(sql.raw('p.tenant_id'))
    const hits = await db.execute(sql`
      SELECT p.public_address_id, c.source, c.indicator_type::text AS itype, c.value,
             c.confidence_score::float8 AS conf, c.malware_family AS family, c.ti_event_id, te.title
      FROM public_addresses p
      JOIN cti_indicators c ON c.indicator_type = 'ip' AND c.value = p.ip
      LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
      WHERE ${where} AND ${visible}
      UNION ALL
      SELECT p.public_address_id, c.source, c.indicator_type::text, c.value,
             c.confidence_score::float8, c.malware_family, c.ti_event_id, te.title
      FROM public_addresses p
      JOIN cti_indicators c ON c.indicator_type = 'url'
        AND substring(c.value from '^[A-Za-z][A-Za-z0-9+.-]*://([0-9.]+)([:/?#]|$)') = p.ip
      LEFT JOIN ti_events te ON te.ti_event_id = c.ti_event_id
      WHERE ${where} AND ${visible}
      LIMIT 5000`)
    for (const h of hits.rows as { public_address_id: string; source: string; itype: string; value: string; conf: number | null; family: string | null; ti_event_id: string | null; title: string | null }[]) {
      const fromEvent = !!h.ti_event_id
      listings.get(h.public_address_id)?.push({
        kind: listKindOf(h.source, h.itype, h.conf, fromEvent), source: fromEvent ? (h.title ?? 'Threat-intel event') : h.source,
        value: h.value.slice(0, 300), confidence: h.conf, family: h.family, ref: h.ti_event_id,
      })
    }
    const ranges = await dropRanges(kv)
    for (const a of addrs) {
      const mine = listings.get(a.public_address_id)!
      if (ranges) {
        for (const r of rangesContaining(a.ip, ranges)) {
          mine.push({ kind: 'range', source: DROP_SOURCE, value: r.cidr, confidence: null, family: null, ref: r.sblid })
        }
      } else {
        // no DROP copy here: keep what DROP said last time
        const before = ((a.blocklists as { listings?: Listing[] } | null)?.listings ?? []).filter((l) => l.source === DROP_SOURCE)
        mine.push(...before)
      }
    }
  }

  // What each list says now, on the address (the Network page)
  const now = new Date()
  for (let i = 0; i < addrs.length; i += 200) {
    const values = sql.join(addrs.slice(i, i + 200).map((a) =>
      sql`(${a.public_address_id}::uuid, ${JSON.stringify({ listings: listings.get(a.public_address_id) })}::jsonb)`), sql`, `)
    await db.execute(sql`
      UPDATE public_addresses p SET blocklists = v.b, checked_at = ${now.toISOString()}::timestamptz
      FROM (VALUES ${values}) AS v(id, b) WHERE p.public_address_id = v.id`)
  }
  out.listed = addrs.filter((a) => listings.get(a.public_address_id)!.length > 0).length

  // The alerts
  const want: R11Want[] = []
  for (const a of addrs) {
    const status = isPublicAddressStatus(a.status) ? a.status : 'unconfirmed'
    const list = listings.get(a.public_address_id)!
    const severity = r11Severity(status, list)
    if (!severity || !a.asset_id) continue
    want.push({ assetId: a.asset_id, ip: a.ip, severity, details: r11Details(a.ip, a.public_address_id, status, list) })
  }
  const haveRes = await db.execute(sql`
    SELECT e.event_id, e.asset_id, a.tenant_id, e.status::text AS status, e.severity::text AS severity, e.details
    FROM events e JOIN assets a ON a.asset_id = e.asset_id
    WHERE e.event_type = 'cti_match' AND e.details->>'match_kind' = 'public_address'
      AND ${'tenantId' in scope ? sql`a.tenant_id = ${scope.tenantId}::uuid` : sql`true`}
    ORDER BY (e.status IN ('open', 'in_progress')) DESC, e.last_seen DESC`)
  const haveRows = haveRes.rows as { event_id: string; asset_id: string; tenant_id: string; status: string; severity: string; details: Record<string, unknown> }[]
  const have: R11Have[] = haveRows.map((r) => ({
    eventId: r.event_id, assetId: r.asset_id, ip: String(r.details?.indicator_value ?? ''), status: r.status,
    severity: r.severity, details: r.details ?? {},
  }))
  const tenantOfEvent = new Map(haveRows.map((r) => [r.event_id, r.tenant_id]))
  const statusOfEvent = new Map(haveRows.map((r) => [r.event_id, r.status]))
  const plan = planR11(want, have)

  const stmts: unknown[] = []
  for (const w of plan.create) {
    stmts.push(db.insert(events).values({ assetId: w.assetId, eventType: 'cti_match', severity: w.severity, details: w.details, firstSeen: now, lastSeen: now }))
  }
  for (const u of plan.update) {
    stmts.push(db.update(events).set({
      severity: u.want.severity, details: sql`${events.details} || ${JSON.stringify(u.want.details)}::jsonb`, lastSeen: now, updatedAt: now,
      ...(u.reopen ? {
        status: 'open' as const, resolvedAt: null, resolvedBy: null,
        resolutionNote: 'Reopened: the address is on a blocklist again', occurrences: sql`${events.occurrences} + 1`,
      } : {}),
    }).where(eq(events.eventId, u.eventId)))
    if (u.reopen) {
      stmts.push(db.insert(auditLogs).values({ userId: null, tenantId: tenantOfEvent.get(u.eventId) ?? null, actionType: 'alert_auto',
        targetEntity: u.eventId, previousState: { status: 'resolved' }, newState: { status: 'open', note: 'the address is on a blocklist again' } }))
    }
  }
  if (plan.resolve.length) {
    stmts.push(db.update(events).set({ status: 'resolved', resolvedAt: now, updatedAt: now,
      resolutionNote: 'Auto-resolved: the address is no longer listed, was marked not ours, or was removed' })
      .where(and(inArray(events.eventId, plan.resolve), inArray(events.status, ['open', 'in_progress']))))
    for (const id of plan.resolve) {
      stmts.push(db.insert(auditLogs).values({ userId: null, tenantId: tenantOfEvent.get(id) ?? null, actionType: 'alert_auto',
        targetEntity: id, previousState: { status: statusOfEvent.get(id) ?? 'open' }, newState: { status: 'resolved', note: 'the address is no longer listed, was marked not ours, or was removed' } }))
    }
  }
  for (let i = 0; i < stmts.length; i += 100) {
    const part = stmts.slice(i, i + 100)
    if (part.length) await db.batch(part as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
  }
  out.created = plan.create.length
  out.updated = plan.update.filter((u) => !u.reopen).length
  out.reopened = plan.update.filter((u) => u.reopen).length
  out.resolved = plan.resolve.length
  return out
}

/** checkPublicAddresses for one tenant, logged instead of thrown (after an address or status change). */
export async function checkTenantAddresses(db: DB, kv: KVNamespace | null, tenantId: string): Promise<CheckResult | null> {
  try {
    return await checkPublicAddresses(db, kv, { tenantId })
  } catch (err) {
    console.error('public addresses: blocklist check failed:', err)
    return null
  }
}

// The list leaves out addresses only agents saw, nobody confirmed, and no agent has used for this long
// (a laptop's home addresses); the nightly retention deletes them later (RETENTION_DAYS).
export const LIST_DAYS = 90
export const RETENTION_DAYS = 180
// "Shared": agents of another tenant reported the same address within this many days.
const SHARED_DAYS = 30

/** A heartbeat came from `ip`: add the address (unconfirmed) or refresh when and by whom it was last seen.
 *  Returns true when the address is new for the tenant. */
export async function recordPublicAddress(db: DB, tenantId: string, agentId: string, ip: string, now: Date): Promise<boolean> {
  const rows = await db.insert(publicAddresses)
    .values({ tenantId, ip, source: 'agent', status: 'unconfirmed', firstSeen: now, lastSeen: now, lastAgentId: agentId })
    .onConflictDoUpdate({
      target: [publicAddresses.tenantId, publicAddresses.ip],
      set: {
        lastSeen: now, lastAgentId: agentId, updatedAt: now,
        firstSeen: sql`COALESCE(${publicAddresses.firstSeen}, ${now.toISOString()}::timestamptz)`,
      },
    })
    .returning({ inserted: sql<boolean>`(xmax = 0)` })
  return rows[0]?.inserted === true
}

export interface PublicAddressRow {
  public_address_id: string
  ip: string
  source: string
  status: string
  note: string | null
  first_seen: string | null
  last_seen: string | null
  last_agent: { agent_id: string; name: string } | null
  agents_now: { agent_id: string; name: string }[]
  shared: boolean
  blocklists: unknown
  checked_at: string | null
}

/** The tenant's addresses for the Network page: confirmed and hand-added ones, and those an agent used in
 *  the last LIST_DAYS. With the agents connecting from each now (its current address, checked in within
 *  2 hours; a changed address reaches the database at once, the AgentHub only answers unchanged ones) and
 *  whether another tenant's agents use it too (never which tenant). */
export async function listPublicAddresses(db: DB, tenantId: string): Promise<PublicAddressRow[]> {
  const res = await db.execute(sql`
    SELECT p.public_address_id, p.ip, p.source, p.status, p.note, p.first_seen, p.last_seen,
           p.blocklists, p.checked_at,
           CASE WHEN la.agent_id IS NULL THEN NULL
                ELSE json_build_object('agent_id', la.agent_id, 'name', la.name) END AS last_agent,
           COALESCE((
             SELECT json_agg(json_build_object('agent_id', a.agent_id, 'name', a.name) ORDER BY a.name)
             FROM agents a
             WHERE a.tenant_id = p.tenant_id AND a.public_ip = p.ip AND a.retired_at IS NULL
               AND a.last_heartbeat > now() - interval '2 hours'
           ), '[]'::json) AS agents_now,
           EXISTS (
             SELECT 1 FROM public_addresses o
             WHERE o.ip = p.ip AND o.tenant_id <> p.tenant_id AND o.source = 'agent'
               AND o.last_seen > now() - make_interval(days => ${SHARED_DAYS})
           ) AS shared
    FROM public_addresses p
    LEFT JOIN agents la ON la.agent_id = p.last_agent_id
    WHERE p.tenant_id = ${tenantId}::uuid
      AND (p.status = 'ours' OR p.source = 'manual' OR p.last_seen > now() - make_interval(days => ${LIST_DAYS}))
    ORDER BY (p.status = 'ours') DESC, (p.status = 'not_ours') ASC, p.last_seen DESC NULLS LAST, p.ip
    LIMIT 200
  `)
  return res.rows as unknown as PublicAddressRow[]
}

/** Nightly retention: addresses only agents saw, nobody marked as the organisation's, unused for RETENTION_DAYS. */
export async function pruneUnusedPublicAddresses(db: DB): Promise<number> {
  const res = await db.execute(sql`
    DELETE FROM public_addresses
    WHERE source = 'agent' AND status <> 'ours'
      AND last_seen < now() - make_interval(days => ${RETENTION_DAYS})
    RETURNING 1
  `)
  return res.rows.length
}
