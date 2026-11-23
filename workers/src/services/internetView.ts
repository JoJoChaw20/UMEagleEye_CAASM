// What the internet sees on the organisation's public addresses (lib/internetView.ts): asking Shodan
// InternetDB (weekly per address, at most PER_RUN a run), storing its answer on the address, and one
// exposure alert per risky port open to the internet on an address marked as the organisation's own.
// Only tenants with the switch on (tenants.public_address_lookup) are asked about.
import { and, eq, inArray, sql, type SQL } from 'drizzle-orm'
import type { DB } from '../db/client'
import { auditLogs, events } from '../db/schema'
import {
  INTERNETDB_URL, INTERNET_RULE, NOTHING, PER_RUN, RECHECK_MS, internetDetails, internetFindings, parseInternetDb,
  planInternetAlerts, type InternetHave, type InternetView, type InternetWant,
} from '../lib/internetView'
import { addressesWithAsset } from './publicAddresses'

export interface ViewResult { asked: number; failed: number; created: number; refreshed: number; resolved: number }

/** Ask InternetDB about one IPv4 address: its view, NOTHING when it has none (404), null on failure. */
export async function fetchInternetView(ip: string): Promise<InternetView | null> {
  const res = await fetch(`${INTERNETDB_URL}${encodeURIComponent(ip)}`, { headers: { Accept: 'application/json' } })
  if (res.status === 404) return NOTHING
  if (!res.ok) throw new Error(`InternetDB ${ip}: HTTP ${res.status}`)
  return parseInternetDb(await res.json())
}

/**
 * Ask about the addresses due (never asked, or asked over a week ago): ours and unconfirmed ones,
 * IPv4, of tenants with the switch on; or exactly `ids` (an address just marked ours). Then the
 * alerts of every tenant touched.
 */
export async function refreshInternetViews(db: DB, opts: { tenantId?: string; ids?: string[] } = {}): Promise<ViewResult> {
  const out: ViewResult = { asked: 0, failed: 0, created: 0, refreshed: 0, resolved: 0 }
  const due = new Date(Date.now() - RECHECK_MS).toISOString()
  const conds: SQL[] = [
    sql`t.public_address_lookup`, sql`p.status IN ('ours', 'unconfirmed')`, sql`p.ip ~ '^[0-9.]+$'`,
    opts.ids?.length
      ? sql`p.public_address_id IN (${sql.join(opts.ids.map((id) => sql`${id}::uuid`), sql`, `)})`
      : sql`(p.internetdb_at IS NULL OR p.internetdb_at < ${due}::timestamptz)`,
  ]
  if (opts.tenantId) conds.push(sql`p.tenant_id = ${opts.tenantId}::uuid`)
  const rows = await db.execute(sql`
    SELECT p.public_address_id, p.tenant_id, p.ip FROM public_addresses p JOIN tenants t ON t.tenant_id = p.tenant_id
    WHERE ${sql.join(conds, sql` AND `)}
    ORDER BY (p.status = 'ours') DESC, p.internetdb_at NULLS FIRST
    LIMIT ${PER_RUN}`)
  const todo = rows.rows as { public_address_id: string; tenant_id: string; ip: string }[]
  const tenants = new Set<string>()
  for (const a of todo) {
    let view: InternetView | null
    try {
      view = await fetchInternetView(a.ip)
    } catch (err) {
      out.failed++
      console.error('internet view: InternetDB failed:', err)
      if (String(err).includes('HTTP 429')) break           // rate limited: the rest wait for the next run
      continue
    }
    if (!view) { out.failed++; continue }
    out.asked++
    tenants.add(a.tenant_id)
    await db.execute(sql`
      UPDATE public_addresses SET internetdb = ${JSON.stringify(view)}::jsonb, internetdb_at = now()
      WHERE public_address_id = ${a.public_address_id}::uuid`)
  }
  for (const t of tenants) {
    const r = await syncInternetAlerts(db, t)
    out.created += r.created; out.refreshed += r.refreshed; out.resolved += r.resolved
  }
  return out
}

/** The tenant's internet-view alerts from what is stored: one per (asset, risky port) on its own
 *  addresses; none when the switch is off or the address is not (or no longer) marked ours. */
export async function syncInternetAlerts(db: DB, tenantId: string): Promise<{ created: number; refreshed: number; resolved: number }> {
  const addrs = await addressesWithAsset(db, sql`p.tenant_id = ${tenantId}::uuid`)
  const want: InternetWant[] = []
  for (const a of addrs) {
    if (!a.lookup || a.status !== 'ours' || !a.asset_id || !a.internetdb || !a.internetdb_at) continue
    const view = a.internetdb as InternetView
    const checkedAt = new Date(a.internetdb_at).toISOString()
    for (const f of internetFindings(view)) {
      want.push({ assetId: a.asset_id, port: f.port, finding: f, details: internetDetails(f, a.ip, a.public_address_id, checkedAt, view) })
    }
  }
  const haveRes = await db.execute(sql`
    SELECT e.event_id, e.asset_id, e.status::text AS status, e.severity::text AS severity, (e.details->>'port')::int AS port
    FROM events e JOIN assets a ON a.asset_id = e.asset_id
    WHERE e.event_type = 'exposure' AND e.details->>'rule' = ${INTERNET_RULE} AND a.tenant_id = ${tenantId}::uuid
    ORDER BY (e.status IN ('open', 'in_progress')) DESC, e.last_seen DESC`)
  const have = (haveRes.rows as { event_id: string; asset_id: string; status: string; severity: string; port: number }[])
    .map((r): InternetHave => ({ eventId: r.event_id, assetId: r.asset_id, port: r.port, status: r.status, severity: r.severity }))
  const plan = planInternetAlerts(want, have)

  const now = new Date()
  const stmts: unknown[] = []
  for (const w of plan.create) {
    stmts.push(db.insert(events).values({ assetId: w.assetId, eventType: 'exposure', severity: w.finding.severity, details: w.details, firstSeen: now, lastSeen: now }))
  }
  for (const r of plan.refresh) {
    stmts.push(db.update(events).set({
      severity: r.want.finding.severity, details: r.want.details, lastSeen: now, updatedAt: now,
      ...(r.reopen ? { status: 'open' as const, resolvedAt: null, resolvedBy: null,
        resolutionNote: 'Reopened: Shodan sees the port open again', occurrences: sql`${events.occurrences} + 1` } : {}),
    }).where(eq(events.eventId, r.eventId)))
    if (r.reopen) {
      stmts.push(db.insert(auditLogs).values({ userId: null, tenantId, actionType: 'alert_auto', targetEntity: r.eventId,
        previousState: { status: 'resolved' }, newState: { status: 'open', note: 'Shodan sees the port open again' } }))
    }
  }
  if (plan.resolve.length) {
    stmts.push(db.update(events).set({ status: 'resolved', resolvedAt: now, updatedAt: now,
      resolutionNote: 'Auto-resolved: Shodan no longer sees the port open, or the address is no longer marked ours or checked' })
      .where(and(inArray(events.eventId, plan.resolve), inArray(events.status, ['open', 'in_progress']))))
  }
  for (let i = 0; i < stmts.length; i += 100) {
    const part = stmts.slice(i, i + 100)
    if (part.length) await db.batch(part as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
  }
  return { created: plan.create.length, refreshed: plan.refresh.length, resolved: plan.resolve.length }
}
