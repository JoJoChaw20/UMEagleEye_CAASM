/**
 * kg/sync.ts — keeps the graph in step with the source tables.
 *
 * Triggers (migration 0029) list every changed row in kg_outbox. Nothing polls it: a write
 * sends one debounced queue message (signalKgSync), the chatbot applies what is outstanding
 * before it answers, and the existing 6-hourly cron drains anything left. Rows are claimed for
 * 90 seconds so concurrent drains split the work, and a drain that dies leaves them to the next.
 *
 * The debounce drops the signal of any write inside its window, so every signalled job is followed
 * by one sweep once the window has passed. A sweep that applies rows looks once more, and a sweep
 * that finds nothing ends the chain, so an idle database is left asleep. Rows that only fail apply
 * nothing, so they cannot keep a chain going either.
 */
import type { Env } from '../types'
import {
  extractAddress, extractAdvisory, extractAgent, extractAsset, extractDependency, extractEvent, extractIdentifier,
  extractLink, extractPosture, extractRelationship, extractSbom, extractScan, extractSoftware, extractTiEvent,
  extractTopology, safeDelta, type GraphDelta, type Row,
} from './extract'
import { backfillEmbeddings, deleteStatements, edgesStatements, embedChanged, kgQuery, nodesStatement, runBatch, type Q, type Stmt } from './store'
import { refreshProblems } from './problems'
import { recordJob } from './perf'

interface Source { prefix: string; pk: string; sql: string; extract: (r: Row) => GraphDelta }

const ASSET_JOIN = `JOIN assets a ON a.asset_id = t.asset_id`

// Each query names its columns: this list is the allowlist of what can enter the graph.
const SOURCES: Record<string, Source> = {
  assets: {
    prefix: 'asset', pk: 'asset_id', extract: extractAsset,
    sql: `SELECT asset_id, tenant_id, hostname, ip_address, mac_address, owner, device_type, hardware_vendor, os_info,
            endpoint_inventory -> 'os' AS inv_os, criticality_score, posture_score, is_internet_facing, internet_facing_override,
            source, in_my_assets, last_scanned
          FROM assets WHERE asset_id = ANY($1::uuid[])`,
  },
  asset_addresses: {
    prefix: 'address', pk: 'address_id', extract: extractAddress,
    sql: `SELECT address_id, asset_id, tenant_id, ip_address, mac_address, first_seen, last_seen, ended_at FROM asset_addresses WHERE address_id = ANY($1::uuid[])`,
  },
  asset_software: {
    prefix: 'software', pk: 'software_id', extract: extractSoftware,
    sql: `SELECT t.software_id, t.asset_id, t.name, t.version, t.publisher, a.tenant_id, a.hostname, a.ip_address
          FROM asset_software t ${ASSET_JOIN} WHERE t.software_id = ANY($1::uuid[])`,
  },
  asset_identifiers: {
    prefix: 'identifier', pk: 'identifier_id', extract: extractIdentifier,
    sql: `SELECT identifier_id, asset_id, tenant_id, kind, value FROM asset_identifiers WHERE identifier_id = ANY($1::uuid[])`,
  },
  asset_relationships: {
    prefix: 'relationship', pk: 'relationship_id', extract: extractRelationship,
    sql: `SELECT t.relationship_id, t.source_asset_id, t.target_asset_id, t.relationship_type, t.confidence, s.tenant_id, d.tenant_id AS target_tenant_id,
            COALESCE(s.hostname, s.ip_address) AS source_label, COALESCE(d.hostname, d.ip_address) AS target_label
          FROM asset_relationships t JOIN assets s ON s.asset_id = t.source_asset_id JOIN assets d ON d.asset_id = t.target_asset_id
          WHERE t.relationship_id = ANY($1::uuid[]) AND s.tenant_id IS NOT DISTINCT FROM d.tenant_id`,
  },
  sboms: {
    prefix: 'sbom', pk: 'sbom_id', extract: extractSbom,
    sql: `SELECT t.sbom_id, t.asset_id, t.format, t.tool_used, t.generated_at, a.tenant_id, a.hostname, a.ip_address
          FROM sboms t ${ASSET_JOIN} WHERE t.sbom_id = ANY($1::uuid[])`,
  },
  dependencies: {
    prefix: 'dependency', pk: 'dependency_id', extract: extractDependency,
    sql: `SELECT t.dependency_id, t.asset_id, t.name, t.version, t.package_manager, a.tenant_id, a.hostname, a.ip_address
          FROM dependencies t ${ASSET_JOIN} WHERE t.dependency_id = ANY($1::uuid[])`,
  },
  events: {
    prefix: 'event', pk: 'event_id', extract: extractEvent,
    sql: `SELECT t.event_id, t.asset_id, t.event_type, t.severity, t.details, t.composite_risk_score, t.timestamp, t.status, t.occurrences,
            a.tenant_id, a.hostname, a.ip_address,
            (SELECT json_agg(json_build_object('indicator_id', c.indicator_id, 'indicator_type', c.indicator_type, 'value', c.value, 'source', c.source, 'malware_family', c.malware_family))
             FROM event_cti_indicators j JOIN cti_indicators c ON c.indicator_id = j.indicator_id WHERE j.event_id = t.event_id) AS indicators
          FROM events t ${ASSET_JOIN} WHERE t.event_id = ANY($1::uuid[])`,
  },
  advisories: {
    prefix: 'advisory', pk: 'advisory_id', extract: extractAdvisory,
    sql: `SELECT t.advisory_id, t.event_id, t.summary, t.recommended_action, t.status, t.created_at, e.severity, e.event_type, e.asset_id,
            a.tenant_id, a.hostname, a.ip_address
          FROM advisories t JOIN events e ON e.event_id = t.event_id JOIN assets a ON a.asset_id = e.asset_id
          WHERE t.advisory_id = ANY($1::uuid[])`,
  },
  ti_events: {
    prefix: 'ti_event', pk: 'ti_event_id', extract: extractTiEvent,
    sql: `SELECT ti_event_id, tenant_id, title, description, threat_level, status, malware_family FROM ti_events WHERE ti_event_id = ANY($1::uuid[])`,
  },
  agents: {
    prefix: 'agent', pk: 'agent_id', extract: extractAgent,
    sql: `SELECT agent_id, tenant_id, name, status, gateway_ip, version, retired_at, host_asset_id, kind FROM agents WHERE agent_id = ANY($1::uuid[])`,
  },
  topology_nodes: {
    prefix: 'topology', pk: 'node_id', extract: extractTopology,
    sql: `SELECT node_id, asset_id, tenant_id, parent_node_id, node_type, layer, label FROM topology_nodes WHERE node_id = ANY($1::uuid[])`,
  },
  network_links: {
    prefix: 'link', pk: 'link_id', extract: extractLink,
    sql: `SELECT link_id, tenant_id, a_name, a_port, a_asset_id, b_name, b_port, b_asset_id FROM network_links WHERE link_id = ANY($1::uuid[])`,
  },
  scan_results: {
    prefix: 'scan', pk: 'scan_id', extract: extractScan,
    sql: `SELECT scan_id, agent_id, tenant_id, scan_type, subnet, status, hosts_discovered, failure_reason, started_at FROM scan_results WHERE scan_id = ANY($1::uuid[])`,
  },
  posture_metrics: {
    prefix: 'posture_row', pk: 'snapshot_id', extract: extractPosture,
    sql: `SELECT snapshot_id, tenant_id, overall_score, total_assets, total_critical_assets, open_critical_events, timestamp
          FROM posture_metrics WHERE snapshot_id = ANY($1::uuid[]) ORDER BY timestamp`,
  },
}

export interface DrainResult { processed: number; remaining: number; blocked: number; quarantined: number; tenants: string[] }

/** A row that failed this many claims is set aside (excluded from claims) until a new change resets it. */
export const MAX_ATTEMPTS = 5
const CLAIM_SECONDS = 90

/** What one changed row turns into. A row with no node (deleted, blocked, no tenant) removes its old node. */
interface RowDelta { table: string; id: string; nodes: GraphDelta['nodes']; edges: GraphDelta['edges']; owner: string | null; goneKey: string | null }

/**
 * The requests one drain may use in all. A Worker run has 50 subrequests, and the refreshes and
 * backfill after a queue drain can take 26 of them. A chat also pays for its model calls and tools,
 * so it gets less. Rows the budget does not reach wait for the next drain.
 */
export const DRAIN_REQUESTS = 18
/**
 * A chat's drain: the six base requests and two splits. Its embedding calls come on top (at most
 * three for 100 rows), so a chat's drain costs at most 11 of the 45 subrequests a chat may use
 * (agent.ts CHAT_SUBREQUESTS).
 */
export const CHAT_DRAIN_REQUESTS = 8
/**
 * Claim, read, the deleted rows' companies, the embedding read, the first write and the finish.
 * Splitting spends only what is above these, so the finish always has its request.
 */
const DRAIN_BASE_REQUESTS = 6

/** One drain's bookkeeping: rows proven bad, rows it did not get to, and the extra requests it may still use. */
interface DrainRun { failed: Set<string>; left: Set<string>; splits: number }

const outboxId = (table: string, id: string) => `${table}|${id}`

// The Workers runtime's words for a run that has used its subrequests. The Neon driver quotes them in its own error.
const SUBREQUEST_LIMIT = /too many (?:subrequests|api requests)/i
const isSubrequestLimit = (err: unknown): boolean => SUBREQUEST_LIMIT.test(`${String(err)} ${String((err as { cause?: unknown } | null)?.cause ?? '')}`)

/**
 * Runs `attempt` on all the items as one request. A failure splits them in two, so one poison row
 * cannot sink the others. Only an item that fails alone is counted as bad. Once the budget is spent,
 * or the Worker reports its subrequest limit (which says nothing about the rows), what was not
 * tried is left for the next drain with nothing counted against it.
 */
async function trySplitting<T>(run: DrainRun, items: T[], idOf: (item: T) => string, what: string, attempt: (part: T[]) => Promise<void>, isSplit = false): Promise<void> {
  if (items.length === 0) return
  const leave = () => { for (const item of items) run.left.add(idOf(item)) }
  if (isSplit) {
    if (run.splits < 1) return leave()
    run.splits--
  }
  try {
    await attempt(items)
  } catch (err) {
    if (isSubrequestLimit(err)) {
      console.warn(`[kg] subrequest limit reached during ${what}: ${items.length} row(s) left for the next drain`)
      run.splits = 0
      return leave()
    }
    if (items.length === 1) {
      console.error(`[kg] ${what} of ${idOf(items[0]!)} failed (attempt counted):`, err)
      run.failed.add(idOf(items[0]!))
      return
    }
    const mid = Math.floor(items.length / 2)
    await trySplitting(run, items.slice(0, mid), idOf, what, attempt, true)
    await trySplitting(run, items.slice(mid), idOf, what, attempt, true)
  }
}

/** Reads every changed row in one request and turns each into its graph delta. */
async function readDeltas(q: Q, byTable: Map<string, string[]>, tenants: Set<string>, run: DrainRun): Promise<{ deltas: RowDelta[]; blocked: number }> {
  const deltas: RowDelta[] = []
  let blocked = 0
  const toDeltas = (table: string, ids: string[], rows: Row[]) => {
    const source = SOURCES[table]!
    const gone = new Set(ids)
    for (const r of rows) {
      const id = String(r[source.pk])
      let delta: ReturnType<typeof safeDelta>
      try {
        delta = safeDelta(source.extract(r))
      } catch (err) {
        // The row exists, so it must not read as deleted. It fails alone and the rest carry on.
        console.error(`[kg] extract of ${outboxId(table, id)} failed (attempt counted):`, err)
        gone.delete(id)
        run.failed.add(outboxId(table, id))
        continue
      }
      blocked += delta.blocked
      const first = delta.nodes[0]
      if (!first) continue
      gone.delete(id)
      deltas.push({ table, id, nodes: delta.nodes, edges: delta.edges, owner: first.key, goneKey: null })
      for (const n of delta.nodes) if (n.tenantId) tenants.add(n.tenantId)
    }
    for (const id of gone) deltas.push({ table, id, nodes: [], edges: [], owner: null, goneKey: `${source.prefix}:${id}` })
  }
  const rows = [...byTable].filter(([t]) => SOURCES[t]).flatMap(([table, ids]) => ids.map(id => ({ table, id })))
  await trySplitting(run, rows, r => outboxId(r.table, r.id), 'read', async part => {
    const tables = new Map<string, string[]>()
    for (const { table, id } of part) tables.set(table, [...(tables.get(table) ?? []), id])
    const entries = [...tables]
    const results = await runBatch(q, entries.map(([t, ids]) => ({ text: SOURCES[t]!.sql, params: [ids] })))
    // Checked before any row is used, so a short answer cannot make the missing rows read as deleted.
    if (results.length !== entries.length) throw new Error('the read batch returned too few results')
    entries.forEach(([table, ids], i) => toDeltas(table, ids, results[i] ?? []))
  })
  return { deltas, blocked }
}

/** One write for a set of rows. A failure splits the set in two, so one poison row cannot sink the others. */
async function writeDeltas(q: Q, deltas: RowDelta[], vectors: Map<string, string>, run: DrainRun): Promise<void> {
  await trySplitting(run, deltas, d => outboxId(d.table, d.id), 'write', async part => {
    const nodes = nodesStatement(part.flatMap(d => d.nodes), vectors)
    const owners = part.flatMap(d => (d.owner ? [d.owner] : []))
    const goneKeys = part.flatMap(d => (d.goneKey ? [d.goneKey] : []))
    await runBatch(q, [...(nodes ? [nodes] : []), ...edgesStatements(owners, part.flatMap(d => d.edges)), ...deleteStatements(goneKeys)])
  })
}

/**
 * Applies up to `limit` outstanding changes to the graph. With a tenant, only that company's rows
 * are claimed and `remaining` counts its rows plus rows whose company is not yet known, so a
 * "still catching up" note errs on the cautious side. Without one it is global (queue job, cron).
 */
export async function drainOutbox(q: Q, env: Env, limit = 500, tenantId?: string, requests = DRAIN_REQUESTS): Promise<DrainResult> {
  const scope = tenantId ?? null
  const claimed = await q(`
    UPDATE kg_outbox o SET claimed_until = now() + interval '${CLAIM_SECONDS} seconds', attempts = o.attempts + 1
    FROM (SELECT table_name, row_pk FROM kg_outbox
          WHERE (claimed_until IS NULL OR claimed_until < now()) AND attempts < ${MAX_ATTEMPTS}
            AND ($2::uuid IS NULL OR tenant_id = $2::uuid)
          ORDER BY changed_at LIMIT $1 FOR UPDATE SKIP LOCKED) c
    WHERE o.table_name = c.table_name AND o.row_pk = c.row_pk
    RETURNING o.table_name, o.row_pk, o.tenant_id, o.changed_at::text AS changed_at`, [limit, scope])

  const tenants = new Set<string>()
  let blocked = 0
  const run: DrainRun = { failed: new Set(), left: new Set(), splits: Math.max(0, requests - DRAIN_BASE_REQUESTS) }
  if (claimed.length > 0) {
    const byTable = new Map<string, string[]>()
    for (const c of claimed) {
      byTable.set(c.table_name, [...(byTable.get(c.table_name) ?? []), c.row_pk])
      if (c.tenant_id) tenants.add(String(c.tenant_id))
    }

    // The rows' companies and the deleted rows' companies are all known before anything is written.
    const { deltas, blocked: b } = await readDeltas(q, byTable, tenants, run)
    blocked += b
    const goneKeys = deltas.flatMap(d => (d.goneKey ? [d.goneKey] : []))
    if (goneKeys.length > 0) {
      for (const t of await q(`SELECT DISTINCT tenant_id FROM kg_nodes WHERE key = ANY($1::text[]) AND tenant_id IS NOT NULL`, [goneKeys])) {
        if (t.tenant_id) tenants.add(String(t.tenant_id))
      }
    }
    const nodes = deltas.flatMap(d => d.nodes)
    await writeDeltas(q, deltas, await embedChanged(q, env, nodes), run)
  }

  // Only entries unchanged since the claim: a newer change stays queued. A failed row stays too,
  // claimed, and is tried again when the claim expires, until it is set aside.
  const idOf = (c: Row) => outboxId(c.table_name, c.row_pk)
  const done = claimed.filter(c => !run.failed.has(idOf(c)) && !run.left.has(idOf(c)))
  const finish: Stmt[] = done.length > 0
    ? [{
        text: `
        DELETE FROM kg_outbox o USING unnest($1::text[], $2::text[], $3::timestamptz[]) AS d(table_name, row_pk, changed_at)
        WHERE o.table_name = d.table_name AND o.row_pk = d.row_pk AND o.changed_at = d.changed_at`,
        params: [done.map(c => c.table_name), done.map(c => c.row_pk), done.map(c => c.changed_at)],
      }]
    : []
  // Rows this drain did not get to go back as they were: free to claim, and their attempt returned,
  // so healthy rows behind many poison rows are never set aside. A newer change has already reset them.
  const waiting = claimed.filter(c => run.left.has(idOf(c)))
  if (waiting.length > 0) {
    finish.push({
      text: `
      UPDATE kg_outbox o SET claimed_until = NULL, attempts = GREATEST(o.attempts - 1, 0)
      FROM unnest($1::text[], $2::text[], $3::timestamptz[]) AS d(table_name, row_pk, changed_at)
      WHERE o.table_name = d.table_name AND o.row_pk = d.row_pk AND o.changed_at = d.changed_at`,
      params: [waiting.map(c => c.table_name), waiting.map(c => c.row_pk), waiting.map(c => c.changed_at)],
    })
  }
  finish.push({
    text: `
    SELECT count(*) FILTER (WHERE (claimed_until IS NULL OR claimed_until < now()) AND attempts < ${MAX_ATTEMPTS})::int AS n,
           count(*) FILTER (WHERE attempts >= ${MAX_ATTEMPTS})::int AS quarantined
    FROM kg_outbox WHERE $1::uuid IS NULL OR tenant_id = $1::uuid OR tenant_id IS NULL`,
    params: [scope],
  })
  const finished = await runBatch(q, finish)
  const left = finished[finished.length - 1]?.[0]
  const quarantined = Number(left?.quarantined ?? 0)
  if (quarantined > 0) console.warn(`[kg] ${quarantined} outbox row(s) set aside after ${MAX_ATTEMPTS} failed attempts`)
  return { processed: done.length, remaining: Number(left?.n ?? 0), blocked, quarantined, tenants: [...tenants] }
}

// A refresh is about four requests; a drain about ten; a run has 50 subrequests in all.
const MAX_REFRESH_PER_JOB = 6

const SIGNAL_KEY = 'kg:sync:signal'
const SIGNAL_TTL = 120

/** Whether a finished API request may have changed graph tables. Heartbeats, chat and sign-in write none. */
export function shouldSignalKg(method: string, path: string, status: number): boolean {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) || status >= 400) return false
  return !/\/heartbeat$/.test(path) && !/\/chatbot(\/|$)/.test(path) && !/\/auth(\/|$)/.test(path)
}

/** Asks for a sync soon. Many writes in a row send one message. */
export async function signalKgSync(env: Env): Promise<void> {
  if (await env.KV_CACHE.get(SIGNAL_KEY)) return
  await env.KV_CACHE.put(SIGNAL_KEY, '1', { expirationTtl: SIGNAL_TTL })
  await env.ADVISORY_QUEUE.send({ type: 'kg_sync' }, { delaySeconds: 30 })
}

/** Why a job is running. A cron run sets neither flag: it finds what is left and schedules no sweep of its own. */
export interface KgSyncFlags { signalled?: boolean; owesSweep?: boolean }

/** What the kg_sync messages of a queue batch ask for. A message with no followUp flag came from a signal. */
export function kgSyncFlags(bodies: unknown[]): KgSyncFlags {
  const messages = bodies as Array<{ followUp?: boolean; owesSweep?: boolean } | null>
  return { signalled: messages.some(m => !m?.followUp), owesSweep: messages.some(m => !!m?.owesSweep) }
}

/** One queue job: drain, refresh the companies it touched, and carry on while it is making progress. */
export async function runKgSync(q: Q, env: Env, refresh: (tenantId: string) => Promise<void>, flags: KgSyncFlags = {}): Promise<void> {
  const r = await drainOutbox(q, env)
  if (r.blocked) console.warn(`[kg] ${r.blocked} node(s) blocked by the secret check`)
  // Every drain refreshes the companies it touched, up to what one Worker run can afford. A company
  // past the cap is recovered the next time its chat runs (refreshIfStale). The cron cannot recover
  // it, because the company's rows have already left the outbox.
  const refreshing = r.tenants.slice(0, MAX_REFRESH_PER_JOB)
  if (r.tenants.length > MAX_REFRESH_PER_JOB) console.warn(`[kg] ${r.tenants.length - MAX_REFRESH_PER_JOB} company(ies) not refreshed this round`)
  for (const t of refreshing) {
    try { await refresh(t) } catch (err) { console.error(`[kg] refresh of ${t} failed:`, err) }
  }
  const filled = r.remaining === 0 ? await backfillEmbeddings(q, env) : 0
  // Requeue only when progress was made: a drain that applied nothing (all claimed by others, or
  // failing) waits for the cron instead of spinning. A failed embedding fills nothing, so an outage cannot loop.
  const owesSweep = !!flags.signalled || !!flags.owesSweep || r.processed > 0
  if ((r.remaining > 0 && r.processed > 0) || filled > 0) await env.ADVISORY_QUEUE.send({ type: 'kg_sync', followUp: true, ...(owesSweep ? { owesSweep } : {}) }, { delaySeconds: 1 })
  // Writes during the signal's debounce window send no signal of their own, so a finished drain looks
  // once more after that window. It stops by itself: a sweep that applies nothing schedules nothing.
  else if (owesSweep) await env.ADVISORY_QUEUE.send({ type: 'kg_sync', followUp: true }, { delaySeconds: SIGNAL_TTL + 5 })
  console.log(`[kg_sync] processed ${r.processed}, remaining ${r.remaining}, quarantined ${r.quarantined}, embedded ${filled}`)
}

/** The job as the queue and the cron run it: own connection, problems refreshed per changed company. */
export async function runKgSyncJob(env: Env, flags: KgSyncFlags = {}): Promise<void> {
  const q = kgQuery(env)
  await runKgSync(q, env, tenantId => refreshProblems(q, env, tenantId), flags)
}

/**
 * Runs the job once for all the kg_sync messages of a queue batch. A batch is one Worker run, so
 * separate jobs would share its 50 subrequests, and one drain already covers what they ask for.
 */
export async function handleKgSyncMessages(
  env: Env,
  messages: Array<{ body: unknown; ack: () => void; retry: () => void }>,
  run: (env: Env, flags: KgSyncFlags) => Promise<void> = runKgSyncJob,
): Promise<void> {
  if (messages.length === 0) return
  const start = Date.now()
  try {
    await run(env, kgSyncFlags(messages.map(m => m.body)))
    recordJob(env, 'kg_sync', Date.now() - start, true)
    for (const m of messages) m.ack()
  } catch (err) {
    recordJob(env, 'kg_sync', Date.now() - start, false)
    console.error('Queue job failed:', err)
    for (const m of messages) m.retry()
  }
}

/** Signals after work that wrote graph tables. A failed signal is logged, never thrown. */
export async function signalKgSyncSafe(env: Env): Promise<void> {
  try { await signalKgSync(env) } catch (err) { console.error('[kg] signal failed:', err) }
}
