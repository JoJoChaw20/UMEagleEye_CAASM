/**
 * kg/sync.ts — keeps the graph in step with the source tables.
 *
 * Triggers (migration 0029) list every changed row in kg_outbox. Nothing polls it: a write
 * sends one debounced queue message (signalKgSync), the chatbot applies what is outstanding
 * before it answers, and the existing 6-hourly cron drains anything left. Rows are claimed for
 * 90 seconds so concurrent drains split the work, and a drain that dies leaves them to the next.
 */
import type { Env } from '../types'
import {
  extractAddress, extractAdvisory, extractAgent, extractAsset, extractDependency, extractEvent, extractIdentifier,
  extractLink, extractPosture, extractRelationship, extractSbom, extractScan, extractSoftware, extractTiEvent,
  extractTopology, safeDelta, type GraphDelta, type Row,
} from './extract'
import { backfillEmbeddings, deleteNodes, kgQuery, replaceEdges, upsertNodes, type Q } from './store'
import { refreshProblems } from './problems'

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

/** Reads, extracts and writes one table's rows. Returns how many nodes the secret check blocked. */
async function applyTable(q: Q, env: Env, source: Source, ids: string[], tenants: Set<string>): Promise<number> {
  const rows = await q(source.sql, [ids])
  const nodes: GraphDelta['nodes'] = [], edges: GraphDelta['edges'] = [], owners: string[] = [], gone = new Set(ids)
  let blocked = 0
  for (const r of rows) {
    const delta = safeDelta(source.extract(r))
    blocked += delta.blocked
    const first = delta.nodes[0]
    if (!first) continue
    gone.delete(String(r[source.pk]))
    nodes.push(...delta.nodes)
    edges.push(...delta.edges)
    owners.push(first.key)
    for (const n of delta.nodes) if (n.tenantId) tenants.add(n.tenantId)
  }
  const goneKeys = [...gone].map(id => `${source.prefix}:${id}`)
  if (goneKeys.length > 0) {
    // A deleted row's company still needs its status and problems recomputed.
    for (const t of await q(`SELECT DISTINCT tenant_id FROM kg_nodes WHERE key = ANY($1::text[]) AND tenant_id IS NOT NULL`, [goneKeys])) {
      if (t.tenant_id) tenants.add(String(t.tenant_id))
    }
  }
  await upsertNodes(q, env, nodes)
  await replaceEdges(q, owners, edges)
  await deleteNodes(q, goneKeys)
  return blocked
}

/**
 * Applies up to `limit` outstanding changes to the graph. With a tenant, only that company's rows
 * are claimed and `remaining` counts its rows plus rows whose company is not yet known, so a
 * "still catching up" note errs on the cautious side. Without one it is global (queue job, cron).
 */
export async function drainOutbox(q: Q, env: Env, limit = 500, tenantId?: string): Promise<DrainResult> {
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
  const failed = new Set<string>()
  if (claimed.length > 0) {
    const byTable = new Map<string, string[]>()
    for (const c of claimed) {
      byTable.set(c.table_name, [...(byTable.get(c.table_name) ?? []), c.row_pk])
      if (c.tenant_id) tenants.add(String(c.tenant_id))
    }

    for (const [table, ids] of byTable) {
      const source = SOURCES[table]
      if (!source) continue
      try {
        blocked += await applyTable(q, env, source, ids, tenants)
      } catch (err) {
        // One bad row must not hold back the others: retry the table's rows one at a time.
        console.error(`[kg] ${table} batch failed, applying rows one by one:`, err)
        for (const id of ids) {
          try { blocked += await applyTable(q, env, source, [id], tenants) } catch (e) {
            console.error(`[kg] ${table} ${id} failed (attempt counted):`, e)
            failed.add(`${table}|${id}`)
          }
        }
      }
    }

    // Only entries unchanged since the claim: a newer change stays queued. A failed row stays too,
    // claimed, and is tried again when the claim expires, until it is set aside.
    const done = claimed.filter(c => !failed.has(`${c.table_name}|${c.row_pk}`))
    if (done.length > 0) {
      await q(`
        DELETE FROM kg_outbox o USING unnest($1::text[], $2::text[], $3::timestamptz[]) AS d(table_name, row_pk, changed_at)
        WHERE o.table_name = d.table_name AND o.row_pk = d.row_pk AND o.changed_at = d.changed_at`,
      [done.map(c => c.table_name), done.map(c => c.row_pk), done.map(c => c.changed_at)])
    }
  }
  const [left] = await q(`
    SELECT count(*) FILTER (WHERE (claimed_until IS NULL OR claimed_until < now()) AND attempts < ${MAX_ATTEMPTS})::int AS n,
           count(*) FILTER (WHERE attempts >= ${MAX_ATTEMPTS})::int AS quarantined
    FROM kg_outbox WHERE $1::uuid IS NULL OR tenant_id = $1::uuid OR tenant_id IS NULL`, [scope])
  const quarantined = Number(left?.quarantined ?? 0)
  if (quarantined > 0) console.warn(`[kg] ${quarantined} outbox row(s) set aside after ${MAX_ATTEMPTS} failed attempts`)
  return { processed: claimed.length - failed.size, remaining: Number(left?.n ?? 0), blocked, quarantined, tenants: [...tenants] }
}

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

/** One queue job: drain, refresh the companies it touched, and carry on while it is making progress. */
export async function runKgSync(q: Q, env: Env, refresh: (tenantId: string) => Promise<void>): Promise<void> {
  const r = await drainOutbox(q, env)
  if (r.blocked) console.warn(`[kg] ${r.blocked} node(s) blocked by the secret check`)
  // Every drain refreshes the companies it touched, so none is lost between batches.
  for (const t of r.tenants) {
    try { await refresh(t) } catch (err) { console.error(`[kg] refresh of ${t} failed:`, err) }
  }
  const filled = r.remaining === 0 ? await backfillEmbeddings(q, env) : 0
  // Requeue only when progress was made: a drain that applied nothing (all claimed by others, or
  // failing) waits for the cron instead of spinning. A failed embedding fills nothing, so an outage cannot loop.
  if ((r.remaining > 0 && r.processed > 0) || filled > 0) await env.ADVISORY_QUEUE.send({ type: 'kg_sync' }, { delaySeconds: 1 })
  console.log(`[kg_sync] processed ${r.processed}, remaining ${r.remaining}, quarantined ${r.quarantined}, embedded ${filled}`)
}

/** The job as the queue and the cron run it: own connection, problems refreshed per changed company. */
export async function runKgSyncJob(env: Env): Promise<void> {
  const q = kgQuery(env)
  await runKgSync(q, env, tenantId => refreshProblems(q, env, tenantId))
}

/** Signals after work that wrote graph tables. A failed signal is logged, never thrown. */
export async function signalKgSyncSafe(env: Env): Promise<void> {
  try { await signalKgSync(env) } catch (err) { console.error('[kg] signal failed:', err) }
}
