/**
 * kg/problems.ts — loads one company's facts from the graph, runs the rules, and stores the
 * problem nodes and the company status node. Agents are read live, because heartbeats are
 * deliberately not sent through the outbox.
 */
import type { Env } from '../types'
import { evaluateRules, evaluatePlatformRules, PLATFORM_RULES, ALERT_AGE_DAYS, type AgentFact, type AlertFact, type AssetFact, type FeedFact, type Problem, type ScanFact } from './rules'
import type { PerfWindow } from './perf'
import { LAST_INGEST_KEY, type LastIngest } from '../services/cti'
import { deleteStatements, edgesStatements, embedChanged, nodesStatement, runBatch, type Q, type Stmt } from './store'
import { MAX_ATTEMPTS } from './sync'
import type { KgEdge, KgNode, Row } from './extract'

function problemNode(tenantId: string, p: Problem): KgNode {
  return {
    key: `problem:${tenantId}:${p.id}`, tenantId, visibility: 'company', roleGroup: 'analyst', type: 'problem',
    title: p.title, body: `Problem (${p.severity}): ${p.title}. ${p.detail} Recommended solution: ${p.solution}`,
    props: { rule: p.rule, rank: p.rank, severity: p.severity, count: p.count, solution: p.solution },
  }
}

export async function refreshProblems(q: Q, env: Env, tenantId: string, now = new Date()): Promise<void> {
  const cutoff = new Date(now.getTime() - ALERT_AGE_DAYS * 86_400_000).toISOString()
  // Every read in one request: a Worker on the free plan cannot afford one round trip per read.
  const reads: Stmt[] = [
    { text: `SELECT key, title, props FROM kg_nodes WHERE tenant_id = $1 AND type = 'asset'`, params: [tenantId] },
    { text: `SELECT DISTINCT to_key FROM kg_edges WHERE tenant_id = $1 AND relation = 'SBOM_OF'`, params: [tenantId] },
    { text: `SELECT key, props FROM kg_nodes WHERE tenant_id = $1 AND type = 'advisory' AND props @> '{"active":true}'`, params: [tenantId] },
    { text: `SELECT key, title, props FROM kg_nodes WHERE tenant_id = $1 AND type = 'event' AND props @> '{"open":true}'
        AND props ->> 'severity' IN ('high','critical') AND props ->> 'timestamp' < $2 ORDER BY props ->> 'timestamp' LIMIT 50`, params: [tenantId, cutoff] },
    { text: `SELECT count(*)::int AS n FROM kg_nodes WHERE tenant_id = $1 AND type = 'event' AND props @> '{"open":true}'
        AND props ->> 'severity' IN ('high','critical') AND props ->> 'timestamp' < $2`, params: [tenantId, cutoff] },
    { text: `SELECT agent_id, name, status, last_heartbeat, retired_at FROM agents WHERE tenant_id = $1`, params: [tenantId] },
    { text: `SELECT key, props FROM kg_nodes WHERE tenant_id = $1 AND type = 'scan' ORDER BY props ->> 'startedAt' DESC LIMIT 200`, params: [tenantId] },
    { text: `SELECT props FROM kg_nodes WHERE key = $1`, params: [`posture:${tenantId}`] },
    { text: `SELECT
        count(*) FILTER (WHERE type = 'asset')::int AS assets,
        count(*) FILTER (WHERE type = 'asset' AND props @> '{"inMyAssets":true}')::int AS my_assets,
        count(*) FILTER (WHERE type = 'event' AND props @> '{"open":true,"severity":"critical"}')::int AS critical,
        count(*) FILTER (WHERE type = 'advisory' AND props @> '{"active":true}')::int AS advisories
      FROM kg_nodes WHERE tenant_id = $1`, params: [tenantId] },
    { text: `SELECT key FROM kg_nodes WHERE tenant_id = $1 AND type = 'problem'`, params: [tenantId] },
  ]
  const [assets = [], sboms = [], advisories = [], aging = [], agingCount = [], agents = [], scans = [], posture = [], status = [], old = []] = await runBatch(q, reads)
  const covered = new Set(sboms.map(s => s.to_key as string))
  const problems = evaluateRules({
    assets: assets.map((a: Row): AssetFact => ({
      key: a.key, title: a.title, criticality: Number(a.props.criticality ?? 0), internetFacing: Boolean(a.props.internetFacing),
      inMyAssets: Boolean(a.props.inMyAssets), ports: (a.props.ports ?? []) as number[], hasSbom: covered.has(a.key),
    })),
    advisories: advisories.map((a: Row) => ({ key: a.key, assetKey: a.props.assetKey, severity: a.props.severity })),
    agingAlerts: aging.map((a: Row): AlertFact => ({ key: a.key, title: a.title, severity: a.props.severity, timestamp: a.props.timestamp })),
    agingTotal: Number(agingCount[0]?.n ?? 0),
    agents: agents.map((a: Row): AgentFact => ({
      key: `agent:${a.agent_id}`, name: a.name, status: a.status,
      lastHeartbeat: a.last_heartbeat ? new Date(a.last_heartbeat).toISOString() : null, retired: a.retired_at != null,
    })),
    scans: scans.map((s: Row): ScanFact => ({ key: s.key, agentKey: s.props.agentKey ?? null, status: s.props.status, startedAt: s.props.startedAt })),
    postureMeasuredAt: (posture[0]?.props?.measuredAt as string | undefined) ?? null,
  }, now)

  // The count query always returns one row; an empty result reads as an empty company.
  const s = status[0] ?? { assets: 0, my_assets: 0, critical: 0, advisories: 0 }
  const score = posture[0]?.props?.score
  const nodes: KgNode[] = problems.map(p => problemNode(tenantId, p))
  nodes.push({
    key: `status:${tenantId}`, tenantId, visibility: 'company', roleGroup: 'all', type: 'status', title: 'Company status',
    body: `Company status: ${s.assets} total assets, ${s.my_assets} in My Assets, ${s.critical} open critical alerts, ${s.advisories} open advisories${score != null ? `, security score ${score} out of 100` : ', security score not yet measured'}.`,
    props: { totalAssets: s.assets, myAssets: s.my_assets, openCritical: s.critical, openAdvisories: s.advisories, score: score ?? null, refreshedAt: now.toISOString() },
  })
  const edges: KgEdge[] = problems.flatMap(p => p.evidence.map(e => ({ from: `problem:${tenantId}:${p.id}`, to: e, relation: 'EVIDENCE', tenantId })))

  const current = new Set(nodes.map(n => n.key))
  const stale = old.map(o => o.key as string).filter(k => !current.has(k))
  const nodeWrite = nodesStatement(nodes, await embedChanged(q, env, nodes))
  // Every write in one request too. A CVE or indicator no alert points at any more was fixed, closed,
  // or made private by its owner.
  await runBatch(q, [
    ...deleteStatements(stale),
    ...(nodeWrite ? [nodeWrite] : []),
    ...edgesStatements(problems.map(p => `problem:${tenantId}:${p.id}`), edges),
    { text: `DELETE FROM kg_nodes n WHERE n.tenant_id = $1 AND n.type IN ('cve', 'indicator') AND NOT EXISTS (SELECT 1 FROM kg_edges e WHERE e.to_key = n.key)`, params: [tenantId] },
  ])
}

const STATUS_MAX_AGE_MS = 5 * 60_000

/** Recomputes a company's problems when the sync touched it or they are old. */
export async function refreshIfStale(q: Q, env: Env, tenantId: string, touched: boolean): Promise<void> {
  if (!touched) {
    const [row] = await q(`SELECT updated_at FROM kg_nodes WHERE key = $1`, [`status:${tenantId}`])
    if (row && Date.now() - new Date(row.updated_at).getTime() < STATUS_MAX_AGE_MS) return
  }
  await refreshProblems(q, env, tenantId)
}

// ── Platform problems: UMEagleEye's own speed, feeds and graph sync (superadmin only) ──

const PLATFORM_WINDOW_HOURS = 24

function platformProblemNode(p: Problem): KgNode {
  return {
    key: `problem:platform:${p.id}`, tenantId: null, visibility: 'platform', roleGroup: 'analyst', type: 'problem',
    title: p.title, body: `Platform problem (${p.severity}): ${p.title}. ${p.detail} Recommended solution: ${p.solution}`,
    props: { rule: p.rule, rank: p.rank, severity: p.severity, count: p.count, solution: p.solution },
  }
}

/**
 * Computes the platform problems (shared layer, `platform` visibility, no tenant) and removes the
 * ones no longer true. Only problems of the rules in PLATFORM_RULES are replaced, so other shared
 * problems (code hotspots) are left alone.
 */
export async function refreshPlatformProblems(q: Q, env: Env, now = new Date()): Promise<void> {
  const since = new Date(now.getTime() - PLATFORM_WINDOW_HOURS * 3_600_000).toISOString()
  // Every read in one request and every write in one more: a chat about speed runs this before it
  // answers, inside the same subrequest budget as its lookups (agent.ts CHAT_SUBREQUESTS).
  const [windows = [], outbox = [], old = []] = await runBatch(q, [
    { text: `SELECT props FROM kg_nodes WHERE tenant_id IS NULL AND type = 'performance_window' AND props ->> 'start' > $1 ORDER BY props ->> 'start'`, params: [since] },
    // A stuck row is one the drain has set aside: it failed MAX_ATTEMPTS claims, and no drain claims it
    // again until a new change to the same source row resets its attempts.
    { text: `SELECT count(*)::int AS n, min(changed_at) AS oldest, count(*) FILTER (WHERE attempts >= ${MAX_ATTEMPTS})::int AS stuck FROM kg_outbox` },
    { text: `SELECT key FROM kg_nodes WHERE tenant_id IS NULL AND type = 'problem' AND props ->> 'rule' = ANY($1::text[])`, params: [[...PLATFORM_RULES]] },
  ])
  let feeds: FeedFact[] = []
  try {
    const last = await env.KV_CACHE.get<LastIngest>(LAST_INGEST_KEY, 'json')
    feeds = Object.entries(last?.feeds ?? {}).map(([source, f]) => ({ source, ok: f.ok, lastOkAt: f.last_ok_at ?? null }))
  } catch (err) {
    console.error('[kg] feed record unreadable:', err instanceof Error ? err.message : err)
  }
  const o = outbox[0]
  const problems = evaluatePlatformRules({
    windows: windows.map(w => w.props as PerfWindow),
    feeds,
    outbox: o ? { count: Number(o.n ?? 0), oldestAt: o.oldest ? new Date(o.oldest).toISOString() : null, stuck: Number(o.stuck ?? 0) } : null,
  }, now)

  const nodes = problems.map(platformProblemNode)
  const owners = nodes.map(n => n.key)
  const edges: KgEdge[] = problems.flatMap(p => p.evidence.map(e => ({ from: `problem:platform:${p.id}`, to: e, relation: 'EVIDENCE', tenantId: null })))
  const current = new Set(owners)
  const nodeWrite = nodesStatement(nodes, await embedChanged(q, env, nodes))
  await runBatch(q, [
    ...deleteStatements(old.map(r => String(r.key)).filter(k => !current.has(k))),
    ...(nodeWrite ? [nodeWrite] : []),
    ...edgesStatements(owners, edges),
  ])
}
