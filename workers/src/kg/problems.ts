/**
 * kg/problems.ts — loads one company's facts from the graph, runs the rules, and stores the
 * problem nodes and the company status node. Agents are read live, because heartbeats are
 * deliberately not sent through the outbox.
 */
import type { Env } from '../types'
import { evaluateRules, ALERT_AGE_DAYS, type AgentFact, type AlertFact, type AssetFact, type Problem, type ScanFact } from './rules'
import { deleteNodes, replaceEdges, upsertNodes, type Q } from './store'
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
  const [assets, sboms, advisories, aging, agingCount, agents, scans, posture, status] = await Promise.all([
    q(`SELECT key, title, props FROM kg_nodes WHERE tenant_id = $1 AND type = 'asset'`, [tenantId]),
    q(`SELECT DISTINCT to_key FROM kg_edges WHERE tenant_id = $1 AND relation = 'SBOM_OF'`, [tenantId]),
    q(`SELECT key, props FROM kg_nodes WHERE tenant_id = $1 AND type = 'advisory' AND props @> '{"active":true}'`, [tenantId]),
    q(`SELECT key, title, props FROM kg_nodes WHERE tenant_id = $1 AND type = 'event' AND props @> '{"open":true}'
        AND props ->> 'severity' IN ('high','critical') AND props ->> 'timestamp' < $2 ORDER BY props ->> 'timestamp' LIMIT 50`, [tenantId, cutoff]),
    q(`SELECT count(*)::int AS n FROM kg_nodes WHERE tenant_id = $1 AND type = 'event' AND props @> '{"open":true}'
        AND props ->> 'severity' IN ('high','critical') AND props ->> 'timestamp' < $2`, [tenantId, cutoff]),
    q(`SELECT agent_id, name, status, last_heartbeat, retired_at FROM agents WHERE tenant_id = $1`, [tenantId]),
    q(`SELECT key, props FROM kg_nodes WHERE tenant_id = $1 AND type = 'scan' ORDER BY props ->> 'startedAt' DESC LIMIT 200`, [tenantId]),
    q(`SELECT props FROM kg_nodes WHERE key = $1`, [`posture:${tenantId}`]),
    q(`SELECT
        count(*) FILTER (WHERE type = 'asset')::int AS assets,
        count(*) FILTER (WHERE type = 'asset' AND props @> '{"inMyAssets":true}')::int AS my_assets,
        count(*) FILTER (WHERE type = 'event' AND props @> '{"open":true,"severity":"critical"}')::int AS critical,
        count(*) FILTER (WHERE type = 'advisory' AND props @> '{"active":true}')::int AS advisories
      FROM kg_nodes WHERE tenant_id = $1`, [tenantId]),
  ])
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

  const old = await q(`SELECT key FROM kg_nodes WHERE tenant_id = $1 AND type = 'problem'`, [tenantId])
  const current = new Set(nodes.map(n => n.key))
  await deleteNodes(q, old.map(o => o.key as string).filter(k => !current.has(k)))
  await upsertNodes(q, env, nodes)
  await replaceEdges(q, problems.map(p => `problem:${tenantId}:${p.id}`), edges)
  // A CVE no alert points at any more was fixed or closed out of existence.
  await q(`DELETE FROM kg_nodes n WHERE n.tenant_id = $1 AND n.type = 'cve' AND NOT EXISTS (SELECT 1 FROM kg_edges e WHERE e.to_key = n.key)`, [tenantId])
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
