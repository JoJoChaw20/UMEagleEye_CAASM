/**
 * Agent coverage and endpoint posture across a tenant — PURE (no DB).
 *
 * Only machines with an agent have a posture, so every aggregate says how many
 * assets it covers (fairness rule 4): "posture 78 across 12 assessed; 57 unassessed".
 * Unassessed is its own state and never averaged in as good (rule 1). Servers and
 * workstations are the assets an agent can run on; network and IoT devices are
 * reported as "not applicable", unidentified devices separately (their type is not
 * known yet, so whether an agent could run there is not known either).
 * Tested by scripts/scoring-v2-demo.ts.
 */

export interface CoverageAsset {
  asset_id: string
  hostname: string | null
  ip: string
  device_type: string
  criticality: number
  inventory_at: string | Date | null
  posture_score: number | null
  posture_checks: unknown
}

interface Check { id: string; label: string; state: string }
const AGENT_TYPES = new Set(['server', 'workstation'])
const brief = (a: CoverageAsset) => ({ asset_id: a.asset_id, hostname: a.hostname, ip: a.ip, device_type: a.device_type })

export function summarizeCoverage(rows: CoverageAsset[]) {
  const capable = rows.filter(a => AGENT_TYPES.has(a.device_type))
  const withAgent = rows.filter(a => a.inventory_at != null)
  const noAgent = capable.filter(a => a.inventory_at == null)
    .sort((x, y) => y.criticality - x.criticality)
  const assessed = rows.filter(a => a.posture_score != null)
  // Unassessed = servers/PCs without a posture (no agent, or too few checks readable),
  // plus any other asset that has an agent but no posture.
  const unassessed = rows.filter(a => a.posture_score == null && (AGENT_TYPES.has(a.device_type) || a.inventory_at != null))

  // Failed and to-review checks across assessed machines.
  const byCheck = new Map<string, { id: string; label: string; bad: number; warn: number; assets: ReturnType<typeof brief>[] }>()
  for (const a of rows) {
    if (!Array.isArray(a.posture_checks)) continue
    for (const c of a.posture_checks as Check[]) {
      if (c.state !== 'bad' && c.state !== 'warn') continue
      const e = byCheck.get(c.id) ?? { id: c.id, label: c.label, bad: 0, warn: 0, assets: [] }
      if (c.state === 'bad') e.bad++; else e.warn++
      if (e.assets.length < 5) e.assets.push(brief(a))
      byCheck.set(c.id, e)
    }
  }
  const failing = [...byCheck.values()].sort((x, y) => (y.bad - x.bad) || (y.warn - x.warn))

  const avg = assessed.length
    ? Math.round(assessed.reduce((n, a) => n + (a.posture_score ?? 0), 0) / assessed.length)
    : null

  return {
    total_assets: rows.length,
    agent_capable: capable.length,
    with_agent: withAgent.length,
    not_applicable: rows.filter(a => a.device_type === 'network' || a.device_type === 'iot').length,
    unidentified: rows.filter(a => a.device_type === 'unknown' && a.inventory_at == null).length,
    no_agent: { count: noAgent.length, items: noAgent.slice(0, 8).map(a => ({ ...brief(a), criticality: a.criticality })) },
    posture: {
      assessed: assessed.length,
      unassessed: unassessed.length,
      average: avg,
      lowest: [...assessed].sort((x, y) => (x.posture_score ?? 0) - (y.posture_score ?? 0)).slice(0, 5)
        .map(a => ({ ...brief(a), posture_score: a.posture_score })),
      failing,
      machines_with_failures: rows.filter(a => Array.isArray(a.posture_checks) && (a.posture_checks as Check[]).some(c => c.state === 'bad')).length,
    },
  }
}
