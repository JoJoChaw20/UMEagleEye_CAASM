/**
 * SBOM coverage: the state of each computer on the SBOM page. PURE (no DB); tested by
 * scripts/pages-redesign-demo.ts.
 *
 * A computer is an asset with an agent bound to it (agents.host_asset_id) or an asset
 * that has an SBOM. The agent builds one every day, so an SBOM older than STALE_HOURS
 * means the daily run has not been arriving.
 */

export const SBOM_STALE_HOURS = 48

export type ComputerState = 'running' | 'queued' | 'failed' | 'none' | 'stale' | 'ok'

export interface ComputerFacts {
  /** When the current SBOM was generated; null when the computer has none. */
  generatedAt: Date | string | null
  /** The computer's latest SBOM job (scan_results, scan_type 'sbom'), if any. */
  job: { status: string; startedAt: Date | string | null } | null
}

const time = (v: Date | string | null): number | null => {
  if (v == null) return null
  const t = new Date(v).getTime()
  return Number.isNaN(t) ? null : t
}

/**
 * What the row shows. A job in progress wins; a failed job counts only when it is newer
 * than the SBOM (a later successful run replaced the problem); then no SBOM, stale, ok.
 */
export function computerState(f: ComputerFacts, now: Date = new Date()): ComputerState {
  const generated = time(f.generatedAt)
  if (f.job?.status === 'running') return 'running'
  if (f.job?.status === 'pending') return 'queued'
  if (f.job?.status === 'failed') {
    const started = time(f.job.startedAt)
    if (generated === null || (started !== null && started > generated)) return 'failed'
  }
  if (generated === null) return 'none'
  return now.getTime() - generated > SBOM_STALE_HOURS * 3600_000 ? 'stale' : 'ok'
}
