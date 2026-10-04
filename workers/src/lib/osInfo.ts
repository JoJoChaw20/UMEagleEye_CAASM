/**
 * Additive merge of scan-observed os_info onto an asset's stored os_info.
 *
 * Production incident this guards against: a passive scan POSTed os_info = {},
 * the upsert did a wholesale `EXCLUDED.os_info` replace, and an active scan's
 * rich os_info (ports/products + SNMP facts) was wiped — which also dropped the
 * criticality score because scoring reads osInfo.ports.
 *
 * Rules:
 *  a) Keys the scan did not observe are preserved (snmp_*, dhcp_*, fingerbank_*,
 *     ai_description, ai_suggestion, name, version, …). They are simply omitted
 *     from `incoming`, so the SQL `||` merge leaves the stored value untouched.
 *  b) Passive scans never touch the port-derived keys (ports/products/versions).
 *  c) Active scans are authoritative for ports/products/versions and always
 *     write all three — an empty array clears stale values.
 *  d) For every other key, a non-empty incoming value wins; an empty incoming
 *     value is dropped so the existing value survives.
 */

/** Port-derived keys only an active (port-scanning) ingest may author. */
const PORT_KEYS = ['ports', 'products', 'versions', 'services'] as const

function isEmptyValue(v: unknown): boolean {
  if (v === null || v === undefined) return true
  if (typeof v === 'string') return v.trim() === ''
  if (Array.isArray(v)) return v.length === 0
  if (typeof v === 'object') return Object.keys(v as Record<string, unknown>).length === 0
  return false
}

export interface MergedOsInfo {
  /**
   * The subset to write as the INSERT ... VALUES os_info, so that the SQL
   * `COALESCE(assets.os_info, '{}'::jsonb) || EXCLUDED.os_info` upsert produces
   * the correct additive merge. Omitted keys fall through to the stored value.
   */
  incoming: Record<string, unknown>
  /**
   * Full shallow merge of existing + incoming — identical to what the jsonb `||`
   * operator produces — used for criticality scoring and the first-discovery
   * baseline (where `existing` is null, so this equals `incoming`).
   */
  merged: Record<string, unknown>
}

export function mergeOsInfo(
  existing: Record<string, unknown> | null | undefined,
  incoming: Record<string, unknown> | null | undefined,
  isPassive: boolean,
): MergedOsInfo {
  const base = (existing ?? {}) as Record<string, unknown>
  const src = (incoming ?? {}) as Record<string, unknown>

  const filtered: Record<string, unknown> = {}

  // Non-port keys: incoming wins only when non-empty (rule d); port keys are
  // handled separately below so passive input can never reach them (rule b).
  for (const [key, value] of Object.entries(src)) {
    if ((PORT_KEYS as readonly string[]).includes(key)) continue
    if (!isEmptyValue(value)) filtered[key] = value
  }

  if (!isPassive) {
    // Rule (c): active owns the port-derived keys and always writes them,
    // using [] when the scan found none so stale values are cleared.
    for (const key of PORT_KEYS) {
      const v = src[key]
      filtered[key] = Array.isArray(v) ? v : []
    }
  }
  // Rule (b): passive → port keys omitted entirely, stored values survive.

  return { incoming: filtered, merged: { ...base, ...filtered } }
}
