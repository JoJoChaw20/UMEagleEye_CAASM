import type { DB } from '../db/client'
import { assets, events } from '../db/schema'
import { isNotNull, and, eq, gte, inArray, sql } from 'drizzle-orm'
import { normalizeMac } from '../lib/mac'

// ── Baseline shape stored in assets.baseline_state ────────────────
export interface AssetBaseline {
  ports?:             number[]             // integer port numbers, e.g. [22, 80, 443]
  os_version?:        string | null
  packages?:          Record<string, string> // pkg → version (from SBOM)
  hostname?:          string | null
  mac_address?:       string | null
  is_internet_facing?: boolean
  device_type?:       string
  captured_at?:       string
  auto_set?:          boolean              // true when set automatically on first scan
}

type DriftSeverity = 'low' | 'medium' | 'high' | 'critical'
type EventType     = typeof events.$inferInsert['eventType']

interface DriftEvent {
  type:     EventType
  severity: DriftSeverity
  details:  Record<string, unknown>
}

// ── Port helpers ──────────────────────────────────────────────────
// Accepts both integer (22) and string ("22/tcp") port representations.
function parsePort(p: unknown): number {
  if (typeof p === 'number') return p
  if (typeof p === 'string') return parseInt(p.split('/')[0], 10)
  return NaN
}

export function extractPorts(osInfo: Record<string, unknown> | null | undefined): number[] {
  const raw = (osInfo as Record<string, unknown> | null)?.ports
  return (Array.isArray(raw) ? raw : []).map(parsePort).filter(n => !isNaN(n))
}

export function extractOsVersion(osInfo: Record<string, unknown> | null | undefined): string | null {
  if (!osInfo) return null
  const v = (osInfo as Record<string, unknown>).os_version
         ?? (osInfo as Record<string, unknown>).version
         ?? (osInfo as Record<string, unknown>).osVersion
  return typeof v === 'string' && v ? v : null
}

function extractPackages(osInfo: Record<string, unknown> | null | undefined): Record<string, string> {
  if (!osInfo) return {}
  const pkgs = (osInfo as Record<string, unknown>).packages
  if (typeof pkgs === 'object' && pkgs !== null && !Array.isArray(pkgs)) {
    return pkgs as Record<string, string>
  }
  return {}
}

// ── Build a canonical baseline snapshot from asset state ──────────
// Used both by the manual POST /assets/:id/baseline endpoint and by
// auto-baselining on first scan ingest.
export function buildBaseline(params: {
  ports:            number[]
  osInfo:           Record<string, unknown> | null
  hostname?:        string | null
  macAddress?:      string | null
  isInternetFacing: boolean
  deviceType:       string
  autoSet?:         boolean
}): AssetBaseline {
  return {
    ports:             params.ports,
    os_version:        extractOsVersion(params.osInfo),
    packages:          extractPackages(params.osInfo),
    hostname:          params.hostname ?? null,
    mac_address:       params.macAddress ?? null,
    is_internet_facing: params.isInternetFacing,
    device_type:       params.deviceType,
    captured_at:       new Date().toISOString(),
    auto_set:          params.autoSet ?? false,
  }
}

// ── Core drift comparison ─────────────────────────────────────────
function detectDrift(
  baseline: AssetBaseline,
  asset:    typeof assets.$inferSelect,
): DriftEvent[] {
  const drifts: DriftEvent[] = []
  const osInfo = asset.osInfo as Record<string, unknown> | null

  // ── Open ports ─────────────────────────────────────────────────
  const basePorts = new Set(baseline.ports ?? [])
  const curPorts  = new Set(extractPorts(osInfo))

  for (const p of curPorts) {
    if (!basePorts.has(p)) {
      drifts.push({
        type:     'port_opened',
        severity: p < 1024 ? 'high' : 'medium',
        details:  { port: p, protocol: 'tcp' },
      })
    }
  }
  for (const p of basePorts) {
    if (!curPorts.has(p)) {
      drifts.push({ type: 'port_closed', severity: 'low', details: { port: p } })
    }
  }

  // ── OS version ─────────────────────────────────────────────────
  const baseVer = baseline.os_version ?? null
  const curVer  = extractOsVersion(osInfo)
  if (baseVer && curVer && baseVer !== curVer) {
    const isDowngrade = baseVer > curVer
    drifts.push({
      type:     isDowngrade ? 'version_downgrade' : 'version_upgrade',
      severity: isDowngrade ? 'high' : 'low',
      details:  { changed_attribute: 'os_version', from: baseVer, to: curVer },
    })
  }

  // ── Packages (only meaningful if SBOM has been run) ────────────
  const basePkgs = baseline.packages ?? {}
  const curPkgs  = extractPackages(osInfo)

  for (const [pkg, ver] of Object.entries(curPkgs)) {
    if (!(pkg in basePkgs)) {
      drifts.push({ type: 'new_package', severity: 'low', details: { package: pkg, version: ver } })
    } else if (basePkgs[pkg] !== ver) {
      const isDowngrade = (basePkgs[pkg] ?? '') > ver
      drifts.push({
        type:     isDowngrade ? 'version_downgrade' : 'version_upgrade',
        severity: isDowngrade ? 'medium' : 'low',
        details:  { changed_attribute: 'package_version', package: pkg, from: basePkgs[pkg], to: ver },
      })
    }
  }
  for (const pkg of Object.keys(basePkgs)) {
    if (!(pkg in curPkgs)) {
      drifts.push({ type: 'removed_package', severity: 'low', details: { package: pkg } })
    }
  }

  // ── Hostname change ────────────────────────────────────────────
  if (baseline.hostname && asset.hostname && baseline.hostname !== asset.hostname) {
    drifts.push({
      type:     'config_change',
      severity: 'medium',
      details:  { changed_attribute: 'hostname', from: baseline.hostname, to: asset.hostname },
    })
  }

  // ── MAC address change (potential spoofing / hardware swap) ────
  // Compare normalized forms so legacy mixed-case / dash-format baselines don't
  // raise false drift against a now-normalized current value. The stored
  // baseline_state is left untouched; from/to show the actual stored values.
  const baselineMac = normalizeMac(baseline.mac_address)
  const currentMac  = normalizeMac(asset.macAddress)
  if (baselineMac && currentMac && baselineMac !== currentMac) {
    drifts.push({
      type:     'config_change',
      severity: 'high',
      details:  { changed_attribute: 'mac_address', from: baseline.mac_address, to: asset.macAddress },
    })
  }

  // ── Internet-facing exposure change ────────────────────────────
  if (
    baseline.is_internet_facing !== undefined &&
    baseline.is_internet_facing !== null &&
    baseline.is_internet_facing !== asset.isInternetFacing
  ) {
    drifts.push({
      type:     'config_change',
      severity: asset.isInternetFacing ? 'critical' : 'medium',
      details:  {
        changed_attribute: 'internet_facing',
        from: baseline.is_internet_facing,
        to:   asset.isInternetFacing,
      },
    })
  }

  // ── Device type change ─────────────────────────────────────────
  if (
    baseline.device_type &&
    baseline.device_type !== 'unknown' &&
    asset.deviceType !== 'unknown' &&
    baseline.device_type !== asset.deviceType
  ) {
    drifts.push({
      type:     'config_change',
      severity: 'medium',
      details:  { changed_attribute: 'device_type', from: baseline.device_type, to: asset.deviceType },
    })
  }

  return drifts
}

// ── Deduplication key ─────────────────────────────────────────────
// Used to build the WHERE clause that checks for a recent duplicate.
type DedupFilter =
  | { kind: 'port';   eventType: EventType; port: number }
  | { kind: 'config'; attribute: string }
  | { kind: 'pkg';    eventType: EventType; pkg: string }
  | { kind: 'simple'; eventType: EventType }

function dedupFilter(drift: DriftEvent): DedupFilter {
  if (drift.type === 'port_opened' || drift.type === 'port_closed') {
    return { kind: 'port', eventType: drift.type, port: Number(drift.details.port) }
  }
  if (drift.type === 'config_change') {
    return { kind: 'config', attribute: String(drift.details.changed_attribute) }
  }
  if (drift.type === 'new_package' || drift.type === 'removed_package') {
    return { kind: 'pkg', eventType: drift.type, pkg: String(drift.details.package) }
  }
  return { kind: 'simple', eventType: drift.type }
}

// In-memory dedup key — mirrors the exact WHERE-clause matching the old per-drift
// isDuplicate query used, so bulk prefetch + memory dedup gives identical results.
// Works for both a candidate drift and an already-stored event (pass its type/details).
function driftDedupKey(assetId: string, type: EventType, details: Record<string, unknown>): string {
  const f = dedupFilter({ type, severity: 'low', details } as DriftEvent)
  switch (f.kind) {
    case 'port':   return `${assetId}|port|${f.eventType}|${f.port}`
    case 'config': return `${assetId}|config|${f.attribute}`
    case 'pkg':    return `${assetId}|pkg|${f.eventType}|${f.pkg}`
    case 'simple': return `${assetId}|simple|${f.eventType}`
  }
}

// ── Main audit runner ─────────────────────────────────────────────
// Called by the every-15-min cron and by POST /scans/drift-audit.
// Optional tenantId scopes the audit to a single tenant.
export async function runDriftAudit(db: DB, tenantId?: string | null): Promise<number> {
  const query = tenantId
    ? db.select().from(assets).where(and(isNotNull(assets.baselineState), eq(assets.tenantId, tenantId)))
    : db.select().from(assets).where(isNotNull(assets.baselineState))

  const assetRows = await query
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000)

  // 1) Detect all drifts in memory (detectDrift is pure).
  const candidates: { assetId: string; type: EventType; severity: DriftEvent['severity']; details: Record<string, unknown> }[] = []
  const driftAssetIds: string[] = []
  for (const asset of assetRows) {
    if (!asset.baselineState) continue
    const drifts = detectDrift(asset.baselineState as AssetBaseline, asset)
    if (drifts.length === 0) continue
    driftAssetIds.push(asset.assetId)
    for (const d of drifts) candidates.push({ assetId: asset.assetId, type: d.type, severity: d.severity, details: d.details })
  }
  if (candidates.length === 0) return 0

  // 2) Prefetch recent events (within the 24h dedup window) for the involved
  //    assets in ONE query, and build the set of existing dedup keys.
  const recent = await db
    .select({ assetId: events.assetId, eventType: events.eventType, details: events.details })
    .from(events)
    .where(and(inArray(events.assetId, driftAssetIds), gte(events.timestamp, cutoff)))
  const seen = new Set<string>()
  for (const e of recent) seen.add(driftDedupKey(e.assetId, e.eventType, (e.details ?? {}) as Record<string, unknown>))

  // 3) Keep only non-duplicate drifts (in-memory dedup also covers two drifts in
  //    this run sharing a key — matching the old sequential insert-then-check order).
  const toInsert: { assetId: string; eventType: EventType; severity: DriftEvent['severity']; details: Record<string, unknown> }[] = []
  for (const c of candidates) {
    const key = driftDedupKey(c.assetId, c.type, c.details)
    if (seen.has(key)) continue
    seen.add(key)
    toInsert.push({ assetId: c.assetId, eventType: c.type, severity: c.severity, details: c.details })
  }

  // 4) Insert in ~100-statement batches (one batch = one subrequest).
  for (let i = 0; i < toInsert.length; i += 100) {
    const slice = toInsert.slice(i, i + 100)
    if (slice.length === 0) continue
    await db.batch(slice.map(v => db.insert(events).values(v)) as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
  }

  return toInsert.length
}
