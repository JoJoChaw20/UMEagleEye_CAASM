import type { DB } from '../db/client'
import { assets, events } from '../db/schema'
import { isNotNull, and, eq, gte, sql } from 'drizzle-orm'

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
  if (baseline.mac_address && asset.macAddress && baseline.mac_address !== asset.macAddress) {
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

async function isDuplicate(
  db:      DB,
  assetId: string,
  drift:   DriftEvent,
  cutoff:  Date,
): Promise<boolean> {
  const f = dedupFilter(drift)
  let rows: { eventId: string }[]

  if (f.kind === 'port') {
    rows = await db
      .select({ eventId: events.eventId })
      .from(events)
      .where(and(
        eq(events.assetId, assetId),
        eq(events.eventType, f.eventType),
        sql`${events.details}->>'port' = ${String(f.port)}`,
        gte(events.timestamp, cutoff),
      ))
      .limit(1)
  } else if (f.kind === 'config') {
    rows = await db
      .select({ eventId: events.eventId })
      .from(events)
      .where(and(
        eq(events.assetId, assetId),
        eq(events.eventType, 'config_change'),
        sql`${events.details}->>'changed_attribute' = ${f.attribute}`,
        gte(events.timestamp, cutoff),
      ))
      .limit(1)
  } else if (f.kind === 'pkg') {
    rows = await db
      .select({ eventId: events.eventId })
      .from(events)
      .where(and(
        eq(events.assetId, assetId),
        eq(events.eventType, f.eventType),
        sql`${events.details}->>'package' = ${f.pkg}`,
        gte(events.timestamp, cutoff),
      ))
      .limit(1)
  } else {
    rows = await db
      .select({ eventId: events.eventId })
      .from(events)
      .where(and(
        eq(events.assetId, assetId),
        eq(events.eventType, f.eventType),
        gte(events.timestamp, cutoff),
      ))
      .limit(1)
  }

  return rows.length > 0
}

// ── Main audit runner ─────────────────────────────────────────────
// Called by the every-15-min cron and by POST /scans/drift-audit.
// Optional tenantId scopes the audit to a single tenant.
export async function runDriftAudit(db: DB, tenantId?: string | null): Promise<number> {
  const query = tenantId
    ? db.select().from(assets).where(and(isNotNull(assets.baselineState), eq(assets.tenantId, tenantId)))
    : db.select().from(assets).where(isNotNull(assets.baselineState))

  const assetRows = await query

  let driftCount = 0
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000)

  for (const asset of assetRows) {
    if (!asset.baselineState) continue

    const baseline = asset.baselineState as AssetBaseline
    const drifts   = detectDrift(baseline, asset)

    for (const drift of drifts) {
      if (await isDuplicate(db, asset.assetId, drift, cutoff)) continue

      await db.insert(events).values({
        assetId:   asset.assetId,
        eventType: drift.type,
        severity:  drift.severity,
        details:   drift.details,
      })
      driftCount++
    }
  }

  return driftCount
}
