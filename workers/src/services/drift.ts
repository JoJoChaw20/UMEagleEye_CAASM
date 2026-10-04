import type { DB } from '../db/client'
import { assets, events } from '../db/schema'
import { isNotNull, and, eq, inArray, sql } from 'drizzle-orm'
import { OPEN_STATUSES } from '../lib/eventStatus'
import { compareVersions, newPortSeverity } from '../lib/exposure'
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
  snmp_sysdescr?:     string | null        // network-device firmware/model string
  captured_at?:       string
  auto_set?:          boolean              // true when set automatically on first scan
  ports_known?:       boolean              // false when captured by a passive scan (no port visibility)
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
  if (typeof p === 'string') return parseInt(p.split('/')[0] ?? '', 10)
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

function extractSnmpDescr(osInfo: Record<string, unknown> | null | undefined): string | null {
  const v = osInfo?.snmp_sysdescr
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
  portsKnown?:      boolean
}): AssetBaseline {
  return {
    ports:             params.ports,
    os_version:        extractOsVersion(params.osInfo),
    packages:          extractPackages(params.osInfo),
    hostname:          params.hostname ?? null,
    mac_address:       params.macAddress ?? null,
    is_internet_facing: params.isInternetFacing,
    device_type:       params.deviceType,
    snmp_sysdescr:     extractSnmpDescr(params.osInfo),
    captured_at:       new Date().toISOString(),
    auto_set:          params.autoSet ?? false,
    ports_known:       params.portsKnown ?? true,
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
  // Skipped until an active scan has seen the host (ports_known === false),
  // and when the asset has no port data at all.
  if (baseline.ports_known !== false && Array.isArray(osInfo?.ports)) {
    const basePorts = new Set(baseline.ports ?? [])
    const curPorts  = new Set(extractPorts(osInfo))

    for (const p of curPorts) {
      if (!basePorts.has(p)) {
        drifts.push({
          type:     'port_opened',
          severity: newPortSeverity(p, asset.isInternetFacing),
          details:  { port: p, protocol: 'tcp' },
        })
      }
    }
    for (const p of basePorts) {
      if (!curPorts.has(p)) {
        drifts.push({ type: 'port_closed', severity: 'low', details: { port: p } })
      }
    }
  }

  // ── OS version ─────────────────────────────────────────────────
  const baseVer = baseline.os_version ?? null
  const curVer  = extractOsVersion(osInfo)
  if (baseVer && curVer && baseVer !== curVer) {
    const isDowngrade = compareVersions(curVer, baseVer) < 0
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
      const isDowngrade = compareVersions(ver, basePkgs[pkg] ?? '') < 0
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

  // ── Network-device firmware / model change (SNMP sysDescr) ─────
  const baseSnmp = baseline.snmp_sysdescr ?? null
  const curSnmp  = extractSnmpDescr(osInfo)
  if (baseSnmp && curSnmp && baseSnmp !== curSnmp) {
    drifts.push({
      type:     'config_change',
      severity: 'medium',
      details:  { changed_attribute: 'firmware', from: baseSnmp.slice(0, 200), to: curSnmp.slice(0, 200) },
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

// Stable identity of a drift finding, so the same condition maps to one alert.
function driftKey(type: EventType, details: Record<string, unknown>): string {
  const f = dedupFilter({ type, severity: 'low', details })
  if (f.kind === 'port')   return `${type}::port:${f.port}`
  if (f.kind === 'config') return `${type}::attr:${f.attribute}`
  if (f.kind === 'pkg')    return `${type}::pkg:${f.pkg}`
  // OS and each package version change are separate conditions
  return `${type}::${String(details.package ?? 'os')}`
}

const DRIFT_TYPES: EventType[] = [
  'port_opened', 'port_closed', 'version_downgrade', 'version_upgrade',
  'config_change', 'new_package', 'removed_package',
]

// ── Main audit runner ─────────────────────────────────────────────
// Called by the every-15-min cron and by POST /scans/drift-audit.
// Optional tenantId scopes the audit to a single tenant.
//
// One alert per condition: a drift that is still present bumps last_seen and
// occurrences on its open alert instead of raising a new one. An open drift
// alert whose condition is gone (port closed again, hostname reverted) is
// auto-resolved. A condition an analyst marked false positive stays quiet.
export async function runDriftAudit(db: DB, tenantId?: string | null, assetIds?: string[]): Promise<number> {
  if (assetIds && assetIds.length === 0) return 0
  const assetRows = await db.select().from(assets).where(and(
    isNotNull(assets.baselineState),
    tenantId ? eq(assets.tenantId, tenantId) : undefined,
    assetIds ? inArray(assets.assetId, assetIds) : undefined,
  ))

  let driftCount = 0
  const now = new Date()

  for (const asset of assetRows) {
    if (!asset.baselineState) continue

    const baseline = asset.baselineState as AssetBaseline
    const drifts   = detectDrift(baseline, asset)

    // Drift alerts that still matter for this asset: open ones (to update or
    // auto-resolve) and false positives (to keep suppressed).
    const existing = await db
      .select({ eventId: events.eventId, eventType: events.eventType, details: events.details, status: events.status })
      .from(events)
      .where(and(
        eq(events.assetId, asset.assetId),
        inArray(events.eventType, DRIFT_TYPES),
        inArray(events.status, [...OPEN_STATUSES, 'false_positive']),
      ))

    const openByKey  = new Map<string, string>()
    const suppressed = new Set<string>()
    const duplicates: string[] = []   // e.g. two copies after merging duplicate assets
    for (const e of existing) {
      const key = driftKey(e.eventType, (e.details ?? {}) as Record<string, unknown>)
      if (e.status === 'false_positive') suppressed.add(key)
      else if (openByKey.has(key)) duplicates.push(e.eventId)
      else openByKey.set(key, e.eventId)
    }
    if (duplicates.length > 0) {
      await db.update(events)
        .set({ status: 'resolved', resolvedAt: now, updatedAt: now,
               resolutionNote: 'Merged into an identical open alert on the same asset' })
        .where(inArray(events.eventId, duplicates))
    }

    const currentKeys = new Set<string>()
    for (const drift of drifts) {
      const key = driftKey(drift.type, drift.details)
      currentKeys.add(key)
      if (suppressed.has(key)) continue

      const openId = openByKey.get(key)
      if (openId) {
        await db.update(events)
          .set({
            lastSeen:    now,
            occurrences: sql`${events.occurrences} + 1`,
            severity:    drift.severity,
            details:     drift.details,
            updatedAt:   now,
          })
          .where(eq(events.eventId, openId))
        continue
      }

      await db.insert(events).values({
        assetId:   asset.assetId,
        eventType: drift.type,
        severity:  drift.severity,
        details:   drift.details,
        firstSeen: now,
        lastSeen:  now,
      })
      driftCount++
    }

    const gone = [...openByKey.entries()].filter(([key]) => !currentKeys.has(key)).map(([, id]) => id)
    if (gone.length > 0) {
      await db.update(events)
        .set({
          status:         'resolved',
          resolvedAt:     now,
          resolutionNote: 'Auto-resolved: condition no longer detected by drift audit',
          updatedAt:      now,
        })
        .where(inArray(events.eventId, gone))
    }
  }

  return driftCount
}
