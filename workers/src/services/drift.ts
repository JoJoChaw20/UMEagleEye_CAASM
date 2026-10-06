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
  // false until a real SBOM has been ingested. A baseline captured before any SBOM
  // (manual/CSV, passive, or active — active scans don't collect installed packages)
  // has no package visibility, so the drift audit must NOT treat the first SBOM's
  // packages as "new". Mirrors ports_known. See buildBaseline / detectDrift.
  packages_known?:    boolean
  captured_from?:     string               // 'manual' when seeded at hand/CSV creation
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

// ── Package-baseline "known" test (mirrors ports_known) ───────────
// A baseline's packages are UNKNOWN when the `packages` key is absent, or the
// map is empty and packages_known is not explicitly true. Legacy scan-created
// baselines that carry an empty `packages:{}` and no flag therefore count as
// unknown and get completed by their next first SBOM. Pure.
export function baselinePackagesKnown(baseline: AssetBaseline | null | undefined): boolean {
  if (!baseline) return false
  if (baseline.packages_known === true) return true
  return Object.keys(baseline.packages ?? {}).length > 0
}

// ── CycloneDX components → canonical package map (name → version) ──
// Same shape the drift audit compares (extractPackages). Last version wins on a
// duplicate name; components missing name or version are dropped. Pure.
export function buildPackageMap(components: unknown): Record<string, string> {
  const map: Record<string, string> = {}
  if (!Array.isArray(components)) return map
  for (const c of components) {
    const comp = c as Record<string, unknown>
    if (comp?.name == null || comp?.version == null) continue
    map[String(comp.name)] = String(comp.version)
  }
  return map
}

// ── Plan the first-SBOM baseline completion (pure) ────────────────
// Returns the PARTIAL patch to jsonb-merge into baseline_state when a real SBOM
// (≥1 package) is ingested for an asset whose baseline packages are still unknown,
// or null when nothing should change: no baseline row (null-baseline assets are
// skipped by the audit), an already-known baseline, or an empty SBOM result.
// The caller merges this with `baseline_state || patch` so ports/hostname/etc. are
// left untouched, and runs it in the SAME batch as the SBOM write.
export function planPackageBaselineCompletion(
  baseline: AssetBaseline | null | undefined,
  pkgMap: Record<string, string>,
): { packages: Record<string, string>; packages_known: true } | null {
  if (!baseline) return null
  if (baselinePackagesKnown(baseline)) return null
  if (Object.keys(pkgMap).length === 0) return null
  return { packages: pkgMap, packages_known: true }
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
  // Only treat packages as known when the asset actually has package data (an SBOM
  // has landed in os_info). Active/passive scans don't collect packages, so this is
  // normally false and the `packages` key is omitted — never an empty `{}` — so the
  // first SBOM completes it without a flood of false new_package drift.
  const pkgs = extractPackages(params.osInfo)
  const hasPkgs = Object.keys(pkgs).length > 0
  const b: AssetBaseline = {
    ports:             params.ports,
    os_version:        extractOsVersion(params.osInfo),
    hostname:          params.hostname ?? null,
    mac_address:       params.macAddress ?? null,
    is_internet_facing: params.isInternetFacing,
    device_type:       params.deviceType,
    snmp_sysdescr:     extractSnmpDescr(params.osInfo),
    captured_at:       new Date().toISOString(),
    auto_set:          params.autoSet ?? false,
    ports_known:       params.portsKnown ?? true,
    packages_known:    hasPkgs,
  }
  if (hasPkgs) b.packages = pkgs
  return b
}

// ── Manual-creation baseline (POST /assets + CSV import) ──────────
// Seeds a baseline from only the fields known at hand/CSV creation. Deliberately
// OMITS ports and packages keys (not empty arrays) and sets ports_known=false, so
// the first ACTIVE scan completes ports via the ingest "complete baseline" path
// without raising "port opened" drift, and hostname/MAC/exposure are already
// baselined so they don't flag either. Pure.
export function buildManualBaseline(params: {
  hostname?: string | null
  macAddress?: string | null
  deviceType: string
  isInternetFacing: boolean
  osVersion?: string | null
}): AssetBaseline {
  const b: AssetBaseline = {
    hostname:           params.hostname ?? null,
    mac_address:        params.macAddress ?? null,
    device_type:        params.deviceType,
    is_internet_facing: params.isInternetFacing,
    captured_at:        new Date().toISOString(),
    auto_set:           true,
    ports_known:        false,
    packages_known:     false,
    captured_from:      'manual',
  }
  if (params.osVersion) b.os_version = params.osVersion
  return b
}

// ── Partial baseline merge (used by PATCH update_baseline) ────────
// Merges ONLY the edited drift-tracked attributes into an existing baseline, using
// the same jsonb keys buildBaseline writes, leaving ports/packages/os_version/etc.
// untouched. Returns null when there is no baseline to update (null/absent) so the
// caller can skip the write — a null baseline is never created here. Pure.
export function mergeBaselineFields(
  baseline: AssetBaseline | null | undefined,
  edited: { hostname?: string | null; device_type?: string; is_internet_facing?: boolean; mac_address?: string | null },
): AssetBaseline | null {
  if (!baseline || Object.keys(baseline).length === 0) return null
  const next: AssetBaseline = { ...baseline }
  if ('hostname' in edited)           next.hostname = edited.hostname ?? null
  if ('device_type' in edited)        next.device_type = edited.device_type
  if ('is_internet_facing' in edited) next.is_internet_facing = edited.is_internet_facing
  if ('mac_address' in edited)        next.mac_address = edited.mac_address ?? null
  next.captured_at = new Date().toISOString()
  return next
}

// ── Core drift comparison ─────────────────────────────────────────
// Exported for the packages-known demo; still pure.
export function detectDrift(
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

  // ── Packages ────────────────────────────────────────────────────
  // Mirror ports_known: compare only when the baseline packages are KNOWN and the
  // asset actually has current package data. A baseline captured before any SBOM
  // (manual/CSV, passive, or a legacy `packages:{}`) has unknown packages, so the
  // first SBOM that completes it can't look like every package is new; an asset
  // with no current packages is also skipped so a completed baseline doesn't flag
  // every package as removed from an empty/failed scan.
  const basePkgs = baseline.packages ?? {}
  const curPkgs  = extractPackages(osInfo)
  if (baselinePackagesKnown(baseline) && Object.keys(curPkgs).length > 0) {
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

// Stable identity of a drift finding on an asset, so the same condition maps
// to one alert. Works for a candidate drift and a stored event alike.
function driftKey(assetId: string, type: EventType, details: Record<string, unknown>): string {
  const f = dedupFilter({ type, severity: 'low', details })
  if (f.kind === 'port')   return `${assetId}|${type}::port:${f.port}`
  if (f.kind === 'config') return `${assetId}|${type}::attr:${f.attribute}`
  if (f.kind === 'pkg')    return `${assetId}|${type}::pkg:${f.pkg}`
  // OS and each package version change are separate conditions
  return `${assetId}|${type}::${String(details.package ?? 'os')}`
}

const DRIFT_TYPES: EventType[] = [
  'port_opened', 'port_closed', 'version_downgrade', 'version_upgrade',
  'config_change', 'new_package', 'removed_package',
]

// Run statements in ~100-statement chunks (one db.batch = one subrequest).
async function runBatched(db: DB, stmts: unknown[]): Promise<void> {
  for (let i = 0; i < stmts.length; i += 100) {
    const slice = stmts.slice(i, i + 100)
    if (slice.length === 0) continue
    await db.batch(slice as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
  }
}

// ── Main audit runner ─────────────────────────────────────────────
// Called by the every-15-min cron and by POST /scans/drift-audit.
// Optional tenantId scopes the audit to a single tenant.
//
// One alert per condition: a drift that is still present bumps last_seen and
// occurrences on its open alert instead of raising a new one. An open drift
// alert whose condition is gone (port closed again, hostname reverted) is
// auto-resolved. A condition an analyst marked false positive stays quiet.
// All reads are bulk prefetches and all writes go through db.batch, so the
// subrequest count stays constant regardless of asset count.
export async function runDriftAudit(db: DB, tenantId?: string | null, assetIds?: string[]): Promise<number> {
  if (assetIds && assetIds.length === 0) return 0
  const assetRows = await db.select().from(assets).where(and(
    isNotNull(assets.baselineState),
    tenantId ? eq(assets.tenantId, tenantId) : undefined,
    assetIds ? inArray(assets.assetId, assetIds) : undefined,
  ))
  if (assetRows.length === 0) return 0
  const now = new Date()

  // 1) Detect all drifts in memory (detectDrift is pure).
  const candidates: { assetId: string; type: EventType; severity: DriftEvent['severity']; details: Record<string, unknown> }[] = []
  for (const asset of assetRows) {
    if (!asset.baselineState) continue
    for (const d of detectDrift(asset.baselineState as AssetBaseline, asset)) {
      candidates.push({ assetId: asset.assetId, type: d.type, severity: d.severity, details: d.details })
    }
  }

  // 2) Prefetch, in ONE query, the drift alerts that still matter for these
  //    assets: open ones (to update or auto-resolve) and false positives (to
  //    keep suppressed).
  const existing = await db
    .select({ eventId: events.eventId, assetId: events.assetId, eventType: events.eventType, details: events.details, status: events.status })
    .from(events)
    .where(and(
      inArray(events.assetId, assetRows.map(a => a.assetId)),
      inArray(events.eventType, DRIFT_TYPES),
      inArray(events.status, [...OPEN_STATUSES, 'false_positive']),
    ))

  const openByKey  = new Map<string, string>()
  const suppressed = new Set<string>()
  const duplicates: string[] = []   // e.g. two copies after merging duplicate assets
  for (const e of existing) {
    const key = driftKey(e.assetId, e.eventType, (e.details ?? {}) as Record<string, unknown>)
    if (e.status === 'false_positive') suppressed.add(key)
    else if (openByKey.has(key)) duplicates.push(e.eventId)
    else openByKey.set(key, e.eventId)
  }

  // 3) Decide per candidate: refresh its open alert, skip, or insert new.
  const stmts: unknown[] = []
  const currentKeys = new Set<string>()
  let driftCount = 0
  for (const c of candidates) {
    const key = driftKey(c.assetId, c.type, c.details)
    if (currentKeys.has(key)) continue   // same condition twice in this run
    currentKeys.add(key)
    if (suppressed.has(key)) continue

    const openId = openByKey.get(key)
    if (openId) {
      stmts.push(db.update(events)
        .set({
          lastSeen:    now,
          occurrences: sql`${events.occurrences} + 1`,
          severity:    c.severity,
          details:     c.details,
          updatedAt:   now,
        })
        .where(eq(events.eventId, openId)))
      continue
    }

    stmts.push(db.insert(events).values({
      assetId:   c.assetId,
      eventType: c.type,
      severity:  c.severity,
      details:   c.details,
      firstSeen: now,
      lastSeen:  now,
    }))
    driftCount++
  }

  // 4) Collapse duplicates and auto-resolve alerts whose condition is gone.
  if (duplicates.length > 0) {
    stmts.push(db.update(events)
      .set({ status: 'resolved', resolvedAt: now, updatedAt: now,
             resolutionNote: 'Merged into an identical open alert on the same asset' })
      .where(inArray(events.eventId, duplicates)))
  }
  const gone = [...openByKey.entries()].filter(([key]) => !currentKeys.has(key)).map(([, id]) => id)
  if (gone.length > 0) {
    stmts.push(db.update(events)
      .set({
        status:         'resolved',
        resolvedAt:     now,
        resolutionNote: 'Auto-resolved: condition no longer detected by drift audit',
        updatedAt:      now,
      })
      .where(inArray(events.eventId, gone)))
  }

  await runBatched(db, stmts)
  return driftCount
}
