import type { DB } from '../db/client'
import { assets, assetIdentifiers, events } from '../db/schema'
import { isNotNull, and, eq, inArray, sql } from 'drizzle-orm'
import { OPEN_STATUSES } from '../lib/eventStatus'
import { compareVersions, newPortSeverity } from '../lib/exposure'
import { normalizeMac } from '../lib/mac'
import { isGenericHostname } from '../lib/hostnames'
import { NEW_DEVICE_UNSEEN_DAYS, UNSEEN_NOTE } from './alertHygiene'

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
  // Version of the detection rule each attribute was captured under (see RULE_VERSIONS).
  // Absent = version 1.
  rule_versions?:     Record<string, number>
}

// ── Detection-rule versions ───────────────────────────────────────
// When the rule that computes an attribute changes, bump its version here. The next
// drift audit then moves every baseline captured under an older rule to the asset's
// current value (no alert: the device did not change, the rule did) and resolves the
// alerts the old rule raised. Attributes not listed are never refreshed this way.
//   internet_facing 2: exposure comes from the scanning agent's default gateway
//     (lib/exposure.ts resolveInternetFacing), Oct 2026. Baselines from the older rule
//     raised "internet-facing true -> false" on routers that never changed.
export const RULE_VERSIONS: Record<string, number> = { internet_facing: 2 }

/** The attributes of a baseline captured under an older detection rule. Pure. */
export function outdatedRuleAttributes(baseline: AssetBaseline): string[] {
  return Object.entries(RULE_VERSIONS)
    .filter(([attr, version]) => (baseline.rule_versions?.[attr] ?? 1) < version)
    .map(([attr]) => attr)
}

/** When an asset was last observed by a scan or its agent's inventory, or null. */
export function lastObservedAt(asset: { lastScanned?: Date | string | null; inventoryCollectedAt?: Date | string | null }): Date | null {
  const times = [asset.lastScanned, asset.inventoryCollectedAt]
    .filter((t): t is Date | string => !!t).map(t => new Date(t).getTime()).filter(n => !Number.isNaN(n))
  return times.length ? new Date(Math.max(...times)) : null
}

// A Discovered asset not observed for this long is gone (a visitor, a lab VM, a network
// the agent left): its open drift alerts are closed unreviewed and no new ones are raised
// for it. My Assets are exempt (runDriftAudit): their alerts stay open while they are away.
// Same period as unreviewed new-device alerts (services/alertHygiene.ts).
export const DRIFT_UNSEEN_DAYS = NEW_DEVICE_UNSEEN_DAYS
export { UNSEEN_NOTE }
const RULE_CHANGE_NOTE = 'Auto-resolved: the detection rule changed and the baseline was refreshed to the current value'

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
    rule_versions:     { ...RULE_VERSIONS },
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
    rule_versions:      { ...RULE_VERSIONS },
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
export interface DriftOptions {
  // MACs the asset's own agent reported for this machine's adapters (asset_identifiers
  // kind 'mac'). A scan seeing another adapter of the same machine is not a MAC change.
  agentMacs?: Set<string>
}

/** The last active scan saw the host but no open port at all while the baseline has some:
 *  almost always a missed scan (host asleep, firewall, timeout), not every service stopping.
 *  Port drift is not judged on such a scan, and its open port alerts are left as they are. */
export function portsUnreliable(baseline: AssetBaseline, osInfo: Record<string, unknown> | null): boolean {
  return Array.isArray(osInfo?.ports) && extractPorts(osInfo).length === 0 && (baseline.ports ?? []).length > 0
}

/** Which open alerts a scan with unreliable ports leaves as they are: port_opened only.
 *  port_closed is no longer raised, so its old alerts must still resolve; frozen, they
 *  stayed open for good on a host whose last scan saw no port. */
export function frozenOnUnreliablePorts(type: EventType): boolean {
  return type === 'port_opened'
}

export function detectDrift(
  baseline: AssetBaseline,
  asset:    typeof assets.$inferSelect,
  opts:     DriftOptions = {},
): DriftEvent[] {
  const drifts: DriftEvent[] = []
  const osInfo = asset.osInfo as Record<string, unknown> | null

  // ── Open ports ─────────────────────────────────────────────────
  // Skipped until an active scan has seen the host (ports_known === false), when the
  // asset has no port data at all, and on a scan that found no open port (see above).
  // Only a NEW port alerts: a port that closed lowers risk, and simply resolves its
  // port_opened alert (runDriftAudit), so there is no port_closed alert.
  if (baseline.ports_known !== false && Array.isArray(osInfo?.ports) && !portsUnreliable(baseline, osInfo)) {
    const basePorts = new Set(baseline.ports ?? [])
    for (const p of new Set(extractPorts(osInfo))) {
      if (!basePorts.has(p)) {
        drifts.push({
          type:     'port_opened',
          severity: newPortSeverity(p, asset.isInternetFacing),
          details:  { port: p, protocol: 'tcp' },
        })
      }
    }
  }

  // ── OS version ─────────────────────────────────────────────────
  // A downgrade alerts (rollback to an unpatched build). An upgrade is returned as
  // version_upgrade too, but runDriftAudit moves the baseline instead of alerting.
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

  // Packages are not compared: installed packages change with every update, and the
  // ones that matter are covered by CVE alerts from the SBOM (routes/sbom.ts).

  // ── Hostname change ────────────────────────────────────────────
  // A platform default or a random id (Android, iPhone, a UUID) on either side is not a
  // name anybody chose, so replacing it, or seeing one, is not a rename. runDriftAudit
  // moves a baseline that holds such a name to the real one.
  if (baseline.hostname && asset.hostname && baseline.hostname !== asset.hostname
      && !isGenericHostname(baseline.hostname) && !isGenericHostname(asset.hostname)) {
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
  // One private (locally administered) MAC replacing another is a phone or tablet
  // rotating its random Wi-Fi address, not a hardware swap or spoofing: no alert.
  const isPrivate = (m: string) => (parseInt(m.slice(0, 2), 16) & 0x02) !== 0
  const rotation = !!baselineMac && !!currentMac && isPrivate(baselineMac) && isPrivate(currentMac)
  if (baselineMac && currentMac && baselineMac !== currentMac && !rotation && !opts.agentMacs?.has(currentMac)) {
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
    baseline.is_internet_facing !== asset.isInternetFacing &&
    !outdatedRuleAttributes(baseline).includes('internet_facing')
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

// Types the audit owns. port_closed, version_upgrade and the package types are no longer
// raised, but stay listed so alerts raised before are auto-resolved by the next audit.
const DRIFT_TYPES: EventType[] = [
  'port_opened', 'port_closed', 'version_downgrade', 'version_upgrade',
  'config_change', 'new_package', 'removed_package',
]

// An alert auto-resolved this recently is reopened when its condition returns, rather
// than raising a new one, so a condition that flaps between scans stays one alert.
const REOPEN_WITHIN_DAYS = 14

// Run statements in ~100-statement chunks (one db.batch = one subrequest).
async function runBatched(db: DB, stmts: unknown[]): Promise<void> {
  for (let i = 0; i < stmts.length; i += 100) {
    const slice = stmts.slice(i, i + 100)
    if (slice.length === 0) continue
    await db.batch(slice as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
  }
}

// ── Audit decisions (pure) ────────────────────────────────────────
/** Not observed for DRIFT_UNSEEN_DAYS (never observed: counted from when it was created). */
export function isUnseen(observed: Date | null, createdAt: Date | string | null | undefined, now: Date): boolean {
  const since = observed ?? (createdAt ? new Date(createdAt) : null)
  return !!since && now.getTime() - since.getTime() >= DRIFT_UNSEEN_DAYS * 86_400_000
}

/** What the audit does with an open alert whose condition is still present. Re-checking
 *  stored data is not a sighting: occurrences and last_seen only move when a scan or the
 *  agent observed the device after the alert was last seen ('bump'); otherwise only a
 *  changed severity or detail is written ('update'), or nothing. */
export function openAlertAction(observed: Date | null, lastSeen: Date | string, changed: boolean): 'bump' | 'update' | 'none' {
  if (observed && observed.getTime() > new Date(lastSeen).getTime()) return 'bump'
  return changed ? 'update' : 'none'
}

/** A recently auto-resolved alert is reopened only when the device was observed after it
 *  was resolved: the same stored data must not resolve and reopen it on alternate audits. */
export function shouldReopen(observed: Date | null, resolvedAt: Date | string | null): boolean {
  return !!observed && !!resolvedAt && observed.getTime() > new Date(resolvedAt).getTime()
}

/** Baseline moves that are not drift: an OS upgrade, a real name replacing a generic one,
 *  and attributes captured under an older detection rule. Returns the jsonb patch (or
 *  null) and the attributes refreshed because their rule changed. Pure. */
export function baselineMoves(baseline: AssetBaseline, asset: typeof assets.$inferSelect, osUpgradeTo: string | null):
    { patch: Partial<AssetBaseline> | null; ruleRefreshed: string[] } {
  const patch: Partial<AssetBaseline> = {}
  if (osUpgradeTo) patch.os_version = osUpgradeTo
  if (baseline.hostname && asset.hostname && baseline.hostname !== asset.hostname
      && isGenericHostname(baseline.hostname) && !isGenericHostname(asset.hostname)) {
    patch.hostname = asset.hostname
  }
  const ruleRefreshed = outdatedRuleAttributes(baseline)
  if (ruleRefreshed.length) {
    if (ruleRefreshed.includes('internet_facing')) patch.is_internet_facing = asset.isInternetFacing
    patch.rule_versions = { ...(baseline.rule_versions ?? {}), ...Object.fromEntries(ruleRefreshed.map(a => [a, RULE_VERSIONS[a]!])) }
  }
  return { patch: Object.keys(patch).length ? patch : null, ruleRefreshed }
}

// The drift alert an attribute refreshed by a rule change belongs to.
const RULE_ATTRIBUTE_KEY: Record<string, { type: EventType; details: Record<string, unknown> }> = {
  internet_facing: { type: 'config_change', details: { changed_attribute: 'internet_facing' } },
}

// ── Main audit runner ─────────────────────────────────────────────
// Called by the 6-hourly cron, after each scan and inventory, and by POST /scans/drift-audit.
// Optional tenantId scopes the audit to a single tenant.
//
// One alert per condition. A condition still present keeps its open alert; occurrences and
// last_seen move only when the device was observed again since (openAlertAction). An open
// drift alert whose condition is gone (port closed again, hostname reverted) is
// auto-resolved; one on a Discovered device not observed for DRIFT_UNSEEN_DAYS is closed
// unreviewed (UNSEEN_NOTE). A condition an analyst marked false positive stays quiet.
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
  const ids = assetRows.map(a => a.assetId)

  // 1) Prefetch, in ONE query each: the MACs agents reported for these machines, and
  //    the drift alerts that still matter for these assets: open ones (to update or
  //    auto-resolve), false positives (to keep suppressed) and recently auto-resolved
  //    ones (to reopen if their condition returns).
  const [macRows, existing] = await Promise.all([
    db.select({ assetId: assetIdentifiers.assetId, value: assetIdentifiers.value })
      .from(assetIdentifiers)
      .where(and(inArray(assetIdentifiers.assetId, ids), eq(assetIdentifiers.kind, 'mac'))),
    db.select({ eventId: events.eventId, assetId: events.assetId, eventType: events.eventType, details: events.details,
                status: events.status, severity: events.severity, lastSeen: events.lastSeen, resolvedAt: events.resolvedAt })
      .from(events)
      .where(and(
        inArray(events.assetId, ids),
        inArray(events.eventType, DRIFT_TYPES),
        sql`(${events.status} IN ('open', 'in_progress', 'false_positive')
          OR (${events.status} = 'resolved' AND ${events.resolutionNote} LIKE 'Auto-resolved%'
              AND ${events.resolvedAt} > now() - make_interval(days => ${REOPEN_WITHIN_DAYS})))`,
      )),
  ])
  const agentMacs = new Map<string, Set<string>>()
  for (const r of macRows) {
    const mac = normalizeMac(r.value)
    if (!mac) continue
    if (!agentMacs.has(r.assetId)) agentMacs.set(r.assetId, new Set())
    agentMacs.get(r.assetId)!.add(mac)
  }

  // 2) Detect all drifts in memory (detectDrift is pure). Baseline moves that are not
  //    drift are written instead of alerting; a scan that saw no open port freezes port
  //    alerts; a device not observed for DRIFT_UNSEEN_DAYS raises nothing.
  const candidates: { assetId: string; type: EventType; severity: DriftEvent['severity']; details: Record<string, unknown> }[] = []
  const stmts: unknown[] = []   // every write, run in db.batch chunks (one subrequest each)
  const frozenPorts = new Set<string>()
  const unseenAssets = new Set<string>()
  const ruleRefreshedKeys = new Set<string>()
  const observedByAsset = new Map<string, Date | null>()
  for (const asset of assetRows) {
    if (!asset.baselineState) continue
    const baseline = asset.baselineState as AssetBaseline
    const observed = lastObservedAt(asset)
    observedByAsset.set(asset.assetId, observed)
    const drifts = detectDrift(baseline, asset, { agentMacs: agentMacs.get(asset.assetId) })
    const upgrade = drifts.find(d => d.type === 'version_upgrade' && d.details.changed_attribute === 'os_version')
    const { patch, ruleRefreshed } = baselineMoves(baseline, asset, upgrade ? String(upgrade.details.to) : null)
    if (patch) {
      stmts.push(db.update(assets)
        .set({ baselineState: sql`${assets.baselineState} || ${JSON.stringify(patch)}::jsonb`, updatedAt: now })
        .where(eq(assets.assetId, asset.assetId)))
    }
    for (const attr of ruleRefreshed) {
      const k = RULE_ATTRIBUTE_KEY[attr]
      if (k) ruleRefreshedKeys.add(driftKey(asset.assetId, k.type, k.details))
    }
    // My Assets are the devices someone said matter: an alert on one stays open while it is
    // away (it only stops counting); Discovered devices that went quiet are closed unreviewed.
    if (!asset.inMyAssets && isUnseen(observed, asset.createdAt, now)) { unseenAssets.add(asset.assetId); continue }
    if (portsUnreliable(baseline, asset.osInfo as Record<string, unknown> | null)) frozenPorts.add(asset.assetId)
    for (const d of drifts) {
      if (d === upgrade) continue
      candidates.push({ assetId: asset.assetId, type: d.type, severity: d.severity, details: d.details })
    }
  }

  type Known = { id: string; assetId: string; type: EventType; status: string; severity: string; details: unknown; lastSeen: Date }
  const openByKey  = new Map<string, Known>()
  const recentlyResolved = new Map<string, { id: string; resolvedAt: Date | null }>()
  const suppressed = new Set<string>()
  const duplicates: string[] = []   // e.g. two copies after merging duplicate assets
  for (const e of existing) {
    const key = driftKey(e.assetId, e.eventType, (e.details ?? {}) as Record<string, unknown>)
    if (e.status === 'false_positive') suppressed.add(key)
    else if (e.status === 'resolved') recentlyResolved.set(key, { id: e.eventId, resolvedAt: e.resolvedAt })
    else if (openByKey.has(key)) duplicates.push(e.eventId)
    else openByKey.set(key, { id: e.eventId, assetId: e.assetId, type: e.eventType, status: e.status,
                              severity: e.severity, details: e.details, lastSeen: e.lastSeen })
  }

  // 3) Decide per candidate: refresh its open alert, reopen a recent one, skip, or insert new.
  const currentKeys = new Set<string>()
  let driftCount = 0
  for (const c of candidates) {
    const key = driftKey(c.assetId, c.type, c.details)
    if (currentKeys.has(key)) continue   // same condition twice in this run
    currentKeys.add(key)
    if (suppressed.has(key)) continue
    const observed = observedByAsset.get(c.assetId) ?? null

    const open = openByKey.get(key)
    if (open) {
      const changed = open.severity !== c.severity || JSON.stringify(open.details) !== JSON.stringify(c.details)
      const action = openAlertAction(observed, open.lastSeen, changed)
      if (action === 'bump') {
        stmts.push(db.update(events)
          .set({ lastSeen: observed!, occurrences: sql`${events.occurrences} + 1`, severity: c.severity, details: c.details, updatedAt: now })
          .where(eq(events.eventId, open.id)))
      } else if (action === 'update') {
        stmts.push(db.update(events)
          .set({ severity: c.severity, details: c.details, updatedAt: now })
          .where(eq(events.eventId, open.id)))
      }
      continue
    }
    const recent = recentlyResolved.get(key)
    if (recent) {
      if (shouldReopen(observed, recent.resolvedAt)) {
        stmts.push(db.update(events)
          .set({
            status: 'open', resolvedAt: null, resolvedBy: null,
            resolutionNote: 'Reopened: the change was detected again',
            lastSeen: observed!, occurrences: sql`${events.occurrences} + 1`,
            severity: c.severity, details: c.details, updatedAt: now,
          })
          .where(eq(events.eventId, recent.id)))
      }
      continue   // not observed since it was resolved: the same data must not reopen it
    }

    stmts.push(db.insert(events).values({
      assetId:   c.assetId,
      eventType: c.type,
      severity:  c.severity,
      details:   c.details,
      firstSeen: now,
      lastSeen:  observed ?? now,
    }))
    driftCount++
  }

  // 4) Collapse duplicates, close alerts on devices not seen for DRIFT_UNSEEN_DAYS (open
  //    ones only: someone working on an alert keeps it), and auto-resolve alerts whose
  //    condition is gone, saying when a rule change rather than the device made it go.
  if (duplicates.length > 0) {
    stmts.push(db.update(events)
      .set({ status: 'resolved', resolvedAt: now, updatedAt: now,
             resolutionNote: 'Merged into an identical open alert on the same asset' })
      .where(inArray(events.eventId, duplicates)))
  }
  const unseen: string[] = [], ruleChanged: string[] = [], gone: string[] = []
  for (const [key, e] of openByKey) {
    if (unseenAssets.has(e.assetId)) {
      if (e.status === 'open') unseen.push(e.id)
      continue
    }
    if (currentKeys.has(key)) continue
    if (frozenPorts.has(e.assetId) && frozenOnUnreliablePorts(e.type)) continue   // left as it is
    if (ruleRefreshedKeys.has(key)) ruleChanged.push(e.id)
    else gone.push(e.id)
  }
  const closes: [string[], string][] = [
    [unseen, UNSEEN_NOTE],
    [ruleChanged, RULE_CHANGE_NOTE],
    [gone, 'Auto-resolved: condition no longer detected by drift audit'],
  ]
  for (const [closeIds, note] of closes) {
    if (closeIds.length === 0) continue
    stmts.push(db.update(events)
      .set({ status: 'resolved', resolvedAt: now, resolutionNote: note, updatedAt: now })
      .where(inArray(events.eventId, closeIds)))
  }

  await runBatched(db, stmts)
  return driftCount
}
