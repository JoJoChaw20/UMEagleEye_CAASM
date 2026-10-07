/**
 * Asset identity resolver — replaces IP-keyed identity with a device/address
 * split and ordered matching rules. See the prompt spec "Asset identity:
 * matching rules and data model".
 *
 * This module has two layers:
 *   1. PURE core (classifyMac, sanitizeHostKey, deriveNetworkKey, matchAsset) —
 *      no DB access, fully unit-testable (see scripts/identity-demo.ts).
 *   2. DB wrapper (resolveAssetIdentity) — fetches candidate rows for the pure
 *      matcher and returns a decision the caller executes.
 */
import { and, asc, desc, eq, inArray, isNull, or } from 'drizzle-orm'
import type { DB } from '../db/client'
import { assets, assetAddresses } from '../db/schema'
import { normalizeMac } from './mac'
import type { IdentityPrefetch } from './ingest-plan'
import type { AssetBaseline } from '../services/drift'

// ── MAC classification ───────────────────────────────────────────
export type MacClass = 'invalid' | 'local' | 'global'

// Shared / virtual / protocol MACs that must never identify a unique device.
const SHARED_VIRTUAL_PATTERNS: RegExp[] = [
  /^02:00:4c:4f:4f:50$/,          // Microsoft KM-TEST loopback
  /^00:50:56:c0:00:0[0-9a-f]$/,   // VMware host-only / NAT adapters
  /^00:00:5e:00:01:[0-9a-f]{2}$/, // VRRP virtual router
  /^00:00:0c:07:ac:[0-9a-f]{2}$/, // Cisco HSRP virtual
  /^02:bf:/,                      // Microsoft NLB
]

/**
 * Normalize + classify a MAC.
 *  - invalid: null / broadcast / multicast (first-byte bit0 set) / all-zeros
 *  - local:   locally-administered bit set (first-byte bit1) OR shared/virtual
 *  - global:  everything else valid (a real burned-in OUI)
 * Returns the normalized MAC (null when invalid, so callers treat it as "no MAC").
 */
export function classifyMac(raw: unknown): { mac: string | null; macClass: MacClass } {
  const mac = normalizeMac(raw)
  if (!mac) return { mac: null, macClass: 'invalid' }
  if (mac === 'ff:ff:ff:ff:ff:ff') return { mac: null, macClass: 'invalid' }
  if (mac === '00:00:00:00:00:00') return { mac: null, macClass: 'invalid' }

  const firstByte = parseInt(mac.slice(0, 2), 16)
  if (firstByte & 0x01) return { mac: null, macClass: 'invalid' }        // multicast
  if ((firstByte & 0x02) !== 0 || SHARED_VIRTUAL_PATTERNS.some(re => re.test(mac))) {
    return { mac, macClass: 'local' }                                     // locally administered / virtual
  }
  return { mac, macClass: 'global' }
}

/** True when a normalized MAC is on the shared/virtual list (VMware, VRRP, HSRP,
 *  MS NLB/loopback). Such MACs must never identify a unique device, so duplicate
 *  detection must never group assets on them. Reuses the same SHARED_VIRTUAL list. */
export function isSharedVirtualMac(mac: string | null | undefined): boolean {
  if (!mac) return false
  const n = normalizeMac(mac)
  return n != null && SHARED_VIRTUAL_PATTERNS.some(re => re.test(n))
}

// ── Host key sanitisation ────────────────────────────────────────
const GENERIC_HOST_PATTERNS: RegExp[] = [
  /^android-/,                                                        // android-xxxxxxxx
  /^localhost$/,
  /^iphone$/, /^ipad$/,                                               // default Apple names
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,   // UUID-style
]

/** Lowercase a host identifier; return null for empty or generic/default names. */
export function sanitizeHostKey(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const v = raw.trim().toLowerCase()
  if (!v) return null
  if (GENERIC_HOST_PATTERNS.some(re => re.test(v))) return null
  return v
}

// ── Network key ──────────────────────────────────────────────────
/**
 * Network scope key = the host IP's IPv4 /24 (e.g. "192.168.0.0/24") — IDENTICAL
 * to the migration backfill. Deliberately stable: it does NOT depend on whether a
 * scan saw the gateway, and does not change between active and passive ingest.
 * network.{subnet,gateway_ip,gateway_mac} are still accepted and stored on the
 * scan result, but are not used for the key. IPv6 / unparseable IP → null, and
 * manual/CSV → null (both unscoped).
 */
export function deriveNetworkKey(input: { ip: string; isManualSource?: boolean }): string | null {
  if (input.isManualSource) return null
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec((input.ip ?? '').trim())
  if (!m) return null                                   // IPv6 or unparseable → unscoped
  const o = [m[1], m[2], m[3], m[4]].map(Number)
  if (o.some(n => n > 255)) return null                 // invalid octet → unscoped
  return `${o[0]}.${o[1]}.${o[2]}.0/24`
}

// ── Pure matcher ─────────────────────────────────────────────────
export type MatchRuleLabel = 1 | 2 | 3 | 4 | 5 | 6 | '1-possible-duplicate'

export interface MatcherInput {
  macClass: MacClass
  mac: string | null       // normalized; null when invalid/no MAC
  ip: string
  hostKey: string | null   // already sanitised
  networkKey: string | null
}

export interface CandidateAddress {
  addressId: string
  assetId: string
  networkKey: string | null
  ipAddress: string
  macAddress: string | null
  assetDeviceType: string
}

export interface MatcherCandidates {
  /** Current (ended_at NULL) addresses whose mac == input.mac, any network. */
  macAddresses: CandidateAddress[]
  /** Assets with host_key == input.hostKey AND a current address on input.networkKey. */
  hostKeyAssetIds: string[]
  /** Current addresses matching (networkKey+ip), or an unscoped row with that ip. */
  netIpAddresses: CandidateAddress[]
}

export type MatchDecision =
  | { rule: 1; assetId: string; matchedAddressId: string }
  | { rule: '1-possible-duplicate'; assetId: null; possibleDuplicateOf: string }
  | { rule: 2; assetId: string; matchedAddressId: string }
  | { rule: 3; assetId: string; matchedAddressId: null }
  | { rule: 4; assetId: string; matchedAddressId: string }
  | { rule: 5; assetId: null; endAddressId: string }
  | { rule: 6; assetId: null }

/**
 * First-match-wins matcher. Hostname alone NEVER matches (callers pass a
 * sanitised hostKey, and rule 3 additionally requires a same-network address).
 *
 * Tiebreakers: when several legacy assets (IP-keyed era) share a MAC or IP, the
 * candidate arrays MUST be ordered so the preferred asset is first — most recent
 * `last_seen`, then oldest `created_at`. resolveAssetIdentity enforces this via
 * ORDER BY; this matcher then deterministically takes index 0 / the first `find`.
 */
export function matchAsset(input: MatcherInput, cand: MatcherCandidates): MatchDecision {
  const usableMac = input.macClass === 'global' || input.macClass === 'local'

  // Rule 1 — global MAC, any network.
  if (input.macClass === 'global' && cand.macAddresses.length > 0) {
    const hit = cand.macAddresses[0]!
    // The "network/server device on a different network" exception applies ONLY
    // when BOTH keys are non-null and differ. An unscoped matched address
    // (network_key NULL, e.g. a manual asset) counts as compatible → still merge
    // (the caller fills in its network_key on match).
    const crossNetwork = hit.networkKey !== null && input.networkKey !== null && hit.networkKey !== input.networkKey
    if ((hit.assetDeviceType === 'network' || hit.assetDeviceType === 'server') && crossNetwork) {
      // A router/server's global MAC seen on a different network is more likely a
      // second device sharing an uplink than the same box — do NOT merge.
      return { rule: '1-possible-duplicate', assetId: null, possibleDuplicateOf: hit.assetId }
    }
    return { rule: 1, assetId: hit.assetId, matchedAddressId: hit.addressId }
  }

  // Rule 2 — local MAC + same network. An unscoped address (network_key NULL) is
  // eligible only when its IP equals the incoming IP (treat it as the same network).
  if (input.macClass === 'local' && input.networkKey !== null) {
    const hit = cand.macAddresses.find(a =>
      a.networkKey === input.networkKey ||
      (a.networkKey === null && a.ipAddress === input.ip))
    if (hit) return { rule: 2, assetId: hit.assetId, matchedAddressId: hit.addressId }
  }

  // Rule 3 — host_key + same network.
  if (input.hostKey && input.networkKey !== null && cand.hostKeyAssetIds.length > 0) {
    return { rule: 3, assetId: cand.hostKeyAssetIds[0]!, matchedAddressId: null }
  }

  // Rules 4 / 5 — current (net+ip) or unscoped-ip address. netIpAddresses already
  // includes unscoped rows (network_key NULL) with the matching IP, so rule 5
  // (same IP, different valid MAC) applies to unscoped manual assets too.
  const ipHit = cand.netIpAddresses[0]
  if (ipHit) {
    if (!usableMac || ipHit.macAddress === null) {
      return { rule: 4, assetId: ipHit.assetId, matchedAddressId: ipHit.addressId } // fill MAC/network
    }
    if (input.mac && ipHit.macAddress !== input.mac) {
      return { rule: 5, assetId: null, endAddressId: ipHit.addressId }              // different device on reused IP
    }
    return { rule: 4, assetId: ipHit.assetId, matchedAddressId: ipHit.addressId }   // same MAC (unscoped local)
  }

  // Rule 6 — new asset.
  return { rule: 6, assetId: null }
}

// ── DB wrapper ───────────────────────────────────────────────────
export interface ResolveInput {
  tenantId: string | null
  ip: string
  rawMac: unknown
  hostKey: unknown
  isManualSource: boolean
}

export interface ResolveResult {
  rule: MatchRuleLabel
  assetId: string | null            // null → create a new asset
  possibleDuplicateOf: string | null
  endAddressId: string | null       // rule 5: old address to end before inserting the new device
  /** The matched asset's current address on THIS network, if any — lets the
   *  caller detect an IP change (DHCP) and fill MAC/network onto an existing row. */
  currentAddress: { addressId: string; ipAddress: string; macAddress: string | null; networkKey: string | null } | null
  mac: string | null                // normalized/classified MAC (null if unusable)
  macClass: MacClass
  hostKey: string | null            // sanitised host key
  networkKey: string | null         // derived /24 (or null); caller stamps it on address rows
}

const tenantCond = (tenantId: string | null) =>
  tenantId ? eq(assetAddresses.tenantId, tenantId) : isNull(assetAddresses.tenantId)

/**
 * Resolve which asset an observed (ip, mac, hostKey, network) belongs to.
 * Read-only: fetches candidates and runs the pure matcher. The caller performs
 * the UPDATE or INSERT (and the address-row writes) so a new asset's id is
 * available for its address row. See scans.ts for the write sequencing + the
 * unique-violation retry that makes the check-then-insert race harmless.
 */
export async function resolveAssetIdentity(db: DB, input: ResolveInput): Promise<ResolveResult> {
  const { mac, macClass } = classifyMac(input.rawMac)
  const hostKey = sanitizeHostKey(input.hostKey)
  const networkKey = deriveNetworkKey({ ip: input.ip, isManualSource: input.isManualSource })
  const usableMac = macClass === 'global' || macClass === 'local'

  // Tiebreaker ordering for all candidate sets: most-recent last_seen, then oldest
  // created_at — so legacy duplicates resolve to a single deterministic asset.
  const tiebreak = [desc(assetAddresses.lastSeen), asc(assets.createdAt)] as const

  // Candidate set 1 — current addresses with this MAC (any network), + device type.
  let macAddresses: CandidateAddress[] = []
  if (usableMac && mac) {
    const rows = await db
      .select({
        addressId: assetAddresses.addressId,
        assetId: assetAddresses.assetId,
        networkKey: assetAddresses.networkKey,
        ipAddress: assetAddresses.ipAddress,
        macAddress: assetAddresses.macAddress,
        assetDeviceType: assets.deviceType,
      })
      .from(assetAddresses)
      .innerJoin(assets, eq(assets.assetId, assetAddresses.assetId))
      .where(and(tenantCond(input.tenantId), isNull(assetAddresses.endedAt), eq(assetAddresses.macAddress, mac)))
      .orderBy(...tiebreak)
    macAddresses = rows as CandidateAddress[]
  }

  // Candidate set 2 — assets with this host_key AND a current address on this
  // network, OR an unscoped address with the incoming IP (same-network by IP).
  let hostKeyAssetIds: string[] = []
  if (hostKey && networkKey !== null) {
    const rows = await db
      .select({ assetId: assetAddresses.assetId })
      .from(assetAddresses)
      .innerJoin(assets, eq(assets.assetId, assetAddresses.assetId))
      .where(and(
        tenantCond(input.tenantId),
        isNull(assetAddresses.endedAt),
        eq(assets.hostKey, hostKey),
        or(
          eq(assetAddresses.networkKey, networkKey),
          and(isNull(assetAddresses.networkKey), eq(assetAddresses.ipAddress, input.ip)),
        ),
      ))
      .orderBy(...tiebreak)
    hostKeyAssetIds = rows.map(r => r.assetId)
  }

  // Candidate set 3 — current address on (network+ip), or an unscoped row with that ip.
  const ipScopeCond = networkKey !== null
    ? or(eq(assetAddresses.networkKey, networkKey), isNull(assetAddresses.networkKey))
    : isNull(assetAddresses.networkKey)
  const netIpRows = await db
    .select({
      addressId: assetAddresses.addressId,
      assetId: assetAddresses.assetId,
      networkKey: assetAddresses.networkKey,
      ipAddress: assetAddresses.ipAddress,
      macAddress: assetAddresses.macAddress,
      assetDeviceType: assets.deviceType,
    })
    .from(assetAddresses)
    .innerJoin(assets, eq(assets.assetId, assetAddresses.assetId))
    .where(and(tenantCond(input.tenantId), isNull(assetAddresses.endedAt), eq(assetAddresses.ipAddress, input.ip), ipScopeCond))
    .orderBy(...tiebreak)
  const netIpAddresses = netIpRows as CandidateAddress[]

  const decision = matchAsset(
    { macClass, mac, ip: input.ip, hostKey, networkKey },
    { macAddresses, hostKeyAssetIds, netIpAddresses },
  )

  // For an UPDATE match, find the asset's current address on THIS network so the
  // caller can detect an IP change (DHCP) or fill MAC/network onto an empty row.
  let currentAddress: ResolveResult['currentAddress'] = null
  if (decision.assetId) {
    const matchById = (id: string) =>
      netIpAddresses.find(a => a.addressId === id) ?? macAddresses.find(a => a.addressId === id)
    const direct = 'matchedAddressId' in decision && decision.matchedAddressId
      ? matchById(decision.matchedAddressId)
      : undefined
    const onThisNet = direct
      ?? [...netIpAddresses, ...macAddresses].find(a => a.assetId === decision.assetId && a.networkKey === networkKey)
    if (onThisNet) {
      currentAddress = {
        addressId: onThisNet.addressId,
        ipAddress: onThisNet.ipAddress,
        macAddress: onThisNet.macAddress,
        networkKey: onThisNet.networkKey,
      }
    }
  }

  return {
    rule: decision.rule,
    assetId: decision.assetId,
    possibleDuplicateOf: decision.rule === '1-possible-duplicate' ? decision.possibleDuplicateOf : null,
    endAddressId: decision.rule === 5 ? decision.endAddressId : null,
    currentAddress,
    mac,
    macClass,
    hostKey,
    networkKey,
  }
}

// ── Batch prefetch ───────────────────────────────────────────────
/**
 * Fetch, in at most THREE queries for the whole batch, every candidate row the
 * in-memory planner (lib/ingest-plan.ts) needs: current addresses whose MAC is in
 * the batch, current addresses whose IP is in the batch, and assets whose host_key
 * is in the batch (joined to their current addresses). Replaces the old ~3
 * queries-per-host, keeping subrequests constant. Empty IN-lists are skipped.
 */
export async function prefetchIdentity(
  db: DB,
  tenantId: string | null,
  macs: string[],
  ips: string[],
  hostKeys: string[],
): Promise<IdentityPrefetch> {
  const addrById = new Map<string, IdentityPrefetch['addresses'][number]>()
  const assetById = new Map<string, IdentityPrefetch['assets'][number]>()

  const sel = {
    addressId: assetAddresses.addressId,
    assetId: assetAddresses.assetId,
    networkKey: assetAddresses.networkKey,
    ipAddress: assetAddresses.ipAddress,
    macAddress: assetAddresses.macAddress,
    lastSeen: assetAddresses.lastSeen,
    deviceType: assets.deviceType,
    assetCreatedAt: assets.createdAt,
    osInfo: assets.osInfo,
    hostname: assets.hostname,
    owner: assets.owner,
    hardwareVendor: assets.hardwareVendor,
    assetMac: assets.macAddress,
    source: assets.source,
    deviceTypeSource: assets.deviceTypeSource,
    hostKey: assets.hostKey,
    baselineState: assets.baselineState,
    internetFacingOverride: assets.internetFacingOverride,
  }
  const toMs = (v: unknown): number => (v ? new Date(v as string | Date).getTime() : 0)
  const absorb = (r: Record<string, unknown>) => {
    const addressId = r.addressId as string
    if (!addrById.has(addressId)) {
      addrById.set(addressId, {
        addressId,
        assetId: r.assetId as string,
        networkKey: (r.networkKey as string | null) ?? null,
        ipAddress: r.ipAddress as string,
        macAddress: (r.macAddress as string | null) ?? null,
        deviceType: r.deviceType as string,
        lastSeen: toMs(r.lastSeen),
        assetCreatedAt: toMs(r.assetCreatedAt),
      })
    }
    const assetId = r.assetId as string
    if (!assetById.has(assetId)) {
      assetById.set(assetId, {
        assetId,
        deviceType: r.deviceType as string,
        hostKey: (r.hostKey as string | null) ?? null,
        osInfo: (r.osInfo as Record<string, unknown> | null) ?? null,
        hostname: (r.hostname as string | null) ?? null,
        owner: (r.owner as string | null) ?? null,
        hardwareVendor: (r.hardwareVendor as string | null) ?? null,
        macAddress: (r.assetMac as string | null) ?? null,
        source: r.source as string,
        deviceTypeSource: (r.deviceTypeSource as string | null) ?? null,
        hasBaseline: r.baselineState != null,
        baseline: (r.baselineState as AssetBaseline | null) ?? null,
        internetFacingOverride: (r.internetFacingOverride as boolean | null) ?? null,
      })
    }
  }
  const tCondAddr = tenantId ? eq(assetAddresses.tenantId, tenantId) : isNull(assetAddresses.tenantId)
  const tCondAsset = tenantId ? eq(assets.tenantId, tenantId) : isNull(assets.tenantId)

  if (macs.length > 0) {
    const rows = await db.select(sel).from(assetAddresses)
      .innerJoin(assets, eq(assets.assetId, assetAddresses.assetId))
      .where(and(tCondAddr, isNull(assetAddresses.endedAt), inArray(assetAddresses.macAddress, macs)))
    for (const r of rows) absorb(r as Record<string, unknown>)
  }
  if (ips.length > 0) {
    const rows = await db.select(sel).from(assetAddresses)
      .innerJoin(assets, eq(assets.assetId, assetAddresses.assetId))
      .where(and(tCondAddr, isNull(assetAddresses.endedAt), inArray(assetAddresses.ipAddress, ips)))
    for (const r of rows) absorb(r as Record<string, unknown>)
  }
  if (hostKeys.length > 0) {
    const rows = await db.select(sel).from(assets)
      .innerJoin(assetAddresses, and(eq(assetAddresses.assetId, assets.assetId), isNull(assetAddresses.endedAt)))
      .where(and(tCondAsset, inArray(assets.hostKey, hostKeys)))
    for (const r of rows) absorb(r as Record<string, unknown>)
  }

  return { addresses: [...addrById.values()], assets: [...assetById.values()] }
}
