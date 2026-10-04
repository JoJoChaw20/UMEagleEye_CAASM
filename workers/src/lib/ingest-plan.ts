/**
 * ingest-plan.ts — PURE, batched identity + write planner for scan ingest.
 *
 * The old path issued ~3 reads + ~3 writes per host, so a 9-host scan blew the
 * Cloudflare "Too many subrequests" limit (50 on Free). This planner takes the
 * whole batch plus prefetched candidate rows (3 queries total, done by the
 * caller) and resolves every host IN MEMORY using the existing matchAsset rules,
 * emitting a flat list of write operations. The caller runs those with db.batch()
 * in chunks, so total subrequests are ~constant regardless of host count.
 *
 * Batch-awareness: a mutable working copy of addresses + assets is updated as each
 * host resolves, so two hosts that resolve to the same new asset, or a host that
 * claims an address another host just ended/created, see each other's results.
 *
 * Pure (no DB, no Hono). Tested by scripts/identity-demo.ts.
 */
import {
  classifyMac, sanitizeHostKey, deriveNetworkKey, matchAsset,
  type CandidateAddress, type MatchRuleLabel,
} from './identity'
import { mergeOsInfo } from './osInfo'
import { computeCriticality } from './criticality'
import { buildBaseline, type AssetBaseline } from '../services/drift'

// ── Prefetched candidate data (filled by identity.prefetchIdentity) ──
export interface PrefetchAddress {
  addressId: string
  assetId: string
  networkKey: string | null
  ipAddress: string
  macAddress: string | null
  deviceType: string
  lastSeen: number        // epoch ms — tiebreak (desc)
  assetCreatedAt: number  // epoch ms — tiebreak (asc)
}
export interface PrefetchAsset {
  assetId: string
  deviceType: string
  hostKey: string | null
  osInfo: Record<string, unknown> | null
  hostname: string | null
  owner: string | null
  hardwareVendor: string | null
  macAddress: string | null
  source: string
  hasBaseline: boolean
  baseline?: AssetBaseline | null            // to complete a passive-captured baseline
  internetFacingOverride?: boolean | null    // analyst-confirmed exposure wins over inference
}
export interface IdentityPrefetch {
  addresses: PrefetchAddress[]
  assets: PrefetchAsset[]
}

export type DeviceTypeStr = 'server' | 'workstation' | 'network' | 'iot' | 'unknown'

// ── One host to resolve (caller precomputes deviceType + observedOsInfo) ──
export interface PlanHost {
  ip: string
  rawMac: unknown
  hostname: string | null
  hostKeyRaw: unknown
  deviceType: DeviceTypeStr                  // inferDeviceType + SNMP + LLM fallback
  observedOsInfo: Record<string, unknown>   // buildOsInfo(+snmp), port keys forced for active
  ports: number[]                           // integer ports for the baseline
  hardwareVendor: string | null
  internetFacing: boolean
  isPassive: boolean
  tenantId: string | null
}

// ── Emitted write operations (data only; caller maps to Drizzle) ──
export type IngestOp =
  | { k: 'insertAsset'; values: Record<string, unknown> }
  | { k: 'updateAsset'; assetId: string; set: Record<string, unknown> }
  | { k: 'endAddress'; addressId: string }
  | { k: 'insertAddress'; values: Record<string, unknown> }
  | { k: 'updateAddress'; addressId: string; set: Record<string, unknown> }
  | { k: 'insertEvent'; values: Record<string, unknown> }

export interface PlannedHost {
  ip: string
  assetId: string
  rule: MatchRuleLabel
  isNew: boolean
  possibleDuplicateOf: string | null
  ops: IngestOp[]
}
export interface IngestPlan {
  perHost: PlannedHost[]
  upsertedAssetIds: string[]
  statementCount: number
}

interface WorkAddr {
  addressId: string
  assetId: string
  networkKey: string | null
  ipAddress: string
  macAddress: string | null
  deviceType: string
  lastSeen: number
  assetCreatedAt: number
  ended: boolean
}
interface MutAsset {
  assetId: string
  deviceType: string
  hostKey: string | null
  osInfo: Record<string, unknown>
  hostname: string | null
  owner: string | null
  hardwareVendor: string | null
  macAddress: string | null
  source: string
  hasBaseline: boolean
  baseline?: AssetBaseline | null
  internetFacingOverride?: boolean | null
}

/** Resolve + plan writes for a whole batch in memory. */
export function planIngest(
  hosts: PlanHost[],
  prefetch: IdentityPrefetch,
  opts?: { newId?: () => string; now?: Date },
): IngestPlan {
  const newId = opts?.newId ?? (() => crypto.randomUUID())
  const now = opts?.now ?? new Date()

  // Working store, seeded from the prefetch. Addresses pre-sorted by the
  // tiebreaker so matchAsset's first-element pick is deterministic; new rows are
  // unshifted (newest last_seen → front).
  const workAddrs: WorkAddr[] = prefetch.addresses
    .map(a => ({ ...a, ended: false }))
    .sort((x, y) => (y.lastSeen - x.lastSeen) || (x.assetCreatedAt - y.assetCreatedAt))
  const assetState = new Map<string, MutAsset>()
  for (const a of prefetch.assets) {
    assetState.set(a.assetId, { ...a, osInfo: a.osInfo ?? {} })
  }

  const perHost: PlannedHost[] = []
  const upsertedAssetIds: string[] = []
  let statementCount = 0

  const addrValues = (addressId: string, assetId: string, networkKey: string | null, ip: string, mac: string | null, tenantId: string | null) => ({
    addressId, assetId, tenantId, networkKey, ipAddress: ip, macAddress: mac, firstSeen: now, lastSeen: now,
  })

  for (const host of hosts) {
    const ops: IngestOp[] = []
    const { mac, macClass } = classifyMac(host.rawMac)
    const hostKey = sanitizeHostKey(host.hostKeyRaw)
    const networkKey = deriveNetworkKey({ ip: host.ip, isManualSource: false })
    const usableMac = macClass === 'global' || macClass === 'local'

    const toCand = (w: WorkAddr): CandidateAddress => ({
      addressId: w.addressId, assetId: w.assetId, networkKey: w.networkKey,
      ipAddress: w.ipAddress, macAddress: w.macAddress,
      assetDeviceType: assetState.get(w.assetId)?.deviceType ?? w.deviceType,
    })

    const macAddresses = (usableMac && mac)
      ? workAddrs.filter(w => !w.ended && w.macAddress === mac).map(toCand)
      : []
    const netIpAddresses = workAddrs
      .filter(w => !w.ended && w.ipAddress === host.ip &&
        (networkKey === null ? w.networkKey === null : (w.networkKey === networkKey || w.networkKey === null)))
      .map(toCand)
    let hostKeyAssetIds: string[] = []
    if (hostKey && networkKey !== null) {
      const ids = new Set<string>()
      for (const w of workAddrs) {
        if (w.ended) continue
        const st = assetState.get(w.assetId)
        if (st?.hostKey === hostKey && (w.networkKey === networkKey || (w.networkKey === null && w.ipAddress === host.ip))) {
          ids.add(w.assetId)
        }
      }
      hostKeyAssetIds = [...ids]
    }

    const decision = matchAsset(
      { macClass, mac, ip: host.ip, hostKey, networkKey },
      { macAddresses, hostKeyAssetIds, netIpAddresses },
    )

    let assetId: string
    let isNew: boolean

    if (decision.assetId) {
      // ── UPDATE matched asset ──
      assetId = decision.assetId
      isNew = false
      const st = assetState.get(assetId)!
      const merged = mergeOsInfo(st.osInfo, host.observedOsInfo, host.isPassive).merged
      const resolvedDeviceType = (st.deviceType && st.deviceType !== 'unknown') ? st.deviceType : host.deviceType
      // Analyst-confirmed exposure wins; otherwise the scan's gateway inference
      const exposed = st.internetFacingOverride ?? host.internetFacing
      const crit = computeCriticality({
        deviceType: resolvedDeviceType, isInternetFacing: exposed,
        hostname: host.hostname ?? st.hostname, owner: st.owner ?? null, osInfo: merged,
      }).score
      const resolvedSource = st.source === 'manual' ? 'manual' : (host.isPassive ? 'scan_passive' : 'scan_active')
      const newHostname = st.hostname ?? host.hostname ?? null
      const newMac = mac ?? st.macAddress ?? null
      const newHostKey = st.hostKey ?? hostKey ?? null
      const newVendor = host.hardwareVendor ?? st.hardwareVendor ?? null

      const set: Record<string, unknown> = {
        ipAddress: host.ip,
        hostname: newHostname,
        macAddress: newMac,
        hostKey: newHostKey,
        hardwareVendor: newVendor,
        osInfo: merged,
        deviceType: resolvedDeviceType,
        isInternetFacing: exposed,
        criticalityScore: crit,
        source: resolvedSource,
        lastScanned: now,
        updatedAt: now,
      }
      let nextBaseline: AssetBaseline | null = st.baseline ?? null
      if (!st.hasBaseline) {
        nextBaseline = buildBaseline({
          ports: host.ports, osInfo: merged, hostname: newHostname, macAddress: newMac,
          isInternetFacing: exposed, deviceType: resolvedDeviceType, autoSet: true,
          portsKnown: !host.isPassive,
        })
        set.baselineState = nextBaseline
      } else if (!host.isPassive && st.baseline) {
        // Complete a baseline captured before ports or SNMP were visible —
        // learning a fact for the first time is not drift.
        const patch: Partial<AssetBaseline> = {}
        if (st.baseline.ports_known === false) {
          patch.ports = host.ports
          patch.ports_known = true
        }
        if (!st.baseline.snmp_sysdescr && typeof merged.snmp_sysdescr === 'string') {
          patch.snmp_sysdescr = merged.snmp_sysdescr
        }
        if (Object.keys(patch).length > 0) {
          nextBaseline = { ...st.baseline, ...patch }
          set.baselineState = nextBaseline
        }
      }
      ops.push({ k: 'updateAsset', assetId, set })

      // Address bookkeeping — same IP: refresh; IP changed: end + insert; none: insert.
      const matchedId = (decision.rule !== 3 && 'matchedAddressId' in decision) ? decision.matchedAddressId : null
      let cur = matchedId ? workAddrs.find(w => !w.ended && w.addressId === matchedId) : undefined
      if (!cur) cur = workAddrs.find(w => !w.ended && w.assetId === assetId && (w.networkKey === networkKey || w.networkKey === null))
      if (cur && cur.ipAddress === host.ip) {
        const filledMac = cur.macAddress ?? mac ?? null
        const filledNet = cur.networkKey ?? networkKey ?? null
        ops.push({ k: 'updateAddress', addressId: cur.addressId, set: { lastSeen: now, macAddress: filledMac, networkKey: filledNet } })
        cur.macAddress = filledMac; cur.networkKey = filledNet; cur.lastSeen = now.getTime()
      } else {
        if (cur) { ops.push({ k: 'endAddress', addressId: cur.addressId }); cur.ended = true }
        const nid = newId()
        ops.push({ k: 'insertAddress', values: addrValues(nid, assetId, networkKey, host.ip, mac, host.tenantId) })
        workAddrs.unshift({ addressId: nid, assetId, networkKey, ipAddress: host.ip, macAddress: mac, deviceType: resolvedDeviceType, lastSeen: now.getTime(), assetCreatedAt: 0, ended: false })
      }

      assetState.set(assetId, {
        ...st, osInfo: merged, deviceType: resolvedDeviceType, hostKey: newHostKey,
        hardwareVendor: newVendor, source: resolvedSource, hasBaseline: true,
        hostname: newHostname, macAddress: newMac, baseline: nextBaseline,
      })
    } else {
      // ── CREATE new asset (rule 5 / 6 / 1-possible-duplicate) ──
      assetId = newId()
      isNew = true
      const merged = mergeOsInfo(null, host.observedOsInfo, host.isPassive).merged
      const crit = computeCriticality({
        deviceType: host.deviceType, isInternetFacing: host.internetFacing,
        hostname: host.hostname, owner: null, osInfo: merged,
      }).score
      const baseline = buildBaseline({
        ports: host.ports, osInfo: merged, hostname: host.hostname ?? null, macAddress: mac ?? null,
        isInternetFacing: host.internetFacing, deviceType: host.deviceType, autoSet: true,
        // A passive first sighting sees no ports; the first active scan fills
        // them in instead of raising "port opened" for every service.
        portsKnown: !host.isPassive,
      })
      const source = host.isPassive ? 'scan_passive' : 'scan_active'

      // rule 5: end the reused-IP address first (order: end before inserts).
      if (decision.rule === 5) {
        ops.push({ k: 'endAddress', addressId: decision.endAddressId })
        const w = workAddrs.find(x => !x.ended && x.addressId === decision.endAddressId)
        if (w) w.ended = true
      }
      ops.push({ k: 'insertAsset', values: {
        assetId, tenantId: host.tenantId, ipAddress: host.ip, hostname: host.hostname ?? null,
        macAddress: mac ?? null, hostKey: hostKey ?? null, hardwareVendor: host.hardwareVendor ?? null,
        deviceType: host.deviceType, osInfo: merged, isInternetFacing: host.internetFacing,
        criticalityScore: crit, baselineState: baseline, source, lastScanned: now, createdAt: now, updatedAt: now,
      } })
      const nid = newId()
      ops.push({ k: 'insertAddress', values: addrValues(nid, assetId, networkKey, host.ip, mac, host.tenantId) })
      ops.push({ k: 'insertEvent', values: {
        assetId, eventType: 'new_device', severity: host.internetFacing ? 'high' : 'medium',
        details: { ip: host.ip, mac: mac ?? null, hostname: host.hostname ?? null, source: host.isPassive ? 'passive_scan' : 'active_scan' },
      } })

      assetState.set(assetId, {
        assetId, deviceType: host.deviceType, hostKey, osInfo: merged, hostname: host.hostname ?? null,
        owner: null, hardwareVendor: host.hardwareVendor ?? null, macAddress: mac ?? null, source, hasBaseline: true,
        baseline, internetFacingOverride: null,
      })
      workAddrs.unshift({ addressId: nid, assetId, networkKey, ipAddress: host.ip, macAddress: mac, deviceType: host.deviceType, lastSeen: now.getTime(), assetCreatedAt: now.getTime(), ended: false })
    }

    const possibleDuplicateOf = decision.rule === '1-possible-duplicate' ? decision.possibleDuplicateOf : null
    perHost.push({ ip: host.ip, assetId, rule: decision.rule, isNew, possibleDuplicateOf, ops })
    upsertedAssetIds.push(assetId)
    statementCount += ops.length
  }

  return { perHost, upsertedAssetIds, statementCount }
}

export interface PlanChunk { hosts: PlannedHost[]; ops: IngestOp[] }

/**
 * Group planned hosts into chunks of at most `maxStatements` operations WITHOUT
 * splitting a single host's ops across chunks (so a failed chunk maps to a known
 * host set for the slow-path retry). Each chunk → one db.batch → one subrequest.
 */
export function chunkPlan(perHost: PlannedHost[], maxStatements: number): PlanChunk[] {
  const chunks: PlanChunk[] = []
  let cur: PlanChunk = { hosts: [], ops: [] }
  for (const ph of perHost) {
    if (ph.ops.length === 0) { cur.hosts.push(ph); continue }
    if (cur.ops.length > 0 && cur.ops.length + ph.ops.length > maxStatements) {
      chunks.push(cur); cur = { hosts: [], ops: [] }
    }
    cur.hosts.push(ph)
    cur.ops.push(...ph.ops)
  }
  if (cur.ops.length > 0 || cur.hosts.length > 0) chunks.push(cur)
  return chunks
}
