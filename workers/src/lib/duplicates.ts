/**
 * duplicates.ts — PURE detection of legacy duplicate assets (no DB, no Hono).
 *
 * Phase A split identity from IP, but assets created under the old IP-keyed model
 * can still be split across multiple rows. This groups them (union-find) by the
 * identity evidence rules, flagging each group SAFE (auto-mergeable) or REVIEW.
 *
 * Reuses classifyMac / isSharedVirtualMac / sanitizeHostKey from identity.ts so
 * the evidence rules never diverge from the resolver. Tested by identity-demo.ts.
 */
import { classifyMac, isSharedVirtualMac } from './identity'
import { differentHardware, normalizeHardwareUuid } from './machineIdentity'
import { isGenericHostname } from './hostnames'

// A hostname is evidence only when someone chose it. Platform defaults ("Android",
// "Android-2", "android-<hex>", "iPhone", UUID-style...; lib/hostnames.ts, the same
// list the scans use) are shared by unrelated devices: three different phones called
// "Android" were grouped as one, and had to be dismissed by hand.
function reportHostname(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null
  const v = raw.trim().toLowerCase()
  if (!v) return null
  return isGenericHostname(v) ? null : v
}

export interface DupAsset {
  assetId: string
  hostname: string | null
  ipAddress: string
  macAddress: string | null
  source: string
  inMyAssets: boolean
  deviceType: string
  lastScanned: string | Date | null
  createdAt: string | Date | null
  hostKey?: string | null
}
export interface DupAddress {
  addressId: string
  assetId: string
  networkKey: string | null
  ipAddress: string
  macAddress: string | null
  endedAt: string | Date | null
  firstSeen?: string | Date | null
  lastSeen?: string | Date | null
}
/** A machine identifier an agent reported (asset_identifiers). */
export interface DupIdentifier {
  assetId: string
  kind: string     // hardware_uuid | os_install_id | mac
  value: string
}
export interface DuplicateGroupAsset {
  assetId: string
  hostname: string | null
  ipAddress: string
  macAddress: string | null
  source: string
  inMyAssets: boolean
  deviceType: string
  lastScanned: string | Date | null
  createdAt: string | Date | null
  addressCount: number
  eventCount?: number
}
export interface DuplicateEdge { a: string; b: string; confidence: 'safe' | 'review'; reason: string }
export interface DuplicateGroup {
  groupId: string
  confidence: 'safe' | 'review'
  reasons: string[]
  assets: DuplicateGroupAsset[]
  suggestedSurvivorId: string
  /** The evidence links inside the group (what "Not a duplicate" dismisses). */
  edges: DuplicateEdge[]
  /** A pair in this group was dismissed, but strong evidence appeared since. */
  reraised: boolean
  /** That new strong evidence (empty unless reraised). */
  newEvidence: string[]
}

/**
 * An analyst's "Not a duplicate" for one pair of assets, with the evidence shown when
 * it was dismissed (duplicate_dismissals). The pair stays apart until it is undone, or
 * until a SAFE link appears whose reason is not in `reasons` (new strong evidence,
 * e.g. the same hardware UUID), which brings the pair back for review.
 */
export interface DupDismissal { assetA: string; assetB: string; reasons: string[] }

/** Order-independent key of an asset pair; dismissals are stored with assetA < assetB. */
export const pairKey = (a: string, b: string): string => (a < b ? `${a}|${b}` : `${b}|${a}`)

const ms = (v: string | Date | null | undefined): number => (v ? new Date(v).getTime() : 0)

/** Stable short hash of the sorted asset ids → stable groupId across requests. */
function hashIds(ids: string[]): string {
  const s = [...ids].sort().join('|')
  let h = 0x811c9dc5
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) }
  return 'grp_' + (h >>> 0).toString(16).padStart(8, '0')
}

type Edge = DuplicateEdge

export function findDuplicateGroups(
  assets: DupAsset[],
  addresses: DupAddress[],
  eventCounts?: Map<string, number>,
  identifiers: DupIdentifier[] = [],
  dismissals: DupDismissal[] = [],
): DuplicateGroup[] {
  const assetById = new Map(assets.map(a => [a.assetId, a]))
  const addrByAsset = new Map<string, DupAddress[]>()
  for (const ad of addresses) {
    if (!assetById.has(ad.assetId)) continue
    const list = addrByAsset.get(ad.assetId) ?? []
    list.push(ad); addrByAsset.set(ad.assetId, list)
  }
  const isNetOrServer = (a: DupAsset) => a.deviceType === 'network' || a.deviceType === 'server'

  // ── Union-find ──
  const parent = new Map<string, string>()
  const find = (x: string): string => {
    let r = x
    while (parent.get(r) !== r) r = parent.get(r)!
    while (parent.get(x) !== r) { const n = parent.get(x)!; parent.set(x, r); x = n }
    return r
  }
  const union = (a: string, b: string) => { parent.set(find(a), find(b)) }
  for (const a of assets) parent.set(a.assetId, a.assetId)

  const edges: Edge[] = []

  // ── MAC-based evidence ──
  // Build mac → [{assetId, net, ip}] from every address row (any network, incl. ended).
  interface MacEntry { assetId: string; net: string | null; ip: string }
  const byMac = new Map<string, { cls: 'global' | 'local'; entries: MacEntry[] }>()
  for (const ad of addresses) {
    if (!assetById.has(ad.assetId)) continue
    const { mac, macClass } = classifyMac(ad.macAddress)
    if (!mac || macClass === 'invalid') continue
    if (isSharedVirtualMac(mac)) continue           // never group on shared/virtual
    const bucket = byMac.get(mac) ?? { cls: macClass as 'global' | 'local', entries: [] }
    bucket.entries.push({ assetId: ad.assetId, net: ad.networkKey, ip: ad.ipAddress })
    byMac.set(mac, bucket)
  }

  for (const [mac, { cls, entries }] of byMac) {
    // Distinct assets carrying this MAC.
    const assetIds = [...new Set(entries.map(e => e.assetId))]
    if (assetIds.length < 2) continue
    const entriesByAsset = new Map<string, MacEntry[]>()
    for (const e of entries) { const l = entriesByAsset.get(e.assetId) ?? []; l.push(e); entriesByAsset.set(e.assetId, l) }

    for (let i = 0; i < assetIds.length; i++) {
      for (let j = i + 1; j < assetIds.length; j++) {
        const x = assetById.get(assetIds[i]!)!, y = assetById.get(assetIds[j]!)!
        const ex = entriesByAsset.get(x.assetId)!, ey = entriesByAsset.get(y.assetId)!
        if (cls === 'global') {
          const xNets = new Set(ex.map(e => e.net).filter((n): n is string => n != null))
          const yNets = new Set(ey.map(e => e.net).filter((n): n is string => n != null))
          const disjoint = [...xNets].every(n => !yNets.has(n))
          const crossNetwork = isNetOrServer(x) && isNetOrServer(y) && xNets.size > 0 && yNets.size > 0 && disjoint
          if (crossNetwork) {
            edges.push({ a: x.assetId, b: y.assetId, confidence: 'review', reason: `network/server devices share global MAC ${mac} across different networks` })
          } else {
            edges.push({ a: x.assetId, b: y.assetId, confidence: 'safe', reason: `same global MAC ${mac}` })
          }
        } else {
          // local MAC — same non-null network, or one unscoped with equal IP.
          let matched: string | null = null
          outer: for (const a of ex) for (const b of ey) {
            if (a.net != null && a.net === b.net) { matched = `same local MAC ${mac} on ${a.net}`; break outer }
            if ((a.net == null || b.net == null) && a.ip === b.ip) { matched = `same local MAC ${mac} at ${a.ip} (unscoped)`; break outer }
          }
          if (matched) edges.push({ a: x.assetId, b: y.assetId, confidence: 'safe', reason: matched })
          // else: same local MAC on different networks → never grouped.
        }
      }
    }
  }

  const netsOfAsset = (id: string) => new Set((addrByAsset.get(id) ?? []).map(a => a.networkKey).filter((n): n is string => n != null))
  // When an asset was seen, from its address rows: [first seen, last seen]; null if unknown.
  const seenSpan = (id: string): [number, number] | null => {
    const rows = addrByAsset.get(id) ?? []
    const firsts = rows.map(r => ms(r.firstSeen)).filter(n => n > 0)
    const lasts = rows.map(r => Math.max(ms(r.lastSeen), ms(r.endedAt))).filter(n => n > 0)
    return firsts.length && lasts.length ? [Math.min(...firsts), Math.max(...lasts)] : null
  }
  const privateMac = (mac: string | null): boolean => {
    const { mac: m, macClass } = classifyMac(mac)
    return !!m && macClass === 'local' && !isSharedVirtualMac(m)
  }

  // ── Hostname evidence: same specific (non-generic) hostname, different MACs ──
  // REVIEW, except one case that is SAFE: both MACs private, a network in common, and
  // never seen at the same time. That is a phone or tablet whose private MAC changed
  // (Android and iOS rotate it, e.g. after the Wi-Fi is switched off and on); two
  // devices that share a name (two people with the same phone model) are seen together.
  // Scans never join them on their own (the analyst chose to decide here).
  const byHostname = new Map<string, string[]>()
  for (const a of assets) {
    const hn = reportHostname(a.hostname)
    if (!hn) continue
    const l = byHostname.get(hn) ?? []; l.push(a.assetId); byHostname.set(hn, l)
  }
  for (const [hn, ids] of byHostname) {
    const uniq = [...new Set(ids)]
    if (uniq.length < 2) continue
    for (let i = 0; i < uniq.length; i++) for (let j = i + 1; j < uniq.length; j++) {
      const x = assetById.get(uniq[i]!)!, y = assetById.get(uniq[j]!)!
      const mx = classifyMac(x.macAddress).mac, my = classifyMac(y.macAddress).mac
      if (mx && my && mx === my) continue   // same MAC already grouped as safe
      const sx = seenSpan(x.assetId), sy = seenSpan(y.assetId)
      const sharedNet = [...netsOfAsset(x.assetId)].some(n => netsOfAsset(y.assetId).has(n))
      const neverTogether = !!sx && !!sy && (sx[1] < sy[0] || sy[1] < sx[0])
      if (privateMac(x.macAddress) && privateMac(y.macAddress) && sharedNet && neverTogether) {
        edges.push({ a: x.assetId, b: y.assetId, confidence: 'safe', reason: `same name "${hn}", private MAC changed (never seen at the same time)` })
      } else {
        edges.push({ a: x.assetId, b: y.assetId, confidence: 'review', reason: `same hostname "${hn}", different MACs` })
      }
    }
  }

  // ── host_key evidence (REVIEW): same host_key on different networks ──
  const byHostKey = new Map<string, string[]>()
  for (const a of assets) {
    const hk = a.hostKey ? a.hostKey.toLowerCase() : null
    if (!hk) continue
    const l = byHostKey.get(hk) ?? []; l.push(a.assetId); byHostKey.set(hk, l)
  }
  for (const [hk, ids] of byHostKey) {
    const uniq = [...new Set(ids)]
    if (uniq.length < 2) continue
    for (let i = 0; i < uniq.length; i++) for (let j = i + 1; j < uniq.length; j++) {
      const xn = netsOfAsset(uniq[i]!), yn = netsOfAsset(uniq[j]!)
      const differentNetworks = xn.size > 0 && yn.size > 0 && [...xn].every(n => !yn.has(n))
      if (!differentNetworks) continue
      edges.push({ a: uniq[i]!, b: uniq[j]!, confidence: 'review', reason: `same host_key "${hk}" on different networks` })
    }
  }

  // ── Machine identifiers reported by agents ──
  const idsOf = (kind: string) => {
    const byAsset = new Map<string, string[]>()
    const byValue = new Map<string, string[]>()
    for (const raw of identifiers) {
      if (raw.kind !== kind || !assetById.has(raw.assetId)) continue
      // Hardware UUIDs group in their byte-order independent form (older rows are raw).
      const i = kind === 'hardware_uuid' ? { ...raw, value: normalizeHardwareUuid(raw.value) ?? raw.value.toLowerCase() } : raw
      const a = byAsset.get(i.assetId) ?? []; if (!a.includes(i.value)) a.push(i.value); byAsset.set(i.assetId, a)
      const v = byValue.get(i.value) ?? []; if (!v.includes(i.assetId)) v.push(i.assetId); byValue.set(i.value, v)
    }
    return { byAsset, byValue }
  }
  const hw = idsOf('hardware_uuid')
  const hwOf = (id: string) => hw.byAsset.get(id)
  const pairs = (ids: string[], each: (x: string, y: string) => void) => {
    for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) each(ids[i]!, ids[j]!)
  }
  // Same hardware UUID = same (virtual) machine.
  for (const [value, ids] of hw.byValue) {
    pairs(ids, (x, y) => { edges.push({ a: x, b: y, confidence: 'safe', reason: `same hardware UUID ${value}` }) })
  }
  // Same OS installation: the same machine, unless the hardware differs (cloned VM).
  for (const [value, ids] of idsOf('os_install_id').byValue) {
    pairs(ids, (x, y) => {
      edges.push(differentHardware(hwOf(x), hwOf(y))
        ? { a: x, b: y, confidence: 'review', reason: `same OS installation ID ${value} on different hardware (cloned VM or replaced mainboard)` }
        : { a: x, b: y, confidence: 'safe', reason: `same OS installation ID ${value}` })
    })
  }
  // A MAC the agent reported for its own NIC, seen on another asset by a scan or agent.
  const agentMacs = idsOf('mac')
  for (const [mac, owners] of agentMacs.byValue) {
    if (isSharedVirtualMac(mac)) continue
    const others = new Set<string>([...(byMac.get(mac)?.entries.map(e => e.assetId) ?? []), ...owners])
    for (const owner of owners) {
      for (const other of others) {
        if (other === owner || (owners.includes(other) && other < owner)) continue
        edges.push({ a: owner, b: other, confidence: 'safe', reason: `MAC ${mac} reported by the agent on this machine` })
      }
    }
  }
  // VM-clone guard: two assets with different known hardware UUIDs are different
  // machines, so no evidence makes them a safe merge.
  for (const e of edges) {
    if (e.confidence === 'safe' && differentHardware(hwOf(e.a), hwOf(e.b))) {
      e.confidence = 'review'
      e.reason += ', but the hardware UUIDs differ'
    }
  }

  // ── Dismissed pairs ("Not a duplicate") ──
  // A dismissed pair loses all its links before grouping, so it can only end up in one
  // group through OTHER assets (A~C~B is still a group when only A-B was dismissed).
  // It comes back, with all its links, when a safe link appears that was not part of
  // the evidence at dismissal time.
  const dismissedReasons = new Map(dismissals.map(d => [pairKey(d.assetA, d.assetB), new Set(d.reasons)]))
  const newEvidenceByPair = new Map<string, string[]>()
  for (const e of edges) {
    const known = dismissedReasons.get(pairKey(e.a, e.b))
    if (known && e.confidence === 'safe' && !known.has(e.reason)) {
      const k = pairKey(e.a, e.b)
      newEvidenceByPair.set(k, [...(newEvidenceByPair.get(k) ?? []), e.reason])
    }
  }
  const kept = edges.filter(e => {
    const k = pairKey(e.a, e.b)
    return !dismissedReasons.has(k) || newEvidenceByPair.has(k)
  })
  for (const e of kept) union(e.a, e.b)

  // ── Assemble groups ──
  const groupsByRoot = new Map<string, Set<string>>()
  for (const a of assets) {
    const r = find(a.assetId)
    const g = groupsByRoot.get(r) ?? new Set<string>(); g.add(a.assetId); groupsByRoot.set(r, g)
  }

  const out: DuplicateGroup[] = []
  for (const members of groupsByRoot.values()) {
    if (members.size < 2) continue
    const ids = [...members]
    const groupEdges = kept.filter(e => members.has(e.a) && members.has(e.b))
    const reasons = [...new Set(groupEdges.map(e => e.reason))]
    const confidence: 'safe' | 'review' = groupEdges.some(e => e.confidence === 'review') ? 'review' : 'safe'

    const groupAssets: DuplicateGroupAsset[] = ids.map(id => {
      const a = assetById.get(id)!
      return {
        assetId: a.assetId, hostname: a.hostname, ipAddress: a.ipAddress, macAddress: a.macAddress,
        source: a.source, inMyAssets: a.inMyAssets, deviceType: a.deviceType, lastScanned: a.lastScanned, createdAt: a.createdAt,
        addressCount: (addrByAsset.get(id) ?? []).length,
        ...(eventCounts ? { eventCount: eventCounts.get(id) ?? 0 } : {}),
      }
    })

    // Suggested survivor: My Assets member first → latest last_scanned → oldest created_at.
    const survivor = [...groupAssets].sort((x, y) => {
      const mx = x.inMyAssets ? 1 : 0, my = y.inMyAssets ? 1 : 0
      if (mx !== my) return my - mx
      const ls = ms(y.lastScanned) - ms(x.lastScanned)
      if (ls !== 0) return ls
      return ms(x.createdAt) - ms(y.createdAt)
    })[0]!

    const newEvidence = [...new Set(groupEdges.flatMap(e => newEvidenceByPair.get(pairKey(e.a, e.b)) ?? []))]
    out.push({
      groupId: hashIds(ids), confidence, reasons, assets: groupAssets, suggestedSurvivorId: survivor.assetId,
      edges: groupEdges, reraised: newEvidence.length > 0, newEvidence,
    })
  }

  // Deterministic order: review first (needs attention), then by size.
  out.sort((a, b) => (a.confidence === b.confidence ? b.assets.length - a.assets.length : a.confidence === 'review' ? -1 : 1))
  return out
}
