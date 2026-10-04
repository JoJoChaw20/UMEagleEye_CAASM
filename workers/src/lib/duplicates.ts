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

// Report-specific generic-hostname filter — intentionally NOT sanitizeHostKey
// (that is tuned for ingest and must not change). Ignores localhost, default
// iPhone/iPad, UUID-style names, and the REAL Android default ("android-" + 8+ hex).
// Short names like "Android-2" are treated as SPECIFIC (so they can surface as REVIEW).
const REPORT_GENERIC_HOST: RegExp[] = [
  /^localhost$/,
  /^iphone$/, /^ipad$/,
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,  // UUID-style
  /^android-[0-9a-f]{8,}$/,                                          // real Android default
]
function reportHostname(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null
  const v = raw.trim().toLowerCase()
  if (!v) return null
  return REPORT_GENERIC_HOST.some(re => re.test(v)) ? null : v
}

export interface DupAsset {
  assetId: string
  hostname: string | null
  ipAddress: string
  macAddress: string | null
  source: string
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
}
export interface DuplicateGroupAsset {
  assetId: string
  hostname: string | null
  ipAddress: string
  macAddress: string | null
  source: string
  deviceType: string
  lastScanned: string | Date | null
  createdAt: string | Date | null
  addressCount: number
  eventCount?: number
}
export interface DuplicateGroup {
  groupId: string
  confidence: 'safe' | 'review'
  reasons: string[]
  assets: DuplicateGroupAsset[]
  suggestedSurvivorId: string
}

const ms = (v: string | Date | null | undefined): number => (v ? new Date(v).getTime() : 0)

/** Stable short hash of the sorted asset ids → stable groupId across requests. */
function hashIds(ids: string[]): string {
  const s = [...ids].sort().join('|')
  let h = 0x811c9dc5
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) }
  return 'grp_' + (h >>> 0).toString(16).padStart(8, '0')
}

interface Edge { a: string; b: string; confidence: 'safe' | 'review'; reason: string }

export function findDuplicateGroups(
  assets: DupAsset[],
  addresses: DupAddress[],
  eventCounts?: Map<string, number>,
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
          union(x.assetId, y.assetId)
        } else {
          // local MAC — same non-null network, or one unscoped with equal IP.
          let matched: string | null = null
          outer: for (const a of ex) for (const b of ey) {
            if (a.net != null && a.net === b.net) { matched = `same local MAC ${mac} on ${a.net}`; break outer }
            if ((a.net == null || b.net == null) && a.ip === b.ip) { matched = `same local MAC ${mac} at ${a.ip} (unscoped)`; break outer }
          }
          if (matched) { edges.push({ a: x.assetId, b: y.assetId, confidence: 'safe', reason: matched }); union(x.assetId, y.assetId) }
          // else: same local MAC on different networks → never grouped.
        }
      }
    }
  }

  // ── Hostname evidence (REVIEW): same specific (non-generic) hostname, different MACs ──
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
      edges.push({ a: x.assetId, b: y.assetId, confidence: 'review', reason: `same hostname "${hn}", different MACs` })
      union(x.assetId, y.assetId)
    }
  }

  // ── host_key evidence (REVIEW): same host_key on different networks ──
  const byHostKey = new Map<string, string[]>()
  for (const a of assets) {
    const hk = a.hostKey ? a.hostKey.toLowerCase() : null
    if (!hk) continue
    const l = byHostKey.get(hk) ?? []; l.push(a.assetId); byHostKey.set(hk, l)
  }
  const netsOfAsset = (id: string) => new Set((addrByAsset.get(id) ?? []).map(a => a.networkKey).filter((n): n is string => n != null))
  for (const [hk, ids] of byHostKey) {
    const uniq = [...new Set(ids)]
    if (uniq.length < 2) continue
    for (let i = 0; i < uniq.length; i++) for (let j = i + 1; j < uniq.length; j++) {
      const xn = netsOfAsset(uniq[i]!), yn = netsOfAsset(uniq[j]!)
      const differentNetworks = xn.size > 0 && yn.size > 0 && [...xn].every(n => !yn.has(n))
      if (!differentNetworks) continue
      edges.push({ a: uniq[i]!, b: uniq[j]!, confidence: 'review', reason: `same host_key "${hk}" on different networks` })
      union(uniq[i]!, uniq[j]!)
    }
  }

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
    const groupEdges = edges.filter(e => members.has(e.a) && members.has(e.b))
    const reasons = [...new Set(groupEdges.map(e => e.reason))]
    const confidence: 'safe' | 'review' = groupEdges.some(e => e.confidence === 'review') ? 'review' : 'safe'

    const groupAssets: DuplicateGroupAsset[] = ids.map(id => {
      const a = assetById.get(id)!
      return {
        assetId: a.assetId, hostname: a.hostname, ipAddress: a.ipAddress, macAddress: a.macAddress,
        source: a.source, deviceType: a.deviceType, lastScanned: a.lastScanned, createdAt: a.createdAt,
        addressCount: (addrByAsset.get(id) ?? []).length,
        ...(eventCounts ? { eventCount: eventCounts.get(id) ?? 0 } : {}),
      }
    })

    // Suggested survivor: manual first → latest last_scanned → oldest created_at.
    const survivor = [...groupAssets].sort((x, y) => {
      const mx = x.source === 'manual' ? 1 : 0, my = y.source === 'manual' ? 1 : 0
      if (mx !== my) return my - mx
      const ls = ms(y.lastScanned) - ms(x.lastScanned)
      if (ls !== 0) return ls
      return ms(x.createdAt) - ms(y.createdAt)
    })[0]!

    out.push({ groupId: hashIds(ids), confidence, reasons, assets: groupAssets, suggestedSurvivorId: survivor.assetId })
  }

  // Deterministic order: review first (needs attention), then by size.
  out.sort((a, b) => (a.confidence === b.confidence ? b.assets.length - a.assets.length : a.confidence === 'review' ? -1 : 1))
  return out
}
