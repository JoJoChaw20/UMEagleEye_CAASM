/**
 * merge.ts — PURE planner for merging duplicate assets into one survivor.
 *
 * Produces an ordered list of operations that the route maps to Drizzle and runs
 * in ONE db.batch (atomic on neon-http — no interactive transactions available).
 * Order matters: end colliding current addresses BEFORE moving them, remap/dedupe
 * relationships, merge fields into the survivor, then delete the losers last.
 *
 * Pure (no DB). Tested by identity-demo.ts.
 */
export interface MergeAsset {
  assetId: string
  tenantId: string | null
  hostname: string | null
  ipAddress: string
  macAddress: string | null
  hostKey: string | null
  owner: string | null
  deviceType: string
  deviceTypeSource: string | null
  hardwareVendor: string | null
  osInfo: Record<string, unknown> | null
  criticalityScore: number
  baselineState: Record<string, unknown> | null
  isInternetFacing: boolean
  source: string
  inMyAssets: boolean
  lastScanned: string | Date | null
  createdAt: string | Date | null
}
export interface MergeAddress {
  addressId: string
  assetId: string
  networkKey: string | null
  ipAddress: string
  endedAt: string | Date | null
  lastSeen: string | Date | null
  firstSeen: string | Date | null
}
export interface MergeRelationship {
  relationshipId: string
  sourceAssetId: string
  targetAssetId: string
  relationshipType: string
}
export interface MergeTopologyNode { nodeId: string; assetId: string }

export interface MergeRelated {
  addresses: MergeAddress[]
  relationships: MergeRelationship[]
  topologyNodes: MergeTopologyNode[]
}

export type MergeOp =
  | { k: 'endAddress'; addressId: string }
  | { k: 'endAddressAt'; addressId: string; endedAt: string | Date }
  | { k: 'moveAddresses'; loserIds: string[]; survivorId: string }
  | { k: 'moveEvents'; loserIds: string[]; survivorId: string }
  | { k: 'moveSboms'; loserIds: string[]; survivorId: string }
  | { k: 'moveDependencies'; loserIds: string[]; survivorId: string }
  | { k: 'deleteRelationships'; ids: string[] }
  | { k: 'updateRelationship'; id: string; sourceAssetId: string; targetAssetId: string }
  | { k: 'deleteTopologyNodes'; ids: string[] }
  | { k: 'moveTopologyNode'; nodeId: string; survivorId: string }
  // Reparent any node whose parent_node_id pointed at a node we just deleted, onto the
  // surviving node (never a self-parent; null if there is no surviving node). Set-based,
  // so it fixes children not prefetched here; runs in the same merge batch.
  | { k: 'reparentTopology'; deletedNodeIds: string[]; survivorNodeId: string | null }
  | { k: 'updateAsset'; assetId: string; set: Record<string, unknown> }
  | { k: 'insertAudit'; loserId: string; survivorId: string; snapshot: Record<string, unknown> }
  | { k: 'deleteAssets'; loserIds: string[] }

export interface MergeCounts {
  addressesMoved: number
  addressesEnded: number
  relationshipsMoved: number
  relationshipsDropped: number
  topologyMoved: number
  topologyDropped: number
}
export interface MergePlan {
  ops: MergeOp[]
  mergedFields: Record<string, unknown>
  counts: MergeCounts
}

const ms = (v: string | Date | null | undefined): number => (v ? new Date(v).getTime() : 0)
const nonEmpty = (v: unknown): boolean => v != null && v !== ''

export function planMerge(survivor: MergeAsset, losers: MergeAsset[], related: MergeRelated, now = new Date()): MergePlan {
  const survivorId = survivor.assetId
  const loserIds = losers.map(l => l.assetId)
  const loserSet = new Set(loserIds)
  const all = [survivor, ...losers]
  const ops: MergeOp[] = []

  // ── Field merge into survivor ──
  const byLatest = [...all].sort((a, b) => ms(b.lastScanned) - ms(a.lastScanned))
  const latest = byLatest[0]!
  const firstNonEmpty = <K extends keyof MergeAsset>(key: K): unknown =>
    nonEmpty(survivor[key]) ? survivor[key] : (all.find(a => nonEmpty(a[key]))?.[key] ?? survivor[key])

  // os_info: shallow merge, later last_scanned wins per key.
  const osByOldest = [...all].sort((a, b) => ms(a.lastScanned) - ms(b.lastScanned))
  const mergedOsInfo = osByOldest.reduce<Record<string, unknown>>((acc, a) => ({ ...acc, ...(a.osInfo ?? {}) }), {})

  // Device type keeps the survivor's source. A manual survivor type wins; else a
  // manual loser type (user-confirmed) is taken over the survivor's auto guess; else
  // the usual "survivor's non-unknown, else first non-unknown" auto pick.
  // (Before this change the merge ignored source entirely and always took the
  // survivor's non-unknown type, then the first non-unknown.)
  let mergedDeviceType: string
  let mergedDeviceTypeSource: string
  if (survivor.deviceTypeSource === 'manual') {
    mergedDeviceType = survivor.deviceType
    mergedDeviceTypeSource = 'manual'
  } else {
    const manualLoser = losers.find(l => l.deviceTypeSource === 'manual' && !!l.deviceType && l.deviceType !== 'unknown')
    if (manualLoser) {
      mergedDeviceType = manualLoser.deviceType
      mergedDeviceTypeSource = 'manual'
    } else {
      mergedDeviceType = (survivor.deviceType && survivor.deviceType !== 'unknown')
        ? survivor.deviceType
        : (all.find(a => a.deviceType && a.deviceType !== 'unknown')?.deviceType ?? survivor.deviceType)
      mergedDeviceTypeSource = 'auto'
    }
  }

  const mergedFields: Record<string, unknown> = {
    hostname: firstNonEmpty('hostname') ?? null,
    owner: firstNonEmpty('owner') ?? null,
    hostKey: firstNonEmpty('hostKey') ?? null,
    hardwareVendor: firstNonEmpty('hardwareVendor') ?? null,
    deviceType: mergedDeviceType,
    deviceTypeSource: mergedDeviceTypeSource,
    osInfo: mergedOsInfo,
    baselineState: survivor.baselineState ?? all.find(a => a.baselineState != null)?.baselineState ?? null,
    // source = the latest-scanned asset's observation method. 'manual' only when
    // EVERY merged asset is manual (never scanned); otherwise fall back to the
    // most-recently-scanned non-manual source (byLatest keeps the survivor first on ties).
    source: all.every(a => a.source === 'manual')
      ? 'manual'
      : (byLatest.find(a => a.source !== 'manual')?.source ?? survivor.source),
    // Membership is the OR of survivor + losers: if any was in My Assets, the
    // merged device stays in My Assets.
    inMyAssets: all.some(a => a.inMyAssets),
    isInternetFacing: all.some(a => a.isInternetFacing),
    criticalityScore: Math.max(...all.map(a => a.criticalityScore ?? 0)),
    lastScanned: byLatest.map(a => a.lastScanned).find(v => v != null) ?? null,
    createdAt: all.map(a => ms(a.createdAt)).filter(n => n > 0).sort((x, y) => x - y).map(n => new Date(n))[0] ?? survivor.createdAt,
    ipAddress: latest.ipAddress,            // "latest seen"
    macAddress: latest.macAddress,          // "latest seen"
    updatedAt: now,
  }

  // ── Addresses: end colliding current scoped loser rows, then move all loser rows ──
  let addressesEnded = 0
  const endedByCollision = new Set<string>()
  const currentScoped = related.addresses.filter(a => a.endedAt == null && a.networkKey != null)
  const byNetIp = new Map<string, MergeAddress[]>()
  for (const a of currentScoped) {
    const k = `${a.networkKey}|${a.ipAddress}`
    const l = byNetIp.get(k) ?? []; l.push(a); byNetIp.set(k, l)
  }
  for (const group of byNetIp.values()) {
    if (group.length < 2) continue
    const survivorRow = group.find(a => a.assetId === survivorId)
    const keeper = survivorRow ?? [...group].sort((x, y) => ms(y.lastSeen) - ms(x.lastSeen))[0]!
    for (const a of group) {
      if (a.addressId === keeper.addressId) continue
      if (!loserSet.has(a.assetId)) continue   // never end a survivor row
      ops.push({ k: 'endAddress', addressId: a.addressId }); addressesEnded++; endedByCollision.add(a.addressId)
    }
  }
  const addressesMoved = related.addresses.filter(a => loserSet.has(a.assetId)).length
  if (loserIds.length) {
    ops.push({ k: 'moveAddresses', loserIds, survivorId })
    ops.push({ k: 'moveEvents', loserIds, survivorId })
    ops.push({ k: 'moveSboms', loserIds, survivorId })
    ops.push({ k: 'moveDependencies', loserIds, survivorId })
  }

  // After the move, the survivor's current-address set = every still-current row
  // (its own + the moved loser rows, minus the ones just collision-ended). A device
  // is in one place, so keep exactly ONE current row and end the rest with their own
  // last_seen — otherwise stale "current" rows on networks the device left let the
  // resolver's current-row rules (4/5) attach a different host there later.
  // Ending (not deleting) preserves history; ended rows can't hit the unique index.
  const survivingCurrent = related.addresses.filter(a => a.endedAt == null && !endedByCollision.has(a.addressId))
  if (survivingCurrent.length > 1) {
    const keeper = [...survivingCurrent].sort((x, y) => {
      const ls = ms(y.lastSeen) - ms(x.lastSeen)
      if (ls !== 0) return ls                                              // latest last_seen
      const sx = x.assetId === survivorId ? 1 : 0, sy = y.assetId === survivorId ? 1 : 0
      if (sx !== sy) return sy - sx                                        // tie → survivor's own row
      const fs = ms(y.firstSeen) - ms(x.firstSeen)
      if (fs !== 0) return fs                                             // then newest first_seen
      return x.addressId < y.addressId ? -1 : x.addressId > y.addressId ? 1 : 0  // then lowest address_id
    })[0]!
    for (const a of survivingCurrent) {
      if (a.addressId === keeper.addressId) continue
      ops.push({ k: 'endAddressAt', addressId: a.addressId, endedAt: a.lastSeen ?? now })
      addressesEnded++
    }
  }

  // ── Relationships: drop self-loops + duplicates (on survivor edge), remap the rest ──
  const remap = (id: string) => (loserSet.has(id) ? survivorId : id)
  const keyOf = (s: string, t: string, ty: string) => `${s}|${t}|${ty}`
  const kept = new Set<string>()
  const dropIds: string[] = []
  const updates: { id: string; s: string; t: string }[] = []
  // Pass 1: pure survivor edges (no loser endpoint) claim their keys unchanged.
  for (const r of related.relationships) {
    if (loserSet.has(r.sourceAssetId) || loserSet.has(r.targetAssetId)) continue
    if (r.sourceAssetId === survivorId || r.targetAssetId === survivorId) kept.add(keyOf(r.sourceAssetId, r.targetAssetId, r.relationshipType))
  }
  // Pass 2: edges touching a loser — remap, drop self-loops/duplicates.
  for (const r of related.relationships) {
    if (!loserSet.has(r.sourceAssetId) && !loserSet.has(r.targetAssetId)) continue
    const s = remap(r.sourceAssetId), t = remap(r.targetAssetId)
    if (s === t) { dropIds.push(r.relationshipId); continue }         // self-loop
    const key = keyOf(s, t, r.relationshipType)
    if (kept.has(key)) { dropIds.push(r.relationshipId); continue }   // duplicate survivor edge
    kept.add(key)
    updates.push({ id: r.relationshipId, s, t })
  }
  if (dropIds.length) ops.push({ k: 'deleteRelationships', ids: dropIds })
  for (const u of updates) ops.push({ k: 'updateRelationship', id: u.id, sourceAssetId: u.s, targetAssetId: u.t })

  // ── Topology: one node per asset. Keep survivor's; else move one loser node. ──
  // Any node we DELETE must not leave children with a dangling parent_node_id, so we
  // reparent those children onto the surviving node (survivor's own, or the one we
  // moved) in the same batch. parent_node_id has no FK, so this is app-enforced.
  const survivorHasNode = related.topologyNodes.some(n => n.assetId === survivorId)
  const loserNodes = related.topologyNodes.filter(n => loserSet.has(n.assetId))
  let topologyMoved = 0, topologyDropped = 0
  let deletedNodeIds: string[] = []
  let survivorNodeId: string | null = null
  if (survivorHasNode) {
    survivorNodeId = related.topologyNodes.find(n => n.assetId === survivorId)!.nodeId
    if (loserNodes.length) { deletedNodeIds = loserNodes.map(n => n.nodeId); ops.push({ k: 'deleteTopologyNodes', ids: deletedNodeIds }); topologyDropped = loserNodes.length }
  } else if (loserNodes.length) {
    const [keep, ...rest] = loserNodes
    survivorNodeId = keep!.nodeId
    ops.push({ k: 'moveTopologyNode', nodeId: keep!.nodeId, survivorId }); topologyMoved = 1
    if (rest.length) { deletedNodeIds = rest.map(n => n.nodeId); ops.push({ k: 'deleteTopologyNodes', ids: deletedNodeIds }); topologyDropped = rest.length }
  }
  if (deletedNodeIds.length) ops.push({ k: 'reparentTopology', deletedNodeIds, survivorNodeId })

  // ── Survivor field update, audit rows, delete losers (last) ──
  ops.push({ k: 'updateAsset', assetId: survivorId, set: mergedFields })
  for (const l of losers) {
    ops.push({ k: 'insertAudit', loserId: l.assetId, survivorId, snapshot: loserSnapshot(l) })
  }
  if (loserIds.length) ops.push({ k: 'deleteAssets', loserIds })

  return {
    ops,
    mergedFields,
    counts: {
      addressesMoved, addressesEnded,
      relationshipsMoved: updates.length, relationshipsDropped: dropIds.length,
      topologyMoved, topologyDropped,
    },
  }
}

function loserSnapshot(a: MergeAsset): Record<string, unknown> {
  return {
    asset_id: a.assetId, tenant_id: a.tenantId, hostname: a.hostname, ip_address: a.ipAddress,
    mac_address: a.macAddress, host_key: a.hostKey, owner: a.owner, device_type: a.deviceType,
    device_type_source: a.deviceTypeSource, hardware_vendor: a.hardwareVendor, os_info: a.osInfo, criticality_score: a.criticalityScore,
    baseline_state: a.baselineState, is_internet_facing: a.isInternetFacing, source: a.source,
    in_my_assets: a.inMyAssets, last_scanned: a.lastScanned, created_at: a.createdAt,
  }
}
