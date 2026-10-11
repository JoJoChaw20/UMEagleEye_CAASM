/**
 * Endpoint inventory — PURE helpers (no DB) for POST /agents/:id/inventory.
 *
 * An agent reports the inventory of the machine it runs on. The server must decide
 * which asset that machine is (binding), store the facts, and sync the installed
 * software list. Tested by scripts/endpoint-inventory-demo.ts.
 */
import { classifyMac, sanitizeHostKey } from './identity'
import { differentHardware, physicalMacs } from './machineIdentity'

// ── Payload (validated by the route's zod schema) ────────────────
export interface InventorySoftware {
  name: string
  version?: string | null
  publisher?: string | null
  install_date?: string | null
  scope?: string | null
  arch?: string | null
}
export interface InventoryInterface {
  name?: string | null
  mac?: string | null
  physical?: boolean
  ipv4?: string[]
}
export interface InventoryPayload {
  schema: 1
  platform: string
  collected_at: string
  identity: Record<string, unknown> & { hostname?: string | null; dns_hostname?: string | null }
  hardware?: Record<string, unknown> & { manufacturer?: string | null; form_factor?: string | null }
  os?: Record<string, unknown> & { role?: string | null }
  network: Record<string, unknown> & { primary_ip?: string | null; interfaces: InventoryInterface[]; listening?: unknown[] }
  software: InventorySoftware[]
  [key: string]: unknown
}

// ── Identity evidence ────────────────────────────────────────────
/** Burned-in (global) MACs of the machine's physical NICs. Locally administered,
 *  virtual and shared MACs are excluded: they don't identify one device. */
export function identityMacs(inv: InventoryPayload): string[] {
  return physicalMacs(inv)
}

/** MAC of the NIC that holds the primary IP (what a network scan of that IP sees);
 *  else the first physical global MAC. Locally administered MACs count here, since a
 *  scan on that network sees them too. */
export function primaryMac(inv: InventoryPayload): string | null {
  const primary = inventoryIps(inv)[0]
  for (const nic of inv.network.interfaces ?? []) {
    if (primary && (nic.ipv4 ?? []).includes(primary)) {
      const { mac } = classifyMac(nic.mac)
      if (mac) return mac
    }
  }
  return identityMacs(inv)[0] ?? null
}

/** The host key the identity resolver would derive from this machine's name. */
export function inventoryHostKey(inv: InventoryPayload): string | null {
  return sanitizeHostKey(inv.identity.hostname ?? null)
}

/** IPv4 addresses of the physical NICs, primary first. */
export function inventoryIps(inv: InventoryPayload): string[] {
  const ips: string[] = []
  const primary = inv.network.primary_ip
  if (primary && /^\d{1,3}(\.\d{1,3}){3}$/.test(primary) && primary !== '127.0.0.1') ips.push(primary)
  for (const nic of inv.network.interfaces ?? []) {
    if (!nic.physical) continue
    for (const ip of nic.ipv4 ?? []) if (!ips.includes(ip) && !ip.startsWith('169.254.')) ips.push(ip)
  }
  return ips
}

// ── Binding ──────────────────────────────────────────────────────
export interface BindingCandidate {
  assetId: string
  inMyAssets: boolean
  lastScanned: string | Date | null
  /** Does the asset already have any MAC on record (row or address history)? */
  hasMac: boolean
  /** Hardware UUIDs an agent reported for this asset (none for agentless assets). */
  hardwareUuids?: string[]
}
export interface BindingInput {
  /** Asset the agent was bound to last time, if it still exists in the tenant. */
  boundAssetId: string | null
  /** Hardware UUIDs on record for the bound asset. */
  boundHardwareUuids?: string[]
  /** This machine's hardware UUID (placeholders already dropped), if known. */
  hardwareUuid?: string | null
  hardwareUuidMatches?: BindingCandidate[]
  osInstallIdMatches?: BindingCandidate[]
  macMatches: BindingCandidate[]
  hostKeyMatches: BindingCandidate[]
  ipMatches: BindingCandidate[]
}
export type MatchedBy = 'bound' | 'hardware_uuid' | 'os_install_id' | 'mac' | 'hostname' | 'ip'
export interface BindingDecision { assetId: string; matchedBy: MatchedBy }
export interface BindingResult {
  decision: BindingDecision | null
  /** Assets that matched on OS install id, MAC, hostname or IP but have a different
   *  hardware UUID: a cloned VM (or a replaced mainboard). Never bound; reported. */
  differentHardware: string[]
}

const ts = (v: string | Date | null) => (v ? new Date(v).getTime() : 0)
function best(cands: BindingCandidate[]): BindingCandidate {
  // Prefer the asset the user manages, then the most recently seen one.
  return [...cands].sort((a, b) =>
    (Number(b.inMyAssets) - Number(a.inMyAssets)) || (ts(b.lastScanned) - ts(a.lastScanned)) || a.assetId.localeCompare(b.assetId),
  )[0]!
}
const uniq = (cands: BindingCandidate[]) => [...new Map(cands.map(c => [c.assetId, c])).values()]

/**
 * Which asset is this machine?
 *   1. the asset it was bound to before (stable across DHCP and renames);
 *   2. the same hardware UUID (the strongest evidence; survives OS reinstalls);
 *   3. the same OS install id (MachineGuid / machine-id);
 *   4. a physical NIC's global MAC;
 *   5. the same specific hostname, only when exactly one asset has it;
 *   6. the same IP, only when exactly one asset has it AND that asset has no MAC on
 *      record (otherwise a MAC rule would have matched, so a different MAC = a
 *      different device that reused the IP).
 * Several matches for 2-4 = duplicates: pick the My Assets / most recent one.
 *
 * VM-clone guard: a candidate whose recorded hardware UUID differs from this
 * machine's is a different machine, whatever else matches (a clone keeps the OS
 * install id, hostname and often the MACs). That includes the bound asset: an agent
 * copied along with its VM must not keep writing into the original's asset.
 * decision null = no match: the caller creates a new asset.
 */
export function chooseBinding(input: BindingInput): BindingDecision | null {
  return bindMachine(input).decision
}

export function bindMachine(input: BindingInput): BindingResult {
  const hw = input.hardwareUuid ? [input.hardwareUuid] : []
  const conflicts = new Set<string>()
  const sameMachine = (cands: BindingCandidate[]) => uniq(cands).filter(c => {
    if (differentHardware(hw, c.hardwareUuids)) { conflicts.add(c.assetId); return false }
    return true
  })
  const result = (decision: BindingDecision | null): BindingResult => {
    if (decision) conflicts.delete(decision.assetId)
    return { decision, differentHardware: [...conflicts].sort() }
  }

  if (input.boundAssetId) {
    if (!differentHardware(hw, input.boundHardwareUuids)) return result({ assetId: input.boundAssetId, matchedBy: 'bound' })
    conflicts.add(input.boundAssetId)
  }
  const byHw = uniq(input.hardwareUuidMatches ?? [])
  if (byHw.length > 0) return result({ assetId: best(byHw).assetId, matchedBy: 'hardware_uuid' })
  const byOs = sameMachine(input.osInstallIdMatches ?? [])
  if (byOs.length > 0) return result({ assetId: best(byOs).assetId, matchedBy: 'os_install_id' })
  const mac = sameMachine(input.macMatches)
  if (mac.length > 0) return result({ assetId: best(mac).assetId, matchedBy: 'mac' })
  const host = sameMachine(input.hostKeyMatches)
  if (host.length === 1) return result({ assetId: host[0]!.assetId, matchedBy: 'hostname' })
  const ip = sameMachine(input.ipMatches).filter(c => !c.hasMac)
  if (ip.length === 1) return result({ assetId: ip[0]!.assetId, matchedBy: 'ip' })
  return result(null)
}

/** Device type the machine reports about itself (OS role, then chassis). */
export function deviceTypeFor(inv: InventoryPayload): 'server' | 'workstation' | 'unknown' {
  const role = inv.os?.role
  if (role === 'server' || role === 'domain_controller') return 'server'
  const ff = inv.hardware?.form_factor
  if (ff === 'server') return 'server'
  if (role === 'workstation' || ff === 'laptop' || ff === 'desktop') return 'workstation'
  return 'unknown'
}

/**
 * Device type after an inventory. Sources rank manual > agent > auto (scans):
 *  - a manual known type is never changed (the user's choice);
 *  - otherwise a concrete type reported by the machine itself wins and is marked
 *    'agent' ("confirmed by agent"), so later scans can no longer flip it
 *    (see ingest-plan resolveIngestDeviceType);
 *  - 'unknown' from the agent changes nothing.
 */
export function resolveAgentDeviceType(
  existing: { deviceType: string; deviceTypeSource: string | null } | null,
  reported: string,
): { deviceType: string; deviceTypeSource: string; changed: boolean } {
  const cur = existing ?? { deviceType: 'unknown', deviceTypeSource: 'auto' }
  const curSource = cur.deviceTypeSource ?? 'auto'
  const keep = { deviceType: cur.deviceType, deviceTypeSource: curSource, changed: false }
  if (reported === 'unknown') return keep
  if (curSource === 'manual' && cur.deviceType && cur.deviceType !== 'unknown') return keep
  return { deviceType: reported, deviceTypeSource: 'agent', changed: reported !== cur.deviceType || curSource !== 'agent' }
}

// ── Address bookkeeping ──────────────────────────────────────────
export interface AgentAddressRow {
  addressId: string
  assetId: string
  networkKey: string | null
  ipAddress: string
  macAddress: string | null
}
export type AgentAddressOp =
  | { k: 'refresh'; addressId: string; macAddress: string | null; networkKey: string | null }
  | { k: 'end'; addressId: string }
  | { k: 'insert'; networkKey: string | null; ipAddress: string; macAddress: string | null }

/**
 * Keep asset_addresses in step with where the machine says it is, the way scan ingest
 * does for a matched host:
 *  - already at this IP on this network (or an unscoped row with this IP): refresh it
 *    and fill a missing MAC / network;
 *  - otherwise end its old current address on this network (DHCP change), end another
 *    asset's current hold on this (network, IP) (the IP was reused), and insert the new one.
 * Addresses on other networks are left alone, as in scan ingest.
 * `current` = current rows of this asset plus current holders of (networkKey, ip).
 */
export function planAgentAddress(
  assetId: string, ip: string, mac: string | null, networkKey: string | null, current: AgentAddressRow[],
): AgentAddressOp[] {
  const mine = current.filter(r => r.assetId === assetId)
  const here = mine.find(r => r.ipAddress === ip && (r.networkKey === networkKey || r.networkKey === null))
  if (here) return [{ k: 'refresh', addressId: here.addressId, macAddress: here.macAddress ?? mac, networkKey: here.networkKey ?? networkKey }]
  const ops: AgentAddressOp[] = []
  if (networkKey !== null) {
    for (const r of mine) if (r.networkKey === networkKey) ops.push({ k: 'end', addressId: r.addressId })
    for (const r of current) {
      if (r.assetId !== assetId && r.networkKey === networkKey && r.ipAddress === ip) ops.push({ k: 'end', addressId: r.addressId })
    }
  }
  ops.push({ k: 'insert', networkKey, ipAddress: ip, macAddress: mac })
  return ops
}

// ── Software sync ────────────────────────────────────────────────
export const softwareKey = (s: { name: string; version?: string | null; publisher?: string | null }) =>
  `${s.name.trim().toLowerCase()}|${(s.version ?? '').trim()}|${(s.publisher ?? '').trim().toLowerCase()}`

export interface SoftwareRow { softwareId: string; name: string; version: string | null; publisher: string | null }
export interface SoftwareDiff {
  insert: InventorySoftware[]
  deleteIds: string[]
  unchanged: number
}

/** Rows to insert/delete so the stored list equals the reported one. Duplicates in
 *  either list collapse to one entry per key. */
export function diffSoftware(existing: SoftwareRow[], incoming: InventorySoftware[]): SoftwareDiff {
  const incomingByKey = new Map<string, InventorySoftware>()
  for (const s of incoming) if (s.name?.trim()) incomingByKey.set(softwareKey(s), s)

  const kept = new Set<string>()
  const deleteIds: string[] = []
  for (const row of existing) {
    const key = softwareKey(row)
    if (incomingByKey.has(key) && !kept.has(key)) kept.add(key)
    else deleteIds.push(row.softwareId)          // gone, or a duplicate row
  }
  const insert = [...incomingByKey.entries()].filter(([k]) => !kept.has(k)).map(([, s]) => s)
  return { insert, deleteIds, unchanged: kept.size }
}

// ── What is stored on the asset ──────────────────────────────────
const LIMITS = { listening: 500, interfaces: 64, hotfixes: 200, localAdmins: 100 }

/** The inventory blob stored in assets.endpoint_inventory: everything except the
 *  software list (which has its own table), with list sizes capped. */
export function storedInventory(inv: InventoryPayload): Record<string, unknown> {
  const { software: _software, ...rest } = inv
  const network = { ...inv.network,
    interfaces: (inv.network.interfaces ?? []).slice(0, LIMITS.interfaces),
    listening: (inv.network.listening ?? []).slice(0, LIMITS.listening),
  }
  const patches = inv['patches'] as Record<string, unknown> | undefined
  const security = inv['security'] as Record<string, unknown> | undefined
  return {
    ...rest,
    network,
    ...(patches ? { patches: { ...patches, hotfixes: ((patches['hotfixes'] as unknown[]) ?? []).slice(0, LIMITS.hotfixes) } } : {}),
    ...(security ? { security: { ...security, local_admins: ((security['local_admins'] as unknown[]) ?? []).slice(0, LIMITS.localAdmins) } } : {}),
    software_count: inv.software.length,
  }
}
