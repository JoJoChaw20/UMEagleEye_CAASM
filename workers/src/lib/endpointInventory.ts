/**
 * Endpoint inventory — PURE helpers (no DB) for POST /agents/:id/inventory.
 *
 * An agent reports the inventory of the machine it runs on. The server must decide
 * which asset that machine is (binding), store the facts, and sync the installed
 * software list. Tested by scripts/endpoint-inventory-demo.ts.
 */
import { classifyMac, sanitizeHostKey } from './identity'

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
  const out = new Set<string>()
  for (const nic of inv.network.interfaces ?? []) {
    if (!nic.physical) continue
    const { mac, macClass } = classifyMac(nic.mac)
    if (mac && macClass === 'global') out.add(mac)
  }
  return [...out]
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
}
export interface BindingInput {
  /** Asset the agent was bound to last time, if it still exists in the tenant. */
  boundAssetId: string | null
  macMatches: BindingCandidate[]
  hostKeyMatches: BindingCandidate[]
  ipMatches: BindingCandidate[]
}
export type MatchedBy = 'bound' | 'mac' | 'hostname' | 'ip'
export interface BindingDecision { assetId: string; matchedBy: MatchedBy }

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
 *   2. a physical NIC's global MAC (strong evidence; several matches = duplicates,
 *      pick the My Assets / most recent one);
 *   3. the same specific hostname, only when exactly one asset has it;
 *   4. the same IP, only when exactly one asset has it AND that asset has no MAC on
 *      record (otherwise a MAC rule would have matched, so a different MAC = a
 *      different device that reused the IP).
 * null = no match: the caller creates a new asset.
 */
export function chooseBinding(input: BindingInput): BindingDecision | null {
  if (input.boundAssetId) return { assetId: input.boundAssetId, matchedBy: 'bound' }
  const mac = uniq(input.macMatches)
  if (mac.length > 0) return { assetId: best(mac).assetId, matchedBy: 'mac' }
  const host = uniq(input.hostKeyMatches)
  if (host.length === 1) return { assetId: host[0]!.assetId, matchedBy: 'hostname' }
  const ip = uniq(input.ipMatches).filter(c => !c.hasMac)
  if (ip.length === 1) return { assetId: ip[0]!.assetId, matchedBy: 'ip' }
  return null
}

/** Device type for an asset created from an inventory (existing assets keep theirs;
 *  the full device-type revision is a later phase). */
export function deviceTypeFor(inv: InventoryPayload): 'server' | 'workstation' | 'unknown' {
  const role = inv.os?.role
  if (role === 'server' || role === 'domain_controller') return 'server'
  const ff = inv.hardware?.form_factor
  if (ff === 'server') return 'server'
  if (role === 'workstation' || ff === 'laptop' || ff === 'desktop') return 'workstation'
  return 'unknown'
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
