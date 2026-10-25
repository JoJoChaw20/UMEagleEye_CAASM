/**
 * Which network an address belongs to (asset_addresses.network_key).
 *
 * The key used to be the /24 around each address, so a /22 office LAN was four
 * "networks": a laptop with a private MAC whose DHCP address moved from 10.0.1.x to
 * 10.0.2.x was no longer matched (rule 2 needs the same network) and became a second
 * asset with a second new-device alert. Agents from 2.2.4 report the subnet of the
 * LAN they listen on (network.lan_subnet; 2.2.2+ already sent it as network.subnet for
 * passive uploads), so the key is now that subnet.
 *
 * Keys stay canonical per tenant, so every existing equality check keeps working:
 *  - a reported subnet (a /16 to a /24) that holds the address is the key;
 *  - when it is wider than keys the tenant already has inside it (the old /24s), those
 *    rows are widened to it once (one UPDATE; it cannot collide, because a current
 *    address has one IP and so one /24);
 *  - when the tenant already has a wider key holding the address, that key is used,
 *    also for agents that report nothing (older agents, endpoint inventory);
 *  - otherwise the /24 around the address, as before.
 */
import { and, eq, inArray, isNotNull, isNull, sql } from 'drizzle-orm'
import type { DB } from '../db/client'
import { assetAddresses } from '../db/schema'

const MIN_PREFIX = 16           // never key a whole /8 as one network
const MAX_PREFIX = 24

export interface Cidr { net: number; prefix: number }

export function parseIpv4(ip: string | null | undefined): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec((ip ?? '').trim())
  if (!m) return null
  const o = [m[1], m[2], m[3], m[4]].map(Number)
  if (o.some(n => n > 255)) return null
  return ((o[0]! << 24) | (o[1]! << 16) | (o[2]! << 8) | o[3]!) >>> 0
}

const mask = (prefix: number): number => (prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0)

export function parseCidr(cidr: string | null | undefined): Cidr | null {
  const m = /^([\d.]+)\/(\d{1,2})$/.exec((cidr ?? '').trim())
  if (!m) return null
  const addr = parseIpv4(m[1])
  const prefix = Number(m[2])
  if (addr === null || prefix > 32) return null
  return { net: (addr & mask(prefix)) >>> 0, prefix }
}

export function formatCidr(c: Cidr): string {
  const n = c.net
  return `${n >>> 24}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}/${c.prefix}`
}

export function cidrContainsIp(c: Cidr, ip: number): boolean {
  return ((ip & mask(c.prefix)) >>> 0) === c.net
}

/** True when `outer` holds all of `inner` and is strictly wider. */
export function cidrStrictlyContains(outer: Cidr, inner: Cidr): boolean {
  return outer.prefix < inner.prefix && ((inner.net & mask(outer.prefix)) >>> 0) === outer.net
}

export function slash24(ip: string): string | null {
  const n = parseIpv4(ip)
  return n === null ? null : formatCidr({ net: (n & mask(24)) >>> 0, prefix: 24 })
}

export interface NetworkScope {
  /** The key for an address (null for IPv6 / unparseable). */
  keyFor(ip: string): string | null
  /** Existing keys to rewrite to `widenTo` (old /24s inside the reported subnet). */
  widen: string[]
  widenTo: string | null
}

/**
 * Pure: the scope for one upload, from the tenant's existing keys and the subnet the
 * agent reported for the LAN it listens on (null when it reported none).
 */
export function planNetworkScope(existingKeys: (string | null)[], reported: string | null | undefined): NetworkScope {
  const existing = existingKeys.map(k => ({ key: k, cidr: parseCidr(k) }))
    .filter((e): e is { key: string; cidr: Cidr } => !!e.key && !!e.cidr)
  let lan = parseCidr(reported)
  if (lan && (lan.prefix < MIN_PREFIX || lan.prefix > MAX_PREFIX)) lan = null
  // A wider key the tenant already uses wins over the one reported now.
  if (lan) {
    const wider = existing.filter(e => cidrStrictlyContains(e.cidr, lan!)).sort((a, b) => a.cidr.prefix - b.cidr.prefix)[0]
    if (wider) lan = wider.cidr
  }
  const lanKey = lan ? formatCidr(lan) : null
  const widen = lan ? [...new Set(existing.filter(e => cidrStrictlyContains(lan!, e.cidr)).map(e => e.key))] : []

  const keyFor = (ip: string): string | null => {
    const addr = parseIpv4(ip)
    if (addr === null) return null
    if (lan && cidrContainsIp(lan, addr)) return lanKey
    // An address outside the reported LAN (a routed range, an older agent): the widest
    // existing key that holds it, else its /24.
    const holder = existing
      .filter(e => e.cidr.prefix < 24 && cidrContainsIp(e.cidr, addr))
      .sort((a, b) => a.cidr.prefix - b.cidr.prefix)[0]
    return holder ? holder.key : slash24(ip)
  }
  return { keyFor, widen, widenTo: widen.length ? lanKey : null }
}

/**
 * The scope for one upload of a tenant: reads its existing keys, widens the old /24s
 * inside the reported subnet (one UPDATE, before any matching), and returns keyFor.
 */
export async function resolveNetworkScope(db: DB, tenantId: string | null, reported: string | null | undefined): Promise<NetworkScope> {
  if (!tenantId) return planNetworkScope([], null)
  const rows = await db.selectDistinct({ key: assetAddresses.networkKey }).from(assetAddresses)
    .where(and(eq(assetAddresses.tenantId, tenantId), isNotNull(assetAddresses.networkKey)))
  const scope = planNetworkScope(rows.map(r => r.key), reported)
  if (scope.widenTo && scope.widen.length > 0) {
    const tenant = eq(assetAddresses.tenantId, tenantId)
    // Belt and braces: a current row whose IP is already current under the wider key
    // (which no path should create) is ended first, so the unique index cannot trip.
    await db.update(assetAddresses).set({ endedAt: new Date() }).where(and(
      tenant, inArray(assetAddresses.networkKey, scope.widen), isNull(assetAddresses.endedAt),
      sql`${assetAddresses.ipAddress} IN (SELECT ip_address FROM asset_addresses
            WHERE tenant_id = ${tenantId} AND network_key = ${scope.widenTo} AND ended_at IS NULL)`,
    ))
    await db.update(assetAddresses).set({ networkKey: scope.widenTo })
      .where(and(tenant, inArray(assetAddresses.networkKey, scope.widen)))
    console.log(`[network] tenant ${tenantId}: ${scope.widen.length} network key(s) widened to ${scope.widenTo}`)
  }
  return scope
}
