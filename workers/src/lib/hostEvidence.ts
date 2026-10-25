/**
 * Ingest helpers that keep a passive upload cheap (agent 2.2.2).
 *
 * 1. Hardware vendor. Agents from 2.2.2 look the vendor up offline (Wireshark's
 *    manufacturer list) and send it as `mac_vendor`. That list only holds whole
 *    3-byte prefixes and is frozen at the agent's scapy release, so it misses the
 *    IEEE MA-M/MA-S sub-blocks (small IoT, camera and industrial makers) and newer
 *    prefixes. api.macvendors.com is therefore asked for every real (globally
 *    administered) MAC the agent left without a vendor, and for older agents, which
 *    send none; each answer is kept in KV for 30 days. Its rate limit (about one
 *    request a second) used to leave most devices without a vendor, and private
 *    MACs, which have no vendor, used up the per-upload lookups: they are never asked.
 *
 * 2. LLM descriptions. Every passive round uploads every device heard in it, so the
 *    same unchanged devices came back every few minutes and were described by the
 *    LLM again each time. A host is now sent to the LLM only when what it is
 *    described from (name, MAC, vendor, ports, OS / DHCP / mDNS / SSDP facts) changed
 *    since its stored description; the evidence is kept as a short hash in
 *    os_info.ai_evidence next to os_info.ai_description.
 */
import { normalizeMac } from './mac'

const VENDOR_KV_PREFIX = 'macvendor:'
const VENDOR_KV_TTL = 30 * 24 * 3600
const VENDOR_UNKNOWN = '-'          // cached "no vendor", so it is not asked again
export const VENDOR_LOOKUP_CAP = 16 // online lookups per upload (old agents only)

/** True for a locally administered MAC (randomised/private): it has no vendor. */
export function isLocallyAdministered(mac: string | null | undefined): boolean {
  const norm = normalizeMac(mac)
  return norm !== null && (parseInt(norm.slice(0, 2), 16) & 0x02) !== 0
}

/** The first `digits` hex digits of a MAC that can have a vendor ("7c6130"); null
 *  for a private or multicast MAC. 6 = the IEEE MA-L block; 9 also pins an MA-M or
 *  MA-S sub-block. */
export function vendorPrefix(mac: string | null | undefined, digits = 6): string | null {
  const norm = normalizeMac(mac)
  if (!norm) return null
  if (parseInt(norm.slice(0, 2), 16) & 0x03) return null     // private or multicast
  return norm.replace(/:/g, '').slice(0, digits)
}

/** What a 3-byte lookup answers for a prefix IEEE splits into MA-M/MA-S sub-blocks. */
const SUB_BLOCK_PARENT = /^ieee registration authority/i

export interface VendorHost { ip: string; mac?: string | null; mac_vendor?: string | null }

export interface VendorCache {
  get(key: string): Promise<string | null>
  put(key: string, value: string, options: { expirationTtl: number }): Promise<void>
}

/**
 * ip -> hardware vendor for one upload. The agent's own lookup wins; a real MAC it
 * could not name (or an older agent's) is looked up online (deduplicated, capped,
 * cached). Private and multicast MACs are never looked up.
 */
export async function resolveVendors(
  hosts: VendorHost[],
  lookup: (prefix: string) => Promise<string | null>,
  cache?: VendorCache | null,
): Promise<Map<string, string | null>> {
  const out = new Map<string, string | null>()
  const macOf = new Map<string, string>()                  // ip -> MAC, for the sub-block pass
  const wanted = new Map<string, string[]>()               // prefix -> ips still without a vendor
  for (const h of hosts) {
    const fromAgent = h.mac_vendor?.trim()
    if (fromAgent) {                                       // 2.2.2+: the agent's offline lookup
      out.set(h.ip, fromAgent)
      continue
    }
    const prefix = vendorPrefix(h.mac)
    out.set(h.ip, null)
    if (prefix && h.mac) {
      wanted.set(prefix, [...(wanted.get(prefix) ?? []), h.ip])
      macOf.set(h.ip, h.mac)
    }
  }

  let budget = VENDOR_LOOKUP_CAP                           // online lookups left for this upload
  const resolve = async (prefix: string): Promise<string | null> => {
    const cached = cache ? await cache.get(VENDOR_KV_PREFIX + prefix).catch(() => null) : null
    if (cached !== null) return cached === VENDOR_UNKNOWN ? null : cached
    if (budget <= 0) return null
    budget--
    const vendor = await lookup(prefix)
    // Cache only real answers and confirmed unknowns; a failed lookup (null) is
    // retried next time. lookup() returns '' for a confirmed "not found".
    if (cache && vendor !== null) {
      await cache.put(VENDOR_KV_PREFIX + prefix, vendor || VENDOR_UNKNOWN, { expirationTtl: VENDOR_KV_TTL }).catch(() => {})
    }
    return vendor || null
  }

  // Pass 1: the 3-byte block. Pass 2: where that block is IEEE's own, split into
  // MA-M/MA-S sub-blocks for small makers, ask again with 9 digits for the real one.
  const subBlocks = new Map<string, string[]>()
  await Promise.all([...wanted.entries()].map(async ([prefix, ips]) => {
    const vendor = await resolve(prefix)
    for (const ip of ips) {
      out.set(ip, vendor)
      if (vendor && SUB_BLOCK_PARENT.test(vendor)) {
        const sub = vendorPrefix(macOf.get(ip), 9)
        if (sub) subBlocks.set(sub, [...(subBlocks.get(sub) ?? []), ip])
      }
    }
  }))
  await Promise.all([...subBlocks.entries()].map(async ([sub, ips]) => {
    const vendor = await resolve(sub)
    if (vendor && !SUB_BLOCK_PARENT.test(vendor)) for (const ip of ips) out.set(ip, vendor)
  }))
  return out
}

/** JSON with sorted keys, so equal evidence always gives the same text. */
function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>
    return `{${Object.keys(obj).sort().filter(k => obj[k] !== undefined)
      .map(k => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`
  }
  return JSON.stringify(value ?? null)
}

/** 64-bit FNV-1a as 16 hex digits: a compact, stable fingerprint (not a security hash). */
function fnv1a64(text: string): string {
  let h = 0xcbf29ce484222325n
  const prime = 0x100000001b3n
  for (let i = 0; i < text.length; i++) {
    h ^= BigInt(text.charCodeAt(i))
    h = (h * prime) & 0xffffffffffffffffn
  }
  return h.toString(16).padStart(16, '0')
}

export interface EvidenceInput {
  hostname?: string | null
  mac?: string | null
  vendor?: string | null
  ports?: unknown[] | null
  os?: Record<string, unknown> | null
  isGateway?: boolean
}

/** Fingerprint of what the LLM describes a host from. */
export function aiEvidenceKey(h: EvidenceInput): string {
  const ports = (h.ports ?? []).map((p) => {
    const port = (p ?? {}) as Record<string, unknown>
    return [port['port'], port['protocol'] ?? 'tcp', port['service'] ?? '', port['product'] ?? '', port['version'] ?? '']
  }).sort((a, b) => String(a).localeCompare(String(b)))
  return fnv1a64(stableStringify({
    hostname: (h.hostname ?? '').trim().toLowerCase() || null,
    mac: normalizeMac(h.mac),
    vendor: h.vendor ?? null,
    ports,
    os: h.os ?? null,
    gateway: !!h.isGateway,
  }))
}

export interface PriorDescription { description: string; suggestion: string | null }

/**
 * The stored description of a host, when it was made from the same evidence: the
 * LLM can be skipped and this reused. `osInfo` is the matched asset's os_info.
 */
export function reusableDescription(osInfo: Record<string, unknown> | null | undefined, evidenceKey: string): PriorDescription | null {
  const os = osInfo ?? {}
  const description = typeof os['ai_description'] === 'string' ? (os['ai_description'] as string).trim() : ''
  if (!description || os['ai_evidence'] !== evidenceKey) return null
  const suggestion = typeof os['ai_suggestion'] === 'string' ? (os['ai_suggestion'] as string) : null
  return { description, suggestion }
}
