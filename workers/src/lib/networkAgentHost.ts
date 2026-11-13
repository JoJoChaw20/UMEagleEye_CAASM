// The machine a network agent runs on. A network agent sends no inventory, so its crawl upload
// (POST /network/topology `self`) says which address it reached its first router from, that
// adapter's MAC and the machine's name (agent-gui/eagleeye/netagent/service.py). routes/network.ts
// links the agent to the asset with that MAC, else to the one asset with that address (the crawl
// has just put the machine on the inventory from its router's ARP table). It never creates an
// asset: a network agent in a container reports the container's address, which matches nothing.

import { normalizeMac } from './mac'

export interface AgentSelf { ip: string | null; mac: string | null; hostname: string | null }

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
const HOSTNAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/

/** What a heartbeat's `self` says, kept within limits; null when it says nothing usable. */
export function cleanSelf(raw: unknown): AgentSelf | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const r = raw as Record<string, unknown>
  const ip = typeof r.ip === 'string' && IPV4.test(r.ip) && !r.ip.startsWith('127.') ? r.ip : null
  const mac = normalizeMac(r.mac)
  const hostname = typeof r.hostname === 'string' && HOSTNAME.test(r.hostname.trim()) ? r.hostname.trim() : null
  return ip || mac ? { ip, mac, hostname } : null
}

export interface HostCandidate { assetId: string; ip: string | null; mac: string | null; networkDevice: boolean }

/**
 * The asset the agent runs on: the one with its MAC, else the one with its address. Routers
 * and switches the crawl polled are never it. Two candidates for the same fact = no answer.
 */
export function pickHostAsset(self: AgentSelf, candidates: HostCandidate[]): string | null {
  const usable = candidates.filter((c) => !c.networkDevice)
  const only = (ids: string[]) => {
    const set = new Set(ids)
    return set.size === 1 ? [...set][0]! : null
  }
  if (self.mac) {
    const byMac = only(usable.filter((c) => normalizeMac(c.mac) === self.mac).map((c) => c.assetId))
    if (byMac) return byMac
  }
  if (self.ip) return only(usable.filter((c) => c.ip === self.ip).map((c) => c.assetId))
  return null
}
