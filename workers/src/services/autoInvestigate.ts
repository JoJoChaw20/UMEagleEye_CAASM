import { sql } from 'drizzle-orm'
import type { DB } from '../db/client'
import { classifyMac, isSharedVirtualMac } from '../lib/identity'
import { isGenericHostname } from '../lib/hostnames'

// Auto-investigation of new devices. A device first heard by passive listening is only
// an address, a MAC and maybe a name. When the tenant turns this on, the agent that
// heard it gets a targeted active scan of that one IP (an ordinary active scan job whose
// subnet is the IP, so every agent version runs it), and the result is attached to the
// device's new-device alert (details.investigation).
//
// Guards, so phones joining the Wi-Fi do not cause a scan storm:
//  - only devices that passive listening found (an active scan already probed the others)
//  - not a device with an agent installed (its inventory says more than Nmap)
//  - not a phone whose private MAC changed (same specific name, both MACs private)
//  - not an IP the tenant scanned actively in the last INVESTIGATE_REPEAT_HOURS
//  - at most INVESTIGATE_MAX_PER_HOUR jobs per tenant per hour
//  - the job waits INVESTIGATE_DELAY_MINUTES (a passing visitor is gone by then, and the
//    scan is not tied up with the upload that found it)

export const INVESTIGATE_DELAY_MINUTES = 3
export const INVESTIGATE_REPEAT_HOURS = 24
export const INVESTIGATE_MAX_PER_HOUR = 10
// A queued investigation the agent never picks up (it went offline) is given up on.
export const INVESTIGATE_EXPIRE_HOURS = 2
export const INVESTIGATE_TRIGGER = 'new_device'

export interface InvestigationInfo {
  trigger: typeof INVESTIGATE_TRIGGER
  event_id: string
  asset_id: string
  not_before: string   // ISO time; GET /scans/pending hands the job out only after it
}

export function isInvestigation(networkInfo: unknown): networkInfo is InvestigationInfo {
  return !!networkInfo && typeof networkInfo === 'object'
    && (networkInfo as Record<string, unknown>)['trigger'] === INVESTIGATE_TRIGGER
}

const privateMac = (mac: string | null | undefined): boolean => {
  const { mac: m, macClass } = classifyMac(mac)
  return !!m && macClass === 'local' && !isSharedVirtualMac(m)
}

interface Candidate { event_id: string; asset_id: string; ip_address: string; mac_address: string | null; hostname: string | null }

/** Queue investigations for the new devices of one passive upload. Returns how many. */
export async function queueInvestigations(
  db: DB, opts: { tenantId: string | null; agentId: string; assetIds: string[] },
): Promise<number> {
  const { tenantId, agentId, assetIds } = opts
  if (!tenantId || assetIds.length === 0) return 0

  const setting = await db.execute(sql`SELECT auto_investigate_new_devices AS on FROM tenants WHERE tenant_id = ${tenantId}`)
  if (!(setting.rows[0] as { on?: boolean } | undefined)?.on) return 0

  // New-device alerts this upload just raised (first seen in the last few minutes), not
  // yet investigated, on assets without an agent and not scanned actively lately.
  const found = await db.execute(sql`
    SELECT e.event_id, a.asset_id, a.ip_address, a.mac_address, a.hostname
    FROM events e JOIN assets a ON a.asset_id = e.asset_id
    WHERE e.asset_id IN ${assetIds}
      AND a.tenant_id = ${tenantId}
      AND e.event_type = 'new_device' AND e.status = 'open'
      AND e.first_seen > now() - interval '10 minutes'
      AND e.details->>'source' = 'passive_scan'
      AND NOT (e.details ? 'investigation')
      AND NOT EXISTS (SELECT 1 FROM agents g WHERE g.host_asset_id = a.asset_id AND g.retired_at IS NULL)
      AND NOT EXISTS (
        SELECT 1 FROM scan_results s
        WHERE s.tenant_id = a.tenant_id AND s.scan_type = 'active' AND s.subnet = a.ip_address
          AND s.started_at > now() - make_interval(hours => ${INVESTIGATE_REPEAT_HOURS}))
    ORDER BY e.first_seen`)
  let candidates = found.rows as unknown as Candidate[]
  if (candidates.length === 0) return 0

  // A private MAC with a specific name another private-MAC asset already has: the same
  // phone after its MAC rotated (see lib/duplicates.ts), nothing new to learn.
  const named = candidates.filter(c => privateMac(c.mac_address) && c.hostname && !isGenericHostname(c.hostname))
  if (named.length) {
    const names = [...new Set(named.map(c => c.hostname!.toLowerCase()))]
    const others = await db.execute(sql`
      SELECT lower(hostname) AS name, mac_address FROM assets
      WHERE tenant_id = ${tenantId} AND lower(hostname) IN ${names} AND asset_id NOT IN ${assetIds}`)
    const rotated = new Set((others.rows as { name: string; mac_address: string | null }[])
      .filter(r => privateMac(r.mac_address)).map(r => r.name))
    candidates = candidates.filter(c => !(named.includes(c) && rotated.has(c.hostname!.toLowerCase())))
  }

  const recent = await db.execute(sql`
    SELECT count(*)::int AS n FROM scan_results
    WHERE tenant_id = ${tenantId} AND network_info->>'trigger' = ${INVESTIGATE_TRIGGER}
      AND started_at > now() - interval '1 hour'`)
  const room = INVESTIGATE_MAX_PER_HOUR - ((recent.rows[0] as { n?: number } | undefined)?.n ?? 0)
  // One job per IP, even if two new assets share it in this upload.
  const seen = new Set<string>()
  const chosen = candidates.filter(c => !seen.has(c.ip_address) && seen.add(c.ip_address)).slice(0, Math.max(room, 0))
  if (chosen.length === 0) {
    if (candidates.length) console.log(`auto-investigate: tenant ${tenantId} reached ${INVESTIGATE_MAX_PER_HOUR} per hour; ${candidates.length} new device(s) not scanned`)
    return 0
  }

  const notBefore = new Date(Date.now() + INVESTIGATE_DELAY_MINUTES * 60_000).toISOString()
  for (const c of chosen) {
    const info: InvestigationInfo = { trigger: INVESTIGATE_TRIGGER, event_id: c.event_id, asset_id: c.asset_id, not_before: notBefore }
    const inserted = await db.execute(sql`
      INSERT INTO scan_results (agent_id, tenant_id, scan_type, subnet, status, hosts_discovered, raw_results, network_info)
      VALUES (${agentId}, ${tenantId}, 'active', ${c.ip_address}, 'pending', 0, '[]'::jsonb, ${JSON.stringify(info)}::jsonb)
      RETURNING scan_id`)
    const scanId = (inserted.rows[0] as { scan_id: string }).scan_id
    await setInvestigation(db, c.event_id, { scan_id: scanId, status: 'queued', agent_id: agentId, queued_at: new Date().toISOString() })
  }
  console.log(`auto-investigate: queued ${chosen.length} targeted scan(s) for agent ${agentId}`)
  return chosen.length
}

async function setInvestigation(db: DB, eventId: string, investigation: Record<string, unknown>): Promise<void> {
  await db.execute(sql`
    UPDATE events SET details = details || jsonb_build_object('investigation', ${JSON.stringify(investigation)}::jsonb),
      updated_at = now()
    WHERE event_id = ${eventId}`)
}

/** An investigation scan's results arrived: what it found goes on the new-device alert. */
export async function recordInvestigationResult(
  db: DB, info: InvestigationInfo, scanId: string, ip: string, hosts: Record<string, unknown>[],
): Promise<void> {
  const host = hosts.find(h => h['ip'] === ip)
  const ports = Array.isArray(host?.['ports']) ? (host!['ports'] as Record<string, unknown>[]) : []
  const os = (host?.['os'] ?? null) as Record<string, unknown> | null
  await setInvestigation(db, info.event_id, {
    scan_id: scanId,
    status: host ? 'completed' : 'no_answer',
    completed_at: new Date().toISOString(),
    open_ports: ports.slice(0, 50).map(p => ({
      port: p['port'] ?? p['portid'] ?? null,
      protocol: p['protocol'] ?? null,
      service: p['service'] ?? p['name'] ?? null,
      product: p['product'] ?? null,
      version: p['version'] ?? null,
    })),
    os: os ? (os['name'] ?? os['os_name'] ?? os['osmatch'] ?? null) : null,
    hostname: host?.['hostname'] ?? null,
  })
}

/** The agent could not run the investigation (it failed it, or it expired). */
export async function recordInvestigationFailure(db: DB, info: InvestigationInfo, scanId: string, reason: string): Promise<void> {
  await setInvestigation(db, info.event_id, {
    scan_id: scanId, status: 'failed', reason: reason.slice(0, 500), completed_at: new Date().toISOString(),
  })
}
