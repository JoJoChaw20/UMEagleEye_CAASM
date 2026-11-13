// Loads what the network agents stored for one tenant and builds the map (lib/networkMap.ts):
// for GET /network/map and for relationship inference (measured edges beat guessed ones). Also
// the tenant's networks as all its agents see them (lib/mapNetworks.ts), for the same map.

import { and, eq, isNotNull, isNull, sql } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { agents, assets, networkLinks } from '../db/schema'
import { buildNetworkMap, type MapDevice, type MapHost, type MapLink, type MapNode } from '../lib/networkMap'
import { buildMapNetworks, placeMeasured, type AgentVisit, type AssetAlerts, type GatewaySighting, type NetAddress, type NetAgent } from '../lib/mapNetworks'
import { policyOf, reportedOf, tenantPolicies } from './agentPolicy'

type Db = ReturnType<typeof getDb>

// What is older than this is left out: a cable moved, a device gone.
export const MAP_DAYS = 30

export async function loadNetworkMap(db: Db, tenantId: string) {
  const recent = (col: unknown) => sql`(${col} ->> 'seen_at')::timestamptz > now() - make_interval(days => ${MAP_DAYS})`
  const [deviceRows, linkRows, hostRows] = await Promise.all([
    db.select({ assetId: assets.assetId, ip: assets.ipAddress, nd: assets.networkDevice }).from(assets)
      .where(and(eq(assets.tenantId, tenantId), isNotNull(assets.networkDevice), recent(assets.networkDevice))),
    db.select().from(networkLinks)
      .where(and(eq(networkLinks.tenantId, tenantId), sql`${networkLinks.lastSeen} > now() - make_interval(days => ${MAP_DAYS})`))
      .limit(10000),
    db.select({
      assetId: assets.assetId, hostname: assets.hostname, ip: assets.ipAddress, mac: assets.macAddress,
      deviceType: assets.deviceType, criticality: assets.criticalityScore, loc: assets.networkLocation,
    }).from(assets)
      .where(and(eq(assets.tenantId, tenantId), isNotNull(assets.networkLocation), recent(assets.networkLocation)))
      .limit(20000),
  ])
  const devices: MapDevice[] = deviceRows.map((r) => ({ asset_id: r.assetId, ip: r.ip, network_device: (r.nd ?? {}) as MapDevice['network_device'] }))
  const links: MapLink[] = linkRows.map((l) => ({
    a_name: l.aName, a_port: l.aPort, a_asset_id: l.aAssetId, b_name: l.bName, b_port: l.bPort, b_asset_id: l.bAssetId,
    protocols: Array.isArray(l.protocols) ? (l.protocols as string[]) : [],
  }))
  const hosts: MapHost[] = hostRows.map((h) => ({
    asset_id: h.assetId, label: h.hostname || h.ip, ip: h.ip, mac: h.mac, device_type: h.deviceType,
    criticality: h.criticality, location: (h.loc ?? {}) as MapHost['location'],
  }))
  return buildNetworkMap(devices, links, hosts)
}

/** The tenant's networks: each with its gateway, the agents watching it and its devices
 *  (current addresses seen in the last MAP_DAYS), with their open CVE and exposure alerts. */
export async function loadMapNetworks(db: Db, tenantId: string, measured: MapNode[]) {
  const [addressRows, agentRows, sightingRows, alertRows, policies, visitRows] = await Promise.all([
    db.execute(sql`
      SELECT aa.asset_id, aa.network_key, aa.ip_address AS ip, aa.mac_address AS mac, aa.last_seen,
             COALESCE(NULLIF(a.hostname, ''), a.ip_address) AS label, a.device_type, a.criticality_score,
             a.in_my_assets,
             ((a.network_location IS NOT NULL
                AND (a.network_location ->> 'seen_at')::timestamptz > now() - make_interval(days => ${MAP_DAYS}))
              OR (a.network_device IS NOT NULL
                AND (a.network_device ->> 'seen_at')::timestamptz > now() - make_interval(days => ${MAP_DAYS}))) AS measured
      FROM asset_addresses aa JOIN assets a ON a.asset_id = aa.asset_id
      WHERE aa.tenant_id = ${tenantId} AND aa.ended_at IS NULL AND aa.network_key IS NOT NULL
        AND aa.last_seen > now() - make_interval(days => ${MAP_DAYS})
      LIMIT 20000`),
    db.select().from(agents).where(and(eq(agents.tenantId, tenantId), isNull(agents.retiredAt))),
    db.execute(sql`
      SELECT COALESCE(network_info ->> 'lan_subnet', network_info ->> 'subnet') AS subnet,
             network_info ->> 'gateway_ip' AS gateway_ip, network_info ->> 'gateway_mac' AS gateway_mac,
             max(started_at) AS at
      FROM scan_results
      WHERE tenant_id = ${tenantId} AND started_at > now() - make_interval(days => ${MAP_DAYS})
        AND network_info ->> 'gateway_ip' IS NOT NULL
      GROUP BY 1, 2, 3
      LIMIT 2000`),
    db.execute(sql`
      SELECT e.asset_id,
             count(*) FILTER (WHERE e.event_type = 'cve_detected')::int AS cve_open,
             count(*) FILTER (WHERE e.event_type = 'cve_detected' AND e.severity = 'critical')::int AS cve_critical,
             count(*) FILTER (WHERE e.event_type = 'cve_detected' AND e.severity = 'high')::int AS cve_high,
             count(*) FILTER (WHERE e.event_type = 'cve_detected' AND (e.details ->> 'has_cti_match')::boolean IS TRUE)::int AS kev,
             count(*) FILTER (WHERE e.event_type IN ('exposure', 'vulnerable_service'))::int AS exposure_open,
             max(CASE e.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 END)
               FILTER (WHERE e.event_type IN ('exposure', 'vulnerable_service')) AS exposure_rank
      FROM events e JOIN assets a ON a.asset_id = e.asset_id
      WHERE a.tenant_id = ${tenantId} AND e.status IN ('open', 'in_progress')
        AND e.event_type IN ('cve_detected', 'exposure', 'vulnerable_service')
      GROUP BY e.asset_id`),
    tenantPolicies(db, [tenantId]),
    // When each agent was last on each network (a laptop's networks it has left)
    db.execute(sql`
      SELECT agent_id, COALESCE(network_info ->> 'lan_subnet', network_info ->> 'subnet') AS subnet,
             max(COALESCE(completed_at, started_at)) AS at
      FROM scan_results
      WHERE tenant_id = ${tenantId} AND agent_id IS NOT NULL AND scan_type IN ('passive', 'active')
        AND started_at > now() - make_interval(days => ${MAP_DAYS})
        AND COALESCE(network_info ->> 'lan_subnet', network_info ->> 'subnet') IS NOT NULL
      GROUP BY 1, 2
      LIMIT 2000`),
  ])

  const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : String(v))
  const addresses: NetAddress[] = (addressRows.rows as Record<string, unknown>[]).map((r) => ({
    asset_id: String(r.asset_id), network_key: String(r.network_key), ip: String(r.ip),
    mac: (r.mac as string | null) ?? null, last_seen: iso(r.last_seen), label: String(r.label ?? r.ip),
    device_type: (r.device_type as string | null) ?? null,
    criticality: r.criticality_score == null ? null : Number(r.criticality_score),
    in_my_assets: r.in_my_assets === true, measured: r.measured === true,
  }))
  const tenant = policies.get(tenantId) ?? null
  const netAgents: NetAgent[] = agentRows.map((a) => {
    const effective = policyOf(a, tenant).effective
    const networks = (reportedOf(a) as { networks?: unknown }).networks
    const config = (a.config ?? {}) as Record<string, unknown>
    return {
      agent_id: a.agentId, name: a.name, kind: a.kind, host_asset_id: a.hostAssetId,
      networks: Array.isArray(networks) ? networks.filter((n): n is string => typeof n === 'string') : [],
      default_gateway: typeof config.default_gateway === 'string' ? config.default_gateway : null,
      listens: effective.passive === true, scans: effective.scanner !== false,
    }
  })
  const sightings: GatewaySighting[] = (sightingRows.rows as Record<string, unknown>[]).map((r) => ({
    subnet: (r.subnet as string | null) ?? null, gateway_ip: String(r.gateway_ip),
    gateway_mac: (r.gateway_mac as string | null) ?? null, at: iso(r.at),
  }))
  const SEVERITY = [null, 'low', 'medium', 'high', 'critical'] as const
  const alerts = new Map<string, AssetAlerts>((alertRows.rows as Record<string, unknown>[]).map((r) => [String(r.asset_id), {
    cve_open: Number(r.cve_open), cve_critical: Number(r.cve_critical), cve_high: Number(r.cve_high), kev: Number(r.kev),
    exposure_open: Number(r.exposure_open), exposure_severity: SEVERITY[Number(r.exposure_rank ?? 0)] ?? null,
  }]))
  const visits: AgentVisit[] = (visitRows.rows as Record<string, unknown>[]).map((r) => ({
    agent_id: String(r.agent_id), subnet: String(r.subnet), at: iso(r.at),
  }))
  return placeMeasured(buildMapNetworks(addresses, netAgents, sightings, alerts, visits), measured)
}
