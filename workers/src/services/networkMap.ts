// Loads what the network agents stored for one tenant and builds the map (lib/networkMap.ts):
// for GET /network/map and for relationship inference (measured edges beat guessed ones).

import { and, eq, isNotNull, sql } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { assets, networkLinks } from '../db/schema'
import { buildNetworkMap, type MapDevice, type MapHost, type MapLink } from '../lib/networkMap'

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
