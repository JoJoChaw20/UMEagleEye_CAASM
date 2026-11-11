// The network agent (agent-gui/eagleeye/netagent): what its crawl of the routers and switches
// found, beyond the addresses (those go through POST /scans/ingest with scan_type 'snmp').
//
//   POST /network/topology      the agent: its polled devices, the cables between them, and
//                               where each device is plugged in (after the addresses' ingest,
//                               so the assets exist)
//   GET  /network/links         the tenant's cables, for the topology view
//   POST /network/run/:agentId  "Run now": a crawl job for a network agent
//   GET  /network/map           the measured network as one graph (lib/networkMap.ts)

import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { and, desc, eq, inArray, isNull, or, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { AGENT_MANAGE_ROLES, AGENT_READ_ROLES } from '../lib/permissions'
import { getDb } from '../db/client'
import { agents, assetAddresses, assets, auditLogs, networkLinks, scanResults } from '../db/schema'
import { jobRefusal } from '../lib/agentPolicy'
import { agentPolicy } from '../services/agentPolicy'
import { MAP_DAYS, loadMapNetworks, loadNetworkMap } from '../services/networkMap'
import { normalizeMac } from '../lib/mac'
import {
  assetIndex, crawlSubnets, deviceAssets, linkRows, planLocations, topologySchema, type AssetRef, type CrawlHost,
} from '../lib/networkTopology'

const app = new Hono<{ Bindings: Env }>()
type Db = ReturnType<typeof getDb>

// Links not seen for this long are left out of GET /links (the cable was moved or the
// device is gone); the rows stay for history.
const LINK_DAYS = 30
const CHUNK = 500

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function sameHash(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

async function authenticateAgent(c: { req: { header(name: string): string | undefined } }, db: Db) {
  const auth = c.req.header('Authorization')
  const agentId = c.req.header('X-Agent-ID')
  if (!auth?.startsWith('Bearer ') || !agentId || !z.string().uuid().safeParse(agentId).success) return null
  const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
  return agent && !agent.retiredAt && sameHash(await sha256Hex(auth.slice(7)), agent.apiKeyHash) ? agent : null
}

/** The tenant's current addresses for these IPs and MACs (asset_addresses), and the assets'
 *  own address and MAC (an asset with an agent keeps its own there). */
async function assetRefs(db: Db, tenantId: string, ips: string[], macs: string[]): Promise<AssetRef[]> {
  const refs: AssetRef[] = []
  for (let i = 0; i < Math.max(ips.length, macs.length); i += CHUNK) {
    const ipPart = ips.slice(i, i + CHUNK)
    const macPart = macs.slice(i, i + CHUNK)
    const addrConds = [ipPart.length ? inArray(assetAddresses.ipAddress, ipPart) : undefined,
      macPart.length ? inArray(assetAddresses.macAddress, macPart) : undefined].filter(Boolean)
    const assetConds = [ipPart.length ? inArray(assets.ipAddress, ipPart) : undefined,
      macPart.length ? inArray(assets.macAddress, macPart) : undefined].filter(Boolean)
    if (!addrConds.length) continue
    const [addrs, own] = await Promise.all([
      db.select({ assetId: assetAddresses.assetId, ip: assetAddresses.ipAddress, mac: assetAddresses.macAddress })
        .from(assetAddresses)
        .where(and(eq(assetAddresses.tenantId, tenantId), isNull(assetAddresses.endedAt), or(...addrConds))),
      db.select({ assetId: assets.assetId, ip: assets.ipAddress, mac: assets.macAddress })
        .from(assets).where(and(eq(assets.tenantId, tenantId), or(...assetConds))),
    ])
    refs.push(...addrs, ...own)
  }
  return refs
}

// ── POST /topology ── the network agent's devices, cables and locations ───────
app.post('/topology', zValidator('json', topologySchema, (result, c) => {
  if (!result.success) return c.json({ detail: result.error.issues[0]?.message ?? 'Invalid topology' }, 400)
}), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const agent = await authenticateAgent(c, db)
    if (!agent) return c.json({ detail: 'Invalid credentials' }, 401)
    if (agent.kind !== 'network' || !agent.tenantId) {
      return c.json({ detail: 'Only a network agent sends a network topology' }, 403)
    }
    const tenantId = agent.tenantId
    const body = c.req.valid('json')
    const seenAt = new Date()

    const ips = [...new Set([
      ...body.devices.flatMap((d) => [d.address, ...d.addresses.map((a) => a.ip)]),
      ...body.hosts.map((h) => h.ip).filter((ip): ip is string => !!ip),
    ])]
    const macs = [...new Set([
      ...body.devices.flatMap((d) => d.interfaces.map((i) => normalizeMac(i.mac))),
      ...body.hosts.map((h) => normalizeMac(h.mac)),
    ].filter((m): m is string => !!m))]
    const index = assetIndex(await assetRefs(db, tenantId, ips, macs))
    const deviceAsset = deviceAssets(body.devices, index)

    // What each polled device is: kept on its asset, shown on the asset page.
    const deviceUpdates = body.devices.flatMap((d) => {
      const assetId = deviceAsset.get(d.label)
      if (!assetId) return []
      const record = {
        name: d.name, label: d.label, descr: d.descr ?? null, os: d.os ?? null, version: d.version ?? null,
        vendor: d.vendor ?? null, object_id: d.object_id ?? null, uptime_seconds: d.uptime_seconds ?? null,
        found_via: d.found_via ?? null, bridge_mac: d.bridge_mac ?? null, interfaces: d.interfaces,
        addresses: d.addresses, vlans: d.vlans ?? [], notes: d.notes ?? [], errors: d.errors ?? [],
        agent_id: agent.agentId, seen_at: seenAt.toISOString(),
      }
      return [db.update(assets).set({ networkDevice: record, updatedAt: seenAt })
        .where(and(eq(assets.assetId, assetId), eq(assets.tenantId, tenantId)))]
    })
    for (let i = 0; i < deviceUpdates.length; i += 50) {
      const part = deviceUpdates.slice(i, i + 50)
      if (part.length) await db.batch(part as [typeof part[0], ...typeof part])
    }

    // One row per cable; seen again = last_seen moves on.
    const rows = linkRows(body.links)
    const assetOfName = (n: string) => deviceAsset.get(n) ?? null
    for (let i = 0; i < rows.length; i += CHUNK) {
      const part = rows.slice(i, i + CHUNK)
      if (!part.length) continue
      await db.insert(networkLinks).values(part.map((r) => ({
        tenantId, agentId: agent.agentId, aName: r.aName, aPort: r.aPort, aAssetId: assetOfName(r.aName),
        bName: r.bName, bPort: r.bPort, bAssetId: assetOfName(r.bName), protocols: r.protocols,
        firstSeen: seenAt, lastSeen: seenAt,
      }))).onConflictDoUpdate({
        target: [networkLinks.tenantId, networkLinks.aName, networkLinks.aPort, networkLinks.bName, networkLinks.bPort],
        set: {
          lastSeen: seenAt, agentId: agent.agentId,
          protocols: sql`excluded.protocols`,
          aAssetId: sql`COALESCE(excluded.a_asset_id, ${networkLinks.aAssetId})`,
          bAssetId: sql`COALESCE(excluded.b_asset_id, ${networkLinks.bAssetId})`,
        },
      })
    }

    // Where each device is plugged in: one UPDATE ... FROM (VALUES ...) per chunk.
    const locations = planLocations(body.hosts as CrawlHost[], index, deviceAsset, agent.agentId, seenAt.toISOString())
    for (let i = 0; i < locations.length; i += CHUNK) {
      const part = locations.slice(i, i + CHUNK)
      if (!part.length) continue
      const values = sql.join(part.map((l) => sql`(${l.assetId}::uuid, ${JSON.stringify(l.location)}::jsonb)`), sql`, `)
      await db.execute(sql`
        UPDATE assets AS a SET network_location = v.loc
        FROM (VALUES ${values}) AS v(id, loc)
        WHERE a.asset_id = v.id AND a.tenant_id = ${tenantId}`)
    }

    // The crawl's numbers on its Discovery record (only the agent's own record).
    const summary = {
      devices: body.devices.length, links: rows.length, addresses: body.hosts.filter((h) => h.ip).length,
      located: locations.filter((l) => l.location.port).length,
      subnets: crawlSubnets(body.devices),          // the networks it reached (Discovery's Networks list)
      notes: body.devices.flatMap((d) => (d.notes ?? []).map((n) => `${d.label}: ${n}`)).slice(0, 20),
      unreachable: body.stats?.unreachable ?? [], skipped: body.stats?.skipped ?? 0,
      seconds: body.stats?.seconds ?? null, requests: body.stats?.requests ?? null,
      bytes_received: body.stats?.bytes_received ?? null,
    }
    if (body.scan_id) {
      await db.update(scanResults)
        .set({ networkInfo: sql`COALESCE(${scanResults.networkInfo}, '{}'::jsonb) || ${JSON.stringify({ crawl: summary })}::jsonb` })
        .where(and(eq(scanResults.scanId, body.scan_id), eq(scanResults.agentId, agent.agentId)))
    }
    return c.json({
      devices: body.devices.length, devices_matched: deviceAsset.size, links: rows.length,
      locations: locations.length, located_on_ports: summary.located,
    })
  } catch (err) {
    console.error('network POST /topology error:', err)
    return c.json({ detail: 'Failed to store the network topology' }, 500)
  }
})

// ── GET /links ── the tenant's cables seen in the last LINK_DAYS ───────────────
app.get('/links', authMiddleware, requireRoles(...AGENT_READ_ROLES), async (c) => {
  const user = c.get('user')
  if (!user.tenantId) return c.json({ links: [] })
  const db = getDb(c.env.DATABASE_URL)
  const rows = await db.select().from(networkLinks)
    .where(and(eq(networkLinks.tenantId, user.tenantId),
      sql`${networkLinks.lastSeen} > now() - make_interval(days => ${LINK_DAYS})`))
    .orderBy(networkLinks.aName, networkLinks.aPort)
    .limit(5000)
  return c.json({
    links: rows.map((r) => ({
      link_id: r.linkId, agent_id: r.agentId, protocols: r.protocols,
      a: { device: r.aName, port: r.aPort, asset_id: r.aAssetId },
      b: { device: r.bName, port: r.bPort, asset_id: r.bAssetId },
      first_seen: r.firstSeen, last_seen: r.lastSeen,
    })),
  })
})

// ── POST /run/:agentId ── "Run now": the network agent crawls at its next heartbeat ──
app.post('/run/:agentId', authMiddleware, requireRoles(...AGENT_MANAGE_ROLES), async (c) => {
  const user = c.get('user')
  const agentId = c.req.param('agentId')
  if (!z.string().uuid().safeParse(agentId).success) return c.json({ detail: 'Invalid agent id' }, 400)
  const db = getDb(c.env.DATABASE_URL)
  const found = await agentPolicy(db, agentId)
  if (!found || found.agent.tenantId !== user.tenantId) return c.json({ detail: 'Agent not found' }, 404)
  if (found.agent.retiredAt) return c.json({ detail: 'This agent is retired' }, 400)
  if (found.agent.kind !== 'network') return c.json({ detail: 'This is not a network agent' }, 400)
  const refusal = jobRefusal(found.resolved.effective, 'snmp')
  if (refusal) return c.json({ detail: refusal }, 409)
  const [waiting] = await db.select({ scanId: scanResults.scanId }).from(scanResults)
    .where(and(eq(scanResults.agentId, agentId), eq(scanResults.scanType, 'snmp'),
      inArray(scanResults.status, ['pending', 'running'])))
    .orderBy(desc(scanResults.startedAt)).limit(1)
  if (waiting) return c.json({ scan_id: waiting.scanId, status: 'already waiting' })
  const [job] = await db.insert(scanResults).values({
    agentId, tenantId: user.tenantId, scanType: 'snmp', subnet: 'snmp-crawl', status: 'pending',
    hostsDiscovered: 0, rawResults: [], networkInfo: { trigger: 'manual' },
  }).returning({ scanId: scanResults.scanId })
  await db.insert(auditLogs).values({
    userId: user.userId, tenantId: user.tenantId, actionType: 'agent.network_run', targetEntity: agentId,
    previousState: null, newState: { scan_id: job?.scanId },
  }).catch((err) => console.error('network run audit failed:', err))
  return c.json({ scan_id: job?.scanId, status: 'pending' }, 201)
})

// ── GET /map ── routers, switches, cables and where each device is plugged in, and every
// network the tenant's agents see (its gateway, the agents watching it, its devices) ───
app.get('/map', authMiddleware, requireRoles(...AGENT_READ_ROLES), async (c) => {
  const user = c.get('user')
  const tenantId = user.role === 'superadmin' ? c.req.query('tenant_id') : user.tenantId
  if (!tenantId || !z.string().uuid().safeParse(tenantId).success) {
    return c.json({ nodes: [], edges: [], agents: [], networks: [], days: MAP_DAYS })
  }
  try {
    const db = getDb(c.env.DATABASE_URL)
    const [map, networks, netAgents] = await Promise.all([
      loadNetworkMap(db, tenantId),
      loadMapNetworks(db, tenantId),
      db.select({ agentId: agents.agentId, name: agents.name, lastHeartbeat: agents.lastHeartbeat }).from(agents)
        .where(and(eq(agents.tenantId, tenantId), eq(agents.kind, 'network'), isNull(agents.retiredAt))),
    ])
    return c.json({
      ...map, networks, days: MAP_DAYS,
      agents: netAgents.map((a) => ({ agent_id: a.agentId, name: a.name, last_heartbeat: a.lastHeartbeat })),
    })
  } catch (err) {
    console.error('network GET /map error:', err)
    return c.json({ detail: 'Failed to build the network map' }, 500)
  }
})

export default app
