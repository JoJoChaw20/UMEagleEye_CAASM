import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { and, eq, inArray, isNull, or, sql, type SQL } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { AGENT_MANAGE_ROLES } from '../lib/permissions'
import { getDb } from '../db/client'
import { agents, assets, assetAddresses, assetSoftware, events } from '../db/schema'
import { generateApiKey } from '../lib/auth'
import { isIPv4 } from '../lib/exposure'
import { computeCriticality } from '../lib/criticality'
import { deriveNetworkKey } from '../lib/identity'
import {
  chooseBinding, deviceTypeFor, diffSoftware, identityMacs, inventoryHostKey, inventoryIps, storedInventory,
  type BindingCandidate, type InventoryPayload,
} from '../lib/endpointInventory'

const router = new Hono<{ Bindings: Env }>()

// ── Helper: SHA-256 hash of API key ───────────────────────────────
async function hashApiKey(key: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key))
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
}

// ── Helper: compute status from lastHeartbeat ─────────────────────
function computeStatus(lastHeartbeat: Date | null): 'online' | 'degraded' | 'offline' {
  if (!lastHeartbeat) return 'offline'
  const diffMs = Date.now() - new Date(lastHeartbeat).getTime()
  const diffMin = diffMs / 60_000
  if (diffMin < 2) return 'online'
  if (diffMin < 10) return 'degraded'
  return 'offline'
}

// ── GET / — List agents ───────────────────────────────────────────
router.get('/', authMiddleware, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const user = c.get('user')

  const rows = user.role === 'superadmin'
    ? await db.select().from(agents)
    : user.tenantId
      ? await db.select().from(agents).where(eq(agents.tenantId, user.tenantId))
      : []

  const result = rows.map((a) => ({
    agent_id: a.agentId,
    tenant_id: a.tenantId,
    name: a.name,
    status: computeStatus(a.lastHeartbeat),
    last_heartbeat: a.lastHeartbeat,
    gateway_ip: a.gatewayIp,
    version: a.version,
    config: a.config,
    bridge_id: a.bridgeId,
    created_at: a.createdAt,
  }))

  return c.json({ agents: result })
})

// ── POST / — Register new agent ───────────────────────────────────
router.post(
  '/',
  authMiddleware,
  requireRoles(...AGENT_MANAGE_ROLES),
  zValidator('json', z.object({
    name: z.string().min(1).max(100),
    config: z.record(z.unknown()).optional(),
    bridge_id: z.string().uuid().optional(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const { name, config, bridge_id } = c.req.valid('json')

    if (!user.tenantId && user.role !== 'superadmin') {
      return c.json({ detail: 'User has no tenant assigned' }, 400)
    }

    const apiKey = generateApiKey()
    const apiKeyHash = await hashApiKey(apiKey)

    const inserted = await db.insert(agents).values({
      tenantId: user.tenantId ?? null,
      name,
      apiKeyHash,
      config: config ?? {},
      bridgeId: bridge_id ?? null,
    }).returning()

    const agent = inserted[0]
    if (!agent) return c.json({ detail: 'Failed to create agent' }, 500)

    return c.json({
      agent_id: agent.agentId,
      name: agent.name,
      api_key: apiKey,
      created_at: agent.createdAt,
    }, 201)
  }
)

// ── GET /:agentId — Single agent detail ───────────────────────────
router.get('/:agentId', authMiddleware, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const user = c.get('user')
  const { agentId } = c.req.param()

  const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
  if (!agent) return c.json({ detail: 'Agent not found' }, 404)

  if (user.role !== 'superadmin' && agent.tenantId !== user.tenantId) {
    return c.json({ detail: 'Forbidden' }, 403)
  }

  return c.json({
    agent_id: agent.agentId,
    tenant_id: agent.tenantId,
    name: agent.name,
    status: computeStatus(agent.lastHeartbeat),
    last_heartbeat: agent.lastHeartbeat,
    gateway_ip: agent.gatewayIp,
    version: agent.version,
    config: agent.config,
    bridge_id: agent.bridgeId,
    created_at: agent.createdAt,
  })
})

// ── PATCH /:agentId — Update agent configuration ─────────────────
router.patch(
  '/:agentId',
  authMiddleware,
  requireRoles(...AGENT_MANAGE_ROLES),
  zValidator('json', z.object({
    name: z.string().min(1).max(100).optional(),
    config: z.record(z.unknown()).optional(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const { agentId } = c.req.param()
    const updates = c.req.valid('json')

    const [existing] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!existing) return c.json({ detail: 'Agent not found' }, 404)
    if (user.role !== 'superadmin' && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Forbidden' }, 403)
    }

    const updateData: Record<string, unknown> = {}
    if (updates.name !== undefined) updateData.name = updates.name
    if (updates.config !== undefined) updateData.config = updates.config

    const patched = await db.update(agents).set(updateData).where(eq(agents.agentId, agentId)).returning()
    const updated = patched[0]
    if (!updated) return c.json({ detail: 'Failed to update agent' }, 500)

    return c.json({
      agent_id: updated.agentId,
      tenant_id: updated.tenantId,
      name: updated.name,
      config: updated.config,
    })
  }
)

// ── DELETE /:agentId ──────────────────────────────────────────────
router.delete(
  '/:agentId',
  authMiddleware,
  requireRoles(...AGENT_MANAGE_ROLES),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const { agentId } = c.req.param()

    const [existing] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!existing) return c.json({ detail: 'Agent not found' }, 404)
    if (user.role !== 'superadmin' && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Forbidden' }, 403)
    }

    await db.delete(agents).where(eq(agents.agentId, agentId))
    return c.json({ ok: true })
  }
)

// ── POST /:agentId/heartbeat — Agent API key auth ─────────────────
router.post(
  '/:agentId/heartbeat',
  zValidator('json', z.object({
    version: z.string().optional(),
    gateway_ip: z.string().optional(),
    // Lenient on purpose: a bad value must never reject the whole heartbeat
    // (that would mark the agent offline). Validated below before storing.
    default_gateway: z.string().max(45).optional(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { agentId } = c.req.param()
    const { version, gateway_ip, default_gateway } = c.req.valid('json')

    // Extract API key from Authorization header
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ detail: 'Missing Authorization header' }, 401)
    }
    const providedKey = authHeader.slice(7)

    const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!agent) return c.json({ detail: 'Agent not found' }, 404)

    // Verify API key by SHA-256 hash
    const providedHash = await hashApiKey(providedKey)
    if (providedHash !== agent.apiKeyHash) {
      return c.json({ detail: 'Invalid API key' }, 401)
    }

    // Update heartbeat fields
    const updateData: Record<string, unknown> = {
      lastHeartbeat: new Date(),
      status: 'online',
    }
    if (version) updateData.version = version
    if (gateway_ip) updateData.gatewayIp = gateway_ip
    // gateway_ip has always carried the agent's own LAN IP, so the real default
    // gateway goes in config where scan ingest reads it for internet exposure.
    if (default_gateway && isIPv4(default_gateway)) {
      updateData.config = { ...((agent.config ?? {}) as Record<string, unknown>), default_gateway }
    }

    await db.update(agents).set(updateData).where(eq(agents.agentId, agentId))

    return c.json({ ok: true })
  }
)

// ── POST /:agentId/inventory — endpoint inventory of the agent's own machine ──
// Agent API key auth. Binds the inventory to an asset (see lib/endpointInventory
// chooseBinding), creating one in Discovered when none matches, stores the facts on
// the asset and syncs asset_software by diff.
const inventorySoftware = z.object({
  name: z.string().min(1).max(255),
  version: z.string().max(100).nullish(),
  publisher: z.string().max(255).nullish(),
  install_date: z.string().max(10).nullish(),
  scope: z.string().max(16).nullish(),
  arch: z.string().max(16).nullish(),
})
const inventorySchema = z.object({
  schema: z.literal(1),
  platform: z.string().max(16),
  collected_at: z.string().max(40),
  identity: z.object({
    hostname: z.string().max(255).nullish(),
    dns_hostname: z.string().max(255).nullish(),
  }).passthrough(),
  hardware: z.object({
    manufacturer: z.string().max(255).nullish(),
    form_factor: z.string().max(16).nullish(),
  }).passthrough().optional(),
  os: z.object({ role: z.string().max(32).nullish() }).passthrough().optional(),
  network: z.object({
    primary_ip: z.string().max(45).nullish(),
    interfaces: z.array(z.object({
      name: z.string().max(255).nullish(),
      mac: z.string().max(32).nullish(),
      physical: z.boolean().optional(),
      ipv4: z.array(z.string().max(45)).max(32).optional(),
    }).passthrough()).max(64),
    listening: z.array(z.unknown()).max(5000).optional(),
  }).passthrough(),
  software: z.array(inventorySoftware).max(5000),
}).passthrough()

router.post('/:agentId/inventory', zValidator('json', inventorySchema), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const { agentId } = c.req.param()
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) return c.json({ detail: 'Missing Authorization header' }, 401)

    const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!agent) return c.json({ detail: 'Agent not found' }, 404)
    if (await hashApiKey(authHeader.slice(7)) !== agent.apiKeyHash) return c.json({ detail: 'Invalid API key' }, 401)
    const tenantId = agent.tenantId
    if (!tenantId) return c.json({ detail: 'Agent has no tenant; register it from a tenant account' }, 400)

    const inv = c.req.valid('json') as unknown as InventoryPayload
    const macs = identityMacs(inv)
    const hostKey = inventoryHostKey(inv)
    const ips = inventoryIps(inv)
    const hostname = inv.identity.hostname?.trim() || null
    const vendor = inv.hardware?.manufacturer?.trim() || null
    const now = new Date()
    const parsedAt = new Date(inv.collected_at)
    const collectedAt = isNaN(parsedAt.getTime()) ? now : parsedAt

    // ── Candidate assets (one query per rule, all tenant-scoped) ──
    const hasMac = sql<boolean>`(${assets.macAddress} IS NOT NULL OR EXISTS (
      SELECT 1 FROM ${assetAddresses} aa WHERE aa.asset_id = ${assets.assetId} AND aa.mac_address IS NOT NULL))`
    const candidates = (where: SQL | undefined): Promise<BindingCandidate[]> =>
      where
        ? db.select({ assetId: assets.assetId, inMyAssets: assets.inMyAssets, lastScanned: assets.lastScanned, hasMac })
            .from(assets).where(and(eq(assets.tenantId, tenantId), where))
        : Promise.resolve([])

    const [bound, macMatches, hostKeyMatches, ipMatches] = await Promise.all([
      agent.hostAssetId
        ? db.select({ assetId: assets.assetId }).from(assets)
            .where(and(eq(assets.assetId, agent.hostAssetId), eq(assets.tenantId, tenantId))).limit(1)
        : Promise.resolve([]),
      candidates(macs.length ? or(
        inArray(assets.macAddress, macs),
        inArray(assets.assetId, db.select({ id: assetAddresses.assetId }).from(assetAddresses)
          .where(and(eq(assetAddresses.tenantId, tenantId), inArray(assetAddresses.macAddress, macs)))),
      ) : undefined),
      candidates(hostKey ? or(eq(assets.hostKey, hostKey), sql`lower(${assets.hostname}) = ${hostKey}`) : undefined),
      candidates(ips.length ? inArray(assets.ipAddress, ips) : undefined),
    ])

    const decision = chooseBinding({ boundAssetId: bound[0]?.assetId ?? null, macMatches, hostKeyMatches, ipMatches })
    let assetId: string
    let created = false

    if (decision) {
      assetId = decision.assetId
    } else {
      // ── No match: create the asset in Discovered ──
      const ip = ips[0]
      if (!ip) return c.json({ detail: 'Inventory has no IPv4 address to identify this machine' }, 400)
      assetId = crypto.randomUUID()
      created = true
      const deviceType = deviceTypeFor(inv)
      const networkKey = deriveNetworkKey({ ip })
      // Another device may still hold this IP as its current address (DHCP reuse):
      // end that row first, as scan ingest does, so the unique current-address index holds.
      const holders = networkKey
        ? await db.select({ addressId: assetAddresses.addressId }).from(assetAddresses).where(and(
            eq(assetAddresses.tenantId, tenantId), eq(assetAddresses.networkKey, networkKey),
            eq(assetAddresses.ipAddress, ip), isNull(assetAddresses.endedAt)))
        : []
      await db.batch([
        ...holders.map(h => db.update(assetAddresses).set({ endedAt: now }).where(eq(assetAddresses.addressId, h.addressId))),
        db.insert(assets).values({
          assetId, tenantId, ipAddress: ip, hostname, macAddress: macs[0] ?? null, hostKey,
          hardwareVendor: vendor, deviceType, deviceTypeSource: 'auto', osInfo: {},
          criticalityScore: computeCriticality({ deviceType, isInternetFacing: false, hostname, owner: null, osInfo: {} }).score,
          source: 'agent', inMyAssets: false, lastScanned: now, createdAt: now, updatedAt: now,
        }),
        db.insert(assetAddresses).values({
          assetId, tenantId, networkKey, ipAddress: ip, macAddress: macs[0] ?? null, firstSeen: now, lastSeen: now,
        }),
        db.insert(events).values({
          assetId, eventType: 'new_device', severity: 'medium',
          details: { ip, mac: macs[0] ?? null, hostname, source: 'agent' },
        }),
      ] as unknown as Parameters<typeof db.batch>[0])
    }

    // ── Store facts; fill identity gaps only (never overwrite what a user or scan set) ──
    const existingSoftware = await db.select({
      softwareId: assetSoftware.softwareId, name: assetSoftware.name,
      version: assetSoftware.version, publisher: assetSoftware.publisher,
    }).from(assetSoftware).where(eq(assetSoftware.assetId, assetId))
    const diff = diffSoftware(existingSoftware, inv.software)

    const statements: unknown[] = [
      db.update(assets).set({
        endpointInventory: storedInventory(inv),
        inventoryCollectedAt: collectedAt,
        lastScanned: now,
        updatedAt: now,
        hostname: sql`COALESCE(${assets.hostname}, ${hostname})`,
        hardwareVendor: sql`COALESCE(${assets.hardwareVendor}, ${vendor})`,
        hostKey: sql`COALESCE(${assets.hostKey}, ${hostKey})`,
      }).where(eq(assets.assetId, assetId)),
      db.update(agents).set({ hostAssetId: assetId }).where(eq(agents.agentId, agentId)),
    ]
    for (let i = 0; i < diff.deleteIds.length; i += 500) {
      statements.push(db.delete(assetSoftware).where(inArray(assetSoftware.softwareId, diff.deleteIds.slice(i, i + 500))))
    }
    statements.push(db.update(assetSoftware).set({ lastSeen: now }).where(eq(assetSoftware.assetId, assetId)))
    for (let i = 0; i < diff.insert.length; i += 100) {
      statements.push(db.insert(assetSoftware).values(diff.insert.slice(i, i + 100).map(s => ({
        assetId, name: s.name, version: s.version ?? null, publisher: s.publisher ?? null,
        installDate: s.install_date ?? null, scope: s.scope ?? null, arch: s.arch ?? null,
        source: 'agent', firstSeen: now, lastSeen: now,
      }))))
    }
    await db.batch(statements as unknown as Parameters<typeof db.batch>[0])

    return c.json({
      asset_id: assetId,
      created,
      matched_by: decision?.matchedBy ?? null,
      software: { added: diff.insert.length, removed: diff.deleteIds.length, unchanged: diff.unchanged },
    })
  } catch (err) {
    console.error('agents POST /:agentId/inventory error:', err)
    return c.json({ detail: 'Failed to store inventory' }, 500)
  }
})

export default router
