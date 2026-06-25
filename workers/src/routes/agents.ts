import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { agents } from '../db/schema'
import { generateApiKey } from '../lib/auth'

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
  const db = getDb(c.env.HYPERDRIVE.connectionString)
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
  requireRoles('ops_lead', 'superadmin'),
  zValidator('json', z.object({
    name: z.string().min(1).max(100),
    config: z.record(z.unknown()).optional(),
    bridge_id: z.string().uuid().optional(),
  })),
  async (c) => {
    const db = getDb(c.env.HYPERDRIVE.connectionString)
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
  const db = getDb(c.env.HYPERDRIVE.connectionString)
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

// ── PATCH /:agentId — Update config / tenant ─────────────────────
router.patch(
  '/:agentId',
  authMiddleware,
  requireRoles('ops_lead', 'superadmin'),
  zValidator('json', z.object({
    name: z.string().min(1).max(100).optional(),
    config: z.record(z.unknown()).optional(),
    tenant_id: z.string().uuid().nullable().optional(),
  })),
  async (c) => {
    const db = getDb(c.env.HYPERDRIVE.connectionString)
    const user = c.get('user')
    const { agentId } = c.req.param()
    const updates = c.req.valid('json')

    const [existing] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!existing) return c.json({ detail: 'Agent not found' }, 404)
    if (user.role !== 'superadmin' && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Forbidden' }, 403)
    }

    // Only superadmin can reassign tenant
    if (updates.tenant_id !== undefined && user.role !== 'superadmin') {
      return c.json({ detail: 'Only superadmin can reassign tenant' }, 403)
    }

    const updateData: Record<string, unknown> = {}
    if (updates.name !== undefined) updateData.name = updates.name
    if (updates.config !== undefined) updateData.config = updates.config
    if (updates.tenant_id !== undefined) updateData.tenantId = updates.tenant_id

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
  requireRoles('ops_lead', 'superadmin'),
  async (c) => {
    const db = getDb(c.env.HYPERDRIVE.connectionString)
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
  })),
  async (c) => {
    const db = getDb(c.env.HYPERDRIVE.connectionString)
    const { agentId } = c.req.param()
    const { version, gateway_ip } = c.req.valid('json')

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

    await db.update(agents).set(updateData).where(eq(agents.agentId, agentId))

    return c.json({ ok: true })
  }
)

export default router
