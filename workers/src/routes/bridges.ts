import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { bridges, agents } from '../db/schema'
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

// ── GET / — List bridges ──────────────────────────────────────────
router.get('/', authMiddleware, async (c) => {
  const db = getDb(c.env.HYPERDRIVE.connectionString)
  const user = c.get('user')

  const rows = user.role === 'superadmin'
    ? await db.select().from(bridges)
    : user.tenantId
      ? await db.select().from(bridges).where(eq(bridges.tenantId, user.tenantId))
      : []

  // Count agents per bridge
  const agentCounts = await db
    .select({
      bridgeId: agents.bridgeId,
      count: sql<number>`cast(count(*) as int)`,
    })
    .from(agents)
    .groupBy(agents.bridgeId)

  const countMap = new Map(agentCounts.map((r) => [r.bridgeId, r.count]))

  const result = rows.map((b) => ({
    bridge_id: b.bridgeId,
    tenant_id: b.tenantId,
    name: b.name,
    status: computeStatus(b.lastHeartbeat),
    last_heartbeat: b.lastHeartbeat,
    bridge_ip: b.bridgeIp,
    mode: b.mode,
    version: b.version,
    agent_count: countMap.get(b.bridgeId) ?? 0,
    created_at: b.createdAt,
  }))

  return c.json({ bridges: result })
})

// ── POST / — Register new bridge ─────────────────────────────────
router.post(
  '/',
  authMiddleware,
  requireRoles('ops_lead', 'superadmin'),
  zValidator('json', z.object({
    name: z.string().min(1).max(100),
    mode: z.enum(['relay', 'buffer']).optional(),
  })),
  async (c) => {
    const db = getDb(c.env.HYPERDRIVE.connectionString)
    const user = c.get('user')
    const { name, mode } = c.req.valid('json')

    if (!user.tenantId && user.role !== 'superadmin') {
      return c.json({ detail: 'User has no tenant assigned' }, 400)
    }

    const apiKey = generateApiKey()
    const apiKeyHash = await hashApiKey(apiKey)

    const inserted = await db.insert(bridges).values({
      tenantId: user.tenantId ?? null,
      name,
      apiKeyHash,
      mode: mode ?? 'relay',
    }).returning()

    const bridge = inserted[0]
    if (!bridge) return c.json({ detail: 'Failed to create bridge' }, 500)

    return c.json({
      bridge_id: bridge.bridgeId,
      name: bridge.name,
      mode: bridge.mode,
      api_key: apiKey,
      created_at: bridge.createdAt,
    }, 201)
  }
)

// ── PATCH /:bridgeId — Update name / tenant ──────────────────────
router.patch(
  '/:bridgeId',
  authMiddleware,
  requireRoles('ops_lead', 'superadmin'),
  zValidator('json', z.object({
    name: z.string().min(1).max(100).optional(),
    tenant_id: z.string().uuid().nullable().optional(),
  })),
  async (c) => {
    const db = getDb(c.env.HYPERDRIVE.connectionString)
    const user = c.get('user')
    const { bridgeId } = c.req.param()
    const updates = c.req.valid('json')

    const [existing] = await db.select().from(bridges).where(eq(bridges.bridgeId, bridgeId)).limit(1)
    if (!existing) return c.json({ detail: 'Bridge not found' }, 404)
    if (user.role !== 'superadmin' && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Forbidden' }, 403)
    }
    if (updates.tenant_id !== undefined && user.role !== 'superadmin') {
      return c.json({ detail: 'Only superadmin can reassign tenant' }, 403)
    }

    const updateData: Record<string, unknown> = {}
    if (updates.name !== undefined) updateData.name = updates.name
    if (updates.tenant_id !== undefined) updateData.tenantId = updates.tenant_id

    const patched = await db.update(bridges).set(updateData).where(eq(bridges.bridgeId, bridgeId)).returning()
    const updated = patched[0]
    if (!updated) return c.json({ detail: 'Failed to update bridge' }, 500)

    return c.json({ bridge_id: updated.bridgeId, tenant_id: updated.tenantId, name: updated.name })
  }
)

// ── DELETE /:bridgeId — Remove a bridge ───────────────────────────
router.delete(
  '/:bridgeId',
  authMiddleware,
  requireRoles('ops_lead', 'superadmin'),
  async (c) => {
    const db = getDb(c.env.HYPERDRIVE.connectionString)
    const user = c.get('user')
    const { bridgeId } = c.req.param()

    const [existing] = await db.select().from(bridges).where(eq(bridges.bridgeId, bridgeId)).limit(1)
    if (!existing) return c.json({ detail: 'Bridge not found' }, 404)
    if (user.role !== 'superadmin' && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Forbidden' }, 403)
    }

    await db.delete(bridges).where(eq(bridges.bridgeId, bridgeId))
    return c.json({ ok: true })
  }
)

// ── POST /:bridgeId/heartbeat — Bridge API key auth ───────────────
router.post(
  '/:bridgeId/heartbeat',
  zValidator('json', z.object({
    version: z.string().optional(),
    bridge_ip: z.string().optional(),
    queue_depth: z.number().optional(),
  })),
  async (c) => {
    const db = getDb(c.env.HYPERDRIVE.connectionString)
    const { bridgeId } = c.req.param()
    const { version, bridge_ip } = c.req.valid('json')

    // Extract API key from Authorization header
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ detail: 'Missing Authorization header' }, 401)
    }
    const providedKey = authHeader.slice(7)

    const [bridge] = await db.select().from(bridges).where(eq(bridges.bridgeId, bridgeId)).limit(1)
    if (!bridge) return c.json({ detail: 'Bridge not found' }, 404)

    // Verify API key by SHA-256 hash
    const providedHash = await hashApiKey(providedKey)
    if (providedHash !== bridge.apiKeyHash) {
      return c.json({ detail: 'Invalid API key' }, 401)
    }

    // Update heartbeat fields
    const updateData: Record<string, unknown> = {
      lastHeartbeat: new Date(),
      status: 'online',
    }
    if (version) updateData.version = version
    if (bridge_ip) updateData.bridgeIp = bridge_ip

    await db.update(bridges).set(updateData).where(eq(bridges.bridgeId, bridgeId))

    return c.json({ ok: true, bridge_id: bridgeId })
  }
)

export default router
