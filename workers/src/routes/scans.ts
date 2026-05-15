import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb } from '../db/client'
import { scanResults, agents, assets } from '../db/schema'

const app = new Hono<{ Bindings: Env }>()

// ── Helper: SHA-256 hex digest ───────────────────────────────────
async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder()
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(input))
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// ── POST /active ─────────────────────────────────────────────────
const activeScanSchema = z.object({
  subnet: z.string().optional(),
  agent_id: z.string().uuid().optional(),
})

app.post('/active', authMiddleware, zValidator('json', activeScanSchema), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { subnet, agent_id } = c.req.valid('json')

    const effectiveSubnet = subnet ?? c.env.SCAN_DEFAULT_SUBNET ?? '192.168.1.0/24'

    const scanRows = await db
      .insert(scanResults)
      .values({
        agentId: agent_id ?? null,
        tenantId: user.tenantId ?? null,
        scanType: 'active',
        subnet: effectiveSubnet,
        status: 'pending',
        hostsDiscovered: 0,
        rawResults: [],
      })
      .returning()

    const scan = scanRows[0]
    if (!scan) {
      return c.json({ detail: 'Failed to create scan record' }, 500)
    }

    // Notify agent via Telegram if agent_id is provided
    if (agent_id && c.env.TELEGRAM_BOT_TOKEN && c.env.TELEGRAM_CHAT_ID) {
      const message = `Scan Dispatched\nScan ID: ${scan.scanId}\nSubnet: ${effectiveSubnet}\nAgent: ${agent_id}\nTriggered by: ${user.username}`
      fetch(`https://api.telegram.org/bot${c.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: c.env.TELEGRAM_CHAT_ID,
          text: message,
          parse_mode: 'Markdown',
        }),
      }).catch((err) => console.error('Telegram notify error:', err))
    }

    return c.json({ scan_id: scan.scanId, status: 'pending', message: 'Scan dispatched to agent' }, 202)
  } catch (err) {
    console.error('scans POST /active error:', err)
    return c.json({ detail: 'Failed to initiate scan' }, 500)
  }
})

// ── POST /ingest ─────────────────────────────────────────────────
const hostSchema = z.object({
  ip: z.string().min(1).max(45),
  hostname: z.string().max(255).optional(),
  mac: z.string().max(17).optional(),
  ports: z.array(z.unknown()).optional(),
  os: z.record(z.unknown()).optional(),
})

const ingestSchema = z.object({
  agent_id: z.string().uuid(),
  scan_id: z.string().uuid(),
  hosts: z.array(hostSchema),
})

app.post('/ingest', zValidator('json', ingestSchema), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)

    // Agent authentication via API key
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ detail: 'Missing or invalid Authorization header' }, 401)
    }

    const incomingKey = authHeader.slice(7)
    const incomingKeyHash = await sha256Hex(incomingKey)

    const { agent_id, scan_id, hosts } = c.req.valid('json')

    // Fetch agent and verify API key hash
    const [agent] = await db.select().from(agents).where(eq(agents.agentId, agent_id)).limit(1)

    if (!agent) {
      return c.json({ detail: 'Agent not found' }, 401)
    }

    // Constant-time comparison: compare SHA-256 of incoming key vs stored hash
    if (incomingKeyHash !== agent.apiKeyHash) {
      return c.json({ detail: 'Invalid API key' }, 401)
    }

    // Update agent heartbeat and status
    await db
      .update(agents)
      .set({ status: 'online', lastHeartbeat: new Date() })
      .where(eq(agents.agentId, agent_id))

    // Verify scan exists
    const [scan] = await db.select().from(scanResults).where(eq(scanResults.scanId, scan_id)).limit(1)
    if (!scan) {
      return c.json({ detail: 'Scan not found' }, 404)
    }

    const tenantId = agent.tenantId

    // Upsert assets for each discovered host
    const upsertedAssetIds: string[] = []
    for (const host of hosts) {
      // Check if asset with this IP already exists in this tenant
      const conditions = [eq(assets.ipAddress, host.ip)]
      if (tenantId) {
        conditions.push(eq(assets.tenantId, tenantId))
      }

      const [existing] = await db
        .select()
        .from(assets)
        .where(and(...conditions))
        .limit(1)

      if (existing) {
        // Update existing asset
        const updatedRows = await db
          .update(assets)
          .set({
            hostname: host.hostname ?? existing.hostname,
            macAddress: host.mac ?? existing.macAddress,
            osInfo: host.os ?? existing.osInfo ?? {},
            lastScanned: new Date(),
            updatedAt: new Date(),
          })
          .where(eq(assets.assetId, existing.assetId))
          .returning({ assetId: assets.assetId })

        const updatedId = updatedRows[0]?.assetId
        if (updatedId) upsertedAssetIds.push(updatedId)
      } else {
        // Insert new asset
        const createdRows = await db
          .insert(assets)
          .values({
            ipAddress: host.ip,
            hostname: host.hostname,
            macAddress: host.mac,
            osInfo: host.os ?? {},
            tenantId: tenantId ?? null,
            deviceType: 'unknown',
            lastScanned: new Date(),
          })
          .returning({ assetId: assets.assetId })

        const createdId = createdRows[0]?.assetId
        if (createdId) upsertedAssetIds.push(createdId)
      }
    }

    // Update scan result
    await db
      .update(scanResults)
      .set({
        status: 'completed',
        hostsDiscovered: hosts.length,
        rawResults: hosts,
        completedAt: new Date(),
      })
      .where(eq(scanResults.scanId, scan_id))

    // Trigger drift check advisory for each asset
    for (const assetId of upsertedAssetIds) {
      await c.env.ADVISORY_QUEUE.send({
        type: 'drift_check',
        assetId,
        scanId: scan_id,
        agentId: agent_id,
      })
    }

    return c.json({
      message: 'Scan results ingested',
      scan_id,
      hosts_discovered: hosts.length,
      assets_upserted: upsertedAssetIds.length,
    })
  } catch (err) {
    console.error('scans POST /ingest error:', err)
    return c.json({ detail: 'Failed to ingest scan results' }, 500)
  }
})

// ── GET /status/:scanId ──────────────────────────────────────────
app.get('/status/:scanId', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { scanId } = c.req.param()

    const [scan] = await db.select().from(scanResults).where(eq(scanResults.scanId, scanId)).limit(1)

    if (!scan) {
      return c.json({ detail: 'Scan not found' }, 404)
    }

    // Tenant check
    if (user.role !== 'superadmin' && user.tenantId && scan.tenantId !== user.tenantId) {
      return c.json({ detail: 'Scan not found' }, 404)
    }

    return c.json(scan)
  } catch (err) {
    console.error('scans GET /status error:', err)
    return c.json({ detail: 'Failed to fetch scan status' }, 500)
  }
})

export default app
