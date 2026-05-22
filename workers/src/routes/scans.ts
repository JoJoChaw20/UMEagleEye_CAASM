import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb } from '../db/client'
import { scanResults, agents, assets, topologyNodes } from '../db/schema'
import { inferForTenant } from './topology'
import { inferRelationshipsForTenant } from './relationships'
import { rescoreAssets } from '../lib/rescore'

const app = new Hono<{ Bindings: Env }>()

// ── Helper: SHA-256 hex digest ───────────────────────────────────
async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder()
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(input))
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// ── GET / ─── list scans for authenticated user ──────────────────
app.get('/', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    let rows = await db
      .select()
      .from(scanResults)
      .limit(100)

    if (user.role !== 'superadmin' && user.tenantId) {
      rows = rows.filter(r => r.tenantId === user.tenantId)
    }

    return c.json({ scans: rows, total: rows.length })
  } catch (err) {
    console.error('scans GET / error:', err)
    return c.json({ detail: 'Failed to fetch scans' }, 500)
  }
})

// ── GET /pending ─── agent polls for pending scans ───────────────
app.get('/pending', async (c) => {
  try {
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ detail: 'Missing or invalid Authorization header' }, 401)
    }
    const incomingKey = authHeader.slice(7)
    const enc = new TextEncoder()
    const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(incomingKey))
    const incomingKeyHash = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0')).join('')

    const agentId = c.req.header('X-Agent-ID')
    if (!agentId) return c.json({ detail: 'X-Agent-ID header required' }, 400)

    const db = getDb(c.env.DATABASE_URL)
    const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!agent || incomingKeyHash !== agent.apiKeyHash) {
      return c.json({ detail: 'Invalid agent credentials' }, 401)
    }

    await db.update(agents)
      .set({ status: 'online', lastHeartbeat: new Date() })
      .where(eq(agents.agentId, agentId))

    const pending = await db
      .select()
      .from(scanResults)
      .where(and(eq(scanResults.agentId, agentId), eq(scanResults.status, 'pending')))
      .limit(5)

    return c.json({ scans: pending })
  } catch (err) {
    console.error('scans GET /pending error:', err)
    return c.json({ detail: 'Failed to fetch pending scans' }, 500)
  }
})

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
  scan_id:  z.string().uuid().optional(),   // omit for passive/self-initiated scans
  scan_type: z.enum(['active', 'passive']).optional().default('active'),
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

    const { agent_id, scan_id, scan_type = 'active', hosts } = c.req.valid('json')

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

    const tenantId = agent.tenantId

    // Resolve scan record — for passive scans the agent omits scan_id so we
    // create one automatically here instead of requiring a prior dispatch.
    let resolvedScanId: string
    if (scan_id) {
      const [existing] = await db.select().from(scanResults).where(eq(scanResults.scanId, scan_id)).limit(1)
      if (!existing) return c.json({ detail: 'Scan not found' }, 404)
      resolvedScanId = existing.scanId
    } else {
      const [created] = await db.insert(scanResults).values({
        agentId:   agent_id,
        tenantId:  tenantId ?? null,
        scanType:  scan_type,
        status:    'pending',
        hostsDiscovered: 0,
        rawResults: [],
      }).returning()
      if (!created) return c.json({ detail: 'Failed to create scan record' }, 500)
      resolvedScanId = created.scanId
    }

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

      // Merge OS info and port list so scoring has full data
      const mergedOsInfo = {
        ...((existing?.osInfo ?? {}) as Record<string, unknown>),
        ...(host.os ? (host.os as Record<string, unknown>) : {}),
        ...(Array.isArray(host.ports) && host.ports.length > 0 ? { ports: host.ports } : {}),
      }

      if (existing) {
        // Update existing asset (never downgrade source from manual)
        const updatedRows = await db
          .update(assets)
          .set({
            hostname: host.hostname ?? existing.hostname,
            macAddress: host.mac ?? existing.macAddress,
            osInfo: mergedOsInfo,
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
            osInfo: mergedOsInfo,
            tenantId: tenantId ?? null,
            deviceType: 'unknown',
            source: scan_type === 'passive' ? 'scan_passive' : 'scan_active',
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
      .where(eq(scanResults.scanId, resolvedScanId))

    // Trigger drift check advisory for each asset
    for (const assetId of upsertedAssetIds) {
      await c.env.ADVISORY_QUEUE.send({
        type: 'drift_check',
        assetId,
        scanId: resolvedScanId,
        agentId: agent_id,
      })
    }

    // Auto-rebuild topology and relationship graph, then rescore criticality.
    if (tenantId && upsertedAssetIds.length > 0) {
      try {
        const tenantAssets = await db.select().from(assets).where(eq(assets.tenantId, tenantId))
        await db.delete(topologyNodes).where(eq(topologyNodes.tenantId, tenantId))
        await inferForTenant(db, tenantAssets, tenantId)
        await inferRelationshipsForTenant(db, tenantId)
        // Rescore only the assets touched by this scan — topology is now up to date
        await rescoreAssets(db, tenantId, upsertedAssetIds)
      } catch (inferErr) {
        console.warn('Auto-infer/rescore after scan failed (non-fatal):', inferErr)
      }
    }

    return c.json({
      message: 'Scan results ingested',
      scan_id: resolvedScanId,
      scan_type,
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
