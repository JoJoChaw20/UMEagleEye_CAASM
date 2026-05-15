import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { topologyNodes, assets, assetRelationships } from '../db/schema'

const router = new Hono<{ Bindings: Env }>()

// ── Types ─────────────────────────────────────────────────────────
interface TreeNode {
  node_id: string
  label: string | null
  node_type: string
  layer: number
  asset_id: string | null
  metadata: unknown
  children: TreeNode[]
}

// ── Helper: build tree from flat node list ────────────────────────
function buildTree(rows: typeof topologyNodes.$inferSelect[]): TreeNode[] {
  const nodeMap = new Map<string, TreeNode>()

  for (const row of rows) {
    nodeMap.set(row.nodeId, {
      node_id: row.nodeId,
      label: row.label,
      node_type: row.nodeType,
      layer: row.layer,
      asset_id: row.assetId,
      metadata: row.metadata,
      children: [],
    })
  }

  const roots: TreeNode[] = []
  for (const row of rows) {
    const node = nodeMap.get(row.nodeId)!
    if (!row.parentNodeId) {
      roots.push(node)
    } else {
      const parent = nodeMap.get(row.parentNodeId)
      if (parent) {
        parent.children.push(node)
      } else {
        roots.push(node)
      }
    }
  }

  return roots
}

// ── GET / — Return full topology tree for current tenant ──────────
router.get('/', authMiddleware, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const user = c.get('user')

  if (!user.tenantId && user.role !== 'superadmin') {
    return c.json({ tree: [] })
  }

  const rows = user.role === 'superadmin'
    ? await db.select().from(topologyNodes)
    : await db.select().from(topologyNodes).where(eq(topologyNodes.tenantId, user.tenantId!))

  const tree = buildTree(rows)
  return c.json({ tree })
})

// ── POST /nodes — Create/upsert topology nodes ────────────────────
router.post(
  '/nodes',
  authMiddleware,
  requireRoles('ops_lead', 'security_engineer', 'superadmin'),
  zValidator('json', z.object({
    nodes: z.array(z.object({
      asset_id: z.string().uuid().optional(),
      parent_node_id: z.string().uuid().optional(),
      node_type: z.enum(['gateway', 'router', 'switch', 'access_point', 'host']),
      layer: z.number().int().min(1).max(7).default(4),
      label: z.string().max(100).optional(),
      metadata: z.record(z.unknown()).optional(),
    })),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const { nodes } = c.req.valid('json')

    if (!user.tenantId && user.role !== 'superadmin') {
      return c.json({ detail: 'User has no tenant assigned' }, 400)
    }

    const inserted = await db.insert(topologyNodes).values(
      nodes.map((n) => ({
        tenantId: user.tenantId ?? null,
        assetId: n.asset_id ?? null,
        parentNodeId: n.parent_node_id ?? null,
        nodeType: n.node_type,
        layer: n.layer,
        label: n.label ?? null,
        metadata: n.metadata ?? {},
      }))
    ).returning()

    return c.json({ nodes: inserted.map((n) => ({ node_id: n.nodeId, label: n.label })) }, 201)
  }
)

// ── DELETE /nodes/:nodeId ─────────────────────────────────────────
router.delete(
  '/nodes/:nodeId',
  authMiddleware,
  requireRoles('ops_lead', 'superadmin'),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const { nodeId } = c.req.param()

    const [node] = await db.select().from(topologyNodes).where(eq(topologyNodes.nodeId, nodeId)).limit(1)
    if (!node) return c.json({ detail: 'Node not found' }, 404)
    if (user.role !== 'superadmin' && node.tenantId !== user.tenantId) {
      return c.json({ detail: 'Forbidden' }, 403)
    }

    await db.delete(topologyNodes).where(eq(topologyNodes.nodeId, nodeId))
    return c.json({ ok: true })
  }
)

// ── POST /infer — Infer topology from asset relationships ─────────
router.post(
  '/infer',
  authMiddleware,
  requireRoles('ops_lead', 'security_engineer', 'superadmin'),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')

    if (!user.tenantId && user.role !== 'superadmin') {
      return c.json({ detail: 'User has no tenant assigned' }, 400)
    }

    // Fetch assets for this tenant
    const tenantAssets = user.role === 'superadmin'
      ? await db.select().from(assets)
      : await db.select().from(assets).where(eq(assets.tenantId, user.tenantId!))

    // Fetch connects_to relationships
    const allRels = await db.select().from(assetRelationships)
    const connectsTo = allRels.filter(r => r.relationshipType === 'connects_to')

    // Count outbound connections per asset
    const outboundCount = new Map<string, number>()
    for (const rel of connectsTo) {
      outboundCount.set(rel.sourceAssetId, (outboundCount.get(rel.sourceAssetId) ?? 0) + 1)
    }

    // Clear existing topology nodes for this tenant
    if (user.role === 'superadmin') {
      await db.delete(topologyNodes)
    } else {
      await db.delete(topologyNodes).where(eq(topologyNodes.tenantId, user.tenantId!))
    }

    const nodeRows: (typeof topologyNodes.$inferInsert)[] = []

    // Classify assets into topology roles
    let gatewayId: string | null = null

    for (const asset of tenantAssets) {
      const outbound = outboundCount.get(asset.assetId) ?? 0
      const hostnameLC = (asset.hostname ?? '').toLowerCase()
      const ipLast = asset.ipAddress.split('.').pop()

      let nodeType: 'gateway' | 'router' | 'switch' | 'access_point' | 'host' = 'host'
      let layer = 4

      if (hostnameLC.includes('gateway') || ipLast === '1') {
        nodeType = 'gateway'
        layer = 1
        gatewayId = asset.assetId
      } else if (hostnameLC.includes('router') || (outbound > 3 && asset.deviceType !== 'network')) {
        nodeType = 'router'
        layer = 2
      } else if (asset.deviceType === 'network' && outbound > 3) {
        nodeType = 'switch'
        layer = 3
      } else if (hostnameLC.includes('ap') || hostnameLC.includes('wifi') || hostnameLC.includes('access_point')) {
        nodeType = 'access_point'
        layer = 3
      }

      nodeRows.push({
        tenantId: user.tenantId ?? null,
        assetId: asset.assetId,
        parentNodeId: null, // will be resolved below
        nodeType,
        layer,
        label: asset.hostname ?? asset.ipAddress,
        metadata: { ip_address: asset.ipAddress, device_type: asset.deviceType },
      })
    }

    if (nodeRows.length === 0) {
      return c.json({ nodes_created: 0, message: 'No assets found to infer topology' })
    }

    // Insert all nodes first without parent relationships
    const insertedNodes = await db.insert(topologyNodes).values(nodeRows).returning()

    // Build a map: assetId -> nodeId
    const assetToNodeId = new Map<string, string>()
    for (const n of insertedNodes) {
      if (n.assetId) assetToNodeId.set(n.assetId, n.nodeId)
    }

    // Find gateway node and router nodes
    const gatewayNodeId = gatewayId ? assetToNodeId.get(gatewayId) : null
    const routerNodes = insertedNodes.filter(n => n.nodeType === 'router')
    const switchNodes = insertedNodes.filter(n => n.nodeType === 'switch')

    // Assign parent relationships: routers -> gateway, switches -> router, hosts -> switch/gateway
    for (const node of insertedNodes) {
      let parentId: string | null = null

      if (node.nodeType === 'router' && gatewayNodeId) {
        parentId = gatewayNodeId
      } else if (node.nodeType === 'switch') {
        parentId = routerNodes[0]?.nodeId ?? gatewayNodeId ?? null
      } else if (node.nodeType === 'access_point') {
        parentId = switchNodes[0]?.nodeId ?? routerNodes[0]?.nodeId ?? gatewayNodeId ?? null
      } else if (node.nodeType === 'host') {
        parentId = switchNodes[0]?.nodeId ?? routerNodes[0]?.nodeId ?? gatewayNodeId ?? null
      }

      if (parentId && parentId !== node.nodeId) {
        await db.update(topologyNodes)
          .set({ parentNodeId: parentId })
          .where(eq(topologyNodes.nodeId, node.nodeId))
      }
    }

    return c.json({ nodes_created: insertedNodes.length, message: 'Topology inferred successfully' })
  }
)

export default router
