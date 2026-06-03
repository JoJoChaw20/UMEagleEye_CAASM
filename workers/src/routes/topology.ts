import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { topologyNodes, assets, tenants } from '../db/schema'

const router = new Hono<{ Bindings: Env }>()

// ── Types ─────────────────────────────────────────────────────────
type NodeType = 'gateway' | 'router' | 'switch' | 'access_point' | 'host'

interface TreeNode {
  node_id: string
  label: string | null
  node_type: string
  layer: number
  asset_id: string | null
  metadata: unknown
  children: TreeNode[]
}

// ── Asset classification ──────────────────────────────────────────
// Rules (priority order):
//   network + internet_facing            → gateway   L1
//   network + fw-/gw- prefix (internal)  → router    L2
//   network + core-sw/core-router prefix → switch    L2
//   network + router/lab-router keyword  → router    L2
//   network + dist-sw prefix             → switch    L3
//   network + wifi/ap- keyword           → access_point L3
//   network (default)                    → switch    L3
//   server + internet_facing             → host      L2  (DMZ)
//   server                               → host      L4
//   workstation                          → host      L5
//   iot                                  → host      L6
function classifyAsset(asset: typeof assets.$inferSelect): { nodeType: NodeType; layer: number } {
  const h = (asset.hostname ?? '').toLowerCase()
  const dt = asset.deviceType

  if (dt === 'network') {
    if (asset.isInternetFacing)                              return { nodeType: 'gateway',      layer: 1 }
    if (/^(fw|gw|firewall)[-_]/.test(h))                    return { nodeType: 'router',       layer: 2 }
    if (/(core[-_])(sw|switch|router|rtr)/.test(h))         return { nodeType: 'switch',       layer: 2 }
    if (/(^router[-_]|^rtr[-_]|lab[-_]router)/.test(h))    return { nodeType: 'router',       layer: 2 }
    if (/(dist[-_])(sw|switch|router)/.test(h))             return { nodeType: 'switch',       layer: 3 }
    if (/(wifi|^ap[-_]|wap[-_]|access[-_]?point)/.test(h)) return { nodeType: 'access_point', layer: 4 }
    return { nodeType: 'switch', layer: 3 }
  }

  if (dt === 'server')      return { nodeType: 'host', layer: asset.isInternetFacing ? 2 : 4 }
  if (dt === 'workstation') return { nodeType: 'host', layer: 5 }
  if (dt === 'iot')         return { nodeType: 'host', layer: 6 }
  return { nodeType: 'host', layer: 4 }
}

function getSubnet(ip: string): string {
  return ip.split('.').slice(0, 3).join('.')
}

// ── Parent resolution ─────────────────────────────────────────────
interface FlatNode {
  nodeId: string
  nodeType: NodeType
  layer: number
  ip: string
  subnet: string
}

// Type preference: closer to a physical switch is better for hosts
const TYPE_SCORE: Record<string, number> = { switch: 4, router: 3, gateway: 2, access_point: 2, host: 0 }

function resolveParent(node: FlatNode, others: FlatNode[]): string | null {
  // Step 1: same-subnet candidates with strictly lower layer
  const subnetCandidates = others
    .filter(n => n.subnet === node.subnet && n.layer < node.layer)
    .sort((a, b) =>
      (TYPE_SCORE[b.nodeType] ?? 0) - (TYPE_SCORE[a.nodeType] ?? 0) || b.layer - a.layer
    )
  if (subnetCandidates.length > 0) return subnetCandidates[0]?.nodeId ?? null

  // Step 2: cross-subnet, target layer = this layer - 1
  // Use last IP octet to distribute evenly across same-layer parents
  const targetLayer = node.layer - 1
  const layerCandidates = others
    .filter(n => n.layer === targetLayer)
    .sort((a, b) => (TYPE_SCORE[b.nodeType] ?? 0) - (TYPE_SCORE[a.nodeType] ?? 0))
  if (layerCandidates.length > 0) {
    const lastOctet = parseInt(node.ip.split('.').pop() ?? '1', 10)
    return layerCandidates[lastOctet % layerCandidates.length]?.nodeId ?? null
  }

  // Step 3: any node with lower layer
  const fallback = others
    .filter(n => n.layer < node.layer)
    .sort((a, b) => b.layer - a.layer)
  return fallback[0]?.nodeId ?? null
}

// ── Build tree from flat rows ─────────────────────────────────────
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
      if (parent) parent.children.push(node)
      else roots.push(node)
    }
  }
  function ipToNum(ip: string): number {
    return ip.split('.').reduce((acc, oct) => acc * 256 + parseInt(oct, 10), 0)
  }

  // Sort children by layer then IP address ascending
  function sortTree(nodes: TreeNode[]): void {
    nodes.sort((a, b) => {
      if (a.layer !== b.layer) return a.layer - b.layer
      const aIp = (a.metadata as { ip_address?: string })?.ip_address ?? ''
      const bIp = (b.metadata as { ip_address?: string })?.ip_address ?? ''
      return ipToNum(aIp) - ipToNum(bIp)
    })
    for (const n of nodes) sortTree(n.children)
  }
  sortTree(roots)
  return roots
}

// ── Infer topology for a single tenant's assets ───────────────────
export async function inferForTenant(
  db: ReturnType<typeof getDb>,
  tenantAssets: (typeof assets.$inferSelect)[],
  tenantId: string | null,
): Promise<number> {
  if (tenantAssets.length === 0) return 0

  // Insert all nodes without parent refs
  const insertRows: (typeof topologyNodes.$inferInsert)[] = tenantAssets.map(asset => {
    const { nodeType, layer } = classifyAsset(asset)
    return {
      tenantId,
      assetId: asset.assetId,
      parentNodeId: null,
      nodeType,
      layer,
      label: asset.hostname ?? asset.ipAddress,
      metadata: {
        ip_address: asset.ipAddress,
        device_type: asset.deviceType,
        criticality_score: asset.criticalityScore,
        is_internet_facing: asset.isInternetFacing,
      },
    }
  })

  const insertedNodes = await db.insert(topologyNodes).values(insertRows).returning()

  // Build flat view for parent resolution
  const assetMap = new Map(tenantAssets.map(a => [a.assetId, a]))
  const flatNodes: FlatNode[] = insertedNodes
    .filter(n => n.assetId != null)
    .map(n => {
      const a = assetMap.get(n.assetId!)!
      return { nodeId: n.nodeId, nodeType: n.nodeType as NodeType, layer: n.layer, ip: a.ipAddress, subnet: getSubnet(a.ipAddress) }
    })

  // Resolve parents and batch-update
  const updates: Array<{ nodeId: string; parentId: string }> = []
  for (const node of flatNodes) {
    if (node.layer === 1) continue // gateways have no parent
    const parentId = resolveParent(node, flatNodes.filter(n => n.nodeId !== node.nodeId))
    if (parentId) updates.push({ nodeId: node.nodeId, parentId })
  }

  await Promise.all(
    updates.map(({ nodeId, parentId }) =>
      db.update(topologyNodes).set({ parentNodeId: parentId }).where(eq(topologyNodes.nodeId, nodeId))
    )
  )

  return insertedNodes.length
}

// ── GET / — Topology tree for current user ────────────────────────
// Superadmin: returns { tenant_trees: [{tenant_id, tenant_name, tree, node_count}] }
//             or { tree: [...] } when ?tenant_id= is specified
// Regular user: { tree: [...] }
router.get('/', authMiddleware, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const user = c.get('user')
  const tenantIdFilter = c.req.query('tenant_id')

  if (!user.tenantId && user.role !== 'superadmin') return c.json({ tree: [] })

  // Single-tenant view (regular user or superadmin with filter)
  if (user.role !== 'superadmin' || tenantIdFilter) {
    const scopedId = tenantIdFilter ?? user.tenantId!
    const rows = await db.select().from(topologyNodes).where(eq(topologyNodes.tenantId, scopedId))
    return c.json({ tree: buildTree(rows) })
  }

  // Superadmin all-tenant view
  const allRows = await db.select().from(topologyNodes)
  const allTenants = await db.select().from(tenants)
  const tenantNameMap = new Map(allTenants.map(t => [t.tenantId, t.name]))

  const byTenant = new Map<string, typeof allRows>()
  for (const row of allRows) {
    const key = row.tenantId ?? '__null__'
    if (!byTenant.has(key)) byTenant.set(key, [])
    byTenant.get(key)!.push(row)
  }

  const tenantTrees = []
  for (const [tid, rows] of byTenant.entries()) {
    if (tid === '__null__') continue // skip unassigned nodes
    const tree = buildTree(rows)
    function countNodes(nodes: TreeNode[]): number {
      return nodes.reduce((s, n) => s + 1 + countNodes(n.children), 0)
    }
    tenantTrees.push({
      tenant_id: tid,
      tenant_name: tenantNameMap.get(tid) ?? 'Unknown',
      node_count: countNodes(tree),
      tree,
    })
  }

  // Sort tenants alphabetically
  tenantTrees.sort((a, b) => a.tenant_name.localeCompare(b.tenant_name))

  return c.json({ tree: [], tenant_trees: tenantTrees })
})

// ── POST /nodes — Create topology nodes manually ──────────────────
router.post(
  '/nodes',
  authMiddleware,
  requireRoles('ops_lead', 'security_engineer', 'superadmin'),
  zValidator('json', z.object({
    nodes: z.array(z.object({
      asset_id:       z.string().uuid().optional(),
      parent_node_id: z.string().uuid().optional(),
      node_type:      z.enum(['gateway', 'router', 'switch', 'access_point', 'host']),
      layer:          z.number().int().min(1).max(7).default(4),
      label:          z.string().max(100).optional(),
      metadata:       z.record(z.unknown()).optional(),
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
      nodes.map(n => ({
        tenantId:     user.tenantId ?? null,
        assetId:      n.asset_id ?? null,
        parentNodeId: n.parent_node_id ?? null,
        nodeType:     n.node_type,
        layer:        n.layer,
        label:        n.label ?? null,
        metadata:     n.metadata ?? {},
      }))
    ).returning()

    return c.json({ nodes: inserted.map(n => ({ node_id: n.nodeId, label: n.label })) }, 201)
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

// ── POST /infer — Rebuild topology from assets ────────────────────
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

    let totalNodes = 0
    let tenantsProcessed = 0

    if (user.role === 'superadmin') {
      // Clear ALL topology nodes then re-infer per tenant
      await db.delete(topologyNodes)

      const allTenants = await db.select().from(tenants)
      for (const tenant of allTenants) {
        const tenantAssets = await db.select().from(assets).where(
          and(
            eq(assets.tenantId, tenant.tenantId),
            eq(assets.source, 'manual')
          )
        )
        const count = await inferForTenant(db, tenantAssets, tenant.tenantId)
        if (count > 0) tenantsProcessed++
        totalNodes += count
      }
    } else {
      // Clear and re-infer for this tenant only
      await db.delete(topologyNodes).where(eq(topologyNodes.tenantId, user.tenantId!))
      const tenantAssets = await db.select().from(assets).where(
        and(
          eq(assets.tenantId, user.tenantId!),
          eq(assets.source, 'manual')
        )
      )
      totalNodes = await inferForTenant(db, tenantAssets, user.tenantId!)
      tenantsProcessed = 1
    }

    return c.json({
      nodes_created: totalNodes,
      tenants_processed: tenantsProcessed,
      message: `Topology inferred: ${totalNodes} nodes across ${tenantsProcessed} tenant(s)`,
    })
  }
)

export default router
