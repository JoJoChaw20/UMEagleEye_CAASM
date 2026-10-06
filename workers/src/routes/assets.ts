import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, or, isNull, inArray, desc, ilike, sql, getTableColumns, type SQL, type SQLWrapper } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { assets, assetAddresses, scanResults, agents, events, sboms, dependencies, assetRelationships, topologyNodes, auditLogs } from '../db/schema'
import { rescoreAssets, scoreAsset } from '../lib/rescore'
import { computeCriticality } from '../lib/criticality'
import { normalizeMac } from '../lib/mac'
import { computeMatches, matchRank, looksMacFragment, type AddrRow, type MatchAsset } from '../lib/addressSearch'
import { classifyMac, matchAsset, prefetchIdentity, resolveAssetIdentity, type CandidateAddress } from '../lib/identity'
import { findDuplicateGroups, type DupAsset, type DupAddress } from '../lib/duplicates'
import { planMerge, type MergeAsset, type MergeOp, type MergeRelated } from '../lib/merge'
import { buildBaseline, buildManualBaseline, extractPorts, extractOsVersion, mergeBaselineFields, type AssetBaseline } from '../services/drift'

const app = new Hono<{ Bindings: Env }>()

const READ_ROLES   = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner']
const WRITE_ROLES  = ['tenant_superadmin', 'tenant_admin']
const DELETE_ROLES = ['tenant_superadmin']
const MERGE_ROLES  = ['tenant_superadmin']   // same guard as delete (destructive, irreversible)

// Map a pure MergeOp to a Drizzle statement for one db.batch. userId/tenantId are
// supplied here (the pure planner has no request context).
function mergeOpToStmt(db: ReturnType<typeof getDb>, op: MergeOp, ctx: { userId: string; tenantId: string | null }): unknown {
  switch (op.k) {
    case 'endAddress':        return db.update(assetAddresses).set({ endedAt: new Date() }).where(eq(assetAddresses.addressId, op.addressId))
    case 'endAddressAt':      return db.update(assetAddresses).set({ endedAt: new Date(op.endedAt) }).where(eq(assetAddresses.addressId, op.addressId))
    case 'moveAddresses':     return db.update(assetAddresses).set({ assetId: op.survivorId }).where(inArray(assetAddresses.assetId, op.loserIds))
    case 'moveEvents':        return db.update(events).set({ assetId: op.survivorId }).where(inArray(events.assetId, op.loserIds))
    case 'moveSboms':         return db.update(sboms).set({ assetId: op.survivorId }).where(inArray(sboms.assetId, op.loserIds))
    case 'moveDependencies':  return db.update(dependencies).set({ assetId: op.survivorId }).where(inArray(dependencies.assetId, op.loserIds))
    case 'deleteRelationships': return db.delete(assetRelationships).where(inArray(assetRelationships.relationshipId, op.ids))
    case 'updateRelationship': return db.update(assetRelationships).set({ sourceAssetId: op.sourceAssetId, targetAssetId: op.targetAssetId }).where(eq(assetRelationships.relationshipId, op.id))
    case 'deleteTopologyNodes': return db.delete(topologyNodes).where(inArray(topologyNodes.nodeId, op.ids))
    case 'moveTopologyNode':  return db.update(topologyNodes).set({ assetId: op.survivorId }).where(eq(topologyNodes.nodeId, op.nodeId))
    case 'updateAsset':       return db.update(assets).set(op.set as Partial<typeof assets.$inferInsert>).where(eq(assets.assetId, op.assetId))
    case 'insertAudit':       return db.insert(auditLogs).values({ userId: ctx.userId, tenantId: ctx.tenantId, actionType: 'asset.merge', targetEntity: op.loserId, previousState: op.snapshot, newState: { survivor_id: op.survivorId } })
    case 'deleteAssets':      return db.delete(assets).where(inArray(assets.assetId, op.loserIds))
  }
}

// Record/refresh an asset's current address for the manual write paths (POST,
// PATCH, CSV import). Updates the most-recently-seen current address in place —
// so an IP/MAC edit moves it — else inserts a new unscoped (network_key NULL)
// row. Never clears a stored MAC.
async function recordManualAddress(
  db: ReturnType<typeof getDb>,
  p: { assetId: string; tenantId: string | null; ip: string; mac: string | null },
): Promise<void> {
  const now = new Date()
  const [current] = await db
    .select({ addressId: assetAddresses.addressId, macAddress: assetAddresses.macAddress })
    .from(assetAddresses)
    .where(and(eq(assetAddresses.assetId, p.assetId), isNull(assetAddresses.endedAt)))
    .orderBy(desc(assetAddresses.lastSeen))
    .limit(1)
  if (current) {
    await db.update(assetAddresses).set({
      ipAddress: p.ip, lastSeen: now, macAddress: current.macAddress ?? p.mac ?? null,
    }).where(eq(assetAddresses.addressId, current.addressId))
  } else {
    await db.insert(assetAddresses).values({
      assetId: p.assetId, tenantId: p.tenantId, networkKey: null,
      ipAddress: p.ip, macAddress: p.mac ?? null, firstSeen: now, lastSeen: now,
    })
  }
}


// ── GET / ────────────────────────────────────────────────────────
app.get('/', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const page = Math.max(1, parseInt(c.req.query('page') ?? '1'))
    const limit = Math.min(200, Math.max(1, parseInt(c.req.query('limit') ?? '50')))
    const offset = (page - 1) * limit
    const device_type = c.req.query('device_type')
    const hostname = c.req.query('hostname')
    const search = c.req.query('search')
    const source = c.req.query('source')
    const inMyAssetsParam = c.req.query('in_my_assets')
    const tenant_id_param = c.req.query('tenant_id')
    const assetIdParam = c.req.query('asset_id')
    const gap = c.req.query('gap')
    const portParam = c.req.query('port')

    const conditions = []

    if (user.role !== 'superadmin') {
      if (user.tenantId) {
        conditions.push(eq(assets.tenantId, user.tenantId))
      }
    } else if (tenant_id_param) {
      conditions.push(eq(assets.tenantId, tenant_id_param))
    }

    if (device_type) {
      conditions.push(
        eq(assets.deviceType, device_type as 'server' | 'workstation' | 'network' | 'iot' | 'unknown'),
      )
    }

    if (hostname) {
      conditions.push(ilike(assets.hostname, `%${hostname}%`))
    }

    // Tenant scope applied to the address-history EXISTS (keeps tenant isolation on
    // every subquery, and lets the (tenant_id, mac_address) index help MAC lookups).
    const tenantScopeId = user.role !== 'superadmin' ? (user.tenantId ?? null) : (tenant_id_param ?? null)

    // Build a MAC match on a column: a full term → exact normalized equality; a MAC
    // fragment → separator-insensitive contains; otherwise null (term can't be a MAC).
    const normMac = search ? normalizeMac(search) : null
    const macFrag = (search && looksMacFragment(search)) ? search.toLowerCase().replace(/[:.\-]/g, '') : null
    const macColMatch = (col: SQLWrapper): SQL | null => {
      if (normMac) return sql`${col} = ${normMac}`
      if (macFrag && /^[0-9a-f]+$/.test(macFrag) && macFrag.length >= 2)
        return sql`replace(replace(replace(lower(${col}), ':', ''), '-', ''), '.', '') LIKE ${'%' + macFrag + '%'}`
      return null
    }

    // Search matches hostname, hardware vendor, current IP, current MAC (asset row)
    // OR any historical address (current/ended) in asset_addresses — so an old IP/MAC
    // still finds the device. EXISTS (not JOIN) keeps asset rows unique. rowFieldMatch
    // also drives the ordering CASE below, so vendor hits rank with current matches.
    let rowFieldMatch: SQL | undefined
    if (search) {
      const likeT = `%${search}%`
      const rowConds: SQL[] = [
        ilike(assets.hostname, likeT) as SQL,
        ilike(assets.hardwareVendor, likeT) as SQL,
        ilike(assets.ipAddress, likeT) as SQL,
      ]
      const assetMac = macColMatch(assets.macAddress); if (assetMac) rowConds.push(assetMac)
      rowFieldMatch = or(...rowConds)!

      const aaMac = macColMatch(sql`aa.mac_address`)
      const addrMatch = aaMac ? sql`(aa.ip_address ILIKE ${likeT} OR ${aaMac})` : sql`aa.ip_address ILIKE ${likeT}`
      const tenantScope = tenantScopeId ? sql` AND aa.tenant_id = ${tenantScopeId}` : sql``
      const addrExists = sql`EXISTS (SELECT 1 FROM ${assetAddresses} aa WHERE aa.asset_id = ${assets.assetId}${tenantScope} AND ${addrMatch})`

      conditions.push(or(rowFieldMatch, addrExists)!)
    }

    // Exact asset (deep links from the dashboard / alert drawer)
    if (assetIdParam && z.string().uuid().safeParse(assetIdParam).success) {
      conditions.push(eq(assets.assetId, assetIdParam))
    }

    if (c.req.query('internet_facing') === 'true') conditions.push(eq(assets.isInternetFacing, true))

    // Hosts with this port open in their latest scan (ports stored as 22 or "22/tcp")
    if (portParam && /^\d{1,5}$/.test(portParam)) {
      conditions.push(sql`jsonb_typeof(${assets.osInfo}->'ports') = 'array' AND EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(${assets.osInfo}->'ports') p WHERE split_part(p, '/', 1) = ${portParam})`)
    }

    // Coverage gaps — same rules as the dashboard's hygiene cards, so the
    // card count equals the list it opens.
    const weekAgo = new Date(Date.now() - 7 * 86400000)
    if (gap === 'new_7d') {
      conditions.push(sql`${assets.source} <> 'manual' AND ${assets.createdAt} >= ${weekAgo}`)
    } else if (gap === 'unidentified') {
      conditions.push(sql`(${assets.deviceType} = 'unknown'
        OR (COALESCE(${assets.hardwareVendor}, '') = '' AND COALESCE(${assets.hostname}, '') = ''))`)
    } else if (gap === 'stale') {
      conditions.push(sql`${assets.source} <> 'manual' AND (${assets.lastScanned} IS NULL OR ${assets.lastScanned} < ${weekAgo})`)
    } else if (gap === 'no_sbom') {
      conditions.push(sql`${assets.deviceType} IN ('server', 'workstation')
        AND NOT EXISTS (SELECT 1 FROM ${sboms} WHERE ${sboms.assetId} = ${assets.assetId})`)
    }

    // My Assets membership filter (new canonical param).
    if (inMyAssetsParam === 'true') conditions.push(eq(assets.inMyAssets, true))
    else if (inMyAssetsParam === 'false') conditions.push(eq(assets.inMyAssets, false))

    // `source` filters by the LAST observation method only (manual = hand/CSV and
    // never scanned since). This is NOT My Assets membership — use in_my_assets for
    // that. Unknown values are ignored (no filter), matching prior behavior.
    if (source === 'manual' || source === 'scan_active' || source === 'scan_passive') {
      conditions.push(eq(assets.source, source))
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined

    // When searching: current-field matches (hostname/IP/MAC) before history-only,
    // exact before partial, then last_scanned desc. Otherwise last_scanned desc.
    const orderByClause: SQL[] = (search && rowFieldMatch)
      ? [
          sql`CASE WHEN ${rowFieldMatch} THEN 0 ELSE 1 END`,
          sql`CASE WHEN ${assets.ipAddress} = ${search} OR lower(${assets.hostname}) = ${search.toLowerCase()}${normMac ? sql` OR ${assets.macAddress} = ${normMac}` : sql``} THEN 0 ELSE 1 END`,
          sql`${assets.lastScanned} DESC NULLS LAST`,
          desc(assets.createdAt) as SQL,
        ]
      : [sql`${assets.lastScanned} DESC NULLS LAST`, desc(assets.createdAt) as SQL]

    const [rows, countRows] = await Promise.all([
      db.select().from(assets).where(whereClause).orderBy(...orderByClause).limit(limit).offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(assets).where(whereClause),
    ])

    // One extra query for the page's address rows (all rows → addressCount; the
    // matching subset feeds the per-asset "why it matched" explanation). No per-row
    // queries. Tenant-scoped to match the EXISTS above.
    const pageIds = rows.map(r => r.assetId)
    const addrByAsset = new Map<string, AddrRow[]>()
    if (pageIds.length > 0) {
      const addrScope = tenantScopeId
        ? and(inArray(assetAddresses.assetId, pageIds), eq(assetAddresses.tenantId, tenantScopeId))
        : inArray(assetAddresses.assetId, pageIds)
      const addrRows = await db.select({
        addressId: assetAddresses.addressId, assetId: assetAddresses.assetId, networkKey: assetAddresses.networkKey,
        ipAddress: assetAddresses.ipAddress, macAddress: assetAddresses.macAddress,
        firstSeen: assetAddresses.firstSeen, lastSeen: assetAddresses.lastSeen, endedAt: assetAddresses.endedAt,
      }).from(assetAddresses).where(addrScope)
      for (const r of addrRows) {
        const l = addrByAsset.get(r.assetId) ?? []; l.push(r as AddrRow); addrByAsset.set(r.assetId, l)
      }
    }

    const items = rows.map(r => {
      const rowsForAsset = addrByAsset.get(r.assetId) ?? []
      const addressCount = rowsForAsset.length
      if (search) {
        const { matches, matchedAddressCount } = computeMatches(r as MatchAsset, rowsForAsset, search)
        return { ...r, addressCount, matches, matchedAddressCount }
      }
      return { ...r, addressCount, matches: [], matchedAddressCount: 0 }
    })

    // Within the returned page, current-field matches before history-only (ties keep
    // the DB order, which already applied the same rank + last_scanned desc).
    if (search) items.sort((a, b) => matchRank(a.matches) - matchRank(b.matches))

    return c.json({ total: countRows[0]?.count ?? 0, page, limit, items })
  } catch (err) {
    console.error('assets GET / error:', err)
    return c.json({ detail: 'Failed to fetch assets' }, 500)
  }
})

// ── GET /duplicates ─── detect legacy duplicate asset groups (tenant-scoped) ──
// Subrequests: 2 (tenant assets, tenant addresses).
app.get('/duplicates', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const tenantId = user.role === 'superadmin' ? (c.req.query('tenant_id') ?? null) : (user.tenantId ?? null)
    const tCond = tenantId ? eq(assets.tenantId, tenantId) : undefined

    const assetRows = await db.select({
      assetId: assets.assetId, hostname: assets.hostname, ipAddress: assets.ipAddress, macAddress: assets.macAddress,
      source: assets.source, inMyAssets: assets.inMyAssets, deviceType: assets.deviceType, lastScanned: assets.lastScanned, createdAt: assets.createdAt, hostKey: assets.hostKey,
    }).from(assets).where(tCond)

    const ids = assetRows.map(a => a.assetId)
    const addrRows = ids.length
      ? await db.select({
          addressId: assetAddresses.addressId, assetId: assetAddresses.assetId, networkKey: assetAddresses.networkKey,
          ipAddress: assetAddresses.ipAddress, macAddress: assetAddresses.macAddress, endedAt: assetAddresses.endedAt,
        }).from(assetAddresses).where(inArray(assetAddresses.assetId, ids))
      : []

    const groups = findDuplicateGroups(assetRows as DupAsset[], addrRows as DupAddress[])
    return c.json({ groups, count: groups.length, safe_count: groups.filter(g => g.confidence === 'safe').length })
  } catch (err) {
    console.error('assets GET /duplicates error:', err)
    return c.json({ detail: 'Failed to detect duplicates' }, 500)
  }
})

// ── POST /merge ─── merge losers into a survivor (one db.batch) ──
// Subrequests: 4 reads (assets, addresses, relationships, topology) + 1 batch;
// dry_run: those 4 reads + 3 count reads (events/sboms/deps), no writes.
const mergeSchema = z.object({
  survivor_id: z.string().uuid(),
  loser_ids: z.array(z.string().uuid()).min(1).max(10),
  dry_run: z.boolean().optional(),
})
app.post('/merge', authMiddleware, requireRoles(...MERGE_ROLES), zValidator('json', mergeSchema), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { survivor_id, loser_ids, dry_run } = c.req.valid('json')

    if (loser_ids.includes(survivor_id)) return c.json({ detail: 'survivor_id cannot be in loser_ids' }, 400)
    const uniqueLosers = [...new Set(loser_ids)]
    const allIds = [survivor_id, ...uniqueLosers]

    const assetRows = await db.select().from(assets).where(inArray(assets.assetId, allIds))
    const survivor = assetRows.find(a => a.assetId === survivor_id)
    if (!survivor) return c.json({ detail: 'Survivor not found' }, 404)
    const tenantId = survivor.tenantId
    if (user.role !== 'superadmin' && user.tenantId && tenantId !== user.tenantId) return c.json({ detail: 'Survivor not found' }, 404)
    if (assetRows.length !== allIds.length) return c.json({ detail: 'One or more ids not found' }, 400)
    if (assetRows.some(a => a.tenantId !== tenantId)) return c.json({ detail: 'All assets must belong to the same tenant' }, 400)

    const losers = uniqueLosers.map(id => assetRows.find(a => a.assetId === id)!)

    const addrRows = await db.select({
      addressId: assetAddresses.addressId, assetId: assetAddresses.assetId, networkKey: assetAddresses.networkKey,
      ipAddress: assetAddresses.ipAddress, endedAt: assetAddresses.endedAt, lastSeen: assetAddresses.lastSeen, firstSeen: assetAddresses.firstSeen,
    }).from(assetAddresses).where(inArray(assetAddresses.assetId, allIds))
    const relRows = await db.select({
      relationshipId: assetRelationships.relationshipId, sourceAssetId: assetRelationships.sourceAssetId,
      targetAssetId: assetRelationships.targetAssetId, relationshipType: assetRelationships.relationshipType,
    }).from(assetRelationships).where(or(inArray(assetRelationships.sourceAssetId, allIds), inArray(assetRelationships.targetAssetId, allIds)))
    const topoRows = await db.select({ nodeId: topologyNodes.nodeId, assetId: topologyNodes.assetId })
      .from(topologyNodes).where(inArray(topologyNodes.assetId, allIds))

    const related: MergeRelated = { addresses: addrRows, relationships: relRows, topologyNodes: topoRows.filter((n): n is { nodeId: string; assetId: string } => n.assetId != null) }
    const plan = planMerge(survivor as MergeAsset, losers as MergeAsset[], related)

    if (dry_run) {
      const [ev] = await db.select({ n: sql<number>`count(*)::int` }).from(events).where(inArray(events.assetId, uniqueLosers))
      const [sb] = await db.select({ n: sql<number>`count(*)::int` }).from(sboms).where(inArray(sboms.assetId, uniqueLosers))
      const [dp] = await db.select({ n: sql<number>`count(*)::int` }).from(dependencies).where(inArray(dependencies.assetId, uniqueLosers))
      return c.json({
        dry_run: true, survivor_id, loser_ids: uniqueLosers,
        counts: { ...plan.counts, eventsMoved: ev?.n ?? 0, sbomsMoved: sb?.n ?? 0, dependenciesMoved: dp?.n ?? 0 },
        merged_fields: plan.mergedFields,
      })
    }

    const stmts = plan.ops.map(op => mergeOpToStmt(db, op, { userId: user.userId, tenantId }))
    await db.batch(stmts as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
    return c.json({ merged: true, survivor_id, removed: uniqueLosers, counts: plan.counts })
  } catch (err) {
    console.error('assets POST /merge error:', err)
    return c.json({ detail: 'Failed to merge assets' }, 500)
  }
})

// ── POST /duplicates/merge-safe ─── auto-merge up to 4 SAFE groups ──
// Groups are RECOMPUTED server-side (client group contents are never trusted).
// Subrequests: 2 (assets, addresses) + 2 (relationships, topology) + up to 4 batches = ~8.
const mergeSafeSchema = z.object({ group_ids: z.array(z.string()).optional(), dry_run: z.boolean().optional() })
app.post('/duplicates/merge-safe', authMiddleware, requireRoles(...MERGE_ROLES), zValidator('json', mergeSafeSchema), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { group_ids, dry_run } = c.req.valid('json')
    const tenantId = user.role === 'superadmin' ? (c.req.query('tenant_id') ?? null) : (user.tenantId ?? null)
    const tCond = tenantId ? eq(assets.tenantId, tenantId) : undefined

    const assetRows = await db.select().from(assets).where(tCond)
    const assetById = new Map(assetRows.map(a => [a.assetId, a]))
    const allAssetIds = assetRows.map(a => a.assetId)
    const addrRows = allAssetIds.length
      ? await db.select({
          addressId: assetAddresses.addressId, assetId: assetAddresses.assetId, networkKey: assetAddresses.networkKey,
          ipAddress: assetAddresses.ipAddress, macAddress: assetAddresses.macAddress, endedAt: assetAddresses.endedAt, lastSeen: assetAddresses.lastSeen, firstSeen: assetAddresses.firstSeen,
        }).from(assetAddresses).where(inArray(assetAddresses.assetId, allAssetIds))
      : []

    let groups = findDuplicateGroups(assetRows as unknown as DupAsset[], addrRows as DupAddress[])
      .filter(g => g.confidence === 'safe')
    if (group_ids && group_ids.length) groups = groups.filter(g => group_ids.includes(g.groupId))

    const CAP = 4
    const toProcess = groups.slice(0, CAP)
    const remaining = Math.max(0, groups.length - toProcess.length)

    // Prefetch relationships + topology for all assets across the groups to process.
    const groupAssetIds = [...new Set(toProcess.flatMap(g => g.assets.map(a => a.assetId)))]
    const relRows = groupAssetIds.length
      ? await db.select({ relationshipId: assetRelationships.relationshipId, sourceAssetId: assetRelationships.sourceAssetId, targetAssetId: assetRelationships.targetAssetId, relationshipType: assetRelationships.relationshipType })
          .from(assetRelationships).where(or(inArray(assetRelationships.sourceAssetId, groupAssetIds), inArray(assetRelationships.targetAssetId, groupAssetIds)))
      : []
    const topoRows = groupAssetIds.length
      ? await db.select({ nodeId: topologyNodes.nodeId, assetId: topologyNodes.assetId }).from(topologyNodes).where(inArray(topologyNodes.assetId, groupAssetIds))
      : []

    const merged: { group_id: string; survivor_id: string; removed: string[] }[] = []
    const failed: { group_id: string; error: string }[] = []

    for (const g of toProcess) {
      const survivorId = g.suggestedSurvivorId
      const survivor = assetById.get(survivorId)!
      const losers = g.assets.map(a => a.assetId).filter(id => id !== survivorId).map(id => assetById.get(id)!)
      const ids = new Set(g.assets.map(a => a.assetId))
      const related: MergeRelated = {
        addresses: addrRows.filter(a => ids.has(a.assetId)),
        relationships: relRows.filter(r => ids.has(r.sourceAssetId) || ids.has(r.targetAssetId)),
        topologyNodes: topoRows.filter((n): n is { nodeId: string; assetId: string } => n.assetId != null && ids.has(n.assetId)),
      }
      const plan = planMerge(survivor as MergeAsset, losers as MergeAsset[], related)
      if (dry_run) { merged.push({ group_id: g.groupId, survivor_id: survivorId, removed: losers.map(l => l.assetId) }); continue }
      try {
        const stmts = plan.ops.map(op => mergeOpToStmt(db, op, { userId: user.userId, tenantId: survivor.tenantId }))
        await db.batch(stmts as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
        merged.push({ group_id: g.groupId, survivor_id: survivorId, removed: losers.map(l => l.assetId) })
      } catch (e) {
        failed.push({ group_id: g.groupId, error: (e as Error)?.message ?? 'merge failed' })
      }
    }

    return c.json({ dry_run: dry_run ?? false, merged, remaining, failed })
  } catch (err) {
    console.error('assets POST /duplicates/merge-safe error:', err)
    return c.json({ detail: 'Failed to merge safe duplicates' }, 500)
  }
})

// ── GET /:assetId ────────────────────────────────────────────────
app.get('/:assetId', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()

    const [asset] = await db.select().from(assets).where(eq(assets.assetId, assetId)).limit(1)

    if (!asset) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    if (user.role !== 'superadmin' && user.tenantId && asset.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    return c.json(asset)
  } catch (err) {
    console.error('assets GET /:assetId error:', err)
    return c.json({ detail: 'Failed to fetch asset' }, 500)
  }
})

// ── GET /:assetId/addresses — full address timeline (tenant-scoped, 1 query) ──
app.get('/:assetId/addresses', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()
    if (!z.string().uuid().safeParse(assetId).success) return c.json({ detail: 'Invalid asset id' }, 400)

    const tenantScopeId = user.role !== 'superadmin' ? (user.tenantId ?? null) : (c.req.query('tenant_id') ?? null)
    const where = tenantScopeId
      ? and(eq(assetAddresses.assetId, assetId), eq(assetAddresses.tenantId, tenantScopeId))
      : eq(assetAddresses.assetId, assetId)

    const rows = await db.select({
      addressId: assetAddresses.addressId, networkKey: assetAddresses.networkKey,
      ipAddress: assetAddresses.ipAddress, macAddress: assetAddresses.macAddress,
      firstSeen: assetAddresses.firstSeen, lastSeen: assetAddresses.lastSeen, endedAt: assetAddresses.endedAt,
    }).from(assetAddresses).where(where).orderBy(desc(assetAddresses.lastSeen))

    return c.json({
      asset_id: assetId,
      addresses: rows.map(r => ({
        addressId: r.addressId, ipAddress: r.ipAddress, macAddress: r.macAddress, networkKey: r.networkKey,
        firstSeen: r.firstSeen, lastSeen: r.lastSeen, endedAt: r.endedAt, isCurrent: r.endedAt == null,
      })),
    })
  } catch (err) {
    console.error('assets GET /:assetId/addresses error:', err)
    return c.json({ detail: 'Failed to fetch addresses' }, 500)
  }
})

// ── POST / ───────────────────────────────────────────────────────
const createAssetSchema = z.object({
  ip_address: z.string().min(1).max(45),
  hostname: z.string().max(255).nullish(),
  mac_address: z.string().max(17).nullish(),
  owner: z.string().max(255).optional(),
  device_type: z.enum(['server', 'workstation', 'network', 'iot', 'unknown']).optional(),
  hardware_vendor: z.string().max(255).optional(),
  os_info: z.record(z.unknown()).optional(),
  criticality_score: z.number().int().min(1).max(10).optional(),
  is_internet_facing: z.boolean().optional(),
  source: z.enum(['manual', 'scan_active', 'scan_passive']).optional(),
  tenant_id: z.string().uuid().optional(),
})

app.post('/', authMiddleware, requireRoles(...WRITE_ROLES), zValidator('json', createAssetSchema), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const body = c.req.valid('json')

    // Normalize MAC to canonical lowercase colon form; reject non-empty garbage.
    let normalizedMac: string | null | undefined = undefined
    if (body.mac_address != null) {
      normalizedMac = normalizeMac(body.mac_address)
      if (body.mac_address.trim() !== '' && normalizedMac === null) {
        return c.json({ detail: `Invalid mac_address "${body.mac_address}" — expected 12 hex digits, e.g. aa:bb:cc:dd:ee:ff` }, 400)
      }
    }

    const targetTenantId = (user.role === 'superadmin' && body.tenant_id)
      ? body.tenant_id
      : (user.tenantId ?? null)

    // Identity resolver (unscoped: manual assets carry no network scope). Matching
    // by MAC (rule 1) then IP (rule 4) makes re-POSTing / re-importing idempotent.
    const resolution = await resolveAssetIdentity(db, {
      tenantId: targetTenantId,
      ip: body.ip_address,
      rawMac: body.mac_address,
      hostKey: null,
      isManualSource: true,
    })
    const [existing] = resolution.assetId
      ? await db.select().from(assets).where(eq(assets.assetId, resolution.assetId)).limit(1)
      : []

    // Preserve scanned device type — only override if existing is unknown or absent
    const existingDeviceKnown = existing?.deviceType && existing.deviceType !== 'unknown'
    const deviceType = existingDeviceKnown ? existing!.deviceType : (body.device_type ?? 'unknown')
    const isInternetFacing = body.is_internet_facing ?? existing?.isInternetFacing ?? false
    const osInfo = (body.os_info ?? existing?.osInfo ?? {}) as Record<string, unknown>
    const hostname = body.hostname ?? existing?.hostname

    // Preserve criticality from scan when device type is unchanged; recompute only when type
    // improves. A brand-new asset has no topology layer, so this equals a later rescore.
    const computedScore = (existing?.criticalityScore && deviceType === existing.deviceType)
      ? existing.criticalityScore
      : scoreAsset({ deviceType, isInternetFacing, hostname, osInfo, topologyLayer: null, owner: body.owner ?? existing?.owner })

    if (existing) {
      // Adopt into My Assets. Leave `source` (last observation method) untouched —
      // a scanned asset keeps showing scan_active/scan_passive after being adopted.
      const updateData: Record<string, unknown> = {
        inMyAssets: true,
        criticalityScore: computedScore,
        updatedAt: new Date(),
      }
      if (body.hostname != null) updateData.hostname = body.hostname
      if (body.mac_address != null) updateData.macAddress = normalizedMac
      if (body.owner != null) updateData.owner = body.owner
      // Only write device type if upgrading from unknown
      if (body.device_type !== undefined && !existingDeviceKnown) updateData.deviceType = body.device_type
      if (body.hardware_vendor != null) updateData.hardwareVendor = body.hardware_vendor
      if (body.os_info !== undefined) {
        updateData.osInfo = { ...(existing.osInfo as Record<string, unknown> ?? {}), ...body.os_info }
      }
      if (body.is_internet_facing !== undefined) updateData.isInternetFacing = body.is_internet_facing
      // Seed a baseline only if the adopted asset has none — never overwrite one.
      if (!existing.baselineState || Object.keys(existing.baselineState as Record<string, unknown>).length === 0) {
        updateData.baselineState = buildManualBaseline({
          hostname: (updateData.hostname as string | undefined) ?? existing.hostname,
          macAddress: (updateData.macAddress as string | null | undefined) ?? existing.macAddress,
          deviceType: (updateData.deviceType as string | undefined) ?? deviceType,
          isInternetFacing: (updateData.isInternetFacing as boolean | undefined) ?? isInternetFacing,
          osVersion: extractOsVersion((updateData.osInfo as Record<string, unknown> | undefined) ?? osInfo),
        })
      }
      const [updated] = await db.update(assets).set(updateData).where(eq(assets.assetId, existing.assetId)).returning()
      await recordManualAddress(db, { assetId: existing.assetId, tenantId: targetTenantId, ip: body.ip_address, mac: normalizedMac ?? null })
      return c.json(updated, 200)
    }

    // Create new (rule 6, or rule 5 where a reused unscoped IP had a different MAC)
    if (resolution.endAddressId) {
      await db.update(assetAddresses).set({ endedAt: new Date() }).where(eq(assetAddresses.addressId, resolution.endAddressId))
    }
    const [asset] = await db
      .insert(assets)
      .values({
        ipAddress: body.ip_address,
        hostname: body.hostname ?? null,
        macAddress: normalizedMac ?? null,
        owner: body.owner,
        deviceType,
        hardwareVendor: body.hardware_vendor,
        osInfo,
        criticalityScore: computedScore,
        isInternetFacing,
        baselineState: buildManualBaseline({ hostname: body.hostname, macAddress: normalizedMac, deviceType, isInternetFacing, osVersion: extractOsVersion(osInfo) }),
        source: body.source ?? 'manual',
        inMyAssets: true,              // created by hand → a My Assets member
        tenantId: targetTenantId,
      })
      .returning()

    if (asset) {
      await recordManualAddress(db, { assetId: asset.assetId, tenantId: targetTenantId, ip: body.ip_address, mac: normalizedMac ?? null })
    }
    return c.json(asset, 201)
  } catch (err) {
    console.error('assets POST / error:', err)
    return c.json({ detail: 'Failed to create asset' }, 500)
  }
})

// ── PATCH /:assetId ──────────────────────────────────────────────
const updateAssetSchema = z.object({
  ip_address: z.string().min(1).max(45).optional(),
  hostname: z.string().max(255).optional(),
  mac_address: z.string().max(17).optional(),
  owner: z.string().max(255).optional(),
  device_type: z.enum(['server', 'workstation', 'network', 'iot', 'unknown']).optional(),
  hardware_vendor: z.string().max(255).optional(),
  os_info: z.record(z.unknown()).optional(),
  criticality_score: z.number().int().min(1).max(10).optional(),
  is_internet_facing: z.boolean().optional(),
  // null = stop overriding and let scans infer exposure again
  internet_facing_override: z.boolean().nullable().optional(),
  source: z.enum(['manual', 'scan_active', 'scan_passive']).optional(),
  in_my_assets: z.boolean().optional(),
  // When true, merge the edited drift-tracked fields into the existing baseline in
  // the same update, so the edit is not flagged as drift at the next audit.
  update_baseline: z.boolean().optional(),
})

app.patch('/:assetId', authMiddleware, requireRoles(...WRITE_ROLES), zValidator('json', updateAssetSchema), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()
    const body = c.req.valid('json')

    // Fetch the asset AND its topology layer in one query (leftJoin), so the
    // criticality recompute below can use the same topology input as Rescore
    // without an extra subrequest.
    const [existing] = await db
      .select({ ...getTableColumns(assets), topologyLayer: topologyNodes.layer })
      .from(assets)
      .leftJoin(topologyNodes, eq(topologyNodes.assetId, assets.assetId))
      .where(eq(assets.assetId, assetId))
      .limit(1)
    if (!existing) {
      return c.json({ detail: 'Asset not found' }, 404)
    }
    if (user.role !== 'superadmin' && user.tenantId && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    const updateData: Partial<typeof assets.$inferInsert> = { updatedAt: new Date() }
    if (body.ip_address !== undefined) updateData.ipAddress = body.ip_address
    if (body.hostname !== undefined) updateData.hostname = body.hostname
    if (body.mac_address !== undefined) {
      const nm = normalizeMac(body.mac_address)
      if (body.mac_address.trim() !== '' && nm === null) {
        return c.json({ detail: `Invalid mac_address "${body.mac_address}" — expected 12 hex digits, e.g. aa:bb:cc:dd:ee:ff` }, 400)
      }
      updateData.macAddress = nm
    }
    if (body.owner !== undefined) updateData.owner = body.owner
    if (body.device_type !== undefined) updateData.deviceType = body.device_type
    if (body.hardware_vendor !== undefined) updateData.hardwareVendor = body.hardware_vendor
    if (body.os_info !== undefined) updateData.osInfo = body.os_info
    // An analyst setting exposure by hand is a confirmation: pin it so the next
    // scan's gateway inference does not flip it back.
    if (body.is_internet_facing !== undefined) {
      updateData.isInternetFacing = body.is_internet_facing
      updateData.internetFacingOverride = body.is_internet_facing
    }
    if (body.internet_facing_override !== undefined) {
      updateData.internetFacingOverride = body.internet_facing_override
      if (body.internet_facing_override !== null) updateData.isInternetFacing = body.internet_facing_override
    }
    if (body.source !== undefined) updateData.source = body.source
    if (body.in_my_assets !== undefined) updateData.inMyAssets = body.in_my_assets

    // Recompute criticality unless the caller sets it explicitly. Routed through the
    // SAME single-asset scorer as bulk/per-asset rescore — including the topology
    // layer — so PATCH and Rescore agree. (Matches the bulk run, which does not use
    // owner; see scoreAsset.)
    if (body.criticality_score !== undefined) {
      updateData.criticalityScore = body.criticality_score
    } else {
      const mergedOsInfo = (body.os_info ?? existing.osInfo ?? {}) as Record<string, unknown>
      updateData.criticalityScore = scoreAsset({
        deviceType: body.device_type ?? existing.deviceType,
        isInternetFacing: updateData.isInternetFacing ?? existing.isInternetFacing,
        hostname: body.hostname ?? existing.hostname,
        osInfo: mergedOsInfo,
        topologyLayer: existing.topologyLayer ?? null,
        owner: body.owner !== undefined ? body.owner : existing.owner,
      })
    }

    // Optionally merge the edited drift-tracked fields into the baseline (same
    // UPDATE, no extra query) so the edit is not flagged as drift next audit. Only
    // when a baseline already exists and a tracked field actually changed.
    if (body.update_baseline && existing.baselineState) {
      const edits: { hostname?: string | null; device_type?: string; is_internet_facing?: boolean; mac_address?: string | null } = {}
      if (body.hostname !== undefined && body.hostname !== existing.hostname) edits.hostname = body.hostname
      if (body.device_type !== undefined && body.device_type !== existing.deviceType) edits.device_type = body.device_type
      if (updateData.isInternetFacing !== undefined && updateData.isInternetFacing !== existing.isInternetFacing) edits.is_internet_facing = updateData.isInternetFacing as boolean
      if (updateData.macAddress !== undefined && updateData.macAddress !== existing.macAddress) edits.mac_address = updateData.macAddress as string | null
      if (Object.keys(edits).length > 0) {
        const merged = mergeBaselineFields(existing.baselineState as AssetBaseline, edits)
        if (merged) updateData.baselineState = merged
      }
    }

    const [updated] = await db
      .update(assets)
      .set(updateData)
      .where(eq(assets.assetId, assetId))
      .returning()

    if (!updated) {
      return c.json({ detail: 'Asset not found after update' }, 404)
    }

    // Keep the current address in sync when IP or MAC changes.
    if (body.ip_address !== undefined || body.mac_address !== undefined) {
      await recordManualAddress(db, {
        assetId: existing.assetId,
        tenantId: existing.tenantId,
        ip: updated.ipAddress,
        mac: updated.macAddress ?? null,
      })
    }

    // Audit My Assets add/remove (one row, only when the flag actually changes).
    if (body.in_my_assets !== undefined && body.in_my_assets !== existing.inMyAssets) {
      await db.insert(auditLogs).values({
        userId: user.userId,
        tenantId: existing.tenantId,
        actionType: body.in_my_assets ? 'asset.my_assets_add' : 'asset.my_assets_remove',
        targetEntity: assetId,
        previousState: { in_my_assets: existing.inMyAssets },
        newState: { in_my_assets: body.in_my_assets },
      })
    }

    return c.json(updated)
  } catch (err) {
    console.error('assets PATCH error:', err)
    return c.json({ detail: 'Failed to update asset' }, 500)
  }
})

// ── DELETE /:assetId ─────────────────────────────────────────────
app.delete('/:assetId', authMiddleware, requireRoles(...DELETE_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()

    const [existing] = await db.select().from(assets).where(eq(assets.assetId, assetId)).limit(1)
    if (!existing) {
      return c.json({ detail: 'Asset not found' }, 404)
    }
    if (user.role !== 'superadmin' && user.tenantId && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    await db.delete(assets).where(eq(assets.assetId, assetId))

    return c.json({ message: 'Asset deleted' })
  } catch (err) {
    console.error('assets DELETE error:', err)
    return c.json({ detail: 'Failed to delete asset' }, 500)
  }
})

// ── POST /:assetId/baseline ──────────────────────────────────────
app.post('/:assetId/baseline', authMiddleware, requireRoles(...WRITE_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()

    const [existing] = await db.select().from(assets).where(eq(assets.assetId, assetId)).limit(1)
    if (!existing) {
      return c.json({ detail: 'Asset not found' }, 404)
    }
    if (user.role !== 'superadmin' && user.tenantId && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    const osInfo = existing.osInfo as Record<string, unknown> | null
    const snapshot = buildBaseline({
      ports:            extractPorts(osInfo),
      osInfo,
      hostname:         existing.hostname,
      macAddress:       existing.macAddress,
      isInternetFacing: existing.isInternetFacing,
      deviceType:       existing.deviceType,
      autoSet:          false,
    })

    const [updated] = await db
      .update(assets)
      .set({ baselineState: snapshot, updatedAt: new Date() })
      .where(eq(assets.assetId, assetId))
      .returning()

    return c.json({ message: 'Baseline set', baseline_state: updated?.baselineState ?? null })
  } catch (err) {
    console.error('assets POST baseline error:', err)
    return c.json({ detail: 'Failed to set baseline' }, 500)
  }
})

// ── POST /rescore ─── Bulk re-score tenant assets (scope=my_assets optional) ──
app.post('/rescore', authMiddleware, requireRoles(...WRITE_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    if (!user.tenantId && user.role !== 'superadmin') {
      return c.json({ detail: 'User has no tenant assigned' }, 400)
    }

    const tenantId = user.role === 'superadmin'
      ? (c.req.query('tenant_id') ?? user.tenantId ?? null)
      : user.tenantId!

    // scope=my_assets restricts to in_my_assets=true (same query count).
    const myAssetsOnly = c.req.query('scope') === 'my_assets'
    const { scanned, changes } = await rescoreAssets(db, tenantId, undefined, { myAssetsOnly })
    const changed = changes.length
    const noun = myAssetsOnly ? 'My Assets' : 'assets'
    // Make the zero case explicit so "0 changed" doesn't read like a failure.
    const suffix = changed === 0 ? ' (scores were already up to date)' : ''
    return c.json({ updated: changed, scanned, changed, message: `Rescored ${scanned} ${noun}, ${changed} changed${suffix}` })
  } catch (err) {
    console.error('assets POST /rescore error:', err)
    return c.json({ detail: 'Failed to rescore assets' }, 500)
  }
})

// ── GET /:assetId/score ─── Score breakdown for one asset ─────────
app.get('/:assetId/score', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()

    const [asset] = await db.select().from(assets).where(eq(assets.assetId, assetId)).limit(1)
    if (!asset) return c.json({ detail: 'Asset not found' }, 404)
    if (user.role !== 'superadmin' && user.tenantId && asset.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    const result = computeCriticality({
      deviceType: asset.deviceType,
      isInternetFacing: asset.isInternetFacing,
      hostname: asset.hostname ?? undefined,
      owner: asset.owner ?? undefined,
      osInfo: (asset.osInfo ?? {}) as Record<string, unknown>,
    })

    return c.json({ asset_id: assetId, ...result })
  } catch (err) {
    console.error('assets GET /:assetId/score error:', err)
    return c.json({ detail: 'Failed to compute score' }, 500)
  }
})

// ── POST /:assetId/rescore ─── recompute ONE asset's criticality ──
// Uses the same scorer + topology layer as the bulk run, so per-asset == bulk.
// Writes only when the score changed. Subrequests: 1 (asset+layer leftJoin) + 1
// (update, only if changed). Role: WRITE_ROLES (same as PATCH).
app.post('/:assetId/rescore', authMiddleware, requireRoles(...WRITE_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()
    if (!z.string().uuid().safeParse(assetId).success) return c.json({ detail: 'Invalid asset id' }, 400)

    const [row] = await db
      .select({
        tenantId: assets.tenantId, deviceType: assets.deviceType, isInternetFacing: assets.isInternetFacing,
        hostname: assets.hostname, osInfo: assets.osInfo, criticalityScore: assets.criticalityScore,
        owner: assets.owner, topologyLayer: topologyNodes.layer,
      })
      .from(assets)
      .leftJoin(topologyNodes, eq(topologyNodes.assetId, assets.assetId))
      .where(eq(assets.assetId, assetId))
      .limit(1)
    if (!row) return c.json({ detail: 'Asset not found' }, 404)
    if (user.role !== 'superadmin' && user.tenantId && row.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    const previous = row.criticalityScore
    const current = scoreAsset({
      deviceType: row.deviceType,
      isInternetFacing: row.isInternetFacing,
      hostname: row.hostname,
      osInfo: row.osInfo as Record<string, unknown> | null,
      topologyLayer: row.topologyLayer ?? null,
      owner: row.owner,
    })
    const changed = current !== previous
    if (changed) {
      await db.update(assets).set({ criticalityScore: current, updatedAt: new Date() }).where(eq(assets.assetId, assetId))
    }
    return c.json({ changed, previous, current })
  } catch (err) {
    console.error('assets POST /:assetId/rescore error:', err)
    return c.json({ detail: 'Failed to rescore asset' }, 500)
  }
})

// ── POST /import ─── CSV bulk import ─────────────────────────────
function parseCSVRow(line: string): string[] {
  const result: string[] = []
  let current = ''
  let inQuotes = false
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { current += '"'; i++ }
      else { inQuotes = !inQuotes }
    } else if (ch === ',' && !inQuotes) {
      result.push(current.trim())
      current = ''
    } else {
      current += ch
    }
  }
  result.push(current.trim())
  return result
}

const VALID_DEVICE_TYPES = new Set(['server', 'workstation', 'network', 'iot', 'unknown'])

app.post('/import', authMiddleware, requireRoles(...WRITE_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const targetTenantId = user.role === 'superadmin'
      ? (c.req.query('tenant_id') || user.tenantId || null)
      : (user.tenantId ?? null)

    let formData: FormData
    try {
      formData = await c.req.formData()
    } catch {
      return c.json({ detail: 'Request must be multipart/form-data' }, 400)
    }

    const file = formData.get('file') as File | null
    if (!file || file.size === 0) {
      return c.json({ detail: 'No CSV file provided' }, 400)
    }

    const text = await file.text()
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean)

    if (lines.length < 2) {
      return c.json({ detail: 'CSV must have a header row and at least one data row' }, 400)
    }

    const headers = parseCSVRow(lines[0]!).map(h => h.toLowerCase().replace(/\s+/g, '_'))

    if (!headers.includes('ip_address')) {
      return c.json({ detail: 'CSV must include an "ip_address" column' }, 400)
    }

    type ParsedRow = {
      rowNum: number
      ipAddress: string
      hostname?: string
      macAddress?: string
      owner?: string
      deviceType: 'server' | 'workstation' | 'network' | 'iot' | 'unknown'
      hardwareVendor?: string
      osInfo: Record<string, unknown>
      criticalityScore: number
      isInternetFacing: boolean
    }

    const parsed: ParsedRow[] = []
    const errors: string[] = []

    for (let i = 1; i < lines.length; i++) {
      const cols = parseCSVRow(lines[i]!)
      const row: Record<string, string> = {}
      headers.forEach((h, idx) => { row[h] = cols[idx] ?? '' })

      const ipAddress = row['ip_address']
      if (!ipAddress || !/^[\d.:/a-fA-F]+$/.test(ipAddress)) {
        errors.push(`Row ${i + 1}: invalid or missing ip_address`)
        continue
      }

      const deviceTypeRaw = row['device_type']?.toLowerCase()
      const deviceType = (VALID_DEVICE_TYPES.has(deviceTypeRaw ?? '') ? deviceTypeRaw : 'unknown') as ParsedRow['deviceType']
      const isInternetFacing = row['is_internet_facing']?.toLowerCase() === 'true'

      const osInfo: Record<string, unknown> = {}
      if (row['os_name']) osInfo.name = row['os_name']
      if (row['os_version']) osInfo.version = row['os_version']
      if (row['open_ports']) {
        osInfo.ports = row['open_ports'].split(/[\s,]+/).map(p => p.trim()).filter(Boolean)
      }

      // Normalize MAC; a non-empty invalid value is skipped with a per-row
      // warning rather than failing the whole row.
      let macAddress: string | undefined = undefined
      const rawMac = row['mac_address']
      if (rawMac && rawMac.trim() !== '') {
        const nm = normalizeMac(rawMac)
        if (nm === null) {
          errors.push(`Row ${i + 1}: invalid mac_address "${rawMac}" — skipped`)
        } else {
          macAddress = nm
        }
      }

      const criticalityScore = scoreAsset({
        deviceType,
        isInternetFacing,
        hostname: row['hostname'] || undefined,
        osInfo,
        topologyLayer: null,              // brand-new CSV asset has no topology layer
        owner: row['owner'] || undefined,
      })

      parsed.push({
        rowNum: i + 1,
        ipAddress,
        hostname: row['hostname'] || undefined,
        macAddress,
        owner: row['owner'] || undefined,
        deviceType,
        hardwareVendor: row['hardware_vendor'] || undefined,
        osInfo,
        criticalityScore,
        isInternetFacing,
      })
    }

    if (parsed.length === 0) {
      return c.json({ imported: 0, updated: 0, errors })
    }

    // Batched identity resolution (prefetch → resolve in memory → db.batch), so a
    // large CSV stays within the Worker subrequest limit instead of ~3 queries per
    // row. Unscoped (manual): match by MAC (rule 1) then IP (rule 4); idempotent on
    // re-import. The in-memory working store lets duplicate rows in one CSV dedupe.
    const csvMacs = [...new Set(parsed.map(r => classifyMac(r.macAddress ?? null).mac).filter((m): m is string => !!m))]
    const csvIps = [...new Set(parsed.map(r => r.ipAddress))]
    const prefetch = await prefetchIdentity(db, targetTenantId, csvMacs, csvIps, [])
    // Whether each prefetched asset already has a baseline (to fill-if-null on adopt).
    const assetHasBaseline = new Map(prefetch.assets.map(a => [a.assetId, a.hasBaseline]))

    type WAddr = CandidateAddress & { ended: boolean }
    const workAddrs: WAddr[] = prefetch.addresses.map(a => ({
      addressId: a.addressId, assetId: a.assetId, networkKey: a.networkKey,
      ipAddress: a.ipAddress, macAddress: a.macAddress, assetDeviceType: a.deviceType, ended: false,
    }))
    const isUniqueViolation = (e: unknown): boolean => {
      const err = e as { code?: string; cause?: { code?: string }; message?: string }
      return (err?.code ?? err?.cause?.code) === '23505' || /duplicate key value|unique constraint|23505/i.test(String(err?.message ?? ''))
    }

    // Build per-row statement groups against the in-memory working store.
    const perRow: { row: typeof parsed[number]; kind: 'insert' | 'update'; stmts: unknown[] }[] = []
    for (const r of parsed) {
      const now = new Date()
      const { mac, macClass } = classifyMac(r.macAddress ?? null)
      const usableMac = macClass === 'global' || macClass === 'local'
      const macAddresses = (usableMac && mac) ? workAddrs.filter(w => !w.ended && w.macAddress === mac) : []
      const netIpAddresses = workAddrs.filter(w => !w.ended && w.ipAddress === r.ipAddress && w.networkKey === null)
      const decision = matchAsset({ macClass, mac, ip: r.ipAddress, hostKey: null, networkKey: null }, { macAddresses, hostKeyAssetIds: [], netIpAddresses })
      const stmts: unknown[] = []
      if (decision.assetId) {
        stmts.push(db.update(assets).set({
          ...(r.hostname ? { hostname: r.hostname } : {}),
          ...(r.macAddress ? { macAddress: r.macAddress } : {}),
          ...(r.owner ? { owner: r.owner } : {}),
          deviceType: r.deviceType,
          ...(r.hardwareVendor ? { hardwareVendor: r.hardwareVendor } : {}),
          ...(Object.keys(r.osInfo).length > 0 ? { osInfo: r.osInfo } : {}),
          criticalityScore: r.criticalityScore,
          isInternetFacing: r.isInternetFacing,
          inMyAssets: true,          // adopt the matched asset; leave source alone
          // Seed a baseline only if the adopted asset has none — never overwrite.
          ...(assetHasBaseline.get(decision.assetId) ? {} : { baselineState: buildManualBaseline({ hostname: r.hostname, macAddress: r.macAddress, deviceType: r.deviceType, isInternetFacing: r.isInternetFacing, osVersion: extractOsVersion(r.osInfo) }) }),
          ...(targetTenantId ? { tenantId: targetTenantId } : {}),
          ipAddress: r.ipAddress,
          updatedAt: now,
        }).where(eq(assets.assetId, decision.assetId)))
        assetHasBaseline.set(decision.assetId, true)   // another CSV row won't re-seed it
        const curAddr = workAddrs.find(w => !w.ended && w.assetId === decision.assetId && w.networkKey === null)
        if (curAddr) {
          const filledMac = curAddr.macAddress ?? r.macAddress ?? null
          stmts.push(db.update(assetAddresses).set({ ipAddress: r.ipAddress, lastSeen: now, macAddress: filledMac }).where(eq(assetAddresses.addressId, curAddr.addressId)))
          curAddr.ipAddress = r.ipAddress; curAddr.macAddress = filledMac
        } else {
          const nid = crypto.randomUUID()
          stmts.push(db.insert(assetAddresses).values({ addressId: nid, assetId: decision.assetId, tenantId: targetTenantId, networkKey: null, ipAddress: r.ipAddress, macAddress: r.macAddress ?? null, firstSeen: now, lastSeen: now }))
          workAddrs.unshift({ addressId: nid, assetId: decision.assetId, networkKey: null, ipAddress: r.ipAddress, macAddress: r.macAddress ?? null, assetDeviceType: r.deviceType, ended: false })
        }
        perRow.push({ row: r, kind: 'update', stmts })
      } else {
        const newAssetId = crypto.randomUUID()
        if (decision.rule === 5) {
          stmts.push(db.update(assetAddresses).set({ endedAt: now }).where(eq(assetAddresses.addressId, decision.endAddressId)))
          const w = workAddrs.find(x => !x.ended && x.addressId === decision.endAddressId); if (w) w.ended = true
        }
        stmts.push(db.insert(assets).values({ assetId: newAssetId, ipAddress: r.ipAddress, hostname: r.hostname ?? null, macAddress: r.macAddress ?? null, owner: r.owner, deviceType: r.deviceType, hardwareVendor: r.hardwareVendor, osInfo: Object.keys(r.osInfo).length > 0 ? r.osInfo : {}, criticalityScore: r.criticalityScore, isInternetFacing: r.isInternetFacing, baselineState: buildManualBaseline({ hostname: r.hostname, macAddress: r.macAddress, deviceType: r.deviceType, isInternetFacing: r.isInternetFacing, osVersion: extractOsVersion(r.osInfo) }), source: 'manual' as const, inMyAssets: true, tenantId: targetTenantId }))
        const nid = crypto.randomUUID()
        stmts.push(db.insert(assetAddresses).values({ addressId: nid, assetId: newAssetId, tenantId: targetTenantId, networkKey: null, ipAddress: r.ipAddress, macAddress: r.macAddress ?? null, firstSeen: now, lastSeen: now }))
        workAddrs.unshift({ addressId: nid, assetId: newAssetId, networkKey: null, ipAddress: r.ipAddress, macAddress: r.macAddress ?? null, assetDeviceType: r.deviceType, ended: false })
        perRow.push({ row: r, kind: 'insert', stmts })
      }
    }

    // Execute in chunks of ~100 statements (one db.batch = one subrequest), without
    // splitting a row. On a chunk failure, retry its rows individually for isolation.
    let imported = 0
    let updated = 0
    const commit = (g: typeof perRow[number]) => { if (g.kind === 'insert') imported++; else updated++ }
    const flush = async (groups: typeof perRow) => {
      if (groups.length === 0) return
      const stmts = groups.flatMap(g => g.stmts)
      try {
        await db.batch(stmts as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
        for (const g of groups) commit(g)
      } catch (e) {
        if (!isUniqueViolation(e)) { for (const g of groups) errors.push(`Row ${g.row.rowNum} (${g.row.ipAddress}): ${(e as Error).message}`); return }
        for (const g of groups) {
          try { await db.batch(g.stmts as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0]); commit(g) }
          catch (err) { errors.push(`Row ${g.row.rowNum} (${g.row.ipAddress}): ${(err as Error).message}`) }
        }
      }
    }
    let curGroups: typeof perRow = []
    let curCount = 0
    for (const g of perRow) {
      if (curCount > 0 && curCount + g.stmts.length > 100) { await flush(curGroups); curGroups = []; curCount = 0 }
      curGroups.push(g); curCount += g.stmts.length
    }
    await flush(curGroups)

    return c.json({ imported, updated, errors })
  } catch (err) {
    console.error('assets POST /import error:', err)
    return c.json({ detail: 'Failed to import assets' }, 500)
  }
})

// ── GET /:assetId/baseline ───────────────────────────────────────
app.get('/:assetId/baseline', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()

    const [asset] = await db
      .select({ assetId: assets.assetId, baselineState: assets.baselineState, updatedAt: assets.updatedAt })
      .from(assets)
      .where(eq(assets.assetId, assetId))
      .limit(1)

    if (!asset) {
      return c.json({ detail: 'Asset not found' }, 404)
    }
    if (user.role !== 'superadmin' && user.tenantId) {
      const [full] = await db.select({ tenantId: assets.tenantId }).from(assets).where(eq(assets.assetId, assetId)).limit(1)
      if (full && full.tenantId !== user.tenantId) {
        return c.json({ detail: 'Asset not found' }, 404)
      }
    }

    return c.json({ asset_id: asset.assetId, baseline_state: asset.baselineState, updated_at: asset.updatedAt })
  } catch (err) {
    console.error('assets GET baseline error:', err)
    return c.json({ detail: 'Failed to fetch baseline' }, 500)
  }
})

// ── GET /:assetId/sbom-scan-status ─── frontend polls this after triggering ───
app.get('/:assetId/sbom-scan-status', authMiddleware, requireRoles(...READ_ROLES), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()
    const [row] = await db
      .select({
        scanId:    scanResults.scanId,
        status:    scanResults.status,
        failureReason: scanResults.failureReason,
        startedAt: scanResults.startedAt,
        completedAt: scanResults.completedAt,
      })
      .from(scanResults)
      .where(and(eq(scanResults.subnet, assetId), eq(scanResults.scanType, 'sbom')))
      .orderBy(desc(scanResults.startedAt))
      .limit(1)
    if (!row) return c.json({ status: 'none' })
    return c.json({
      scan_id:      row.scanId,
      status:       row.status,
      started_at:   row.startedAt,
      completed_at: row.completedAt,
      failure_reason: row.failureReason,
    })
  } catch (err) {
    console.error('sbom-scan-status error:', err)
    return c.json({ detail: 'Failed to fetch SBOM scan status' }, 500)
  }
})

// ── POST /:assetId/scan-sbom ────────────────────────────────────
// Queues a real SBOM scan job — picked up by the EagleEye agent via
// GET /scans/pending, which runs Syft locally and POSTs back to POST /sboms/ingest.
const scanSbomSchema = z.object({
  target: z.string().min(1).optional(),  // hint for the agent (e.g. "dir:C:\", "dir:/")
})

app.post('/:assetId/scan-sbom', authMiddleware, requireRoles(...WRITE_ROLES),
  zValidator('json', scanSbomSchema), async (c) => {
    try {
      const user = c.get('user')
      const db   = getDb(c.env.DATABASE_URL)
      const { assetId } = c.req.param()
      const { target }  = c.req.valid('json')

      // Verify asset exists and belongs to user's tenant
      const [asset] = await db
        .select({ assetId: assets.assetId, tenantId: assets.tenantId })
        .from(assets).where(eq(assets.assetId, assetId)).limit(1)
      if (!asset) return c.json({ detail: 'Asset not found' }, 404)
      if (user.role !== 'superadmin' && user.tenantId && asset.tenantId !== user.tenantId) {
        return c.json({ detail: 'Asset not found' }, 404)
      }

      // Find the most-recently active agent for this tenant.
      // Require a heartbeat within the last 2 minutes — same threshold used by the
      // notifications system — so stale 'online' rows from dead agents are ignored.
      const [agent] = await db
        .select({ agentId: agents.agentId })
        .from(agents)
        .where(and(
          eq(agents.tenantId, asset.tenantId!),
          eq(agents.status, 'online'),
          sql`${agents.lastHeartbeat} > now() - interval '2 minutes'`,
        ))
        .orderBy(desc(agents.lastHeartbeat))
        .limit(1)
      if (!agent) return c.json({ detail: 'No online agent available — start the EagleEye agent on the target machine' }, 503)

      // Cancel any existing pending SBOM scans for this asset to avoid duplicates.
      await db.update(scanResults)
        .set({ status: 'cancelled' })
        .where(and(
          eq(scanResults.subnet, assetId),
          eq(scanResults.scanType, 'sbom'),
          eq(scanResults.status, 'pending'),
        ))

      // Create a pending SBOM scan record.
      // subnet field carries assetId so the agent knows which asset to attach results to.
      // rawResults carries the optional Syft target hint.
      const [scan] = await db.insert(scanResults).values({
        agentId:   agent.agentId,
        tenantId:  asset.tenantId,
        scanType:  'sbom',
        subnet:    assetId,
        status:    'pending',
        rawResults: target ? [{ target }] : [],
      }).returning({ scanId: scanResults.scanId })

      if (!scan) return c.json({ detail: 'Failed to create scan record' }, 500)

      return c.json({
        scan_id:  scan.scanId,
        status:   'pending',
        message:  'SBOM scan queued — agent will pick it up within 30 seconds',
      }, 202)
    } catch (err) {
      console.error('scan-sbom error:', err)
      return c.json({ detail: 'Failed to queue SBOM scan' }, 500)
    }
  }
)

export default app
