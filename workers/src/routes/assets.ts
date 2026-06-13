import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, or, isNull, desc, ilike, sql } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { assets, scanResults, agents } from '../db/schema'
import { rescoreAssets } from '../lib/rescore'
import { computeCriticality } from '../lib/criticality'
import { buildBaseline, extractPorts } from '../services/drift'

const app = new Hono<{ Bindings: Env }>()

const READ_ROLES   = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner']
const WRITE_ROLES  = ['tenant_superadmin', 'tenant_admin']
const DELETE_ROLES = ['tenant_superadmin']

function computeAssetCriticality(input: {
  deviceType: string
  isInternetFacing: boolean
  hostname?: string | null
  owner?: string | null
  osInfo: Record<string, unknown>
}): number {
  return computeCriticality({
    deviceType: input.deviceType,
    isInternetFacing: input.isInternetFacing,
    hostname: input.hostname ?? undefined,
    owner: input.owner ?? undefined,
    osInfo: input.osInfo,
  }).score
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
    const tenant_id_param = c.req.query('tenant_id')

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

    if (search) {
      const searchCondition = or(
        ilike(assets.hostname, `%${search}%`),
        ilike(assets.ipAddress, `%${search}%`),
      )
      if (searchCondition) conditions.push(searchCondition)
    }

    if (source && ['manual', 'scan_active', 'scan_passive'].includes(source)) {
      conditions.push(eq(assets.source, source as 'manual' | 'scan_active' | 'scan_passive'))
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined

    const [rows, countRows] = await Promise.all([
      db
        .select()
        .from(assets)
        .where(whereClause)
        .orderBy(sql`${assets.lastScanned} DESC NULLS LAST`, desc(assets.createdAt))
        .limit(limit)
        .offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(assets).where(whereClause),
    ])

    return c.json({ total: countRows[0]?.count ?? 0, page, limit, items: rows })
  } catch (err) {
    console.error('assets GET / error:', err)
    return c.json({ detail: 'Failed to fetch assets' }, 500)
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

    const targetTenantId = (user.role === 'superadmin' && body.tenant_id)
      ? body.tenant_id
      : (user.tenantId ?? null)

    // Upsert: find existing asset by IP + tenant to avoid duplicates
    const ipConditions = [eq(assets.ipAddress, body.ip_address)]
    if (targetTenantId) {
      ipConditions.push(eq(assets.tenantId, targetTenantId))
    } else {
      ipConditions.push(isNull(assets.tenantId))
    }
    const [existing] = await db.select().from(assets).where(and(...ipConditions)).limit(1)

    // Preserve scanned device type — only override if existing is unknown or absent
    const existingDeviceKnown = existing?.deviceType && existing.deviceType !== 'unknown'
    const deviceType = existingDeviceKnown ? existing!.deviceType : (body.device_type ?? 'unknown')
    const isInternetFacing = body.is_internet_facing ?? existing?.isInternetFacing ?? false
    const osInfo = (body.os_info ?? existing?.osInfo ?? {}) as Record<string, unknown>
    const hostname = body.hostname ?? existing?.hostname

    // Preserve criticality from scan when device type is unchanged; recompute only when type improves
    const computedScore = (existing?.criticalityScore && deviceType === existing.deviceType)
      ? existing.criticalityScore
      : computeAssetCriticality({ deviceType, isInternetFacing, hostname, owner: body.owner ?? existing?.owner, osInfo })

    if (existing) {
      // Promote to manual and update provided fields
      const updateData: Record<string, unknown> = {
        source: body.source ?? 'manual',
        criticalityScore: computedScore,
        updatedAt: new Date(),
      }
      if (body.hostname != null) updateData.hostname = body.hostname
      if (body.mac_address != null) updateData.macAddress = body.mac_address
      if (body.owner != null) updateData.owner = body.owner
      // Only write device type if upgrading from unknown
      if (body.device_type !== undefined && !existingDeviceKnown) updateData.deviceType = body.device_type
      if (body.hardware_vendor != null) updateData.hardwareVendor = body.hardware_vendor
      if (body.os_info !== undefined) updateData.osInfo = body.os_info
      if (body.is_internet_facing !== undefined) updateData.isInternetFacing = body.is_internet_facing
      const [updated] = await db.update(assets).set(updateData).where(eq(assets.assetId, existing.assetId)).returning()
      return c.json(updated, 200)
    }

    // Create new
    const [asset] = await db
      .insert(assets)
      .values({
        ipAddress: body.ip_address,
        hostname: body.hostname ?? null,
        macAddress: body.mac_address ?? null,
        owner: body.owner,
        deviceType,
        hardwareVendor: body.hardware_vendor,
        osInfo,
        criticalityScore: computedScore,
        isInternetFacing,
        source: body.source ?? 'manual',
        tenantId: targetTenantId,
      })
      .returning()

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
  source: z.enum(['manual', 'scan_active', 'scan_passive']).optional(),
})

app.patch('/:assetId', authMiddleware, requireRoles(...WRITE_ROLES), zValidator('json', updateAssetSchema), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { assetId } = c.req.param()
    const body = c.req.valid('json')

    const [existing] = await db.select().from(assets).where(eq(assets.assetId, assetId)).limit(1)
    if (!existing) {
      return c.json({ detail: 'Asset not found' }, 404)
    }
    if (user.role !== 'superadmin' && user.tenantId && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Asset not found' }, 404)
    }

    const updateData: Partial<typeof assets.$inferInsert> = { updatedAt: new Date() }
    if (body.ip_address !== undefined) updateData.ipAddress = body.ip_address
    if (body.hostname !== undefined) updateData.hostname = body.hostname
    if (body.mac_address !== undefined) updateData.macAddress = body.mac_address
    if (body.owner !== undefined) updateData.owner = body.owner
    if (body.device_type !== undefined) updateData.deviceType = body.device_type
    if (body.hardware_vendor !== undefined) updateData.hardwareVendor = body.hardware_vendor
    if (body.os_info !== undefined) updateData.osInfo = body.os_info
    if (body.is_internet_facing !== undefined) updateData.isInternetFacing = body.is_internet_facing
    if (body.source !== undefined) updateData.source = body.source

    // Recompute criticality unless caller explicitly sets it
    if (body.criticality_score !== undefined) {
      updateData.criticalityScore = body.criticality_score
    } else {
      const mergedDeviceType = body.device_type ?? existing.deviceType
      const mergedHostname = body.hostname ?? existing.hostname
      const mergedOsInfo = (body.os_info ?? existing.osInfo ?? {}) as Record<string, unknown>
      const mergedInternetFacing = body.is_internet_facing ?? existing.isInternetFacing
      updateData.criticalityScore = computeAssetCriticality({
        deviceType: mergedDeviceType,
        isInternetFacing: mergedInternetFacing,
        hostname: mergedHostname,
        owner: body.owner !== undefined ? body.owner : existing.owner,
        osInfo: mergedOsInfo,
      })
    }

    const [updated] = await db
      .update(assets)
      .set(updateData)
      .where(eq(assets.assetId, assetId))
      .returning()

    if (!updated) {
      return c.json({ detail: 'Asset not found after update' }, 404)
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

// ── POST /rescore ─── Bulk auto-score all tenant assets ──────────
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

    const updated = await rescoreAssets(db, tenantId)
    return c.json({ updated, message: `Criticality rescored for ${updated} asset(s)` })
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

      const criticalityScore = computeAssetCriticality({
        deviceType,
        isInternetFacing,
        hostname: row['hostname'] || undefined,
        owner: row['owner'] || undefined,
        osInfo,
      })

      parsed.push({
        rowNum: i + 1,
        ipAddress,
        hostname: row['hostname'] || undefined,
        macAddress: row['mac_address'] || undefined,
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

    const allIps = parsed.map(r => r.ipAddress)
    const ipInList = sql`${assets.ipAddress} = ANY(${sql.raw(`ARRAY[${allIps.map(ip => `'${ip.replace(/'/g, "''")}'`).join(',')}]`)})`

    const tenantConditions = targetTenantId
      ? and(ipInList, or(eq(assets.tenantId, targetTenantId), isNull(assets.tenantId)))
      : ipInList

    const existingRows = await db
      .select({ assetId: assets.assetId, ipAddress: assets.ipAddress })
      .from(assets)
      .where(tenantConditions)

    const existingMap = new Map(existingRows.map(r => [r.ipAddress, r.assetId]))

    const toInsert = parsed.filter(r => !existingMap.has(r.ipAddress))
    const toUpdate = parsed.filter(r => existingMap.has(r.ipAddress))

    if (toInsert.length > 0) {
      try {
        await db.insert(assets).values(
          toInsert.map(r => ({
            ipAddress: r.ipAddress,
            hostname: r.hostname,
            macAddress: r.macAddress,
            owner: r.owner,
            deviceType: r.deviceType,
            hardwareVendor: r.hardwareVendor,
            osInfo: Object.keys(r.osInfo).length > 0 ? r.osInfo : {},
            criticalityScore: r.criticalityScore,
            isInternetFacing: r.isInternetFacing,
            source: 'manual' as const,
            tenantId: targetTenantId,
          }))
        )
      } catch (insertErr) {
        toInsert.forEach(r => errors.push(`Row ${r.rowNum} (${r.ipAddress}): ${(insertErr as Error).message}`))
        toInsert.length = 0
      }
    }

    for (const r of toUpdate) {
      const assetId = existingMap.get(r.ipAddress)!
      try {
        await db.update(assets).set({
          ...(r.hostname ? { hostname: r.hostname } : {}),
          ...(r.macAddress ? { macAddress: r.macAddress } : {}),
          ...(r.owner ? { owner: r.owner } : {}),
          deviceType: r.deviceType,
          ...(r.hardwareVendor ? { hardwareVendor: r.hardwareVendor } : {}),
          ...(Object.keys(r.osInfo).length > 0 ? { osInfo: r.osInfo } : {}),
          criticalityScore: r.criticalityScore,
          isInternetFacing: r.isInternetFacing,
          ...(targetTenantId ? { tenantId: targetTenantId } : {}),
          updatedAt: new Date(),
        }).where(eq(assets.assetId, assetId))
      } catch (updateErr) {
        errors.push(`Row ${r.rowNum} (${r.ipAddress}): ${(updateErr as Error).message}`)
        toUpdate.splice(toUpdate.indexOf(r), 1)
      }
    }

    return c.json({ imported: toInsert.length, updated: toUpdate.length, errors })
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
