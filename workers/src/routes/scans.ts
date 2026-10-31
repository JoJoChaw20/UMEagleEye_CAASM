import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, and, or, sql, desc, gte, inArray, isNull, notInArray, type SQL } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { getDb } from '../db/client'
import { scanResults, agents, assets, assetAddresses, events, tenants } from '../db/schema'
import { matchIocs } from '../services/iocMatch'
import { ACTIVE_MODEL, agentRoleOf, scoreAsset } from '../lib/rescore'
import { applyHint, deviceTypeHint } from '../lib/deviceHints'
import { normalizeMac } from '../lib/mac'
import { mergeOsInfo } from '../lib/osInfo'
import { classifyMac, prefetchIdentity, resolveAssetIdentity, sanitizeHostKey } from '../lib/identity'
import { chunkPlan, planIngest, resolveIngestDeviceType, type IngestOp, type PlanHost } from '../lib/ingest-plan'
import { buildBaseline, runDriftAudit } from '../services/drift'
import { reopenReturnedNewDevices, runAlertHygiene } from '../services/alertHygiene'
import { isIPv4, resolveInternetFacing } from '../lib/exposure'
import { inferDeviceType, isNetworkBySnmp, type NmapPort } from '../lib/deviceClassify'
import { PASSIVE_FOLD_MINUTES, mergePassiveHosts, resolveHostAssets, type HostAssetCandidate } from '../lib/scanLog'
import { buildNetworks, networkOf, passiveNetworkOf, scanKind, type ScanKind } from '../lib/discoveryNetworks'
import { aiEvidenceKey, resolveVendors, reusableDescription } from '../lib/hostEvidence'
import { isGenericHostname, newDeviceSeverity, pickHostname } from '../lib/hostnames'
import { resolveNetworkScope } from '../lib/networkScope'
import {
  INVESTIGATE_EXPIRE_HOURS, INVESTIGATE_TRIGGER, isInvestigation, queueInvestigations, recordInvestigationFailure,
  recordInvestigationResult, type InvestigationInfo,
} from '../services/autoInvestigate'

// The scan classifier lives in lib/deviceClassify.ts (shared with "Automatic" type
// reset); re-exported for scripts that import it from here.
export { inferDeviceType }

/** Thrown to leave the LLM block early when every host was unchanged. */
class SkipLlm extends Error {}

// ── Online MAC vendor lookup (api.macvendors.com) ───────────────────────────
// For real MACs the agent's offline list could not name, and older agents
// (lib/hostEvidence.ts). Returns the vendor, '' when
// the prefix is unknown (404, cached as such), or null on error or rate limit
// (not cached, asked again next time) — always non-fatal.
async function fetchMacVendor(mac: string | null | undefined): Promise<string | null> {
  if (!mac) return null
  try {
    // Hex digits only: 6 for the 3-byte block, 9 to pin an MA-M/MA-S sub-block.
    const clean = mac.replace(/[^0-9a-fA-F]/g, '').substring(0, 12)
    if (clean.length < 6) return null
    const res = await fetch(`https://api.macvendors.com/${encodeURIComponent(clean)}`, {
      headers: { 'User-Agent': 'EagleEye-CAASM/2.0' },
      signal: AbortSignal.timeout(4000),  // 4s timeout per lookup
    })
    if (res.status === 404) return ''   // unknown prefix
    if (!res.ok) return null            // 429 = rate limited
    const vendor = (await res.text()).trim()
    return vendor || null
  } catch {
    return null  // network error, timeout — always non-fatal
  }
}

// Port facts from this scan. Active scans always write `ports` (even when empty)
// so a port that closed is noticed; passive scans have no port visibility, so
// they return OS facts only and the upsert merge keeps the last active-scan
// ports instead of wiping them.
function buildOsInfo(os: Record<string, unknown> | null | undefined, ports: NmapPort[], isPassive: boolean): Record<string, unknown> {
  const info: Record<string, unknown> = { ...(os ?? {}) }
  if (!isPassive) {
    info.ports    = ports.map(p => `${p.port}/${p.protocol ?? 'tcp'}`)
    info.products = [...new Set(ports.map(p => p.product).filter(Boolean))]
    info.versions = [...new Set(ports.map(p => p.version).filter(Boolean))]
    info.services = ports.map(p => ({
      port: p.port, protocol: p.protocol ?? 'tcp',
      service: p.service ?? null, product: p.product ?? null, version: p.version ?? null,
    }))
  }
  return info
}

const app = new Hono<{ Bindings: Env }>()

// ── Identity helpers ─────────────────────────────────────────────
// Postgres unique-violation (SQLSTATE 23505) raised by the partial unique index
// on asset_addresses when a concurrent ingest records the same current address.
function isUniqueViolation(e: unknown): boolean {
  const err = e as { code?: string; cause?: { code?: string }; message?: string }
  const code = err?.code ?? err?.cause?.code
  return code === '23505' || /duplicate key value|unique constraint|23505/i.test(String(err?.message ?? ''))
}

// Record/refresh the current address row for a matched (updated) asset.
// Handles: same IP (refresh last_seen, fill empty mac/network), IP change / DHCP
// (end old row + insert new), and first sighting on a new network (insert).
async function recordMatchedAddress(
  db: ReturnType<typeof getDb>,
  p: {
    assetId: string
    tenantId: string | null
    networkKey: string | null
    ip: string
    mac: string | null
    currentAddress: { addressId: string; ipAddress: string; macAddress: string | null; networkKey: string | null } | null
  },
): Promise<void> {
  const seen = new Date()
  const { currentAddress } = p
  if (currentAddress) {
    if (currentAddress.ipAddress === p.ip) {
      await db.update(assetAddresses).set({
        lastSeen: seen,
        macAddress: currentAddress.macAddress ?? p.mac ?? null,       // fill, never clear
        networkKey: currentAddress.networkKey ?? p.networkKey ?? null,
      }).where(eq(assetAddresses.addressId, currentAddress.addressId))
      return
    }
    // IP changed (DHCP) on this network — end the old row, open a new current one.
    try {
      await db.batch([
        db.update(assetAddresses).set({ endedAt: seen }).where(eq(assetAddresses.addressId, currentAddress.addressId)),
        db.insert(assetAddresses).values({
          assetId: p.assetId, tenantId: p.tenantId, networkKey: p.networkKey,
          ipAddress: p.ip, macAddress: p.mac, firstSeen: seen, lastSeen: seen,
        }),
      ])
    } catch (e) { if (!isUniqueViolation(e)) throw e }  // lost race → another ingest recorded it
    return
  }
  // No current address on this network (e.g. rule 1 matched by MAC elsewhere).
  try {
    await db.insert(assetAddresses).values({
      assetId: p.assetId, tenantId: p.tenantId, networkKey: p.networkKey,
      ipAddress: p.ip, macAddress: p.mac, firstSeen: seen, lastSeen: seen,
    })
  } catch (e) { if (!isUniqueViolation(e)) throw e }
}

// ── Helper: SHA-256 hex digest ───────────────────────────────────
async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder()
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(input))
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// ── POST /drift-audit ─── manual on-demand drift run ────────────
app.post('/drift-audit', authMiddleware, requireRoles('tenant_superadmin', 'tenant_admin'), async (c) => {
  try {
    const user = c.get('user')
    const db   = getDb(c.env.DATABASE_URL)
    const tenantId = user.role === 'superadmin' ? undefined : (user.tenantId ?? undefined)
    const count = await runDriftAudit(db, tenantId)
    // Also what the nightly job closes (CVE alerts without an SBOM, reviewed/stale new devices),
    // so staging, which has no cron, can be checked by hand.
    const closed = await runAlertHygiene(db, { tenantId })
    return c.json({
      message: 'Drift audit complete', drift_events_generated: count,
      cve_alerts_closed: closed.cve, new_device_alerts_closed: closed.newDevices,
    })
  } catch (err) {
    console.error('drift-audit error:', err)
    return c.json({ detail: 'Drift audit failed' }, 500)
  }
})

// Active scans (New scan, new-device investigations) that no agent picked up within
// ACTIVE_EXPIRE_HOURS fail with a reason instead of staying 'pending' for ever (the agent
// was offline or closed). Runs when an agent polls and when the dashboard lists scans.
const ACTIVE_EXPIRE_HOURS = INVESTIGATE_EXPIRE_HOURS
async function expireStaleActiveScans(db: ReturnType<typeof getDb>, scope: SQL | undefined): Promise<void> {
  const expired = await db.update(scanResults)
    .set({
      status: 'failed', completedAt: new Date(),
      failureReason: sql`CASE WHEN ${scanResults.networkInfo}->>'trigger' = ${INVESTIGATE_TRIGGER}
        THEN ${`The agent did not pick up this new-device scan within ${ACTIVE_EXPIRE_HOURS} hours`}
        ELSE ${`The agent did not pick up this scan within ${ACTIVE_EXPIRE_HOURS} hours (it was offline or closed)`} END`,
    })
    .where(and(
      scope,
      eq(scanResults.scanType, 'active'),
      eq(scanResults.status, 'pending'),
      sql`${scanResults.startedAt} < now() - make_interval(hours => ${ACTIVE_EXPIRE_HOURS})`,
    ))
    .returning({ scanId: scanResults.scanId, networkInfo: scanResults.networkInfo, failureReason: scanResults.failureReason })
  for (const row of expired) {
    if (isInvestigation(row.networkInfo)) await recordInvestigationFailure(db, row.networkInfo, row.scanId, row.failureReason ?? 'expired')
  }
}

// ── GET / ─── list scans for authenticated user ──────────────────
app.get('/', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const tenantIdParam = c.req.query('tenant_id')
    const effectiveTenantId = user.role === 'superadmin'
      ? (tenantIdParam ?? undefined)
      : (user.tenantId ?? undefined)
    const tenantCondition = effectiveTenantId ? eq(scanResults.tenantId, effectiveTenantId) : undefined

    const whereClause = tenantCondition
      ? and(notInArray(scanResults.scanType, ['sbom', 'inventory']), tenantCondition)
      : notInArray(scanResults.scanType, ['sbom', 'inventory'])

    await expireStaleActiveScans(db, tenantCondition)

    // Paging and filters (Discovery page, Scan history). raw_results is left out: the
    // hosts of one record come from GET /:scanId/hosts.
    const page = Math.max(1, parseInt(c.req.query('page') ?? '1') || 1)
    const pageSize = Math.min(100, Math.max(1, parseInt(c.req.query('page_size') ?? '25') || 25))
    const filters: (SQL | undefined)[] = [whereClause]
    const status = c.req.query('status')
    if (status) filters.push(eq(scanResults.status, status))
    const agentId = c.req.query('agent_id')
    if (agentId) filters.push(eq(scanResults.agentId, agentId))
    const kind = c.req.query('kind') as ScanKind | undefined
    if (kind) filters.push(kindCondition(kind))
    const network = c.req.query('network')
    if (network) filters.push(networkCondition(network))

    const where = and(...filters)
    const [rows, countRows] = await Promise.all([
      db
        .select({
          scanId: scanResults.scanId, agentId: scanResults.agentId, tenantId: scanResults.tenantId,
          scanType: scanResults.scanType, subnet: scanResults.subnet, status: scanResults.status,
          hostsDiscovered: scanResults.hostsDiscovered, networkInfo: scanResults.networkInfo,
          failureReason: scanResults.failureReason, startedAt: scanResults.startedAt, completedAt: scanResults.completedAt,
        })
        .from(scanResults)
        .where(where)
        .orderBy(desc(scanResults.startedAt))
        .limit(pageSize)
        .offset((page - 1) * pageSize),
      db.select({ n: sql<number>`count(*)::int` }).from(scanResults).where(where),
    ])

    const scans = rows.map((r) => {
      const net = networkOf(r)
      const info = (r.networkInfo ?? {}) as Record<string, unknown>
      return {
        ...r,
        kind: scanKind(r),
        network: net?.subnet ?? null,
        gateway: net?.gateway ?? null,
        // a new-device check: its alert
        event_id: typeof info['event_id'] === 'string' ? info['event_id'] : null,
      }
    })
    return c.json({ scans, total: countRows[0]?.n ?? 0, page, page_size: pageSize })
  } catch (err) {
    console.error('scans GET / error:', err)
    return c.json({ detail: 'Failed to fetch scans' }, 500)
  }
})

// SQL for lib/discoveryNetworks.ts scanKind (kept in step with it).
const CIDR_RE = '^[0-9]{1,3}(\\.[0-9]{1,3}){3}/[0-9]{1,2}$'
function kindCondition(kind: ScanKind): SQL {
  const investigation = sql`${scanResults.networkInfo}->>'trigger' = ${INVESTIGATE_TRIGGER}`
  const notInvestigation = sql`${scanResults.networkInfo}->>'trigger' IS DISTINCT FROM ${INVESTIGATE_TRIGGER}`
  const rangeTarget = sql`(${scanResults.subnet} ~ ${CIDR_RE} AND ${scanResults.subnet} NOT LIKE '%/32')`
  switch (kind) {
    case 'passive':       return eq(scanResults.scanType, 'passive')
    case 'investigation': return and(eq(scanResults.scanType, 'active'), investigation)!
    case 'network':       return and(eq(scanResults.scanType, 'active'), notInvestigation, rangeTarget)!
    default:              return and(eq(scanResults.scanType, 'active'), notInvestigation, sql`NOT ${rangeTarget}`)!
  }
}
// Records that belong to a network (lib/discoveryNetworks.ts networkOf).
function networkCondition(subnet: string): SQL {
  const lan = sql`${scanResults.networkInfo}->>'lan_subnet'`
  return or(
    and(eq(scanResults.scanType, 'passive'), sql`COALESCE(${lan}, ${scanResults.networkInfo}->>'subnet') = ${subnet}`),
    and(eq(scanResults.scanType, 'active'), kindCondition('network'), eq(scanResults.subnet, subnet)),
    and(eq(scanResults.scanType, 'active'), sql`NOT (${kindCondition('network')})`, sql`${lan} = ${subnet}`),
  )!
}

// ── GET /networks ─── one summary per network the agents have been on (Discovery page) ──
// From the last NETWORK_DAYS of Discovery records: the agents on it, when it was last
// heard passively, the last full scan of it, hosts seen in 24 h, open new-device alerts.
const NETWORK_DAYS = 30
app.get('/networks', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const tenantId = user.role === 'superadmin' ? (c.req.query('tenant_id') || undefined) : (user.tenantId ?? undefined)
    if (user.role !== 'superadmin' && !tenantId) return c.json({ networks: [], days: NETWORK_DAYS })
    const inTenant = tenantId ? eq(scanResults.tenantId, tenantId) : undefined
    const since = new Date(Date.now() - NETWORK_DAYS * 86400_000)
    const dayAgo = new Date(Date.now() - 86400_000)

    const [records, recentIps, newDevices] = await Promise.all([
      db
        .select({
          scanId: scanResults.scanId, agentId: scanResults.agentId, scanType: scanResults.scanType,
          subnet: scanResults.subnet, status: scanResults.status, hostsDiscovered: scanResults.hostsDiscovered,
          networkInfo: scanResults.networkInfo, startedAt: scanResults.startedAt, completedAt: scanResults.completedAt,
        })
        .from(scanResults)
        .where(and(notInArray(scanResults.scanType, ['sbom', 'inventory']), gte(scanResults.startedAt, since), inTenant))
        .orderBy(desc(scanResults.startedAt))
        .limit(5000),
      db.execute(sql`
        SELECT r.scan_id, array_agg(DISTINCT h->>'ip') AS ips
        FROM scan_results r, jsonb_array_elements(CASE WHEN jsonb_typeof(r.raw_results) = 'array' THEN r.raw_results ELSE '[]'::jsonb END) h
        WHERE r.scan_type NOT IN ('sbom', 'inventory') AND r.started_at >= ${dayAgo}
          AND ${tenantId ? sql`r.tenant_id = ${tenantId}` : sql`true`}
          AND h->>'ip' IS NOT NULL
        GROUP BY r.scan_id`),
      db
        .select({ ip: sql<string | null>`${events.details}->>'ip'` })
        .from(events)
        .innerJoin(assets, eq(assets.assetId, events.assetId))
        .where(and(
          eq(events.eventType, 'new_device'),
          inArray(events.status, ['open', 'in_progress']),
          tenantId ? eq(assets.tenantId, tenantId) : undefined,
        )),
    ])

    const ipsByScan = new Map<string, string[]>()
    for (const row of recentIps.rows as { scan_id: string; ips: string[] }[]) ipsByScan.set(row.scan_id, row.ips ?? [])
    const networks = buildNetworks(records, ipsByScan, newDevices.map((d) => d.ip).filter((ip): ip is string => !!ip))
    return c.json({ networks, days: NETWORK_DAYS })
  } catch (err) {
    console.error('scans GET /networks error:', err)
    return c.json({ detail: 'Failed to fetch networks' }, 500)
  }
})

// ── GET /:scanId/hosts ─── one record's hosts, each with the asset it became ──
app.get('/:scanId/hosts', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const scanId = c.req.param('scanId')
    if (!/^[0-9a-f-]{36}$/i.test(scanId)) return c.json({ detail: 'Scan not found' }, 404)
    const [scan] = await db.select().from(scanResults).where(eq(scanResults.scanId, scanId)).limit(1)
    if (!scan || (user.role !== 'superadmin' && scan.tenantId !== user.tenantId)) return c.json({ detail: 'Scan not found' }, 404)

    const hosts = Array.isArray(scan.rawResults) ? (scan.rawResults as Record<string, unknown>[]) : []
    const ips = [...new Set(hosts.map((h) => h['ip']).filter((ip): ip is string => typeof ip === 'string' && !!ip))]
    let candidates: HostAssetCandidate[] = []
    if (ips.length > 0) {
      const tenantCond = scan.tenantId ? eq(assets.tenantId, scan.tenantId) : isNull(assets.tenantId)
      const rows = await db
        .select({
          assetId: assets.assetId, hostname: assets.hostname, inMyAssets: assets.inMyAssets,
          assetIp: assets.ipAddress, assetMac: assets.macAddress,
          addrIp: assetAddresses.ipAddress, addrMac: assetAddresses.macAddress, endedAt: assetAddresses.endedAt,
        })
        .from(assets)
        .leftJoin(assetAddresses, eq(assetAddresses.assetId, assets.assetId))
        .where(and(tenantCond, or(inArray(assets.ipAddress, ips), inArray(assetAddresses.ipAddress, ips))))
      const byId = new Map<string, HostAssetCandidate>()
      for (const r of rows) {
        let cand = byId.get(r.assetId)
        if (!cand) {
          cand = { assetId: r.assetId, hostname: r.hostname, inMyAssets: r.inMyAssets, ips: [r.assetIp], currentIps: [r.assetIp], macs: [r.assetMac] }
          byId.set(r.assetId, cand)
        }
        if (r.addrIp) {
          cand.ips.push(r.addrIp)
          if (!r.endedAt) cand.currentIps.push(r.addrIp)
        }
        if (r.addrMac) cand.macs.push(r.addrMac)
      }
      candidates = [...byId.values()]
    }
    const resolved = resolveHostAssets(hosts, candidates)
    const net = networkOf(scan)
    return c.json({
      scan: {
        scan_id: scan.scanId, agent_id: scan.agentId, tenant_id: scan.tenantId, scan_type: scan.scanType,
        kind: scanKind(scan), subnet: scan.subnet, network: net?.subnet ?? null, gateway: net?.gateway ?? null,
        status: scan.status, started_at: scan.startedAt, completed_at: scan.completedAt,
      },
      hosts: hosts.map((h, i) => ({
        ...h,
        asset: resolved[i]
          ? { asset_id: resolved[i]!.assetId, hostname: resolved[i]!.hostname, in_my_assets: resolved[i]!.inMyAssets }
          : null,
      })),
    })
  } catch (err) {
    console.error('scans GET /:scanId/hosts error:', err)
    return c.json({ detail: 'Failed to fetch hosts' }, 500)
  }
})

// ── GET /compare ─── cross-reference active vs passive results ───
// Finds IPs that appear in both scan types and diffs captured data.
app.get('/compare', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)

    const tenantCond = (user.role !== 'superadmin' && user.tenantId)
      ? and(eq(scanResults.status, 'completed'), notInArray(scanResults.scanType, ['sbom', 'inventory']), eq(scanResults.tenantId, user.tenantId))
      : and(eq(scanResults.status, 'completed'), notInArray(scanResults.scanType, ['sbom', 'inventory']))

    const scans = await db
      .select()
      .from(scanResults)
      .where(tenantCond)
      .orderBy(desc(scanResults.startedAt))
      .limit(500)

    // Collect most-recent data per IP per scan type (first occurrence = most recent)
    type HostEntry = { host: Record<string, unknown>; scanId: string; scannedAt: Date; subnet: string | null }
    const activeByIp = new Map<string, HostEntry>()
    const passiveByIp = new Map<string, HostEntry>()

    for (const scan of scans) {
      const hosts = Array.isArray(scan.rawResults) ? scan.rawResults : []
      const map = scan.scanType === 'passive' ? passiveByIp : activeByIp
      for (const h of hosts) {
        const host = h as Record<string, unknown>
        const ip = host['ip'] as string
        if (ip && !map.has(ip)) {
          map.set(ip, { host, scanId: scan.scanId, scannedAt: scan.startedAt, subnet: scan.subnet })
        }
      }
    }

    // Build overlap: IPs found by both
    const overlap = []
    for (const [ip, activeEntry] of activeByIp) {
      const passiveEntry = passiveByIp.get(ip)
      if (!passiveEntry) continue

      const ah = activeEntry.host
      const ph = passiveEntry.host
      const ports = Array.isArray(ah['ports']) ? ah['ports'] as Record<string, unknown>[] : []
      const ahOs  = ah['os'] as Record<string, unknown> | null | undefined
      const hasOs = !!(ahOs && Object.keys(ahOs).length > 0)

      const ahHostname = (ah['hostname'] as string | null) ?? null
      const phHostname = (ph['hostname'] as string | null) ?? null
      const ahMac = normalizeMac(ah['mac'])
      const phMac = normalizeMac(ph['mac'])

      const activeRichness = [ahHostname, ah['mac'], hasOs || null, ports.length > 0 || null].filter(Boolean).length
      const passiveRichness = [phHostname, ph['mac']].filter(Boolean).length

      overlap.push({
        ip,
        active: {
          scan_id:    activeEntry.scanId,
          subnet:     activeEntry.subnet,
          scanned_at: activeEntry.scannedAt,
          hostname:   ahHostname,
          mac:        ah['mac'] ?? null,
          ports:      ports.map(p => ({ port: p['port'], protocol: p['protocol'] ?? 'tcp', service: p['service'] ?? null })),
          os:         ahOs ?? null,
          description: ah['description'] ?? null,
          suggestion:  ah['suggestion']  ?? null,
        },
        passive: {
          scan_id:    passiveEntry.scanId,
          subnet:     passiveEntry.subnet,
          scanned_at: passiveEntry.scannedAt,
          hostname:   phHostname,
          mac:        ph['mac'] ?? null,
          description: ph['description'] ?? null,
          suggestion:  ph['suggestion']  ?? null,
        },
        delta: {
          ports_found:    ports.length,
          has_os:         hasOs,
          hostname_match: ahHostname !== null && ahHostname === phHostname,
          mac_match:      !!(ahMac && phMac && ahMac === phMac),
          active_richness:  activeRichness,
          passive_richness: passiveRichness,
          extra_fields_from_active: ports.length + (hasOs ? 1 : 0),
        },
      })
    }

    overlap.sort((a, b) => {
      const toNum = (ip: string) => ip.split('.').reduce((acc, o) => acc * 256 + parseInt(o, 10), 0)
      return toNum(a.ip) - toNum(b.ip)
    })

    const activeOnlyCount  = [...activeByIp.keys()].filter(ip => !passiveByIp.has(ip)).length
    const passiveOnlyCount = [...passiveByIp.keys()].filter(ip => !activeByIp.has(ip)).length

    return c.json({
      overlap,
      total_overlap:       overlap.length,
      total_active_ips:    activeByIp.size,
      total_passive_ips:   passiveByIp.size,
      active_only_count:   activeOnlyCount,
      passive_only_count:  passiveOnlyCount,
    })
  } catch (err) {
    console.error('scans GET /compare error:', err)
    return c.json({ detail: 'Failed to compare scans' }, 500)
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

    // Auto-expire passive scans pending > 10 min
    await db.update(scanResults)
      .set({
        status: 'failed',
        completedAt: new Date(),
        failureReason: 'Passive scan was not picked up by the agent within 10 minutes',
      })
      .where(and(
        eq(scanResults.agentId, agentId),
        eq(scanResults.status, 'pending'),
        eq(scanResults.scanType, 'passive'),
        sql`${scanResults.startedAt} < now() - interval '10 minutes'`,
      ))

    // Auto-expire SBOM scans the agent never picked up (pending > 90 min) or never finished
    // (running > 3 h). A full run (agent 2.2.6) may list for 90 minutes of awake time, Grype
    // takes up to 20 (its first run downloads its database), the upload retries for a few
    // minutes, and a laptop asleep in between adds to the clock time. If the agent died
    // without calling /fail, clean up here. A late SBOM still completes the record.
    await db.update(scanResults)
      .set({
        status: 'failed',
        completedAt: new Date(),
        failureReason: sql`CASE WHEN ${scanResults.status} = 'pending'
          THEN 'The agent did not pick up this SBOM job within 90 minutes (it was offline or closed)'
          ELSE 'SBOM scan did not finish within 3 hours (the agent was closed or stuck)' END`,
      })
      .where(and(
        eq(scanResults.agentId, agentId),
        eq(scanResults.scanType, 'sbom'),
        sql`((${scanResults.status} = 'pending' AND ${scanResults.startedAt} < now() - interval '90 minutes')
          OR (${scanResults.status} = 'running' AND ${scanResults.startedAt} < now() - interval '3 hours'))`,
      ))

    // Inventory jobs: a few seconds of work, so give up sooner than SBOM jobs.
    await db.update(scanResults)
      .set({
        status: 'failed',
        completedAt: new Date(),
        failureReason: sql`CASE WHEN ${scanResults.status} = 'pending'
          THEN 'The agent did not pick up this inventory job within 30 minutes (it was offline, closed or older than 2.3.0)'
          ELSE 'The inventory did not arrive within 15 minutes' END`,
      })
      .where(and(
        eq(scanResults.agentId, agentId),
        eq(scanResults.scanType, 'inventory'),
        sql`((${scanResults.status} = 'pending' AND ${scanResults.startedAt} < now() - interval '30 minutes')
          OR (${scanResults.status} = 'running' AND ${scanResults.startedAt} < now() - interval '15 minutes'))`,
      ))

    await expireStaleActiveScans(db, eq(scanResults.agentId, agentId))

    const pending = await db
      .select()
      .from(scanResults)
      .where(and(
        eq(scanResults.agentId, agentId),
        eq(scanResults.status, 'pending'),
        // A new-device investigation waits a few minutes before it is handed out
        sql`(${scanResults.networkInfo}->>'not_before' IS NULL
          OR (${scanResults.networkInfo}->>'not_before')::timestamptz <= now())`,
        // Skip SBOM and inventory jobs whose asset (stored in subnet) no longer exists
        sql`(${scanResults.scanType} NOT IN ('sbom', 'inventory') OR EXISTS (
          SELECT 1 FROM assets WHERE asset_id::text = ${scanResults.subnet}
        ))`,
      ))
      .limit(5)

    return c.json({ scans: pending })
  } catch (err) {
    console.error('scans GET /pending error:', err)
    return c.json({ detail: 'Failed to fetch pending scans' }, 500)
  }
})

// (Retired with the 1.x agent: GET /agent-status/:scanId. Active scans cannot be
// cancelled from the dashboard, so the agent does not poll for it; SBOM scans can,
// through GET /sboms/agent-status/:scanId.)

// ── POST /:scanId/cancel ── tenant admin cancels pending/running SBOM scan ──
app.post('/:scanId/cancel', authMiddleware,
  requireRoles('tenant_superadmin', 'tenant_admin'), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { scanId } = c.req.param()

    const [scan] = await db
      .select({
        scanId: scanResults.scanId,
        tenantId: scanResults.tenantId,
        scanType: scanResults.scanType,
        status: scanResults.status,
      })
      .from(scanResults)
      .where(eq(scanResults.scanId, scanId))
      .limit(1)

    if (!scan || !user.tenantId || scan.tenantId !== user.tenantId || scan.scanType !== 'sbom') {
      return c.json({ detail: 'SBOM scan not found' }, 404)
    }
    if (!['pending', 'running'].includes(scan.status)) {
      return c.json({ detail: `Cannot cancel a scan with status ${scan.status}` }, 409)
    }

    await db.update(scanResults)
      .set({ status: 'cancelled', completedAt: new Date(), failureReason: 'Cancelled by user' })
      .where(and(
        eq(scanResults.scanId, scanId),
        inArray(scanResults.status, ['pending', 'running']),
      ))

    return c.json({ scan_id: scanId, status: 'cancelled' })
  } catch (err) {
    console.error('scan cancel error:', err)
    return c.json({ detail: 'Failed to cancel scan' }, 500)
  }
})

// ── POST /active ─────────────────────────────────────────────────
// Subnet validation helpers (mirrors frontend logic)
function isValidIpv4(ip: string): boolean {
  return /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/.test(ip)
}

function isValidSubnet(value: string): boolean {
  const trimmed = value.trim()
  if (!trimmed) return false
  const [ip, prefix] = trimmed.split('/')
  if (!ip || !isValidIpv4(ip)) return false
  if (prefix !== undefined) {
    const num = Number(prefix)
    if (!Number.isInteger(num) || num < 0 || num > 32) return false
  }
  return true
}

const activeScanSchema = z.object({
  subnet: z
    .string()
    .optional()
    .refine((v) => v === undefined || v === 'arp-discovery' || isValidSubnet(v), {
      message: 'Invalid subnet — must be a valid IPv4 address or CIDR range (e.g. 192.168.1.0/24)',
    }),
  agent_id: z.string().uuid().optional(),
  tenant_id: z.string().uuid().nullable().optional(),
  scan_type: z.enum(['active', 'passive']).optional().default('active'),
})

app.post('/active', authMiddleware, requireRoles('tenant_superadmin', 'tenant_admin'), zValidator('json', activeScanSchema, (result, c) => {
  if (!result.success) {
    const firstIssue = result.error.issues[0]
    const detail = firstIssue?.message ?? 'Invalid request body'
    return c.json({ detail }, 400)
  }
}), async (c) => {
  try {
    const user = c.get('user')
    const db = getDb(c.env.DATABASE_URL)
    const { subnet, agent_id, tenant_id, scan_type } = c.req.valid('json')

    const effectiveScanType = scan_type ?? 'active'
    const effectiveSubnet = effectiveScanType === 'passive' ? 'arp-discovery' : (subnet ?? c.env.SCAN_DEFAULT_SUBNET ?? '192.168.1.0/24')

    // Derive tenant: explicit body > agent's tenant > user's tenant
    let effectiveTenantId = tenant_id !== undefined ? tenant_id : (user.tenantId ?? null)
    if (!effectiveTenantId && agent_id) {
      const [agent] = await db.select().from(agents).where(eq(agents.agentId, agent_id)).limit(1)
      if (agent?.tenantId) effectiveTenantId = agent.tenantId
    }

    // The same scan already waiting for this agent: return it instead of queueing a
    // second one (several clicks on New scan would otherwise scan the subnet several times).
    if (effectiveScanType === 'active' && agent_id) {
      const [waiting] = await db.select({ scanId: scanResults.scanId, status: scanResults.status })
        .from(scanResults)
        .where(and(
          eq(scanResults.agentId, agent_id),
          eq(scanResults.scanType, 'active'),
          eq(scanResults.subnet, effectiveSubnet),
          eq(scanResults.status, 'pending'),
          sql`${scanResults.networkInfo}->>'trigger' IS DISTINCT FROM ${INVESTIGATE_TRIGGER}`,
        ))
        .limit(1)
      if (waiting) {
        return c.json({ scan_id: waiting.scanId, status: waiting.status, scan_type: 'active',
          message: 'This scan is already queued for that agent' }, 202)
      }
    }

    // Passive scans are ARP-driven on the agent side — they run continuously
    // via the --passive flag. Triggering one from the UI just creates a record
    // so the dashboard shows it; no nmap dispatch is needed.
    const scanRows = await db
      .insert(scanResults)
      .values({
        agentId: agent_id ?? null,
        tenantId: effectiveTenantId,
        scanType: effectiveScanType,
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

    const message = effectiveScanType === 'passive'
      ? 'Passive scan registered — agent will flush ARP discoveries to this record'
      : 'Scan dispatched to agent'

    return c.json({ scan_id: scan.scanId, status: scan.status, scan_type: effectiveScanType, message }, 202)
  } catch (err) {
    console.error('scans POST /active error:', err)
    return c.json({ detail: 'Failed to initiate scan' }, 500)
  }
})

// Marks an agent's active scans that are still 'running' as failed. Called when
// the agent says it is not running anything (it just started, or it is idle and
// starting a new scan), so those records can only be left over from a run that
// was cut short. Results that still arrive later complete the record as usual.
async function failInterruptedScans(db: ReturnType<typeof getDb>, agentId: string): Promise<number> {
  const rows = await db.update(scanResults)
    .set({
      status: 'failed',
      completedAt: new Date(),
      failureReason: 'Interrupted: the agent was closed or restarted before the scan finished',
    })
    .where(and(
      eq(scanResults.agentId, agentId),
      eq(scanResults.scanType, 'active'),
      eq(scanResults.status, 'running'),
    ))
    .returning({ scanId: scanResults.scanId, networkInfo: scanResults.networkInfo, failureReason: scanResults.failureReason })
  for (const r of rows) {
    if (isInvestigation(r.networkInfo)) await recordInvestigationFailure(db, r.networkInfo, r.scanId, r.failureReason ?? 'interrupted')
  }
  return rows.length
}

async function authenticateAgent(c: { req: { header(name: string): string | undefined } }, db: ReturnType<typeof getDb>) {
  const authHeader = c.req.header('Authorization')
  const agentId = c.req.header('X-Agent-ID')
  if (!authHeader?.startsWith('Bearer ') || !agentId) return null
  const incomingKeyHash = await sha256Hex(authHeader.slice(7))
  const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
  return agent && incomingKeyHash === agent.apiKeyHash ? agent : null
}

// ── POST /agent-reset ── the agent (re)started and is running nothing ────────
app.post('/agent-reset', async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const agent = await authenticateAgent(c, db)
    if (!agent) return c.json({ detail: 'Invalid credentials' }, 401)
    const interrupted = await failInterruptedScans(db, agent.agentId)
    return c.json({ interrupted })
  } catch (err) {
    console.error('scans POST /agent-reset error:', err)
    return c.json({ detail: 'Failed to reset scans' }, 500)
  }
})

// ── POST /:scanId/start ── the agent began a scan from the dashboard ─────────
// pending → running, so the dashboard shows the real state (and an agent restart
// marks it interrupted like a local scan). Only the agent's own pending scans.
app.post('/:scanId/start', async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const agent = await authenticateAgent(c, db)
    if (!agent) return c.json({ detail: 'Invalid credentials' }, 401)
    await db.update(scanResults)
      .set({ status: 'running' })
      .where(and(
        eq(scanResults.scanId, c.req.param('scanId')),
        eq(scanResults.agentId, agent.agentId),
        eq(scanResults.status, 'pending'),
      ))
    return c.json({ ok: true })
  } catch (err) {
    console.error('scans POST /:scanId/start error:', err)
    return c.json({ detail: 'Failed to update scan status' }, 500)
  }
})

// ── POST /agent-start ── the agent starts an active scan itself ──────────────
// Used by the agent app's local schedules and its "Scan now" button. Creates the
// scan record already 'running' (the agent starts at once), in the agent's tenant,
// so the results ingest exactly like a dashboard-triggered scan.
const agentStartSchema = z.object({
  subnet: z.string().refine(
    (v) => isValidSubnet(v) && Number(v.trim().split('/')[1] ?? 32) >= 16,
    { message: 'subnet must be an IPv4 address or a CIDR range no larger than /16' },
  ),
  trigger: z.enum(['schedule', 'manual']),
})

app.post('/agent-start', zValidator('json', agentStartSchema, (result, c) => {
  if (!result.success) return c.json({ detail: result.error.issues[0]?.message ?? 'Invalid request body' }, 400)
}), async (c) => {
  try {
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) return c.json({ detail: 'Unauthorized' }, 401)
    const agentId = c.req.header('X-Agent-ID')
    if (!agentId) return c.json({ detail: 'X-Agent-ID required' }, 400)

    const db = getDb(c.env.DATABASE_URL)
    const incomingKeyHash = await sha256Hex(authHeader.slice(7))
    const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!agent || incomingKeyHash !== agent.apiKeyHash) return c.json({ detail: 'Invalid credentials' }, 401)

    const { subnet, trigger } = c.req.valid('json')

    // The tenant may keep active scanning to the dashboard (Tenant settings → Scan policy).
    if (agent.tenantId) {
      const [tenant] = await db.select({ allowLocalScans: tenants.allowLocalScans }).from(tenants)
        .where(eq(tenants.tenantId, agent.tenantId)).limit(1)
      if (tenant && !tenant.allowLocalScans) {
        return c.json({ detail: 'Your administrator has turned off scans started on this computer. '
          + 'Active scans are started from the EagleEye dashboard.' }, 403)
      }
    }

    // The agent runs one active scan at a time and only asks when it is idle, so
    // any of its scans still 'running' here was interrupted (app closed or crashed).
    await failInterruptedScans(db, agentId)

    const [scan] = await db
      .insert(scanResults)
      .values({
        agentId,
        tenantId: agent.tenantId ?? null,
        scanType: 'active',
        subnet: subnet.trim(),
        status: 'running',
        hostsDiscovered: 0,
        rawResults: [],
      })
      .returning({ scanId: scanResults.scanId })
    if (!scan) return c.json({ detail: 'Failed to create scan record' }, 500)

    console.log(`agent ${agentId} started scan ${scan.scanId} of ${subnet} (${trigger})`)
    return c.json({ scan_id: scan.scanId, status: 'running' }, 201)
  } catch (err) {
    console.error('scans POST /agent-start error:', err)
    return c.json({ detail: 'Failed to start scan' }, 500)
  }
})

// ── POST /ingest ─────────────────────────────────────────────────
const hostSchema = z.object({
  ip: z.string().min(1).max(45),
  hostname: z.string().max(255).nullish(),
  mac: z.string().max(17).nullish(),
  // Agent 2.2.2+: vendor looked up offline; null when its list has none (a private MAC,
  // or a prefix it lacks: those real MACs, and older agents' hosts, are looked up online).
  mac_vendor: z.string().max(255).nullish(),
  ports: z.array(z.unknown()).optional(),
  os: z.record(z.unknown()).nullish(),
  snmp_sysdescr: z.string().nullish(),
  snmp_sysobjectid: z.string().nullish(),
  snmp_interfaces: z.array(z.string()).optional(),
})

const ingestSchema = z.object({
  agent_id: z.string().uuid(),
  scan_id: z.string().uuid().optional(),   // optional for passive auto-ingest
  scan_type: z.enum(['active', 'passive']).optional().default('active'),
  hosts: z.array(hostSchema),
  // Optional network metadata, stored on the scan record for reference. NOT used
  // for identity — the network key is derived from each host IP's /24.
  network: z.object({
    subnet: z.string().max(64).nullish(),
    // Agent 2.2.4+: the subnet of the LAN the agent listens on (for an active scan,
    // `subnet` is the scanned range instead). Keys identity (lib/networkScope.ts).
    lan_subnet: z.string().max(64).nullish(),
    gateway_ip: z.string().max(45).nullish(),
    gateway_mac: z.string().max(17).nullish(),
  }).nullish(),
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

    const { agent_id, scan_id, scan_type, hosts, network } = c.req.valid('json')
    const isPassive = scan_type === 'passive'

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

    // ── Batch identity prefetch (3 queries total, constant per ingest) ──
    // Collect the batch's MACs / IPs / host_keys, then fetch all candidate
    // addresses+assets at once. Replaces the old ~3 queries-per-host resolver.
    const batchMacs = [...new Set(hosts.map(h => classifyMac(h.mac).mac).filter((m): m is string => !!m))]
    const batchIps = [...new Set(hosts.map(h => h.ip))]
    const batchHostKeys = [...new Set(hosts.map(h => sanitizeHostKey((h.os as Record<string, unknown> | null)?.['smb_computer_name'])).filter((k): k is string => !!k))]
    const criticalityModel = ACTIVE_MODEL
    // Which network each address is on: the LAN subnet the agent reports (2.2.4+; a
    // passive upload's `subnet` from 2.2.2), widening the tenant's old /24 keys inside
    // it first, so the matching below sees one network (lib/networkScope.ts).
    const scope = await resolveNetworkScope(db, tenantId ?? null, network?.lan_subnet ?? (isPassive ? network?.subnet : null))
    const prefetch = await prefetchIdentity(db, tenantId ?? null, batchMacs, batchIps, batchHostKeys)

    // LLM context (existing device_type/hostname/owner per IP) — built from the
    // prefetch, no extra queries. Authoritative identity match happens via planIngest.
    const assetByIdForCtx = new Map(prefetch.assets.map(a => [a.assetId, a]))
    const existingAssetMap: Map<string, { deviceType: string; hostname: string | null; owner: string | null; hardwareVendor: string | null }> = new Map()
    for (const addr of prefetch.addresses) {
      if (existingAssetMap.has(addr.ipAddress)) continue
      const a = assetByIdForCtx.get(addr.assetId)
      if (a) existingAssetMap.set(addr.ipAddress, { deviceType: a.deviceType, hostname: a.hostname, owner: a.owner, hardwareVendor: a.hardwareVendor })
    }

    // ── Hardware vendor: the agent's offline lookup; online (cached) for real MACs
    // it could not name and for older agents, never for private MACs (lib/hostEvidence.ts). ──
    const macVendorMap = await resolveVendors(hosts, fetchMacVendor, c.env.KV_CACHE)

    // Gateway for internet-exposure inference and for the LLM: the agent's current
    // default gateway from this ingest, else the last one it reported on heartbeat.
    // Anything that isn't a real IPv4 ("On-link", blank) is ignored so it can't
    // switch off the fallback inference.
    const reportedGateways = [
      network?.gateway_ip,
      ((agent.config ?? {}) as Record<string, unknown>).default_gateway as string | undefined,
    ]
    const defaultGateway = reportedGateways.find(isIPv4)

    // ── LLM Asset Suggestion (DeepSeek via OpenRouter) ──
    // Only hosts whose evidence changed since their stored description are sent: a
    // passive round re-uploads every device it heard, mostly unchanged.
    const assetOsByMac = new Map<string, Record<string, unknown> | null>()
    for (const a of prefetch.assets) {
      const m = normalizeMac(a.macAddress)
      if (m && !assetOsByMac.has(m)) assetOsByMac.set(m, a.osInfo)
    }
    const assetOsByIp = new Map<string, Record<string, unknown> | null>()
    for (const addr of prefetch.addresses) {
      const a = assetByIdForCtx.get(addr.assetId)
      if (a && !assetOsByIp.has(addr.ipAddress)) assetOsByIp.set(addr.ipAddress, a.osInfo)
    }
    const evidenceByIp = new Map<string, string>()
    const reused = new Map<string, { description: string; suggestion: string | null }>()
    for (const h of hosts) {
      const key = aiEvidenceKey({
        hostname: h.hostname, mac: h.mac, vendor: macVendorMap.get(h.ip) ?? null,
        ports: h.ports ?? null, os: (h.os ?? null) as Record<string, unknown> | null,
        isGateway: h.ip === defaultGateway,
      })
      evidenceByIp.set(h.ip, key)
      const mac = normalizeMac(h.mac)
      const priorOs = (mac && assetOsByMac.get(mac)) || assetOsByIp.get(h.ip)
      const prior = reusableDescription(priorOs, key)
      if (prior) reused.set(h.ip, prior)
    }
    const needLlm = hosts.filter(h => !reused.has(h.ip))

    let enhancedHosts = hosts.map(h => {
      const prior = reused.get(h.ip)
      return prior
        ? { ...h, description: prior.description, ...(prior.suggestion ? { suggestion: prior.suggestion } : {}), aiDescribed: true }
        : { ...h }
    })
    if (hosts.length > 0 && c.env.OPENROUTER_API_KEY) {
      try {
        // Build enriched payload: real vendor name + existing DB context
        const payload = needLlm.map(h => {
          const existing = existingAssetMap.get(h.ip)
          return {
            ip: h.ip,
            mac: h.mac,
            mac_vendor: macVendorMap.get(h.ip) ?? null,  // e.g. "TP-Link Technologies Co. Ltd."
            is_gateway: h.ip === defaultGateway,           // this network's router, as the agent reports it
            os: h.os,
            ports: h.ports,
            existing_device_type: existing?.deviceType ?? null,
            existing_hostname: existing?.hostname ?? null,
            existing_owner: existing?.owner ?? null,
          }
        })

        const systemPrompt = `You are a CAASM security analyst. Analyze these discovered network hosts.
You MUST return a JSON object with a single root key "hosts" containing an array of objects. Each object MUST have exactly these keys:
"ip": the host's IP address
"description": A concise, specific description of the device (e.g., "TP-Link Router", "Windows 10 Workstation", "Raspberry Pi IoT Device", "Ubuntu Server"). Use brand names when available. Be specific.
"suggestion": One of exactly: "Accept - Corporate Device", "Ignore - Personal Device", or "Investigate - Unknown"

Rules for consistent, accurate output:
- If existing_hostname or existing_device_type is present for an IP, PRESERVE the prior classification unless new scan data clearly contradicts it.
- If "os.fingerbank_device" is present, use it as the definitive device name (highest confidence).
- If "os.dhcp_device_hint" is present (e.g., "Windows", "Android"), use it as the primary device-type signal.
- If "os.dhcp_vendor_class" starts with "MSFT" → Windows device; "android-dhcp" → Android phone; "dhcpcd" → Linux device.
- If "os.name" is present (from nmap smb-os-discovery), use it for the exact Windows/Linux version.
- If "mac_vendor" is present and no other signals exist, use it to identify the manufacturer.
- If "hostname" contains words like "router", "switch", "ap", "printer", "cam" → strong device-type signal.
- If "existing_device_type" is "network", lean toward "Accept - Corporate Device".
- If "is_gateway" is true, the host is this network's router/gateway: network infrastructure — use "Accept - Corporate Device".
- Do NOT infer a router or gateway from the address alone: on many networks addresses ending in .1 or .254 are ordinary PCs and phones. A hostname like "DESKTOP-..." or "LAPTOP-..." is a Windows workstation.
- Only use "Investigate - Unknown" when there is genuinely NO identifying information (no vendor, no ports, no DHCP, no hostname, no existing record).

Example:
{ "hosts": [ { "ip": "192.168.0.1", "description": "TP-Link Home Router", "suggestion": "Accept - Corporate Device" } ] }`

        if (payload.length === 0) throw new SkipLlm()
        const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${c.env.OPENROUTER_API_KEY}`,
          },
          body: JSON.stringify({
            model: c.env.OPENROUTER_MODEL ?? 'deepseek/deepseek-chat',
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: JSON.stringify(payload) }
            ],
            response_format: { type: 'json_object' }
          })
        })

        console.log(`[scans] LLM call → ${c.env.OPENROUTER_MODEL ?? 'deepseek/deepseek-chat'}, status=${res.status}, hosts=${payload.length} (${reused.size} unchanged, not sent)`)
        if (res.ok) {
          const data = await res.json() as any
          let content = data.choices?.[0]?.message?.content || '[]'

          // Robust JSON extraction: find first [ or { and last ] or }
          const firstBrace = content.indexOf('{')
          const firstBracket = content.indexOf('[')
          const lastBrace = content.lastIndexOf('}')
          const lastBracket = content.lastIndexOf(']')

          let startIdx = -1
          let endIdx = -1

          if (firstBracket !== -1 && (firstBrace === -1 || firstBracket < firstBrace)) {
            startIdx = firstBracket
            endIdx = lastBracket
          } else if (firstBrace !== -1) {
            startIdx = firstBrace
            endIdx = lastBrace
          }

          if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
            content = content.substring(startIdx, endIdx + 1)
          }

          try {
            const parsed = JSON.parse(content)
            type LlmHost = { ip: string; description: string; suggestion: string }
            const answers: LlmHost[] | null = Array.isArray(parsed) && parsed.length > 0 && !Array.isArray(parsed[0])
              ? parsed as LlmHost[]
              : (parsed && Array.isArray(parsed.hosts) ? parsed.hosts as LlmHost[] : null)
            if (answers) {
              enhancedHosts = enhancedHosts.map(h => {
                if (reused.has(h.ip)) return h
                const match = answers.find((p) => p.ip?.trim() === h.ip?.trim())
                return match ? { ...h, description: match.description, suggestion: match.suggestion, aiDescribed: true } : h
              })
            }
          } catch (parseErr) {
            console.error('Failed to parse LLM JSON:', parseErr, 'Raw content:', content)
          }
        } else {
          console.error('OpenRouter API returned error:', res.status)
        }
      } catch (err) {
        if (!(err instanceof SkipLlm)) console.error('LLM asset suggestion failed:', err)
      }

      // Fallback: if LLM produced no description/suggestion, use a deterministic fallback
      enhancedHosts = enhancedHosts.map(h => {
        const hAny = h as Record<string, unknown>
        if (!hAny['description']) {
          const existing = existingAssetMap.get(h.ip)
          const vendor = macVendorMap.get(h.ip)
          hAny['description'] = existing?.hostname
            ? `${vendor ?? 'Unknown'} Device (${existing.hostname})`
            : (vendor ? `${vendor} Device` : 'AI analysis could not be generated for this asset.')
        }
        if (!hAny['suggestion']) {
          const existing = existingAssetMap.get(h.ip)
          const isGateway = h.ip === defaultGateway
          hAny['suggestion'] = isGateway ? 'Accept - Corporate Device'
            : (existing ? 'Accept - Corporate Device' : 'Investigate - Unknown')
        }
        return h
      })
    }

    // Resolve scan record: use provided scan_id, or auto-create one for passive
    let effectiveScanId: string
    // What the Discovery record holds: this upload, or for a folded passive record the
    // hosts heard over the last hour (asset upserts below still use only this upload).
    let recordHosts: unknown[] = enhancedHosts
    let investigation: InvestigationInfo | null = null
    let investigatedIp: string | null = null
    if (scan_id) {
      const [scan] = await db.select().from(scanResults).where(eq(scanResults.scanId, scan_id)).limit(1)
      if (!scan) return c.json({ detail: 'Scan not found' }, 404)
      effectiveScanId = scan_id
      if (isInvestigation(scan.networkInfo)) { investigation = scan.networkInfo; investigatedIp = scan.subnet }
    } else if (isPassive) {
      // Fold into this agent's passive record of the last hour, so the Discovery log
      // gets one record per agent per hour instead of one per upload (about a minute).
      const [open] = await db
        .select({ scanId: scanResults.scanId, rawResults: scanResults.rawResults })
        .from(scanResults)
        .where(and(
          eq(scanResults.agentId, agent_id),
          eq(scanResults.scanType, 'passive'),
          eq(scanResults.subnet, 'arp-discovery'),
          eq(scanResults.status, 'completed'),
          sql`${scanResults.startedAt} > now() - make_interval(mins => ${PASSIVE_FOLD_MINUTES})`,
          // a laptop that moved to another network starts a new record (one network per record)
          sql`COALESCE(${scanResults.networkInfo}->>'lan_subnet', ${scanResults.networkInfo}->>'subnet') IS NOT DISTINCT FROM ${passiveNetworkOf(network)}`,
        ))
        .orderBy(desc(scanResults.startedAt))
        .limit(1)
      if (open) {
        effectiveScanId = open.scanId
        recordHosts = mergePassiveHosts(open.rawResults, enhancedHosts as Record<string, unknown>[])
      } else {
        // Auto-create a passive scan record so results appear in the dashboard
        const [newScan] = await db
          .insert(scanResults)
          .values({
            agentId: agent_id,
            tenantId: tenantId ?? null,
            scanType: 'passive',
            subnet: 'arp-discovery',
            status: 'completed',
            hostsDiscovered: enhancedHosts.length,
            rawResults: enhancedHosts,
            networkInfo: network ?? null,
            completedAt: new Date(),
          })
          .returning()
        if (!newScan) return c.json({ detail: 'Failed to create passive scan record' }, 500)
        effectiveScanId = newScan.scanId
      }
    } else {
      return c.json({ detail: 'scan_id is required for active scans' }, 400)
    }

    // Upsert assets via the identity resolver (device/address split). Identity is
    // no longer IP-keyed; the network key is the host IP's /24, derived inside the
    // resolver (stable across active/passive, independent of gateway presence).
    // The network.{subnet,gateway_ip,gateway_mac} block is persisted on the scan
    // record below for reference, but is not used for the key.
    const upsertedAssetIds: string[] = []
    let failedHosts = 0

    // Precompute each host's device type + observed os_info (same logic as before),
    // producing the PlanHost inputs the pure batch planner consumes.
    const prepareHost = (host: typeof enhancedHosts[number]): PlanHost => {
      const ports = (host.ports ?? []) as NmapPort[]
      let deviceType = inferDeviceType(ports, host.ip, host.os as Record<string, unknown> | null, defaultGateway)
      if (deviceType === 'unknown' && isNetworkBySnmp(host.snmp_sysdescr, host.snmp_interfaces)) {
        deviceType = 'network'   // SNMP is a strong, direct signal (before LLM fallback)
      }
      // The LLM's description no longer sets the type (Phase C): it is kept as
      // os_info.ai_description and becomes a low-confidence "ai_guess" suggestion in
      // lib/deviceHints.ts, confirmed by an analyst like the other weak hints. Only real
      // LLM answers are kept, not the deterministic fallback text.
      const observedOsInfo = buildOsInfo(host.os as Record<string, unknown> | null, ports, isPassive)
      const hostAny = host as Record<string, unknown>
      if (hostAny['aiDescribed'] && typeof hostAny['description'] === 'string' && hostAny['description'].trim()) {
        observedOsInfo.ai_description = String(hostAny['description']).trim().slice(0, 200)
        // What it was described from, so an unchanged host skips the LLM next time.
        const evidence = evidenceByIp.get(host.ip)
        if (evidence) observedOsInfo.ai_evidence = evidence
        if (typeof hostAny['suggestion'] === 'string' && hostAny['suggestion']) {
          observedOsInfo.ai_suggestion = String(hostAny['suggestion']).slice(0, 60)
        }
      }
      if (host.snmp_sysdescr) observedOsInfo.snmp_sysdescr = host.snmp_sysdescr
      if (host.snmp_sysobjectid) observedOsInfo.snmp_sysobjectid = host.snmp_sysobjectid
      if (host.snmp_interfaces) observedOsInfo.snmp_interfaces = host.snmp_interfaces
      return {
        ip: host.ip,
        rawMac: host.mac,
        hostname: host.hostname ?? null,
        hostKeyRaw: (host.os as Record<string, unknown> | null)?.['smb_computer_name'],
        deviceType,
        observedOsInfo,
        ports: ports.map(p => p.port),
        hardwareVendor: macVendorMap.get(host.ip) ?? null,
        internetFacing: resolveInternetFacing(host.ip, defaultGateway, null),
        isPassive,
        tenantId: tenantId ?? null,
      }
    }

    const planHosts = enhancedHosts.map(prepareHost)
    // Resolve the entire batch in memory against the prefetched candidates.
    const plan = planIngest(planHosts, prefetch, { criticalityModel, networkKeyFor: scope.keyFor })
    for (const ph of plan.perHost) {
      if (ph.possibleDuplicateOf) {
        console.log(`identity: possible_duplicate hint ip=${ph.ip} rule=${ph.rule} relatedAsset=${ph.possibleDuplicateOf}`)
      }
    }
    const planHostByIp = new Map(planHosts.map(p => [p.ip, p]))
    const rawHostByIp = new Map(enhancedHosts.map(h => [h.ip, h]))

    // Map a planned op to a Drizzle statement for db.batch.
    const toStmt = (op: IngestOp): unknown => {
      switch (op.k) {
        case 'insertAsset':   return db.insert(assets).values(op.values as typeof assets.$inferInsert)
        case 'updateAsset':   return db.update(assets).set(op.set as Partial<typeof assets.$inferInsert>).where(eq(assets.assetId, op.assetId))
        case 'insertAddress': return db.insert(assetAddresses).values(op.values as typeof assetAddresses.$inferInsert)
        case 'updateAddress': return db.update(assetAddresses).set(op.set as Partial<typeof assetAddresses.$inferInsert>).where(eq(assetAddresses.addressId, op.addressId))
        case 'endAddress':    return db.update(assetAddresses).set({ endedAt: new Date() }).where(eq(assetAddresses.addressId, op.addressId))
        case 'insertEvent':   return db.insert(events).values(op.values as typeof events.$inferInsert)
      }
    }

    // Slow per-host fallback — the proven resolver path, used only when a bulk
    // chunk hits a unique violation (transactional batch → whole chunk rolled back).
    const persistHostSlow = async (p: PlanHost, rawMac: unknown): Promise<string | null> => {
      const resolution = await resolveAssetIdentity(db, {
        tenantId: tenantId ?? null, ip: p.ip, rawMac, hostKey: p.hostKeyRaw, isManualSource: false,
        networkKey: scope.keyFor(p.ip),
      })
      const mac = resolution.mac
      const networkKey = resolution.networkKey
      if (resolution.assetId) {
        const [existing] = await db.select().from(assets).where(eq(assets.assetId, resolution.assetId)).limit(1)
        const { merged } = mergeOsInfo(existing?.osInfo as Record<string, unknown> | null, p.observedOsInfo, p.isPassive)
        const dt = resolveIngestDeviceType(existing ? { deviceType: existing.deviceType, deviceTypeSource: existing.deviceTypeSource ?? null } : null, p.deviceType, p.isPassive)
        const slowHint = deviceTypeHint({ hostname: p.hostname ?? existing?.hostname, mac: mac ?? existing?.macAddress, vendor: p.hardwareVendor ?? existing?.hardwareVendor, osInfo: merged })
        const hinted = applyHint({ deviceType: dt.deviceType, deviceTypeSource: dt.deviceTypeSource }, slowHint)
        const resolvedDeviceType = hinted.deviceType
        const exposed = existing?.internetFacingOverride ?? p.internetFacing
        const crit = scoreAsset({ deviceType: resolvedDeviceType, deviceTypeSource: hinted.deviceTypeSource, deviceTypeHint: slowHint, isInternetFacing: exposed, internetFacingOverride: existing?.internetFacingOverride ?? null, hostname: p.hostname ?? existing?.hostname, owner: existing?.owner ?? null, osInfo: merged, agentRole: agentRoleOf(existing?.endpointInventory) }, criticalityModel)
        const baselineForUpdate = buildBaseline({ ports: p.ports, osInfo: merged as Record<string, unknown> | null, hostname: p.hostname ?? existing?.hostname ?? null, macAddress: mac ?? existing?.macAddress ?? null, isInternetFacing: exposed, deviceType: resolvedDeviceType, autoSet: true, portsKnown: !p.isPassive })
        const slowHostname = pickHostname(existing?.hostname, p.hostname)
        const existingBaseline = existing?.baselineState as { auto_set?: boolean; hostname?: string | null; ports_known?: boolean } | null | undefined
        // A real name replacing a generic one is not drift (see lib/hostnames.ts), and an
        // active scan completing a baseline captured without ports (added by hand, or seen
        // passively) is learning, not "port opened" (same as the fast path, lib/ingest-plan.ts).
        let renamedBaseline: Record<string, unknown> | null = existingBaseline && existingBaseline.auto_set === true && slowHostname !== existing?.hostname
          && isGenericHostname(existing?.hostname) && existingBaseline.hostname === existing?.hostname
          ? { ...existingBaseline, hostname: slowHostname } : null
        if (existingBaseline && existingBaseline.ports_known === false && !p.isPassive) {
          renamedBaseline = { ...(renamedBaseline ?? existingBaseline), ports: p.ports, ports_known: true }
        }
        await db.update(assets).set({
          ipAddress: p.ip,
          hostname: slowHostname,
          macAddress: mac ?? existing?.macAddress ?? null,
          hostKey: existing?.hostKey ?? resolution.hostKey ?? null,
          hardwareVendor: p.hardwareVendor ?? existing?.hardwareVendor ?? null,
          osInfo: merged,
          deviceType: resolvedDeviceType as typeof p.deviceType,
          deviceTypeSource: hinted.deviceTypeSource,
          deviceTypeHint: slowHint,
          isInternetFacing: exposed,
          criticalityScore: crit,
          criticalityModel,
          source: p.isPassive ? 'scan_passive' : 'scan_active',
          lastScanned: new Date(), updatedAt: new Date(),
          ...(existing?.baselineState ? (renamedBaseline ? { baselineState: renamedBaseline as typeof baselineForUpdate } : {}) : { baselineState: baselineForUpdate }),
        }).where(eq(assets.assetId, resolution.assetId))
        await recordMatchedAddress(db, { assetId: resolution.assetId, tenantId: tenantId ?? null, networkKey, ip: p.ip, mac, currentAddress: resolution.currentAddress })
        return resolution.assetId
      }
      const newAssetId = crypto.randomUUID()
      const { merged } = mergeOsInfo(null, p.observedOsInfo, p.isPassive)
      const newHint = deviceTypeHint({ hostname: p.hostname, mac, vendor: p.hardwareVendor, osInfo: merged })
      const newType = applyHint({ deviceType: p.deviceType, deviceTypeSource: 'auto' }, newHint).deviceType as typeof p.deviceType
      const crit = scoreAsset({ deviceType: newType, deviceTypeSource: 'auto', deviceTypeHint: newHint, isInternetFacing: p.internetFacing, hostname: p.hostname, owner: null, osInfo: merged }, criticalityModel)
      const baseline = buildBaseline({ ports: p.ports, osInfo: merged as Record<string, unknown> | null, hostname: p.hostname ?? null, macAddress: mac ?? null, isInternetFacing: p.internetFacing, deviceType: newType, autoSet: true, portsKnown: !p.isPassive })
      const now = new Date()
      const assetValues = { assetId: newAssetId, tenantId: tenantId ?? null, ipAddress: p.ip, hostname: p.hostname ?? null, macAddress: mac ?? null, hostKey: resolution.hostKey ?? null, hardwareVendor: p.hardwareVendor ?? null, deviceType: newType, deviceTypeSource: 'auto' as const, deviceTypeHint: newHint, osInfo: merged, isInternetFacing: p.internetFacing, criticalityScore: crit, criticalityModel, baselineState: baseline, source: (p.isPassive ? 'scan_passive' : 'scan_active') as 'scan_active' | 'scan_passive', inMyAssets: false, lastScanned: now, createdAt: now, updatedAt: now }
      const addressValues = { assetId: newAssetId, tenantId: tenantId ?? null, networkKey, ipAddress: p.ip, macAddress: mac, firstSeen: now, lastSeen: now }
      if (resolution.endAddressId) {
        await db.batch([
          db.update(assetAddresses).set({ endedAt: now }).where(eq(assetAddresses.addressId, resolution.endAddressId)),
          db.insert(assets).values(assetValues),
          db.insert(assetAddresses).values(addressValues),
        ])
      } else {
        await db.batch([
          db.insert(assets).values(assetValues),
          db.insert(assetAddresses).values(addressValues),
        ])
      }
      await db.insert(events).values({ assetId: newAssetId, eventType: 'new_device', severity: newDeviceSeverity({ internetFacing: p.internetFacing, mac, hostname: p.hostname }), details: { ip: p.ip, mac: mac ?? null, hostname: p.hostname ?? null, source: p.isPassive ? 'passive_scan' : 'active_scan' } })
      return newAssetId
    }

    // Execute in bulk: each chunk is ONE db.batch (one subrequest), transactional.
    let slowBudget = 10
    for (const chunk of chunkPlan(plan.perHost, 100)) {
      if (chunk.ops.length === 0) {
        for (const ph of chunk.hosts) upsertedAssetIds.push(ph.assetId)
        continue
      }
      try {
        await db.batch(chunk.ops.map(toStmt) as [unknown, ...unknown[]] as Parameters<typeof db.batch>[0])
        for (const ph of chunk.hosts) upsertedAssetIds.push(ph.assetId)
      } catch (e) {
        if (!isUniqueViolation(e)) throw e
        // Chunk rolled back — re-run its hosts via the slow path, capped.
        for (const ph of chunk.hosts) {
          const p = planHostByIp.get(ph.ip)
          const raw = rawHostByIp.get(ph.ip)
          if (!p || !raw) { failedHosts++; continue }
          if (slowBudget <= 0) { failedHosts++; console.error(`identity: slow-path cap reached — skipping host ${ph.ip}`); continue }
          slowBudget--
          try {
            const id = await persistHostSlow(p, raw.mac)
            if (id) upsertedAssetIds.push(id)
          } catch (err) {
            failedHosts++
            console.error(`identity: slow-path failed ip=${ph.ip} mac=${normalizeMac(raw.mac) ?? 'none'} rule=${ph.rule}: ${(err as Error)?.message ?? err}`)
          }
        }
      }
    }

    // Mark scan completed — unified for active, dashboard-triggered passive, and
    // auto-created passive records (auto-created are already 'completed' but this is idempotent)
    await db
      .update(scanResults)
      .set({
        status: 'completed',
        hostsDiscovered: recordHosts.length,
        rawResults: recordHosts,
        // the agent's network block, for reference (merged: keeps an investigation's link)
        ...(network ? { networkInfo: sql`COALESCE(${scanResults.networkInfo}, '{}'::jsonb) || ${JSON.stringify(network)}::jsonb` } : {}),
        completedAt: new Date(),
      })
      .where(eq(scanResults.scanId, effectiveScanId))

    // Trigger drift checks — one sendBatch per 100 assets (not one send per asset),
    // keeping queue subrequests constant.
    for (let i = 0; i < upsertedAssetIds.length; i += 100) {
      const slice = upsertedAssetIds.slice(i, i + 100)
      await c.env.ADVISORY_QUEUE.sendBatch(
        slice.map(assetId => ({ body: { type: 'drift_check', assetId, scanId: effectiveScanId, agentId: agent_id } })),
      )
    }

    // A device whose new-device alert was closed unreviewed (not seen for 14 days) is back.
    try {
      await reopenReturnedNewDevices(db, upsertedAssetIds)
    } catch (err) {
      console.error('scan ingest: reopening returned new devices failed:', err)
    }

    // The assets' addresses may be new or changed: match them against threat intel.
    try {
      await matchIocs(db, { assetIds: upsertedAssetIds })
    } catch (err) {
      console.error('scan ingest: threat-intel matching failed:', err)
    }

    // A targeted scan of a new device: its findings go on the device's new-device alert.
    // A passive upload that found new devices may queue such scans (tenant setting).
    try {
      if (investigation && investigatedIp) {
        await recordInvestigationResult(db, investigation, effectiveScanId, investigatedIp, hosts as Record<string, unknown>[])
      } else if (isPassive && upsertedAssetIds.length) {
        await queueInvestigations(db, { tenantId: tenantId ?? null, agentId: agent_id, assetIds: upsertedAssetIds })
      }
    } catch (err) {
      console.error('scan ingest: new-device investigation failed:', err)
    }

    return c.json({
      message: 'Scan results ingested',
      scan_id: effectiveScanId,
      scan_type: isPassive ? 'passive' : 'active',
      hosts_discovered: hosts.length,
      assets_upserted: upsertedAssetIds.length,
      failed_hosts: failedHosts,
    })
  } catch (err) {
    console.error('scans POST /ingest error:', err)
    return c.json({ detail: 'Failed to ingest scan results' }, 500)
  }
})

// ── POST /fail ───────────────────────────────────────────────────
app.post('/fail', async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const authHeader = c.req.header('Authorization')
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ detail: 'Missing or invalid Authorization header' }, 401)
    }

    const incomingKey = authHeader.slice(7)
    const incomingKeyHash = await sha256Hex(incomingKey)

    const { agent_id, scan_id, reason } = await c.req.json<{
      agent_id?: string
      scan_id?: string
      reason?: string
    }>()

    if (!agent_id) return c.json({ detail: 'agent_id is required' }, 400)

    const [agent] = await db.select().from(agents).where(eq(agents.agentId, agent_id)).limit(1)

    if (!agent) {
      return c.json({ detail: 'Agent not found' }, 401)
    }

    if (incomingKeyHash !== agent.apiKeyHash) {
      return c.json({ detail: 'Invalid API key' }, 401)
    }

    if (scan_id) {
      const failureReason = typeof reason === 'string' ? reason.slice(0, 1000) : 'Scan failed on agent'
      const failed = await db
        .update(scanResults)
        .set({ status: 'failed', completedAt: new Date(), failureReason })
        .where(and(
          eq(scanResults.scanId, scan_id),
          eq(scanResults.agentId, agent_id),     // an agent can only fail its own scans
          inArray(scanResults.status, ['pending', 'running']),
        ))
        .returning({ networkInfo: scanResults.networkInfo })
      const info = failed[0]?.networkInfo
      if (isInvestigation(info)) await recordInvestigationFailure(db, info, scan_id, failureReason)
    }

    return c.json({ message: 'Scan marked as failed' })
  } catch (err) {
    console.error('scans POST /fail error:', err)
    return c.json({ detail: 'Failed to mark scan as failed' }, 500)
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
