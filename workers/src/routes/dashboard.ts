/**
 * UMEagleEye Workers — Dashboard summary
 *
 * One call that answers "what is my situation and what do I do next":
 * collection health, the top open alerts by triage priority, attack surface
 * built from the latest scan data, and hygiene work queues.
 */

import { Hono } from 'hono'
import { eq, and, desc, sql, inArray } from 'drizzle-orm'
import type { Env } from '../types'
import { authMiddleware } from '../middleware/auth'
import { getDb } from '../db/client'
import { assets, agents, scanResults, sboms, events, advisories } from '../db/schema'
import { isOpenEvent } from '../lib/eventStatus'
import { priorityExpr } from '../lib/priority'
import { RISKY_PORTS } from '../lib/exposure'
import { extractPorts } from '../services/drift'

const app = new Hono<{ Bindings: Env }>()

const DAY = 86400000
const AGENT_STALE_MS = 10 * 60 * 1000   // heartbeat older than this = offline
const ASSET_STALE_DAYS = 7
const SEV_RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 }

app.get('/summary', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const db   = getDb(c.env.DATABASE_URL)
    const tenantIdParam = c.req.query('tenant_id')
    const tenantId = user.role === 'superadmin' ? (tenantIdParam || undefined) : (user.tenantId ?? undefined)
    const assetScope = tenantId ? eq(assets.tenantId, tenantId) : undefined
    const now = Date.now()

    const [agentRows, scanRows, assetRows, sbomRows, openBySevAsset, topRows, identityRows] = await Promise.all([
      db.select({ agentId: agents.agentId, name: agents.name, status: agents.status, lastHeartbeat: agents.lastHeartbeat, version: agents.version })
        .from(agents).where(tenantId ? eq(agents.tenantId, tenantId) : undefined),
      db.select({
          scanId: scanResults.scanId, scanType: scanResults.scanType, subnet: scanResults.subnet,
          status: scanResults.status, hostsDiscovered: scanResults.hostsDiscovered,
          failureReason: scanResults.failureReason, startedAt: scanResults.startedAt, completedAt: scanResults.completedAt,
        })
        .from(scanResults).where(tenantId ? eq(scanResults.tenantId, tenantId) : undefined)
        .orderBy(desc(scanResults.startedAt)).limit(20),
      db.select({
          assetId: assets.assetId, hostname: assets.hostname, ip: assets.ipAddress, mac: assets.macAddress,
          vendor: assets.hardwareVendor, deviceType: assets.deviceType, osInfo: assets.osInfo,
          criticality: assets.criticalityScore, internetFacing: assets.isInternetFacing,
          internetFacingOverride: assets.internetFacingOverride,
          lastScanned: assets.lastScanned, createdAt: assets.createdAt, source: assets.source,
        })
        .from(assets).where(assetScope),
      db.selectDistinct({ assetId: sboms.assetId })
        .from(sboms).innerJoin(assets, eq(sboms.assetId, assets.assetId)).where(assetScope),
      db.select({ assetId: events.assetId, severity: events.severity, count: sql<number>`count(*)::int` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(assetScope, isOpenEvent()))
        .groupBy(events.assetId, events.severity),
      db.select({
          eventId: events.eventId, eventType: events.eventType, severity: events.severity, details: events.details,
          riskScore: events.compositeRiskScore, status: events.status, firstSeen: events.firstSeen, lastSeen: events.lastSeen,
          occurrences: events.occurrences, assetId: assets.assetId, hostname: assets.hostname, ip: assets.ipAddress,
          internetFacing: assets.isInternetFacing, criticality: assets.criticalityScore, deviceType: assets.deviceType,
          priority: priorityExpr,
        })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(assetScope, isOpenEvent()))
        .orderBy(desc(priorityExpr), desc(events.lastSeen)).limit(5),
      db.select({ count: sql<number>`count(*)::int` })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(assetScope, isOpenEvent(), eq(events.eventType, 'config_change'),
          sql`${events.details}->>'changed_attribute' IN ('mac_address','hostname')`)),
    ])

    // ── Collection health ──────────────────────────────────────────
    const agentsOut = agentRows.map(a => {
      const hb = a.lastHeartbeat ? new Date(a.lastHeartbeat).getTime() : 0
      return {
        agent_id: a.agentId, name: a.name, version: a.version, last_heartbeat: a.lastHeartbeat,
        online: a.status !== 'offline' && hb > 0 && now - hb < AGENT_STALE_MS,
      }
    })
    const lastOf = (type: string) => scanRows.find(s => s.scanType === type && s.status === 'completed')
    const lastActive  = lastOf('active')
    const lastPassive = lastOf('passive')
    const recentFailures = scanRows.filter(s => s.status === 'failed').slice(0, 3)

    // ── Priority actions (top 5 open alerts) ───────────────────────
    const topIds = topRows.map(r => r.eventId)
    const advByEvent = new Map<string, { recommendedAction: string; advisoryId: string }>()
    if (topIds.length > 0) {
      const advRows = await db.select({ eventId: advisories.eventId, advisoryId: advisories.advisoryId, recommendedAction: advisories.recommendedAction })
        .from(advisories).where(inArray(advisories.eventId, topIds)).orderBy(desc(advisories.createdAt))
      for (const a of advRows) if (!advByEvent.has(a.eventId)) advByEvent.set(a.eventId, a)
    }
    const priority_actions = topRows.map(r => {
      const adv = advByEvent.get(r.eventId)
      return {
        event_id: r.eventId, event_type: r.eventType, severity: r.severity, details: r.details,
        risk_score: r.riskScore != null ? Number(r.riskScore) : null, status: r.status,
        first_seen: r.firstSeen, last_seen: r.lastSeen, occurrences: r.occurrences,
        priority_score: r.priority != null ? Number(r.priority) : null,
        asset: { asset_id: r.assetId, hostname: r.hostname, ip: r.ip, internet_facing: r.internetFacing, criticality: r.criticality, device_type: r.deviceType },
        advisory_id: adv?.advisoryId ?? null,
        recommended_action: adv?.recommendedAction?.slice(0, 280) ?? null,
      }
    })

    // ── Attack surface ─────────────────────────────────────────────
    const worstOpen = new Map<string, string>()
    const openCountByAsset = new Map<string, number>()
    for (const r of openBySevAsset) {
      const cur = worstOpen.get(r.assetId)
      if (!cur || SEV_RANK[r.severity]! > SEV_RANK[cur]!) worstOpen.set(r.assetId, r.severity)
      openCountByAsset.set(r.assetId, (openCountByAsset.get(r.assetId) ?? 0) + r.count)
    }

    const brief = (a: typeof assetRows[number]) => ({ asset_id: a.assetId, hostname: a.hostname, ip: a.ip, device_type: a.deviceType })

    const risky = new Map<number, { port: number; service: string; hosts: ReturnType<typeof brief>[]; internet_facing: number }>()
    const deviceMix: Record<string, number> = { server: 0, workstation: 0, network: 0, iot: 0, unknown: 0 }
    const osCounts = new Map<string, number>()
    const internetFacing = []
    const networkDevices = []

    for (const a of assetRows) {
      const os = (a.osInfo ?? {}) as Record<string, unknown>
      const ports = extractPorts(os)
      deviceMix[a.deviceType] = (deviceMix[a.deviceType] ?? 0) + 1

      const osName = String(os.name ?? os.os_name ?? os.dhcp_device_hint ?? '').trim()
      if (osName) osCounts.set(osName, (osCounts.get(osName) ?? 0) + 1)

      for (const p of ports) {
        const svc = RISKY_PORTS[p]
        if (!svc) continue
        const entry = risky.get(p) ?? { port: p, service: svc, hosts: [], internet_facing: 0 }
        entry.hosts.push(brief(a))
        if (a.internetFacing) entry.internet_facing++
        risky.set(p, entry)
      }

      if (a.internetFacing) {
        internetFacing.push({
          ...brief(a), ports, confirmed: a.internetFacingOverride !== null,
          worst_open_severity: worstOpen.get(a.assetId) ?? null,
          open_alerts: openCountByAsset.get(a.assetId) ?? 0,
        })
      }

      if (a.deviceType === 'network') {
        const ifaces = Array.isArray(os.snmp_interfaces) ? (os.snmp_interfaces as unknown[]).length : 0
        networkDevices.push({
          ...brief(a), vendor: a.vendor,
          snmp_sysdescr: typeof os.snmp_sysdescr === 'string' ? os.snmp_sysdescr.slice(0, 160) : null,
          interfaces: ifaces,
          snmp_managed: typeof os.snmp_sysdescr === 'string',
          open_alerts: openCountByAsset.get(a.assetId) ?? 0,
        })
      }
    }

    // ── Hygiene queues ─────────────────────────────────────────────
    const withSbom = new Set(sbomRows.map(r => r.assetId))
    const staleCutoff = now - ASSET_STALE_DAYS * DAY
    const newDevices = assetRows
      .filter(a => a.source !== 'manual' && a.createdAt && new Date(a.createdAt).getTime() >= now - 7 * DAY)
      .sort((x, y) => new Date(y.createdAt).getTime() - new Date(x.createdAt).getTime())
    const unidentified = assetRows.filter(a => a.deviceType === 'unknown' || (!a.vendor && !a.hostname))
    const stale = assetRows
      .filter(a => a.source !== 'manual' && (!a.lastScanned || new Date(a.lastScanned).getTime() < staleCutoff))
      .sort((x, y) => (x.lastScanned ? new Date(x.lastScanned).getTime() : 0) - (y.lastScanned ? new Date(y.lastScanned).getTime() : 0))
    const noSbom = assetRows.filter(a => (a.deviceType === 'server' || a.deviceType === 'workstation') && !withSbom.has(a.assetId))

    const listOf = <T,>(rows: T[], map: (r: T) => unknown) => ({ count: rows.length, items: rows.slice(0, 8).map(map) })

    return c.json({
      generated_at: new Date(now).toISOString(),
      collection: {
        agents_total:  agentsOut.length,
        agents_online: agentsOut.filter(a => a.online).length,
        agents:        agentsOut,
        last_active_scan:  lastActive  ? { scan_id: lastActive.scanId, subnet: lastActive.subnet, hosts: lastActive.hostsDiscovered, completed_at: lastActive.completedAt } : null,
        last_passive_scan: lastPassive ? { scan_id: lastPassive.scanId, hosts: lastPassive.hostsDiscovered, completed_at: lastPassive.completedAt } : null,
        recent_failures:   recentFailures.map(s => ({ scan_id: s.scanId, scan_type: s.scanType, subnet: s.subnet, reason: s.failureReason, started_at: s.startedAt })),
      },
      priority_actions,
      attack_surface: {
        risky_services: [...risky.values()]
          .sort((x, y) => y.internet_facing - x.internet_facing || y.hosts.length - x.hosts.length)
          .map(r => ({ port: r.port, service: r.service, host_count: r.hosts.length, internet_facing: r.internet_facing, hosts: r.hosts.slice(0, 10) })),
        internet_facing: internetFacing
          .sort((x, y) => (SEV_RANK[y.worst_open_severity ?? ''] ?? 0) - (SEV_RANK[x.worst_open_severity ?? ''] ?? 0))
          .slice(0, 10),
        internet_facing_total: internetFacing.length,
        device_mix: deviceMix,
        top_os: [...osCounts.entries()].sort((x, y) => y[1] - x[1]).slice(0, 6).map(([name, count]) => ({ name, count })),
        network_devices: networkDevices.slice(0, 12),
        network_devices_total: networkDevices.length,
        network_devices_unmanaged: networkDevices.filter(n => !n.snmp_managed).length,
      },
      hygiene: {
        new_devices_7d: listOf(newDevices, a => ({ ...brief(a), vendor: a.vendor, mac: a.mac, first_seen: a.createdAt })),
        unidentified:   listOf(unidentified, a => ({ ...brief(a), vendor: a.vendor, mac: a.mac })),
        stale_assets:   listOf(stale, a => ({ ...brief(a), last_scanned: a.lastScanned })),
        no_sbom:        listOf(noSbom, a => ({ ...brief(a), criticality: a.criticality })),
        identity_changes_open: identityRows[0]?.count ?? 0,
        stale_after_days: ASSET_STALE_DAYS,
      },
    })
  } catch (err) {
    console.error('dashboard GET /summary error:', err)
    return c.json({ detail: 'Failed to build dashboard summary' }, 500)
  }
})

export default app
