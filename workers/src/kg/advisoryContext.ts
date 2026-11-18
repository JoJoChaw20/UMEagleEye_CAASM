/**
 * advisoryContext.ts - the facts of one advisory, for a chat opened from that advisory.
 *
 * The caller must hold advisory.generate and the advisory must belong to the caller's tenant;
 * otherwise the loader returns null and the route answers 404 before any model call. The
 * Platform Superadmin is refused at the route before this runs (spec: superadmin may not debug
 * advisories). Every source becomes an S# reference in the agent, so the model can cite it.
 */
import { and, desc, eq, isNull } from 'drizzle-orm'
import type { getDb } from '../db/client'
import { advisories, assets, cveFindings, events } from '../db/schema'
import { decide } from '../lib/actions'
import { sanitizeText } from '../lib/advisoryKit'
import { advisoryView, type AdvisoryContent, type DeviceInfo } from '../lib/advisoryContent'
import { deviceInfoForAssets } from '../services/advisory'

type DB = ReturnType<typeof getDb>

export interface AdvisorySource { key: string; title: string; type: string; text: string }
export interface AdvisoryContext { advisoryId: string; sources: AdvisorySource[] }
export interface AdvisoryUser { role: string; tenantId?: string | null; actions: readonly string[] }

/** The rows one advisory's context is built from. tenantId is the owning asset's tenant. */
export interface AdvisoryRows {
  tenantId: string | null
  advisory: { advisoryId: string; summary: string; recommendedAction: string; status: string; createdAt: Date | string | null; content: AdvisoryContent | null }
  event: { eventId: string; eventType: string; severity: string; status: string; firstSeen: Date | string | null; lastSeen: Date | string | null; occurrences: number; details: unknown }
  asset: { assetId: string; hostname: string | null; ipAddress: string; deviceType: string; osInfo: unknown; endpointInventory: unknown; criticalityScore: number | null; isInternetFacing: boolean; internetFacingOverride: boolean | null }
  device: DeviceInfo
  cves: Array<{ cveId: string; packageName: string; packageVersion: string; severity: string; cvss: string | number; epss: string | number; kev: boolean; fixVersions: string[]; description: string }>
}

export type FetchAdvisoryRows = (db: DB, advisoryId: string) => Promise<AdvisoryRows | null>

/** At most this many CVE findings become sources: KEV first, then the highest CVSS. */
export const MAX_CVE_SOURCES = 8
const TEXT_MAX = 1500
const DETAIL_KEYS = 12

const iso = (v: Date | string | null): string | null => (v == null ? null : v instanceof Date ? v.toISOString() : String(v))
const clean = (v: unknown, max = 300): string => sanitizeText(v, max)
const clip = (t: string): string => (t.length > TEXT_MAX ? `${t.slice(0, TEXT_MAX - 1)}…` : t)
const line = (label: string, value: unknown): string | null =>
  value == null || value === '' ? null : `${label}: ${typeof value === 'string' ? value : JSON.stringify(value)}`
const lines = (...parts: Array<string | null>): string => clip(parts.filter(Boolean).join('\n'))

/** The scalar top-level fields of an alert's details, cleaned. Nested data stays out. */
function detailLines(details: unknown): string[] {
  if (!details || typeof details !== 'object' || Array.isArray(details)) return []
  const out: string[] = []
  for (const [k, v] of Object.entries(details as Record<string, unknown>)) {
    if (out.length >= DETAIL_KEYS) break
    if (v == null || typeof v === 'object') continue
    const key = clean(k, 40)
    if (key) out.push(`${key}: ${clean(v, 120)}`)
  }
  return out
}

function osLabel(asset: AdvisoryRows['asset']): string | null {
  const osInfo = (asset.osInfo ?? {}) as Record<string, unknown>
  const inv = (((asset.endpointInventory ?? {}) as Record<string, unknown>).os ?? {}) as Record<string, unknown>
  const name = clean(inv.name ?? osInfo.name ?? osInfo.os_name ?? '', 80)
  if (!name) return null
  const ver = clean(inv.name ? (inv.display_version ?? inv.version ?? '') : (osInfo.os_version ?? osInfo.version ?? ''), 40)
  return ver ? `${name} ${ver}` : name
}

/** PURE. The advisory, its alert, the device, its CVE findings and each step, as sources in that order. */
export function buildAdvisorySources(rows: AdvisoryRows): AdvisorySource[] {
  const { advisory: a, event: e, asset: d } = rows
  const { content } = advisoryView({ content: a.content }, rows.device)
  const id8 = a.advisoryId.slice(0, 8)
  const sources: AdvisorySource[] = []

  sources.push({
    key: `advisory:${a.advisoryId}`, title: `Advisory ${id8}`, type: 'advisory',
    text: lines(
      line('Advisory', id8), line('Status', a.status), line('Created', iso(a.createdAt)),
      line('Summary', clean(content?.summary || a.summary, 600)),
      line('Recommended action', clean(a.recommendedAction, 600)),
      line('Why now', content?.why_now ? clean(content.why_now, 400) : null),
      line('How to verify', content?.verify ? clean(content.verify, 400) : null),
      line('How to roll back', content?.rollback ? clean(content.rollback, 400) : null),
      line('Advisory confidence', content?.confidence?.level ? `${clean(content.confidence.level, 10)} (${clean(content.confidence.reason, 160)})` : null),
      line('Basis', content?.basis ? clean(content.basis, 200) : null),
    ),
  })

  sources.push({
    key: `event:${e.eventId}`, title: `Alert ${e.eventId.slice(0, 8)}`, type: 'alert',
    text: lines(
      line('Alert type', e.eventType), line('Severity', e.severity), line('Alert status', e.status),
      line('First seen', iso(e.firstSeen)), line('Last seen', iso(e.lastSeen)), line('Occurrences', e.occurrences),
      ...detailLines(e.details),
    ),
  })

  const internetFacing = d.internetFacingOverride ?? d.isInternetFacing
  sources.push({
    key: `asset:${d.assetId}`, title: clean(d.hostname || d.ipAddress, 80) || 'Device', type: 'asset',
    text: lines(
      line('Device', clean(d.hostname || d.ipAddress, 80)), line('IP address', clean(d.ipAddress, 45)),
      line('Device type', d.deviceType), line('Operating system', osLabel(d) ?? 'unknown'),
      line('Internet-facing', internetFacing ? 'yes' : 'no'), line('Criticality', d.criticalityScore),
      line('Endpoint agent', rows.device.hasAgent ? 'installed' : 'not installed'),
    ),
  })

  const cves = [...rows.cves].sort((x, y) => Number(y.kev) - Number(x.kev) || Number(y.cvss) - Number(x.cvss)).slice(0, MAX_CVE_SOURCES)
  for (const c of cves) {
    const cveId = clean(c.cveId, 40)
    if (!cveId) continue
    sources.push({
      key: `cve:${cveId}:${clean(c.packageName, 120)}:${clean(c.packageVersion, 60)}`, title: `${cveId} in ${clean(c.packageName, 80)}`, type: 'cve',
      text: lines(
        line('CVE', cveId), line('Package', clean(c.packageName, 120)), line('Installed version', clean(c.packageVersion, 60) || 'unknown'),
        line('Severity', c.severity), line('CVSS', String(c.cvss)), line('EPSS', String(c.epss)),
        line('Known exploited (CISA KEV)', c.kev ? 'yes' : 'no'),
        line('Fixed in', c.fixVersions.length ? c.fixVersions.map(v => clean(v, 40)).filter(Boolean).join(', ') : 'no fixed version listed'),
        line('Description', clean(c.description, 500)),
      ),
    })
  }

  const steps = Array.isArray(content?.steps) ? content.steps : []
  steps.forEach((st, i) => {
    sources.push({
      key: `advisory-step:${a.advisoryId}:${clean(st.id, 40) || i}`, title: `Advisory ${id8} step ${i + 1}`, type: 'advisory_step',
      text: lines(
        line(`Step ${i + 1}`, clean(st.text, 600)),
        line('Kind', st.kind), line('Risk', st.risk),
        line('Needs reboot', st.needs_reboot ? 'yes' : null),
        line('Expert note', st.expert_note ? clean(st.expert_note, 600) : null),
        line('Why not automatic', st.reason ? clean(st.reason, 300) : null),
      ),
    })
  })
  return sources
}

/** Reads the advisory with its alert, device and open CVE findings. Null when it does not exist.
 *  Four subrequests (the row, then agents + asset type and CVEs): keep agent.ts ADVISORY_CONTEXT_SUBREQUESTS in step. */
export const fetchAdvisoryRows: FetchAdvisoryRows = async (db, advisoryId) => {
  const [row] = await db
    .select({
      tenantId: assets.tenantId,
      advisory: {
        advisoryId: advisories.advisoryId, summary: advisories.summary, recommendedAction: advisories.recommendedAction,
        status: advisories.status, createdAt: advisories.createdAt, content: advisories.content,
      },
      event: {
        eventId: events.eventId, eventType: events.eventType, severity: events.severity, status: events.status,
        firstSeen: events.firstSeen, lastSeen: events.lastSeen, occurrences: events.occurrences, details: events.details,
      },
      asset: {
        assetId: assets.assetId, hostname: assets.hostname, ipAddress: assets.ipAddress, deviceType: assets.deviceType,
        osInfo: assets.osInfo, endpointInventory: assets.endpointInventory, criticalityScore: assets.criticalityScore,
        isInternetFacing: assets.isInternetFacing, internetFacingOverride: assets.internetFacingOverride,
      },
    })
    .from(advisories)
    .innerJoin(events, eq(advisories.eventId, events.eventId))
    .innerJoin(assets, eq(events.assetId, assets.assetId))
    .where(eq(advisories.advisoryId, advisoryId))
    .limit(1)
  if (!row) return null
  const [device, cves] = await Promise.all([
    deviceInfoForAssets(db, [row.asset.assetId]),
    db.select({
        cveId: cveFindings.cveId, packageName: cveFindings.packageName, packageVersion: cveFindings.packageVersion,
        severity: cveFindings.severity, cvss: cveFindings.cvss, epss: cveFindings.epss, kev: cveFindings.kev,
        fixVersions: cveFindings.fixVersions, description: cveFindings.description,
      })
      .from(cveFindings)
      .where(and(eq(cveFindings.eventId, row.event.eventId), isNull(cveFindings.fixedAt), eq(cveFindings.dismissed, false)))
      .orderBy(desc(cveFindings.kev), desc(cveFindings.cvss))
      .limit(MAX_CVE_SOURCES),
  ])
  return {
    ...row,
    advisory: { ...row.advisory, content: (row.advisory.content ?? null) as AdvisoryContent | null },
    device: device.get(row.asset.assetId) ?? { hasAgent: false, isNetworkDevice: false, remediationEnabled: false, capabilities: [] },
    cves,
  }
}

/**
 * The context for a chat about one advisory, or null when the caller may not debug it: no
 * advisory.generate, no tenant, or the advisory belongs to another tenant (or does not exist).
 * The permission check runs first, so a refused caller causes no database read.
 */
export async function loadAdvisoryContext(
  db: DB, user: AdvisoryUser, advisoryId: string, fetchRows: FetchAdvisoryRows = fetchAdvisoryRows,
): Promise<AdvisoryContext | null> {
  if (user.role === 'superadmin' || !user.tenantId) return null
  if (!decide(user, 'advisory.generate').ok) return null
  const rows = await fetchRows(db, advisoryId)
  if (!rows || !rows.tenantId || rows.tenantId !== user.tenantId) return null
  return { advisoryId: rows.advisory.advisoryId, sources: buildAdvisorySources(rows) }
}
