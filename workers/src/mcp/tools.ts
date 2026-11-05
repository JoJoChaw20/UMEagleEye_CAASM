/**
 * mcp/tools.ts — the UMEagleEye tools, defined once and used by both
 *   - the MCP server (routes/mcp.ts) that MCP clients such as Claude Desktop connect to, and
 *   - the dashboard chatbot (mcp/agent.ts), which calls them through the model's tool calls.
 *
 * Rules every tool follows:
 *   - The tenant comes from the signed-in user (ToolContext), never from the model's
 *     arguments. The platform superadmin sees every tenant unless one is picked.
 *   - Read tools only read. The one action that changes data (resolve_advisory) is never
 *     run by a tool call: it returns a proposal that a person confirms in the dashboard.
 *   - Results are compact JSON with hard row limits, so a tool call stays cheap in tokens
 *     and in Worker subrequests. Text that came off the network (hostnames, banners,
 *     package names) is returned as data; the agent tells the model not to obey it.
 */
import { z } from 'zod'
import { and, desc, eq, ilike, inArray, or, sql, type SQL } from 'drizzle-orm'
import type { DB } from '../db/client'
import type { Env } from '../types'
import { advisories, agents, assets, deviceTypeEnum, eventTypeEnum, events, sboms, severityEnum } from '../db/schema'
import { computePosture } from '../services/posture'
import { isOpenEvent, OPEN_STATUSES } from '../lib/eventStatus'
import { priorityExpr } from '../lib/priority'
import {
  ACTIVE_ADVISORY_STATUSES, advisoryIdPrefix, advisoryIdStartsWith, advisoryInTenant,
} from '../lib/advisoryScope'
import { INTEL_TOOLS } from './intel'
import { advScope, assetScope } from './scope'

export interface ToolUser { userId: string; role: string; tenantId?: string | null }

export interface ToolContext {
  db: DB
  env: Env
  user: ToolUser
  /** Tenant the tools read: the user's own; for the superadmin the picked one or undefined (all). */
  tenantId?: string
}

/** Who may call a tool: everyone, or the roles that triage (not business_owner). */
type Access = 'all' | 'analyst'

export interface ToolDef<S extends z.ZodRawShape = z.ZodRawShape> {
  name: string
  title: string
  description: string
  input: S
  access: Access
  /** Actions are only proposed, never run, by a tool call (see resolve_advisory). */
  proposesAction?: boolean
  run: (ctx: ToolContext, args: z.infer<z.ZodObject<S>>) => Promise<unknown>
}

const ANALYST_ROLES = ['superadmin', 'tenant_superadmin', 'tenant_admin']
const ADVISORY_STATUS_ROLES = ['tenant_superadmin', 'tenant_admin']

export function canUse(tool: ToolDef, user: ToolUser): boolean {
  if (tool.access === 'all') return true
  if (tool.proposesAction) return ADVISORY_STATUS_ROLES.includes(user.role)
  return ANALYST_ROLES.includes(user.role)
}

// ── Shared scoping helpers ────────────────────────────────────────
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const clip = (v: unknown, max = 200): string | null => {
  if (v == null || v === '') return null
  const s = String(v).replace(/\s+/g, ' ').trim()
  return s.length > max ? `${s.slice(0, max)}...` : s
}
const assetLabel = (a: { hostname: string | null; ipAddress: string | null }) => a.hostname || a.ipAddress || 'unknown'

/** What an active scan found listening on the asset (osInfo.services from Nmap). */
function servicesOf(osInfo: unknown): Array<{ port: number; protocol: string; service: string | null; product: string | null; version: string | null }> {
  const list = ((osInfo ?? {}) as Record<string, unknown>).services
  if (!Array.isArray(list)) return []
  return list.slice(0, 30).map(s => {
    const o = (s ?? {}) as Record<string, unknown>
    return {
      port: Number(o.port), protocol: String(o.protocol ?? 'tcp'),
      service: clip(o.service, 40), product: clip(o.product, 60), version: clip(o.version, 40),
    }
  }).filter(s => Number.isFinite(s.port))
}

/** The OS: the agent's own report (endpoint inventory) first, else what a scan guessed. */
const osOf = (osInfo: unknown, inventory?: unknown) => {
  const inv = (((inventory ?? {}) as Record<string, unknown>).os ?? {}) as Record<string, unknown>
  if (inv.name) {
    const ver = clip(inv.display_version ?? inv.version, 30)
    return `${clip(inv.name, 80)}${ver ? ` ${ver}` : ''}${inv.build ? ` (build ${clip(inv.build, 20)})` : ''}`
  }
  const o = (osInfo ?? {}) as Record<string, unknown>
  const name = clip(o.name ?? o.os_name, 80)
  const ver = clip(o.os_version ?? o.version, 40)
  return name ? `${name}${ver ? ` ${ver}` : ''} (from a scan, may be a guess)` : null
}

/** The facts worth showing about an alert, without the raw details blob. */
function alertFacts(details: unknown) {
  const d = (details ?? {}) as Record<string, unknown>
  const pick: Record<string, unknown> = {}
  for (const k of ['cve_id', 'package_name', 'package_version', 'package_type', 'fix_versions', 'cvss_base_score',
    'epss_score', 'kev', 'has_cti_match', 'ti_event_titles', 'port', 'protocol', 'service', 'match_kind', 'indicator',
    'missing_kb', 'exploited', 'product', 'changed_attribute', 'from', 'to', 'package', 'old_value', 'new_value',
    'description']) {
    if (d[k] !== undefined && d[k] !== null && d[k] !== '') {
      const v = d[k]
      pick[k] = typeof v === 'string' ? clip(v, k === 'description' ? 300 : 160)
        : Array.isArray(v) ? v.slice(0, 5).map(x => (typeof x === 'string' ? clip(x, 120) : clip(JSON.stringify(x), 120)))
        : typeof v === 'object' ? clip(JSON.stringify(v), 300)
        : v
    }
  }
  return pick
}

async function assetInScope(ctx: ToolContext, assetId: string) {
  if (!UUID.test(assetId)) return null
  const [a] = await ctx.db.select().from(assets)
    .where(and(eq(assets.assetId, assetId), assetScope(ctx))).limit(1)
  return a ?? null
}

// ── Tools ─────────────────────────────────────────────────────────
const getSecurityOverview: ToolDef = {
  name: 'get_security_overview',
  title: 'Security overview',
  description: 'Posture score (0-100), asset counts, open critical and high alerts, and live advisories for the organisation. Start here for "how are we doing" questions.',
  input: {},
  access: 'all',
  async run(ctx) {
    const [posture, sev, adv] = await Promise.all([
      computePosture(ctx.db, ctx.tenantId),
      ctx.db.select({ severity: events.severity, n: sql<number>`count(*)::int` }).from(events)
        .innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(assetScope(ctx), isOpenEvent())).groupBy(events.severity),
      ctx.db.select({ n: sql<number>`count(*)::int` }).from(advisories)
        .where(and(inArray(advisories.status, [...ACTIVE_ADVISORY_STATUSES]), advScope(ctx))),
    ])
    return {
      posture_score: posture.overallScore,
      total_assets: posture.totalAssets,
      critical_assets: posture.totalCriticalAssets,
      open_alerts_by_severity: Object.fromEntries(sev.map(r => [r.severity, r.n])),
      live_advisories: adv[0]?.n ?? 0,
    }
  },
}

const DEVICE_TYPES = z.enum(deviceTypeEnum.enumValues)
const EVENT_TYPES = z.enum(eventTypeEnum.enumValues)
const SEVERITIES = z.enum(severityEnum.enumValues)

const searchAssets: ToolDef<{
  query: z.ZodOptional<z.ZodString>; device_type: z.ZodOptional<typeof DEVICE_TYPES>
  internet_facing: z.ZodOptional<z.ZodBoolean>; limit: z.ZodOptional<z.ZodNumber>
}> = {
  name: 'search_assets',
  title: 'Search assets',
  description: `Find assets by hostname, IP or MAC fragment, device type (${deviceTypeEnum.enumValues.join(', ')}) or internet exposure. Sorted by criticality. Returns asset_id for get_asset.`,
  input: {
    query: z.string().trim().min(1).max(80).optional().describe('hostname, IP or MAC fragment'),
    device_type: DEVICE_TYPES.optional(),
    internet_facing: z.boolean().optional(),
    limit: z.number().int().min(1).max(20).optional(),
  },
  access: 'analyst',
  async run(ctx, a) {
    const q = a.query ? `%${a.query.replace(/[%_\\]/g, m => `\\${m}`)}%` : null
    const rows = await ctx.db.select({
      asset_id: assets.assetId, hostname: assets.hostname, ip: assets.ipAddress, mac: assets.macAddress,
      device_type: assets.deviceType, criticality: assets.criticalityScore, internet_facing: assets.isInternetFacing,
      owner: assets.owner, in_my_assets: assets.inMyAssets, last_scanned: assets.lastScanned,
    }).from(assets)
      .where(and(
        assetScope(ctx),
        q ? or(ilike(assets.hostname, q), ilike(assets.ipAddress, q), ilike(assets.macAddress, q)) : undefined,
        a.device_type ? eq(assets.deviceType, a.device_type) : undefined,
        a.internet_facing !== undefined ? eq(assets.isInternetFacing, a.internet_facing) : undefined,
      ))
      .orderBy(desc(assets.criticalityScore))
      .limit(a.limit ?? 10)
    return { count: rows.length, assets: rows }
  },
}

const getAsset: ToolDef<{ asset_id: z.ZodString }> = {
  name: 'get_asset',
  title: 'Asset details',
  description: 'One asset: identity, OS, exposure, criticality, whether an EagleEye agent and an SBOM cover it (only covered computers are CVE-checked), and its open alerts by severity with the top 5.',
  input: { asset_id: z.string().trim().max(36).describe('asset_id from search_assets or list_alerts') },
  access: 'analyst',
  async run(ctx, a) {
    const asset = await assetInScope(ctx, a.asset_id)
    if (!asset) return { error: 'Asset not found' }
    const [agent, sbom, sev, top] = await Promise.all([
      ctx.db.select({ name: agents.name, version: agents.version, last_heartbeat: agents.lastHeartbeat })
        .from(agents).where(eq(agents.hostAssetId, asset.assetId)).limit(1),
      ctx.db.select({ generated_at: sboms.generatedAt }).from(sboms)
        .where(eq(sboms.assetId, asset.assetId)).orderBy(desc(sboms.generatedAt)).limit(1),
      ctx.db.select({ severity: events.severity, n: sql<number>`count(*)::int` }).from(events)
        .where(and(eq(events.assetId, asset.assetId), isOpenEvent())).groupBy(events.severity),
      ctx.db.select({ event_id: events.eventId, type: events.eventType, severity: events.severity, details: events.details })
        .from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
        .where(and(eq(events.assetId, asset.assetId), isOpenEvent()))
        .orderBy(desc(priorityExpr)).limit(5),
    ])
    return {
      asset_id: asset.assetId, hostname: asset.hostname, ip: asset.ipAddress, mac: asset.macAddress,
      device_type: asset.deviceType, vendor: asset.hardwareVendor, owner: asset.owner,
      os: osOf(asset.osInfo, asset.endpointInventory),
      criticality: asset.criticalityScore, internet_facing: asset.isInternetFacing, in_my_assets: asset.inMyAssets,
      last_scanned: asset.lastScanned,
      services: servicesOf(asset.osInfo).slice(0, 15),
      agent: agent[0] ?? null,
      sbom_generated_at: sbom[0]?.generated_at ?? null,
      cve_checked: !!sbom[0],
      open_alerts_by_severity: Object.fromEntries(sev.map(r => [r.severity, r.n])),
      top_open_alerts: top.map(t => ({ event_id: t.event_id, type: t.type, severity: t.severity, facts: alertFacts(t.details) })),
    }
  },
}

const listAlerts: ToolDef<{
  severity: z.ZodOptional<z.ZodArray<typeof SEVERITIES>>
  event_type: z.ZodOptional<typeof EVENT_TYPES>; asset_id: z.ZodOptional<z.ZodString>
  cve_id: z.ZodOptional<z.ZodString>; limit: z.ZodOptional<z.ZodNumber>
}> = {
  name: 'list_alerts',
  title: 'List open alerts',
  description: `Open alerts (open or in progress), highest priority first: KEV and threat-intel matches, then risk score, exposure and criticality. Filter by severity, event_type (${eventTypeEnum.enumValues.join(', ')}), asset or CVE.`,
  input: {
    severity: z.array(SEVERITIES).max(4).optional(),
    event_type: EVENT_TYPES.optional(),
    asset_id: z.string().trim().max(36).optional(),
    cve_id: z.string().trim().max(20).regex(/^CVE-\d{4}-\d{4,}$/i).optional(),
    limit: z.number().int().min(1).max(20).optional(),
  },
  access: 'analyst',
  async run(ctx, a) {
    if (a.asset_id && !UUID.test(a.asset_id)) return { error: 'asset_id is not valid' }
    const rows = await ctx.db.select({
      event_id: events.eventId, type: events.eventType, severity: events.severity, status: events.status,
      first_seen: events.firstSeen, asset_id: assets.assetId, hostname: assets.hostname, ip: assets.ipAddress,
      details: events.details,
    }).from(events).innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(and(
        assetScope(ctx), inArray(events.status, OPEN_STATUSES),
        a.severity?.length ? inArray(events.severity, a.severity) : undefined,
        a.event_type ? eq(events.eventType, a.event_type) : undefined,
        a.asset_id ? eq(events.assetId, a.asset_id) : undefined,
        a.cve_id ? sql`${events.details}->>'cve_id' = ${a.cve_id.toUpperCase()}` : undefined,
      ))
      .orderBy(desc(priorityExpr), desc(events.firstSeen))
      .limit(a.limit ?? 10)
    return {
      count: rows.length,
      alerts: rows.map(r => ({
        event_id: r.event_id, type: r.type, severity: r.severity, status: r.status, first_seen: r.first_seen,
        asset: { asset_id: r.asset_id, label: assetLabel({ hostname: r.hostname, ipAddress: r.ip }) },
        facts: alertFacts(r.details),
      })),
    }
  },
}

const explainAlert: ToolDef<{ event_id: z.ZodString }> = {
  name: 'explain_alert',
  title: 'Explain an alert',
  description: 'Everything known about one alert: its facts (CVE, package, installed and fix versions, CVSS, EPSS, CISA KEV, threat-intel matches), the asset and its exposure, and the advisory written for it, if any.',
  input: { event_id: z.string().trim().max(36).describe('event_id from list_alerts') },
  access: 'analyst',
  async run(ctx, a) {
    if (!UUID.test(a.event_id)) return { error: 'event_id is not valid' }
    const [row] = await ctx.db.select({ event: events, asset: assets }).from(events)
      .innerJoin(assets, eq(events.assetId, assets.assetId))
      .where(and(eq(events.eventId, a.event_id), assetScope(ctx))).limit(1)
    if (!row) return { error: 'Alert not found' }
    const [adv] = await ctx.db.select({ advisory_id: advisories.advisoryId, status: advisories.status, summary: advisories.summary })
      .from(advisories).where(eq(advisories.eventId, row.event.eventId)).orderBy(desc(advisories.createdAt)).limit(1)
    return {
      event_id: row.event.eventId, type: row.event.eventType, severity: row.event.severity, status: row.event.status,
      first_seen: row.event.firstSeen, last_seen: row.event.lastSeen, occurrences: row.event.occurrences,
      risk_score: row.event.compositeRiskScore, resolution_note: clip(row.event.resolutionNote),
      facts: alertFacts(row.event.details),
      service_on_port: (() => {
        const port = Number(((row.event.details ?? {}) as Record<string, unknown>).port)
        if (!Number.isFinite(port)) return undefined
        return servicesOf(row.asset.osInfo).find(s => s.port === port)
          ?? 'not identified by the last active scan (no service name, product or version recorded)'
      })(),
      asset: {
        asset_id: row.asset.assetId, label: assetLabel(row.asset), hostname: row.asset.hostname, ip: row.asset.ipAddress,
        device_type: row.asset.deviceType, os: osOf(row.asset.osInfo, row.asset.endpointInventory), vendor: row.asset.hardwareVendor,
        criticality: row.asset.criticalityScore, internet_facing: row.asset.isInternetFacing, owner: row.asset.owner,
        last_scanned: row.asset.lastScanned, open_ports: servicesOf(row.asset.osInfo).map(s => `${s.port}/${s.protocol}`).slice(0, 20),
      },
      advisory: adv ? { advisory_id: adv.advisory_id, status: adv.status, summary: clip(adv.summary, 400) } : null,
    }
  },
}

const listAdvisories: ToolDef<{ status: z.ZodOptional<z.ZodEnum<['live', 'resolved', 'all']>>; limit: z.ZodOptional<z.ZodNumber> }> = {
  name: 'list_advisories',
  title: 'List advisories',
  description: 'Remediation advisories, newest first. status "live" (default: open, acknowledged, in progress), "resolved" or "all". Use get_advisory for the full steps.',
  input: {
    status: z.enum(['live', 'resolved', 'all']).optional(),
    limit: z.number().int().min(1).max(20).optional(),
  },
  access: 'analyst',
  async run(ctx, a) {
    const s = a.status ?? 'live'
    const rows = await ctx.db.select({
      advisory_id: advisories.advisoryId, status: advisories.status, summary: advisories.summary,
      created_at: advisories.createdAt, event_id: advisories.eventId,
    }).from(advisories)
      .where(and(
        s === 'live' ? inArray(advisories.status, [...ACTIVE_ADVISORY_STATUSES])
          : s === 'resolved' ? eq(advisories.status, 'resolved') : undefined,
        advScope(ctx),
      ))
      .orderBy(desc(advisories.createdAt)).limit(a.limit ?? 10)
    return { count: rows.length, advisories: rows.map(r => ({ ...r, summary: clip(r.summary, 300) })) }
  },
}

async function advisoryByPrefix(ctx: ToolContext, raw: string, liveOnly: boolean) {
  const prefix = advisoryIdPrefix(raw)
  if (!prefix) return { error: 'advisory_id is not valid' } as const
  const rows = await ctx.db.select().from(advisories)
    .where(and(advisoryIdStartsWith(prefix), liveOnly ? inArray(advisories.status, [...ACTIVE_ADVISORY_STATUSES]) : undefined, advScope(ctx)))
    .limit(2)
  if (rows.length === 0) return { error: liveOnly ? 'No live advisory with that ID' : 'Advisory not found' } as const
  if (rows.length > 1) return { error: 'More than one advisory starts with that ID; give more of it' } as const
  return { advisory: rows[0]! } as const
}

const getAdvisory: ToolDef<{ advisory_id: z.ZodString }> = {
  name: 'get_advisory',
  title: 'Advisory details',
  description: 'One advisory in full: summary, numbered steps, why now, commands, how to verify and roll back, confidence and sources. Accepts the full ID or its first 8 characters.',
  input: { advisory_id: z.string().trim().max(36) },
  access: 'analyst',
  async run(ctx, a) {
    const found = await advisoryByPrefix(ctx, a.advisory_id, false)
    if ('error' in found) return { error: found.error }
    const v = found.advisory
    return {
      advisory_id: v.advisoryId, status: v.status, created_at: v.createdAt, resolved_at: v.resolvedAt,
      event_id: v.eventId, summary: v.summary, recommended_action: clip(v.recommendedAction, 3000),
    }
  },
}

const getCoverage: ToolDef = {
  name: 'get_cve_coverage',
  title: 'CVE check coverage',
  description: 'How many assets are actually CVE-checked: computers with an EagleEye agent and an SBOM. Printers, routers, IoT and phones are discovered but not CVE-checked. Use it before saying an asset or the organisation "has no vulnerabilities".',
  input: {},
  access: 'all',
  async run(ctx) {
    const [row] = await ctx.db.select({
      total: sql<number>`count(*)::int`,
      with_agent: sql<number>`count(*) FILTER (WHERE EXISTS (SELECT 1 FROM agents g WHERE g.host_asset_id = assets.asset_id))::int`,
      with_sbom: sql<number>`count(*) FILTER (WHERE EXISTS (SELECT 1 FROM sboms s WHERE s.asset_id = assets.asset_id))::int`,
    }).from(assets).where(assetScope(ctx))
    const total = row?.total ?? 0, withSbom = row?.with_sbom ?? 0
    return {
      total_assets: total, with_agent: row?.with_agent ?? 0, cve_checked: withSbom, not_cve_checked: total - withSbom,
      note: 'Only assets with an SBOM are checked for CVEs.',
    }
  },
}

const resolveAdvisory: ToolDef<{ advisory_id: z.ZodString; reason: z.ZodString }> = {
  name: 'resolve_advisory',
  title: 'Propose resolving an advisory',
  description: 'Proposes marking a live advisory resolved. It does NOT change anything: the dashboard shows the person a Confirm button, and only their click resolves it. Use only when the user asks to close or mark an advisory as done.',
  input: {
    advisory_id: z.string().trim().max(36),
    reason: z.string().trim().min(3).max(300).describe('why it can be resolved, in the user\'s words'),
  },
  access: 'analyst',
  proposesAction: true,
  async run(ctx, a) {
    const found = await advisoryByPrefix(ctx, a.advisory_id, true)
    if ('error' in found) return { error: found.error }
    return {
      proposal: 'resolve_advisory',
      advisory_id: found.advisory.advisoryId,
      summary: clip(found.advisory.summary, 300),
      reason: a.reason,
      status: 'waiting for the user to confirm in the dashboard; nothing has changed yet',
    }
  },
}

export const TOOLS: ToolDef[] = [
  getSecurityOverview, getCoverage, searchAssets, getAsset, listAlerts, explainAlert,
  listAdvisories, getAdvisory, resolveAdvisory,
  ...INTEL_TOOLS,
] as unknown as ToolDef[]

/** The tools a user may call, optionally without the action proposals (MCP clients). */
export function toolsFor(user: ToolUser, opts: { actions: boolean }): ToolDef[] {
  return TOOLS.filter(t => canUse(t, user) && (opts.actions || !t.proposesAction))
}

/** Validates arguments and runs a tool; errors become a result the model can read. */
export async function runTool(ctx: ToolContext, tool: ToolDef, rawArgs: unknown): Promise<unknown> {
  const parsed = z.object(tool.input).strict().safeParse(rawArgs ?? {})
  if (!parsed.success) {
    return { error: 'Invalid arguments', issues: parsed.error.issues.slice(0, 5).map(i => `${i.path.join('.') || 'args'}: ${i.message}`) }
  }
  try {
    return await tool.run(ctx, parsed.data as never)
  } catch (err) {
    console.error(`[tool] ${tool.name} failed:`, err)
    return { error: 'The tool failed; try again or ask differently.' }
  }
}

