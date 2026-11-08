import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { and, eq, inArray, isNull, or, sql, type SQL } from 'drizzle-orm'
import type { R2Bucket } from '@cloudflare/workers-types'
import type { Env } from '../types'
import { authMiddleware, requireRoles } from '../middleware/auth'
import { AGENT_MANAGE_ROLES, AGENT_READ_ROLES } from '../lib/permissions'
import { POLICY_SPECS, ROLE_KEYS, adoptLocal, applyChange, cleanReport, kindKeys, roleChange, type ResolvedPolicy, type Role } from '../lib/agentPolicy'
import { agentPolicy, policyOf, reportedOf, tenantPolicies } from '../services/agentPolicy'
import { pendingJobsFor } from '../services/pendingJobs'
import { getDb } from '../db/client'
import { audit } from '../services/audit'
import { networkTargetErrors } from '../services/scanTargets'
import { agents, assets, assetAddresses, assetIdentifiers, assetSoftware, auditLogs, scanResults, tenants } from '../db/schema'
import { matchIocs } from '../services/iocMatch'
import { generateApiKey } from '../lib/auth'
import { isIPv4 } from '../lib/exposure'
import { ACTIVE_MODEL, scoreAsset } from '../lib/rescore'
import { postureColumns } from '../lib/endpointPosture'
import { resolveNetworkScope } from '../lib/networkScope'
import { closeReviewedNewDevices } from '../services/alertHygiene'
import { checkWindowsPatch } from '../services/windowsPatch'
import {
  bindMachine, deviceTypeFor, diffSoftware, identityMacs, inventoryHostKey, inventoryIps, planAgentAddress, primaryMac,
  resolveAgentDeviceType, storedInventory, type BindingCandidate, type InventoryPayload,
} from '../lib/endpointInventory'
import { hardwareUuidForms, machineIdentifiers } from '../lib/machineIdentity'

const router = new Hono<{ Bindings: Env }>()

// ── Helper: SHA-256 hash of API key ───────────────────────────────
async function hashApiKey(key: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key))
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
}

// ── Helper: compute status from lastHeartbeat ─────────────────────
function computeStatus(lastHeartbeat: Date | null): 'online' | 'degraded' | 'offline' {
  if (!lastHeartbeat) return 'offline'
  const diffMs = Date.now() - new Date(lastHeartbeat).getTime()
  const diffMin = diffMs / 60_000
  if (diffMin < 2) return 'online'
  if (diffMin < 10) return 'degraded'
  return 'offline'
}

// What the Agents page shows for one agent. The computer it runs on comes from the
// asset its endpoint inventory is bound to (agents.host_asset_id).
type AgentRow = typeof agents.$inferSelect
type HostRow = { assetId: string; hostname: string | null; ipAddress: string; inventoryCollectedAt: Date | null } | null
function agentOut(a: AgentRow, host: HostRow, resolved?: ResolvedPolicy) {
  const applied = reportedOf(a).policy_version ?? null
  return {
    agent_id: a.agentId,
    tenant_id: a.tenantId,
    name: a.name,
    status: a.retiredAt ? 'retired' : computeStatus(a.lastHeartbeat),
    retired_at: a.retiredAt,
    last_heartbeat: a.lastHeartbeat,
    local_ip: a.gatewayIp,          // the column has always held the agent's own LAN IP
    version: a.version,
    // 1.x = the retired eagleeye_agent.py; it cannot connect any more.
    legacy: a.version ? a.version.startsWith('1.') : false,
    host: host ? {
      asset_id: host.assetId, hostname: host.hostname, ip_address: host.ipAddress,
      inventory_collected_at: host.inventoryCollectedAt,
    } : null,
    kind: a.kind,
    // The networks it is directly on (2.5.1+; scans of them go to it: lib/agentRouting.ts).
    networks: Array.isArray((reportedOf(a) as { networks?: unknown }).networks)
      ? (reportedOf(a) as { networks: string[] }).networks : [],
    // Roles read from the settings (lib/agentPolicy.ts).
    roles: resolved?.roles ?? null,
    // Whether the agent runs the settings set for it: it reports the version it applied
    // (2.4.0+; null for older agents, which only know the agent-started scans switch).
    policy: resolved ? {
      version: resolved.version, applied_version: applied,
      in_sync: applied === null ? null : applied === resolved.version,
      managed: Object.keys(resolved.managed).length,
    } : null,
    created_at: a.createdAt,
  }
}

const hostColumns = {
  assetId: assets.assetId, hostname: assets.hostname, ipAddress: assets.ipAddress, inventoryCollectedAt: assets.inventoryCollectedAt,
}

// ── GET / — List agents ───────────────────────────────────────────
router.get('/', authMiddleware, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const user = c.get('user')

  if (user.role !== 'superadmin' && !user.tenantId) return c.json({ agents: [] })
  const rows = await db.select({ agent: agents, host: hostColumns })
    .from(agents)
    .leftJoin(assets, eq(assets.assetId, agents.hostAssetId))
    .where(user.role === 'superadmin' ? undefined : eq(agents.tenantId, user.tenantId!))

  const policies = await tenantPolicies(db, rows.map(r => r.agent.tenantId))
  return c.json({ agents: rows.map(r => agentOut(
    r.agent, r.host?.assetId ? r.host : null, policyOf(r.agent, policies.get(r.agent.tenantId ?? '') ?? null),
  )) })
})

// ── POST / — Register new agent ───────────────────────────────────
router.post(
  '/',
  authMiddleware,
  requireRoles(...AGENT_MANAGE_ROLES),
  zValidator('json', z.object({
    name: z.string().trim().min(1).max(100),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const { name } = c.req.valid('json')

    if (!user.tenantId && user.role !== 'superadmin') {
      return c.json({ detail: 'User has no tenant assigned' }, 400)
    }

    const apiKey = generateApiKey()
    const apiKeyHash = await hashApiKey(apiKey)

    const inserted = await db.insert(agents).values({
      tenantId: user.tenantId ?? null,
      name,
      apiKeyHash,
    }).returning()

    const agent = inserted[0]
    if (!agent) return c.json({ detail: 'Failed to create agent' }, 500)
    await audit(db, c, { userId: user.userId, tenantId: agent.tenantId, actionType: 'agent.create', targetEntity: agent.agentId, newState: { name } })

    return c.json({
      agent_id: agent.agentId,
      name: agent.name,
      api_key: apiKey,
      created_at: agent.createdAt,
    }, 201)
  }
)

// ── The agent's downloads ────────────────────────────────────────
// Uploaded to R2 under agent-installer/ (AGENT_SETUP_GUIDE.md, "Publishing a new version"): the
// Windows installer EagleEyeAgent-Setup-<version>.exe, and the source package for Linux and the
// network agent, eagleeye-agent-<version>.tar.gz. The newest UPLOAD of each is offered, not the
// highest number, so a release renumbered to 1.0 replaces the 2.x development builds. Any signed-in
// user may download them: they hold no secrets, the connection code is what ties an agent to a
// tenant. Declared before /:agentId.
const INSTALLER_PREFIX = 'agent-installer/'
const VERSION_RE = String.raw`(\d+(?:\.\d+){1,3})`
const PACKAGES = {
  windows: { name: new RegExp(String.raw`^agent-installer/(EagleEyeAgent-Setup-${VERSION_RE}\.exe)$`), type: 'application/vnd.microsoft.portable-executable' },
  source: { name: new RegExp(String.raw`^agent-installer/(eagleeye-agent-${VERSION_RE}\.tar\.gz)$`), type: 'application/gzip' },
} as const
type PackageKind = keyof typeof PACKAGES
type Package = { key: string; filename: string; version: string; size: number; uploaded: Date }

async function latestPackages(bucket: R2Bucket): Promise<Record<PackageKind, Package | null>> {
  const latest: Record<PackageKind, Package | null> = { windows: null, source: null }
  const listed = await bucket.list({ prefix: INSTALLER_PREFIX })
  for (const o of listed.objects) {
    for (const kind of Object.keys(PACKAGES) as PackageKind[]) {
      const m = PACKAGES[kind].name.exec(o.key)
      if (!m) continue
      const best = latest[kind]
      if (!best || o.uploaded.getTime() > best.uploaded.getTime()) {
        latest[kind] = { key: o.key, filename: m[1]!, version: m[2]!, size: o.size, uploaded: o.uploaded }
      }
    }
  }
  return latest
}

const packageOut = (p: Package | null) => p && ({ filename: p.filename, version: p.version, size: p.size, uploaded_at: p.uploaded })

router.get('/installer', authMiddleware, async (c) => {
  const latest = await latestPackages(c.env.REPORTS_BUCKET)
  if (!latest.windows && !latest.source) return c.json({ detail: 'No agent installer has been uploaded yet' }, 404)
  // The Windows installer's fields at the top level, as before; `packages` has each download.
  return c.json({ ...packageOut(latest.windows), packages: { windows: packageOut(latest.windows), source: packageOut(latest.source) } })
})

// ?package=windows (default) | source
router.get('/installer/download', authMiddleware, async (c) => {
  const kind = (c.req.query('package') ?? 'windows') as PackageKind
  if (!(kind in PACKAGES)) return c.json({ detail: 'package must be windows or source' }, 400)
  const pkg = (await latestPackages(c.env.REPORTS_BUCKET))[kind]
  const obj = pkg ? await c.env.REPORTS_BUCKET.get(pkg.key) : null
  if (!pkg || !obj) return c.json({ detail: 'That download has not been uploaded yet' }, 404)
  // Streamed: the installer is tens of MB, more than a Worker should hold in memory.
  return c.body(obj.body as unknown as ReadableStream, 200, {
    'Content-Type': PACKAGES[kind].type,
    'Content-Disposition': `attachment; filename="${pkg.filename}"`,
    'Content-Length': String(obj.size),
    'Cache-Control': 'private, max-age=300',
  })
})

// ── GET /:agentId — Single agent detail ───────────────────────────
router.get('/:agentId', authMiddleware, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const user = c.get('user')
  const { agentId } = c.req.param()

  const [row] = await db.select({ agent: agents, host: hostColumns })
    .from(agents)
    .leftJoin(assets, eq(assets.assetId, agents.hostAssetId))
    .where(eq(agents.agentId, agentId)).limit(1)
  if (!row) return c.json({ detail: 'Agent not found' }, 404)

  if (user.role !== 'superadmin' && row.agent.tenantId !== user.tenantId) {
    return c.json({ detail: 'Forbidden' }, 403)
  }

  const policies = await tenantPolicies(db, [row.agent.tenantId])
  return c.json(agentOut(row.agent, row.host?.assetId ? row.host : null,
    policyOf(row.agent, policies.get(row.agent.tenantId ?? '') ?? null)))
})

// ── GET /:agentId/policy — this agent's settings and where each comes from ──
// value + source per setting: 'agent' (this agent's override), 'tenant' (the tenant
// default), 'default' (the built-in default, DEFAULTS).
function policyOut(agent: AgentRow, resolved: ResolvedPolicy, canEdit: boolean) {
  const reported = reportedOf(agent)
  return {
    agent_id: agent.agentId,
    kind: agent.kind,
    version: resolved.version,
    applied_version: reported.policy_version ?? null,
    reported_at: reported.reported_at ?? null,
    capabilities: reported.capabilities ?? {},
    roles: resolved.roles,
    role_settings: ROLE_KEYS,
    settings: resolved.entries.map((e) => ({ ...e, spec: POLICY_SPECS[e.key] })),
    can_edit: canEdit,
  }
}

router.get('/:agentId/policy', authMiddleware, requireRoles(...AGENT_READ_ROLES), async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const user = c.get('user')
  const { agentId } = c.req.param()
  if (!z.string().uuid().safeParse(agentId).success) return c.json({ detail: 'Invalid agent id' }, 400)
  const found = await agentPolicy(db, agentId)
  if (!found || (user.role !== 'superadmin' && found.agent.tenantId !== user.tenantId)) {
    return c.json({ detail: 'Agent not found' }, 404)
  }
  const canEdit = (AGENT_MANAGE_ROLES as readonly string[]).includes(user.role) && !found.agent.retiredAt
  return c.json(policyOut(found.agent, found.resolved, canEdit))
})

// ── PATCH /:agentId/policy — change this agent's overrides ──
// {settings: {setting: value | null}} (null = back to the tenant default / the built-in
// default), and/or {roles: {inventory|sensor|scanner: true|false}}, which sets the role's
// settings. Applied by the agent at its next heartbeat, between jobs.
router.patch(
  '/:agentId/policy',
  authMiddleware,
  requireRoles(...AGENT_MANAGE_ROLES),
  zValidator('json', z.object({
    settings: z.record(z.string(), z.unknown()).optional(),
    roles: z.record(z.enum(Object.keys(ROLE_KEYS) as [Role, ...Role[]]), z.boolean()).optional(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const { agentId } = c.req.param()
    if (!z.string().uuid().safeParse(agentId).success) return c.json({ detail: 'Invalid agent id' }, 400)
    const body = c.req.valid('json')

    const found = await agentPolicy(db, agentId)
    if (!found || found.agent.tenantId !== user.tenantId) return c.json({ detail: 'Agent not found' }, 404)
    if (found.agent.retiredAt) return c.json({ detail: 'This agent is retired' }, 400)

    const change: Record<string, unknown> = {}
    for (const [role, on] of Object.entries(body.roles ?? {}) as [Role, boolean][]) Object.assign(change, roleChange(role, on))
    Object.assign(change, body.settings ?? {})
    const { policy, errors } = applyChange(found.agent.policy, change, kindKeys(found.agent.kind))
    if (errors.length) return c.json({ detail: errors.join('; ') }, 400)
    // The routers a network agent reads get its SNMP credentials: private addresses only (lib/scanTarget.ts).
    const targetErrors = await networkTargetErrors(db, found.agent.tenantId, change)
    if (targetErrors.length) return c.json({ detail: targetErrors.join('; ') }, 400)

    const [updated] = await db.update(agents).set({ policy }).where(eq(agents.agentId, agentId)).returning()
    if (!updated) return c.json({ detail: 'Agent not found' }, 404)
    await db.insert(auditLogs).values({
      userId: user.userId, tenantId: found.agent.tenantId, actionType: 'agent.policy', targetEntity: agentId,
      previousState: { name: found.agent.name, policy: found.agent.policy }, newState: { policy },
    }).catch(err => console.error('agent policy audit failed:', err))

    const policies = await tenantPolicies(db, [updated.tenantId])
    return c.json(policyOut(updated, policyOf(updated, policies.get(updated.tenantId ?? '') ?? null), true))
  }
)

// ── PATCH /:agentId — Rename ──────────────────────────────────────
// The config JSON the 1.x agent read is no longer editable (the current agent is set up
// on its own computer); config now only holds what the agent reports (default gateway).
router.patch(
  '/:agentId',
  authMiddleware,
  requireRoles(...AGENT_MANAGE_ROLES),
  zValidator('json', z.object({
    name: z.string().trim().min(1).max(100).optional(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const { agentId } = c.req.param()
    const updates = c.req.valid('json')

    const [existing] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!existing) return c.json({ detail: 'Agent not found' }, 404)
    if (user.role !== 'superadmin' && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Forbidden' }, 403)
    }

    if (updates.name === undefined) return c.json({ agent_id: existing.agentId, name: existing.name })
    const patched = await db.update(agents).set({ name: updates.name }).where(eq(agents.agentId, agentId)).returning()
    const updated = patched[0]
    if (!updated) return c.json({ detail: 'Failed to update agent' }, 500)
    await audit(db, c, { userId: user.userId, tenantId: updated.tenantId, actionType: 'agent.rename', targetEntity: agentId,
      previousState: { name: existing.name }, newState: { name: updated.name } })

    return c.json({ agent_id: updated.agentId, tenant_id: updated.tenantId, name: updated.name })
  }
)

// ── POST /:agentId/rotate-key — issue a new API key ───────────────
// The old key stops working at once; the new one is returned only here. Used when a
// key was lost or shared by mistake, or to move the agent to another computer.
router.post(
  '/:agentId/rotate-key',
  authMiddleware,
  requireRoles(...AGENT_MANAGE_ROLES),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const { agentId } = c.req.param()
    if (!z.string().uuid().safeParse(agentId).success) return c.json({ detail: 'Invalid agent id' }, 400)

    const [existing] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!existing) return c.json({ detail: 'Agent not found' }, 404)
    if (user.role !== 'superadmin' && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Forbidden' }, 403)
    }
    if (existing.retiredAt) return c.json({ detail: 'This agent is retired. Register a new agent instead.' }, 400)

    const apiKey = generateApiKey()
    await db.batch([
      db.update(agents).set({ apiKeyHash: await hashApiKey(apiKey) }).where(eq(agents.agentId, agentId)),
      db.insert(auditLogs).values({
        userId: user.userId, tenantId: existing.tenantId, actionType: 'agent.rotate_key', targetEntity: agentId,
        previousState: null, newState: { name: existing.name },
      }),
    ])
    return c.json({ agent_id: agentId, name: existing.name, api_key: apiKey })
  }
)

// ── DELETE /:agentId ──────────────────────────────────────────────
router.delete(
  '/:agentId',
  authMiddleware,
  requireRoles(...AGENT_MANAGE_ROLES),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const { agentId } = c.req.param()

    const [existing] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!existing) return c.json({ detail: 'Agent not found' }, 404)
    if (user.role !== 'superadmin' && existing.tenantId !== user.tenantId) {
      return c.json({ detail: 'Forbidden' }, 403)
    }

    await db.delete(agents).where(eq(agents.agentId, agentId))
    await audit(db, c, { userId: user.userId, tenantId: existing.tenantId, actionType: 'agent.delete', targetEntity: agentId,
      previousState: { name: existing.name, kind: existing.kind, host_asset_id: existing.hostAssetId } })
    return c.json({ ok: true })
  }
)

// ── POST /:agentId/heartbeat — Agent API key auth ─────────────────
router.post(
  '/:agentId/heartbeat',
  zValidator('json', z.object({
    version: z.string().optional(),
    gateway_ip: z.string().optional(),
    // Lenient on purpose: a bad value must never reject the whole heartbeat
    // (that would mark the agent offline). Validated below before storing.
    default_gateway: z.string().max(45).optional(),
    // 2.4.0+: what the agent is and does. Lenient for the same reason; cleaned below.
    kind: z.unknown().optional(),
    settings: z.unknown().optional(),
    capabilities: z.unknown().optional(),
    policy_version: z.unknown().optional(),
    networks: z.unknown().optional(),
    // 2.5.0+: send the jobs waiting for it with the answer (instead of GET /scans/pending).
    want_jobs: z.unknown().optional(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { agentId } = c.req.param()
    const body = c.req.valid('json')
    const { version, gateway_ip, default_gateway } = body

    // Extract API key from Authorization header
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ detail: 'Missing Authorization header' }, 401)
    }
    const providedKey = authHeader.slice(7)

    const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!agent) return c.json({ detail: 'Agent not found' }, 404)

    // Verify API key by SHA-256 hash
    const providedHash = await hashApiKey(providedKey)
    if (providedHash !== agent.apiKeyHash) {
      return c.json({ detail: 'Invalid API key' }, 401)
    }

    // Update heartbeat fields
    const updateData: Record<string, unknown> = {
      lastHeartbeat: new Date(),
      status: 'online',
    }
    if (version) updateData.version = version
    if (gateway_ip) updateData.gatewayIp = gateway_ip
    // gateway_ip has always carried the agent's own LAN IP, so the real default
    // gateway goes in config where scan ingest reads it for internet exposure.
    if (default_gateway && isIPv4(default_gateway)) {
      updateData.config = { ...((agent.config ?? {}) as Record<string, unknown>), default_gateway }
    }
    // What a 2.4.0+ agent says about itself: its kind (from its installer), its own
    // settings, what it can do, and the policy version it applied.
    const report = cleanReport(body)
    if (body.settings !== undefined || body.policy_version !== undefined) {
      updateData.reported = {
        settings: report.settings, capabilities: report.capabilities, networks: report.networks,
        policy_version: report.policyVersion, reported_at: new Date().toISOString(),
      }
    }
    if (report.kind && report.kind !== agent.kind) updateData.kind = report.kind

    // Its first report: what it was set up with on its computer becomes its settings on the
    // dashboard (lib/agentPolicy.ts adoptLocal), once; the dashboard decides from then on.
    const policies = await tenantPolicies(db, [agent.tenantId])
    const config = ((updateData.config ?? agent.config ?? {}) as Record<string, unknown>)
    if (body.settings !== undefined && config.adopted_local !== true) {
      updateData.policy = adoptLocal(report.kind ?? agent.kind, report.settings, agent.policy,
        policies.get(agent.tenantId ?? '')?.agentPolicy)
      updateData.config = { ...config, adopted_local: true }
    }

    const [current] = await db.update(agents).set(updateData).where(eq(agents.agentId, agentId)).returning()

    // Every setting of this agent (managed), for it to apply between jobs (2.4.0+).
    const resolved = policyOf(current ?? agent, policies.get(agent.tenantId ?? '') ?? null)
    return c.json({
      ok: true,
      // local_scans: agents before 2.6 grey out their own "Scan now"; scans start from the dashboard.
      policy: { local_scans: false, managed: resolved.managed, version: resolved.version },
      ...(body.want_jobs === true ? { scans: await pendingJobsFor(db, agentId) } : {}),
    })
  }
)

// ── POST /:agentId/inventory — endpoint inventory of the agent's own machine ──
// Agent API key auth. Binds the inventory to an asset (see lib/endpointInventory
// bindMachine: bound > hardware UUID > OS install id > MAC > hostname > IP, with the
// VM-clone guard), creating one in Discovered when none matches. Stores the facts and
// machine identifiers, follows the machine's address and self-reported device type
// (recomputing criticality), and syncs asset_software by diff.
const inventorySoftware = z.object({
  name: z.string().min(1).max(255),
  version: z.string().max(100).nullish(),
  publisher: z.string().max(255).nullish(),
  install_date: z.string().max(10).nullish(),
  scope: z.string().max(16).nullish(),
  arch: z.string().max(16).nullish(),
})
const inventorySchema = z.object({
  schema: z.literal(1),
  platform: z.string().max(16),
  collected_at: z.string().max(40),
  identity: z.object({
    hostname: z.string().max(255).nullish(),
    dns_hostname: z.string().max(255).nullish(),
  }).passthrough(),
  hardware: z.object({
    manufacturer: z.string().max(255).nullish(),
    form_factor: z.string().max(16).nullish(),
  }).passthrough().optional(),
  os: z.object({ role: z.string().max(32).nullish() }).passthrough().optional(),
  network: z.object({
    primary_ip: z.string().max(45).nullish(),
    interfaces: z.array(z.object({
      name: z.string().max(255).nullish(),
      mac: z.string().max(32).nullish(),
      physical: z.boolean().optional(),
      ipv4: z.array(z.string().max(45)).max(32).optional(),
    }).passthrough()).max(64),
    listening: z.array(z.unknown()).max(5000).optional(),
  }).passthrough(),
  software: z.array(inventorySoftware).max(5000),
}).passthrough()

router.post('/:agentId/inventory', zValidator('json', inventorySchema), async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL)
    const { agentId } = c.req.param()
    const authHeader = c.req.header('Authorization')
    if (!authHeader?.startsWith('Bearer ')) return c.json({ detail: 'Missing Authorization header' }, 401)

    const [agent] = await db.select().from(agents).where(eq(agents.agentId, agentId)).limit(1)
    if (!agent) return c.json({ detail: 'Agent not found' }, 404)
    if (await hashApiKey(authHeader.slice(7)) !== agent.apiKeyHash) return c.json({ detail: 'Invalid API key' }, 401)
    const tenantId = agent.tenantId
    if (!tenantId) return c.json({ detail: 'Agent has no tenant; register it from a tenant account' }, 400)

    const inv = c.req.valid('json') as unknown as InventoryPayload
    const macs = identityMacs(inv)
    const hostKey = inventoryHostKey(inv)
    const ips = inventoryIps(inv)
    const identifiers = machineIdentifiers(inv)
    const hardwareUuid = identifiers.find(i => i.kind === 'hardware_uuid')?.value ?? null
    const osInstallId = identifiers.find(i => i.kind === 'os_install_id')?.value ?? null
    const hostname = inv.identity.hostname?.trim() || null
    const vendor = inv.hardware?.manufacturer?.trim() || null
    const ip = ips[0] ?? null
    const mac = primaryMac(inv)
    // Same key as the scans of this tenant use for the address (lib/networkScope.ts).
    const networkKey = ip ? (await resolveNetworkScope(db, tenantId, null)).keyFor(ip) : null
    const reportedType = deviceTypeFor(inv)
    const agentRole = typeof inv.os?.role === 'string' ? inv.os.role : null
    const now = new Date()
    const parsedAt = new Date(inv.collected_at)
    // The agent's clock is not trusted: a time in the future (a PC whose clock runs ahead) would
    // keep its alerts fresh forever and win every "newest inventory" comparison, so it is clamped
    // to now; one more than 7 days old is taken as now too (the report is arriving now).
    const collectedAt = isNaN(parsedAt.getTime()) || parsedAt > now || now.getTime() - parsedAt.getTime() > 7 * 86400_000
      ? now : parsedAt

    // ── Candidate assets (one query per rule, all tenant-scoped) ──
    const hasMac = sql<boolean>`(${assets.macAddress} IS NOT NULL OR EXISTS (
      SELECT 1 FROM ${assetAddresses} aa WHERE aa.asset_id = "assets"."asset_id" AND aa.mac_address IS NOT NULL))`
    // Hardware UUIDs an agent reported for the candidate (the VM-clone guard needs them).
    // Correlated subqueries name "assets"."asset_id" literally: in a select list Drizzle
    // renders ${assets.assetId} unqualified, which inside the subquery would bind to the
    // subquery's own asset_id column and make the condition always true.
    const hardwareUuids = sql<string[]>`ARRAY(SELECT ai.value FROM ${assetIdentifiers} ai
      WHERE ai.asset_id = "assets"."asset_id" AND ai.kind = 'hardware_uuid')::text[]`
    const candidates = (where: SQL | undefined): Promise<BindingCandidate[]> =>
      where
        ? db.select({ assetId: assets.assetId, inMyAssets: assets.inMyAssets, lastScanned: assets.lastScanned, hasMac, hardwareUuids })
            .from(assets).where(and(eq(assets.tenantId, tenantId), where))
        : Promise.resolve([])
    // Hardware UUIDs are looked up in both byte orders (rows stored before normalisation).
    const byIdentifier = (kind: string, value: string | null) => candidates(value
      ? inArray(assets.assetId, db.select({ id: assetIdentifiers.assetId }).from(assetIdentifiers).where(and(
          eq(assetIdentifiers.tenantId, tenantId), eq(assetIdentifiers.kind, kind),
          inArray(assetIdentifiers.value, kind === 'hardware_uuid' ? hardwareUuidForms(value) : [value]))))
      : undefined)

    const criticalityModel = ACTIVE_MODEL
    const [bound, hardwareUuidMatches, osInstallIdMatches, macMatches, hostKeyMatches, ipMatches] = await Promise.all([
      agent.hostAssetId ? candidates(eq(assets.assetId, agent.hostAssetId)) : Promise.resolve([]),
      byIdentifier('hardware_uuid', hardwareUuid),
      byIdentifier('os_install_id', osInstallId),
      candidates(macs.length ? or(
        inArray(assets.macAddress, macs),
        inArray(assets.assetId, db.select({ id: assetAddresses.assetId }).from(assetAddresses)
          .where(and(eq(assetAddresses.tenantId, tenantId), inArray(assetAddresses.macAddress, macs)))),
        inArray(assets.assetId, db.select({ id: assetIdentifiers.assetId }).from(assetIdentifiers)
          .where(and(eq(assetIdentifiers.tenantId, tenantId), eq(assetIdentifiers.kind, 'mac'), inArray(assetIdentifiers.value, macs)))),
      ) : undefined),
      candidates(hostKey ? or(eq(assets.hostKey, hostKey), sql`lower(${assets.hostname}) = ${hostKey}`) : undefined),
      candidates(ips.length ? inArray(assets.ipAddress, ips) : undefined),
    ])

    const binding = bindMachine({
      boundAssetId: bound[0]?.assetId ?? null, boundHardwareUuids: bound[0]?.hardwareUuids ?? [],
      hardwareUuid, hardwareUuidMatches, osInstallIdMatches, macMatches, hostKeyMatches, ipMatches,
    })
    const decision = binding.decision
    if (binding.differentHardware.length > 0) {
      // Same OS install / MACs / name as another asset but different hardware: a cloned
      // VM (or a new mainboard). Kept apart; Duplicates lists the pair for review.
      console.log(`inventory: agent=${agentId} differs in hardware from asset(s) ${binding.differentHardware.join(',')}`)
    }
    let assetId: string
    let created = false
    const statements: unknown[] = []

    if (decision) {
      assetId = decision.assetId
      // ── Matched: device type, criticality and address follow the machine's report ──
      const [cur] = await db.select({
        deviceType: assets.deviceType, deviceTypeSource: assets.deviceTypeSource, baselineState: assets.baselineState,
        hostname: assets.hostname, owner: assets.owner, osInfo: assets.osInfo, isInternetFacing: assets.isInternetFacing,
        internetFacingOverride: assets.internetFacingOverride,
      }).from(assets).where(eq(assets.assetId, assetId)).limit(1)
      if (!cur) return c.json({ detail: 'Asset disappeared while storing the inventory; retry' }, 409)
      const dt = resolveAgentDeviceType(cur, reportedType)
      const set: Record<string, unknown> = {
        deviceType: dt.deviceType,
        deviceTypeSource: dt.deviceTypeSource,
        criticalityScore: scoreAsset({
          deviceType: dt.deviceType, deviceTypeSource: dt.deviceTypeSource, isInternetFacing: cur.isInternetFacing,
          internetFacingOverride: cur.internetFacingOverride, hostname: cur.hostname ?? hostname,
          osInfo: cur.osInfo as Record<string, unknown> | null, owner: cur.owner, agentRole,
        }, criticalityModel),
        criticalityModel,
      }
      // An automatic baseline still holding the old type moves with it (not drift).
      const baseline = cur.baselineState as Record<string, unknown> | null
      if (dt.changed && baseline?.['auto_set'] === true && baseline['device_type'] === cur.deviceType) {
        set.baselineState = { ...baseline, device_type: dt.deviceType }
      }
      if (ip) {
        set.ipAddress = ip
        if (mac) set.macAddress = mac
        const current = await db.select({
          addressId: assetAddresses.addressId, assetId: assetAddresses.assetId, networkKey: assetAddresses.networkKey,
          ipAddress: assetAddresses.ipAddress, macAddress: assetAddresses.macAddress,
        }).from(assetAddresses).where(and(
          eq(assetAddresses.tenantId, tenantId), isNull(assetAddresses.endedAt),
          networkKey
            ? or(eq(assetAddresses.assetId, assetId), and(eq(assetAddresses.networkKey, networkKey), eq(assetAddresses.ipAddress, ip)))
            : eq(assetAddresses.assetId, assetId),
        ))
        for (const op of planAgentAddress(assetId, ip, mac, networkKey, current)) {
          if (op.k === 'refresh') {
            statements.push(db.update(assetAddresses).set({ lastSeen: now, macAddress: op.macAddress, networkKey: op.networkKey })
              .where(eq(assetAddresses.addressId, op.addressId)))
          } else if (op.k === 'end') {
            statements.push(db.update(assetAddresses).set({ endedAt: now }).where(eq(assetAddresses.addressId, op.addressId)))
          } else {
            statements.push(db.insert(assetAddresses).values({
              assetId, tenantId, networkKey: op.networkKey, ipAddress: op.ipAddress, macAddress: op.macAddress, firstSeen: now, lastSeen: now,
            }))
          }
        }
      }
      statements.push(db.update(assets).set(set).where(eq(assets.assetId, assetId)))
    } else {
      // ── No match: create the asset in Discovered ──
      if (!ip) return c.json({ detail: 'Inventory has no IPv4 address to identify this machine' }, 400)
      assetId = crypto.randomUUID()
      created = true
      // Another device may still hold this IP as its current address (DHCP reuse):
      // end that row first, as scan ingest does, so the unique current-address index holds.
      const holders = networkKey
        ? await db.select({ addressId: assetAddresses.addressId }).from(assetAddresses).where(and(
            eq(assetAddresses.tenantId, tenantId), eq(assetAddresses.networkKey, networkKey),
            eq(assetAddresses.ipAddress, ip), isNull(assetAddresses.endedAt)))
        : []
      const known = reportedType !== 'unknown'
      statements.push(
        ...holders.map(h => db.update(assetAddresses).set({ endedAt: now }).where(eq(assetAddresses.addressId, h.addressId))),
        db.insert(assets).values({
          assetId, tenantId, ipAddress: ip, hostname, macAddress: mac, hostKey,
          hardwareVendor: vendor, deviceType: reportedType, deviceTypeSource: known ? 'agent' : 'auto', osInfo: {},
          criticalityScore: scoreAsset({
            deviceType: reportedType, deviceTypeSource: known ? 'agent' : 'auto', isInternetFacing: false,
            hostname, owner: null, osInfo: {}, agentRole,
          }, criticalityModel),
          criticalityModel,
          source: 'agent', inMyAssets: false, lastScanned: now, createdAt: now, updatedAt: now,
        }),
        db.insert(assetAddresses).values({
          assetId, tenantId, networkKey, ipAddress: ip, macAddress: mac, firstSeen: now, lastSeen: now,
        }),
        // No new_device alert: an agent is installed by IT, so its computer is a managed
        // device by definition. New devices are what network scans find.
      )
    }

    // Machine identifiers: history, refreshed on every inventory.
    if (identifiers.length > 0) {
      statements.push(db.insert(assetIdentifiers)
        .values(identifiers.map(i => ({ assetId, tenantId, kind: i.kind, value: i.value, source: 'agent', firstSeen: now, lastSeen: now })))
        .onConflictDoUpdate({
          target: [assetIdentifiers.assetId, assetIdentifiers.kind, assetIdentifiers.value],
          set: { lastSeen: now },
        }))
    }

    // ── Store facts (and the posture they imply); fill identity gaps only (never overwrite what a user or scan set) ──
    const existingSoftware = await db.select({
      softwareId: assetSoftware.softwareId, name: assetSoftware.name,
      version: assetSoftware.version, publisher: assetSoftware.publisher,
    }).from(assetSoftware).where(eq(assetSoftware.assetId, assetId))
    const diff = diffSoftware(existingSoftware, inv.software)
    const stored = storedInventory(inv)

    statements.push(
      db.update(assets).set({
        endpointInventory: stored,
        inventoryCollectedAt: collectedAt,
        ...postureColumns(stored, collectedAt),
        lastScanned: now,
        updatedAt: now,
        hostname: sql`COALESCE(NULLIF(${assets.hostname}, ''), ${hostname})`,
        hardwareVendor: sql`COALESCE(${assets.hardwareVendor}, ${vendor})`,
        hostKey: sql`COALESCE(${assets.hostKey}, ${hostKey})`,
      }).where(eq(assets.assetId, assetId)),
      db.update(agents).set({ hostAssetId: assetId }).where(eq(agents.agentId, agentId)),
      // Any inventory from this agent answers its dashboard "Collect inventory" jobs.
      db.update(scanResults).set({ status: 'completed', completedAt: now, failureReason: null })
        .where(and(eq(scanResults.agentId, agentId), eq(scanResults.scanType, 'inventory'),
          inArray(scanResults.status, ['pending', 'running']))),
    )
    for (let i = 0; i < diff.deleteIds.length; i += 500) {
      statements.push(db.delete(assetSoftware).where(inArray(assetSoftware.softwareId, diff.deleteIds.slice(i, i + 500))))
    }
    statements.push(db.update(assetSoftware).set({ lastSeen: now }).where(eq(assetSoftware.assetId, assetId)))
    for (let i = 0; i < diff.insert.length; i += 100) {
      statements.push(db.insert(assetSoftware).values(diff.insert.slice(i, i + 100).map(s => ({
        assetId, name: s.name, version: s.version ?? null, publisher: s.publisher ?? null,
        installDate: s.install_date ?? null, scope: s.scope ?? null, arch: s.arch ?? null,
        source: 'agent', firstSeen: now, lastSeen: now,
      }))))
    }
    await db.batch(statements as unknown as Parameters<typeof db.batch>[0])
    // This computer now runs a bound agent, so its new-device alert has been dealt with.
    await closeReviewedNewDevices(db, { assetIds: [assetId] }).catch(err => console.error('new-device hygiene failed:', err))
    // The agent's facts (hostname, adapters) may have changed: check drift now rather than
    // at the next scan or the 6-hourly audit. Same queue job scans send.
    try {
      await c.env.ADVISORY_QUEUE.send({ type: 'drift_check', assetId, agentId })
    } catch (err) {
      console.error('inventory: queueing the drift check failed:', err)
    }
    // Its installed software may now be on a watchlist (R6).
    try {
      await matchIocs(db, { assetId })
    } catch (err) {
      console.error('inventory: threat-intel matching failed:', err)
    }
    // Windows build against the fixes Microsoft has released: one alert while it is behind.
    try {
      await checkWindowsPatch(db, c.env.REPORTS_BUCKET, assetId, inv)
    } catch (err) {
      console.error('inventory: Windows patch check failed:', err)
    }

    return c.json({
      asset_id: assetId,
      created,
      matched_by: decision?.matchedBy ?? null,
      different_hardware: binding.differentHardware,
      software: { added: diff.insert.length, removed: diff.deleteIds.length, unchanged: diff.unchanged },
    })
  } catch (err) {
    console.error('agents POST /:agentId/inventory error:', err)
    return c.json({ detail: 'Failed to store inventory' }, 500)
  }
})

export default router
