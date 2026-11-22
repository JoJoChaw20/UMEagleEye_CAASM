import { Hono, type Context } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { eq, count, and } from 'drizzle-orm'
import type { Env } from '../types'
import {
  authMiddleware, hasAction, requireAction, requireOwnTenant, requirePlatformSuperadmin, requireTenantSuperadmin,
} from '../middleware/auth'
import { getDb, type DB } from '../db/client'
import { tenants, users, assets, auditLogs } from '../db/schema'
import { AGENT_KINDS, DEFAULTS, POLICY_SPECS, ROLE_KEYS, applyChange, kindKeys, tenantDefaultsFor, type PolicyKey, type PolicyValue } from '../lib/agentPolicy'
import { actionChanges, addRefusal, parseActionList, type Refusal } from '../lib/userAdmin'
import { defaultsChangeActions, tenantPatchRefusal } from '../lib/policyChange'
import { isFkViolation, isNotNullViolation, isOwnerIndexViolation, isUniqueViolation } from '../lib/fkViolation'
import { decide, normalizeAccount, refusalMessage } from '../lib/actions'
import { planActionsUpdate, roleOf, tenantUserItem } from '../lib/accountRows'
import { audit } from '../services/audit'
import { mfaClearStatements, stepUp } from '../services/mfaStepUp'
import { ACCOUNT_CHANGED, deleteUserStatements } from '../services/userDelete'
import { sendMail } from '../services/mailer'
import { stillOwner } from '../lib/ownership'
import { isDeactivated } from '../lib/sessionGate'
import { ALREADY_OWNED, OWNERSHIP_ONLY, auditOwnerInvite, ownerInviteStatement, planOwnerInvite, usernameFor } from '../services/ownerInvite'
import { confirmMatches, deleteTarget, resetTarget } from '../lib/mfaFlow'
import { NO_PASSWORD_HASH, hashPassword } from '../lib/auth'
import { inviteCredentials } from '../lib/passwordRules'

const USERNAME_TAKEN = { detail: 'That username is already taken. Choose another one.' }
import { networkTargetErrors } from '../services/scanTargets'

const router = new Hono<{ Bindings: Env }>()

// Guards (middleware/guards.ts) are written on each route, so lib/routeGuard.test.ts can see them.
// Until the tenant provisioning flow exists (access-control spec, section 5), the Platform
// Superadmin lists, creates, switches off and deactivates tenants here, and invites a tenant's
// first Tenant Superadmin.


// Every change to a user's actions is audited as user.actions, with what was added and removed.
async function auditActions(db: DB, c: Context, by: string, tenantId: string, target: string, previous: readonly string[], next: readonly string[]) {
  const { added, removed } = actionChanges(previous, next)
  await audit(db, c, {
    userId: by, tenantId, actionType: 'user.actions', targetEntity: target,
    previousState: { actions: previous }, newState: { actions: next, added, removed },
  })
}

// What a refused add says (lib/userAdmin.ts). To a tenant superadmin, an account they may not add
// looks like one that does not exist, so accounts of other tenants cannot be discovered.
function refusalDetail(r: Refusal, callerIsSuperadmin: boolean, what: string): { detail: string; status: 403 | 404 } {
  if (callerIsSuperadmin) {
    if (r === 'tenant_superadmin') return { detail: `That account is already a Tenant Superadmin. ${OWNERSHIP_ONLY}`, status: 403 }
    if (r === 'other_tenant') return { detail: 'This account belongs to another tenant.', status: 403 }
    return { detail: 'The platform superadmin cannot be added to a tenant', status: 403 }
  }
  return { detail: `No user available with that ${what}`, status: 404 }
}

// ── GET / — List all tenants (Platform Superadmin) ────────────────
router.get('/', authMiddleware, requirePlatformSuperadmin, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const rows = await db.select().from(tenants)
  return c.json({
    tenants: rows.map((t) => ({
      tenant_id: t.tenantId,
      name: t.name,
      slug: t.slug,
      is_active: t.isActive,
      created_at: t.createdAt,
    })),
  })
})

// ── POST / — Create tenant (Platform Superadmin) ──────────────────
router.post(
  '/',
  authMiddleware,
  requirePlatformSuperadmin,
  zValidator('json', z.object({
    name: z.string().min(1).max(100),
    slug: z.string().min(1).max(50).regex(/^[a-z0-9-]+$/, 'Slug must be lowercase kebab-case'),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { name, slug } = c.req.valid('json')

    const [existing] = await db.select().from(tenants).where(eq(tenants.slug, slug)).limit(1)
    if (existing) return c.json({ detail: 'Slug already in use' }, 409)

    const tenantRows = await db.insert(tenants).values({ name, slug }).returning()
    const tenant = tenantRows[0]
    if (!tenant) return c.json({ detail: 'Failed to create tenant' }, 500)
    await audit(db, c, { userId: c.get('user').userId, tenantId: tenant.tenantId, actionType: 'tenant.create', targetEntity: tenant.tenantId, newState: { name, slug } })

    return c.json({
      tenant_id: tenant.tenantId,
      name: tenant.name,
      slug: tenant.slug,
      is_active: tenant.isActive,
      created_at: tenant.createdAt,
    }, 201)
  }
)

// ── GET /:tenantId — Single tenant with counts ────────────────────
// "View tenant settings": the Platform Superadmin sees any tenant, everyone else only their own.
router.get('/:tenantId', authMiddleware, requireAction('settings.view'), requireOwnTenant, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const { tenantId } = c.req.param()

  const [tenant] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
  if (!tenant) return c.json({ detail: 'Tenant not found' }, 404)

  const [userCountRow] = await db
    .select({ value: count() })
    .from(users)
    .where(eq(users.tenantId, tenantId))

  const [assetCountRow] = await db
    .select({ value: count() })
    .from(assets)
    .where(and(eq(assets.tenantId, tenantId), eq(assets.inMyAssets, true)))

  return c.json({
    tenant_id: tenant.tenantId,
    name: tenant.name,
    slug: tenant.slug,
    is_active: tenant.isActive,
    created_at: tenant.createdAt,
    auto_investigate_new_devices: tenant.autoInvestigateNewDevices,
    allow_local_scans: tenant.allowLocalScans,
    user_count: Number(userCountRow?.value ?? 0),
    asset_count: Number(assetCountRow?.value ?? 0),
  })
})

// ── PATCH /:tenantId — Update tenant ─────────────────────────────
// Platform Superadmin: is_active only. Tenant Superadmin of this tenant: name. The scan policy
// (auto-investigate new devices, allow agents' local scans) needs "Change scan policy", audited.
// Who may change which field: lib/policyChange.ts (tenantPatchRefusal). Everyone who may change
// something here holds "View tenant settings", the route guard.
router.patch(
  '/:tenantId',
  authMiddleware,
  requireAction('settings.view'),
  zValidator('json', z.object({
    name: z.string().min(1).max(100).optional(),
    is_active: z.boolean().optional(),
    auto_investigate_new_devices: z.boolean().optional(),
    allow_local_scans: z.boolean().optional(),
  }).strict()),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId } = c.req.param()
    const user = c.get('user')
    const updates = c.req.valid('json')
    const refused = tenantPatchRefusal(user, tenantId, updates)
    if (refused) {
      const { status, ...body } = refused
      return c.json(body, status)
    }

    const [existing] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
    if (!existing) return c.json({ detail: 'Tenant not found' }, 404)

    const updateData: Record<string, unknown> = {}
    if (updates.name !== undefined) updateData.name = updates.name
    if (updates.is_active !== undefined) updateData.isActive = updates.is_active
    const policy: Record<string, boolean> = {}
    if (updates.auto_investigate_new_devices !== undefined && updates.auto_investigate_new_devices !== existing.autoInvestigateNewDevices) {
      updateData.autoInvestigateNewDevices = policy.auto_investigate_new_devices = updates.auto_investigate_new_devices
    }
    if (updates.allow_local_scans !== undefined && updates.allow_local_scans !== existing.allowLocalScans) {
      updateData.allowLocalScans = policy.allow_local_scans = updates.allow_local_scans
    }
    if (Object.keys(updateData).length === 0) {
      return c.json({
        tenant_id: existing.tenantId, name: existing.name, slug: existing.slug, is_active: existing.isActive,
        auto_investigate_new_devices: existing.autoInvestigateNewDevices, allow_local_scans: existing.allowLocalScans,
      })
    }

    const updatedRows = await db.update(tenants).set(updateData).where(eq(tenants.tenantId, tenantId)).returning()
    const updated = updatedRows[0]
    if (!updated) return c.json({ detail: 'Tenant not found' }, 404)

    if (Object.keys(policy).length) {
      await db.insert(auditLogs).values({
        userId: user.userId, tenantId, actionType: 'tenant.scan_policy', targetEntity: tenantId,
        previousState: { auto_investigate_new_devices: existing.autoInvestigateNewDevices, allow_local_scans: existing.allowLocalScans },
        newState: policy,
      }).catch(err => console.error('tenant scan policy audit failed:', err))
    }

    return c.json({
      tenant_id: updated.tenantId,
      name: updated.name,
      slug: updated.slug,
      is_active: updated.isActive,
      auto_investigate_new_devices: updated.autoInvestigateNewDevices,
      allow_local_scans: updated.allowLocalScans,
    })
  }
)

// ── Default agent settings of a tenant (lib/agentPolicy.ts) ────────
// A setting set here applies to every agent of that kind in the tenant that has no override
// of its own; one not set here is the built-in default (DEFAULTS, shown as `builtin`). Each
// kind of agent (computers, network agents, phones) has defaults of its own.
type KindDefaults = Record<string, Partial<Record<PolicyKey, PolicyValue>>>

const defaultsByKind = (stored: unknown): KindDefaults =>
  Object.fromEntries(AGENT_KINDS.map((kind) => [kind, tenantDefaultsFor(stored, kind)]))

function agentPolicyOut(t: typeof tenants.$inferSelect, canEdit: boolean) {
  const defaults = defaultsByKind(t.agentPolicy)
  return {
    tenant_id: t.tenantId,
    kinds: AGENT_KINDS.map((kind) => ({
      kind,
      settings: kindKeys(kind).map((key) => ({
        key, value: defaults[kind]![key] ?? null, builtin: DEFAULTS[key], spec: POLICY_SPECS[key],
      })),
    })),
    role_settings: ROLE_KEYS,
    can_edit: canEdit,
  }
}

router.get('/:tenantId/agent-policy', authMiddleware, requireAction('settings.view', 'agent.view'), requireOwnTenant, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const user = c.get('user')
  const [tenant] = await db.select().from(tenants).where(eq(tenants.tenantId, c.req.param('tenantId'))).limit(1)
  if (!tenant) return c.json({ detail: 'Tenant not found' }, 404)
  return c.json(agentPolicyOut(tenant, hasAction(user, 'settings.agent_defaults.edit')))
})

// {settings: {kind: {setting: value | null}}}: null = no tenant default (each agent's own).
router.patch(
  '/:tenantId/agent-policy',
  authMiddleware,
  requireAction('settings.agent_defaults.edit'),
  requireOwnTenant,
  zValidator('json', z.object({ settings: z.record(z.string(), z.record(z.string(), z.unknown())) })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const user = c.get('user')
    const { tenantId } = c.req.param()
    const [tenant] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
    if (!tenant) return c.json({ detail: 'Tenant not found' }, 404)

    const changes = c.req.valid('json').settings
    for (const key of defaultsChangeActions(changes)) {
      const decision = decide(user, key)
      if (!decision.ok) return c.json({ detail: refusalMessage(decision.reason, key), missing_action: key }, 403)
    }
    const policy = defaultsByKind(tenant.agentPolicy)
    const errors: string[] = []
    for (const [kind, change] of Object.entries(changes)) {
      if (!AGENT_KINDS.includes(kind)) { errors.push(`${kind}: not a kind of agent`); continue }
      const applied = applyChange(policy[kind], change, kindKeys(kind))
      policy[kind] = applied.policy
      errors.push(...applied.errors.map((e) => `${kind} ${e}`))
    }
    if (errors.length) return c.json({ detail: errors.join('; ') }, 400)
    const targetErrors = await networkTargetErrors(db, tenantId, changes.network ?? {})
    if (targetErrors.length) return c.json({ detail: targetErrors.join('; ') }, 400)

    const [updated] = await db.update(tenants)
      .set({ agentPolicy: policy })
      .where(eq(tenants.tenantId, tenantId)).returning()
    if (!updated) return c.json({ detail: 'Tenant not found' }, 404)
    await db.insert(auditLogs).values({
      userId: user.userId, tenantId, actionType: 'tenant.agent_policy', targetEntity: tenantId,
      previousState: { agent_policy: tenant.agentPolicy },
      newState: { agent_policy: policy },
    }).catch(err => console.error('tenant agent policy audit failed:', err))
    return c.json(agentPolicyOut(updated, true))
  }
)

// ── DELETE /:tenantId — Deactivate tenant (Platform Superadmin) ───
router.delete('/:tenantId', authMiddleware, requirePlatformSuperadmin, async (c) => {
  const db = getDb(c.env.DATABASE_URL)
  const { tenantId } = c.req.param()

  const [existing] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
  if (!existing) return c.json({ detail: 'Tenant not found' }, 404)

  await db.update(tenants).set({ isActive: false }).where(eq(tenants.tenantId, tenantId))
  await audit(db, c, { userId: c.get('user').userId, tenantId, actionType: 'tenant.deactivate', targetEntity: tenantId, previousState: { is_active: existing.isActive } })

  return c.json({ ok: true })
})

// ── GET /:tenantId/users — List users in tenant ───────────────────
// The tenant's own Tenant Superadmin; the Platform Superadmin reads any tenant's list ("View tenant
// settings" is a read action it holds). Each row has the account's role and granted actions.
router.get(
  '/:tenantId/users',
  authMiddleware,
  (c, next) => (c.get('user').role === 'superadmin' ? requireAction('settings.view') : requireTenantSuperadmin)(c, next),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId } = c.req.param()

    const [tenant] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
    if (!tenant) return c.json({ detail: 'Tenant not found' }, 404)

    const rows = await db.select({
      userId: users.userId,
      username: users.username,
      email: users.email,
      role: users.role,
      actions: users.actions,
      isActive: users.isActive,
      scheduledDeactivationAt: users.scheduledDeactivationAt,
      createdAt: users.createdAt,
      lastLogin: users.lastLogin,
    }).from(users).where(eq(users.tenantId, tenantId))

    // A legacy role reads as a tenant user with its converted actions (lib/accountRows.ts).
    return c.json({ users: rows.map(tenantUserItem) })
  }
)

// ── POST /:tenantId/users — Assign existing user to tenant ────────
// The Tenant Superadmin of this tenant, and only accounts without a tenant (lib/userAdmin.ts).
// The account joins as a tenant user with no actions. Accepts user_id (UUID) or username for lookup.
router.post(
  '/:tenantId/users',
  authMiddleware,
  requireTenantSuperadmin,
  zValidator('json', z.object({
    user_id:  z.string().uuid().optional(),
    username: z.string().min(1).optional(),
  }).refine(d => d.user_id || d.username, { message: 'Either user_id or username is required' })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId } = c.req.param()
    const { user_id, username } = c.req.valid('json')
    const caller = c.get('user')
    const what = user_id ? 'ID' : 'username'

    const [tenant] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
    if (!tenant) return c.json({ detail: 'Tenant not found' }, 404)

    const [user] = await db.select().from(users)
      .where(user_id ? eq(users.userId, user_id) : eq(users.username, username!)).limit(1)
    if (!user) return c.json({ detail: `No user available with that ${what}` }, 404)
    const refusal = addRefusal(caller, { ...user, role: roleOf(user) }, tenantId)
    if (refusal) {
      const { detail, status } = refusalDetail(refusal, false, what)
      return c.json({ detail }, status)
    }
    // Adding again would wipe the actions already granted; those change through PUT .../actions.
    if (user.tenantId === tenantId) return c.json({ detail: 'This user is already in this tenant.' }, 409)

    await db.update(users).set({ tenantId, role: 'tenant_user', actions: [] }).where(eq(users.userId, user.userId))
    await audit(db, c, {
      userId: caller.userId, tenantId, actionType: 'user.assign', targetEntity: user.userId,
      previousState: { tenant_id: user.tenantId, role: user.role, actions: user.actions },
      newState: { tenant_id: tenantId, role: 'tenant_user', actions: [] },
    })
    // The assign also took away any actions the user had: record that as an actions change too
    if (user.actions?.length) await auditActions(db, c, caller.userId, tenantId, user.userId, user.actions, [])

    return c.json({ ok: true, user_id: user.userId, username: user.username, tenant_id: tenantId, role: 'tenant_user', actions: [] })
  }
)

// ── POST /:tenantId/users/invite — Create or assign user by email, or create one with a starting password ──
// The Tenant Superadmin of this tenant invites tenant users, with the actions to grant (closed over
// their requirements). Until the provisioning flow exists (spec, section 5), the Platform Superadmin
// may only invite a tenant's first Tenant Superadmin: as_tenant_superadmin, into a tenant that has none.
// Without an email, `username` and `password` create a new account with that starting password; its owner
// must choose their own at first sign-in and may connect Google later (POST /auth/google/connect).
router.post(
  '/:tenantId/users/invite',
  authMiddleware,
  (c, next) => (c.get('user').role === 'superadmin' ? requirePlatformSuperadmin : requireTenantSuperadmin)(c, next),
  zValidator('json', z.object({
    email: z.string().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
    actions: z.array(z.string()).optional(),
    as_tenant_superadmin: z.boolean().optional(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId } = c.req.param()
    const body = c.req.valid('json')
    const { actions: requested, as_tenant_superadmin } = body
    const creds = inviteCredentials(body)
    if (!creds.ok) return c.json({ detail: creds.detail }, 400)
    const { email, username } = creds
    const startingHash = creds.password ? await hashPassword(creds.password) : undefined
    const caller = c.get('user')
    const byPlatform = caller.role === 'superadmin'

    let role: 'tenant_superadmin' | 'tenant_user'
    let actions: string[] = []   // stays empty for a Tenant Superadmin, which holds every action
    if (byPlatform) {
      if (!as_tenant_superadmin) {
        return c.json({ detail: "The Platform Superadmin can only invite a tenant's first Tenant Superadmin." }, 403)
      }
      if (requested?.length) return c.json({ detail: 'A Tenant Superadmin holds every action; send no actions.' }, 400)
      role = 'tenant_superadmin'
    } else {
      if (as_tenant_superadmin) return c.json({ detail: OWNERSHIP_ONLY }, 403)
      const parsed = parseActionList(requested ?? [])
      if (!parsed.ok) return c.json({ detail: `Unknown actions: ${parsed.unknown.join(', ')}` }, 400)
      role = 'tenant_user'
      actions = parsed.actions
    }

    if (role === 'tenant_superadmin') {
      // The shared owner-invite path (services/ownerInvite.ts), also used by the platform restore.
      const plan = await planOwnerInvite(db, caller, tenantId, email, username, false)
      if (!plan.ok) return c.json({ detail: plan.error.detail }, plan.error.status)
      if (plan.existing && isDeactivated(plan.existing)) {
        return c.json({ detail: 'That account is deactivated. Choose an active account or a new email.' }, 409)
      }
      try {
        const [added] = await ownerInviteStatement(db, plan, tenantId, email, undefined, startingHash)
        if (!added) return c.json(ALREADY_OWNED, 409)
        await auditOwnerInvite(db, c, caller, tenantId, plan, added, email)
        return c.json({
          ok: true, user_id: added.userId, username: added.username, email: added.email,
          role, actions, action: plan.existing ? 'assigned' : 'created',
        }, plan.existing ? 200 : 201)
      } catch (err) {
        // Two invitations at once: the unique index (one tenant superadmin per tenant) refuses the second.
        if (isOwnerIndexViolation(err) || isNotNullViolation(err)) {
          return c.json(ALREADY_OWNED, 409)
        }
        if (isUniqueViolation(err)) return c.json(USERNAME_TAKEN, 409)
        throw err
      }
    }

    const [tenant] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
    if (!tenant) return c.json({ detail: 'Tenant not found' }, 404)

    try {
      const [existing] = email === null ? [] : await db.select().from(users).where(eq(users.email, email)).limit(1)
      if (existing) {
        const refusal = addRefusal(caller, { ...existing, role: roleOf(existing) }, tenantId)
        if (refusal) {
          // Not a 404 here (an unknown email creates an account): the same answer for every refusal.
          return c.json({ detail: byPlatform ? refusalDetail(refusal, true, 'email').detail
            : 'This email cannot be invited to your tenant. Ask the platform administrator.' }, 403)
        }
        // Inviting again would wipe the actions already granted; those change through PUT .../actions.
        if (!byPlatform && existing.tenantId === tenantId) return c.json({ detail: 'This user is already in this tenant.' }, 409)
        await db.update(users).set({ tenantId, role, actions }).where(eq(users.userId, existing.userId))
        await audit(db, c, {
          userId: caller.userId, tenantId, actionType: 'user.assign', targetEntity: existing.userId,
          previousState: { tenant_id: existing.tenantId, role: existing.role, actions: existing.actions },
          newState: { tenant_id: tenantId, by: 'email', role, actions },
        })
        if (actions.length) await auditActions(db, c, caller.userId, tenantId, existing.userId, normalizeAccount(existing.role, existing.actions).actions, actions)
        return c.json({
          ok: true,
          user_id: existing.userId,
          username: existing.username,
          email: existing.email,
          role,
          actions,
          action: 'assigned',
        })
      }

      const uname = username ?? usernameFor(email ?? '')
      const inserted = await db.insert(users).values({
        username: uname,
        email,
        // A starting password must be replaced at first sign-in (lib/sessionGate.ts).
        passwordHash: startingHash ?? NO_PASSWORD_HASH,
        passwordChangeRequired: !!startingHash,
        role,
        actions,
        tenantId,
      }).returning()

      const newUser = inserted[0]
      if (!newUser) return c.json({ detail: 'Failed to create user' }, 500)
      await audit(db, c, {
        userId: caller.userId, tenantId, actionType: 'user.invite', targetEntity: newUser.userId,
        newState: { email, username: newUser.username, role: newUser.role, actions: newUser.actions, starting_password: !!startingHash },
      })
      if (actions.length) await auditActions(db, c, caller.userId, tenantId, newUser.userId, [], actions)

      return c.json({
        ok: true,
        user_id: newUser.userId,
        username: newUser.username,
        email: newUser.email,
        role,
        actions,
        action: 'created',
      }, 201)
    } catch (err) {
      if (isUniqueViolation(err)) return c.json(USERNAME_TAKEN, 409)
      throw err
    }
  }
)

// ── PUT /:tenantId/users/:userId/actions — Set a tenant user's actions ──
// The Tenant Superadmin of this tenant. The list replaces the user's actions; each action's
// requirements are added (added_requirements says which). Effective on the user's next request.
router.put(
  '/:tenantId/users/:userId/actions',
  authMiddleware,
  requireTenantSuperadmin,
  zValidator('json', z.object({ actions: z.array(z.string()) })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId, userId } = c.req.param()
    const requested = c.req.valid('json').actions
    const caller = c.get('user')

    const parsed = parseActionList(requested)
    if (!parsed.ok) return c.json({ detail: `Unknown actions: ${parsed.unknown.join(', ')}` }, 400)

    if (!z.string().uuid().safeParse(userId).success) return c.json({ detail: 'User not found in this tenant' }, 404)
    const [target] = await db.select().from(users)
      .where(and(eq(users.userId, userId), eq(users.tenantId, tenantId))).limit(1)
    const plan = target ? planActionsUpdate(target, parsed.actions) : null
    if (!plan) return c.json({ detail: 'User not found in this tenant' }, 404)

    const next = plan.set.actions
    await db.update(users).set(plan.set).where(eq(users.userId, userId))
    await auditActions(db, c, caller.userId, tenantId, userId, plan.previous, next)

    return c.json({ actions: next, added_requirements: next.filter((k) => !requested.includes(k)) })
  }
)

// ── PATCH /:tenantId/users/:userId/deactivate — Deactivate user ───
// The Tenant Superadmin of this tenant, for tenant users. The Tenant Superadmin's own account
// changes only through an ownership transfer (spec, section 6).
router.patch(
  '/:tenantId/users/:userId/deactivate',
  authMiddleware,
  requireTenantSuperadmin,
  zValidator('json', z.object({
    is_active: z.boolean(),
  })),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL)
    const { tenantId, userId } = c.req.param()
    const { is_active } = c.req.valid('json')
    if (!z.string().uuid().safeParse(userId).success) return c.json({ detail: 'User not found in this tenant' }, 404)

    const [target] = await db
      .select()
      .from(users)
      .where(and(eq(users.userId, userId), eq(users.tenantId, tenantId)))
      .limit(1)

    if (!target) return c.json({ detail: 'User not found in this tenant' }, 404)

    const caller = c.get('user')
    const targetRole = roleOf(target)
    if (targetRole === 'superadmin') return c.json({ detail: 'The platform superadmin cannot be deactivated here' }, 403)
    if (target.userId === caller.userId || targetRole === 'tenant_superadmin') return c.json({ detail: OWNERSHIP_ONLY }, 403)

    const [changed] = await db.update(users).set({ isActive: is_active, scheduledDeactivationAt: null }).where(and(
      eq(users.userId, userId), eq(users.tenantId, tenantId), eq(users.role, 'tenant_user'), stillOwner(caller.userId, tenantId),
    )).returning({ userId: users.userId })
    if (!changed) return c.json({ detail: ACCOUNT_CHANGED }, 409)
    await audit(db, c, {
      userId: caller.userId, tenantId, actionType: is_active ? 'user.activate' : 'user.deactivate', targetEntity: userId,
      previousState: { is_active: target.isActive },
    })

    return c.json({ ok: true, user_id: userId, is_active })
  }
)

// ── POST /:tenantId/users/:userId/mfa-reset — Reset a user's MFA ───
// The Tenant Superadmin of this tenant, for tenant users. Step-up: their password and current MFA
// code. MFA turns off and the secret goes with it, in one write; the user's open sessions end and
// the user sets MFA up again at the next sign-in. Confirm the request in person or by phone first.
router.post(
  '/:tenantId/users/:userId/mfa-reset',
  authMiddleware,
  requireTenantSuperadmin,
  zValidator('json', z.object({ password: z.string().optional(), code: z.string().optional() })),
  async (c) => {
    try {
      const db = getDb(c.env.DATABASE_URL)
      const { tenantId, userId } = c.req.param()
      const { password, code } = c.req.valid('json')
      if (!z.string().uuid().safeParse(userId).success) return c.json({ detail: 'User not found in this tenant' }, 404)

      const caller = c.get('user')
      const [target] = await db.select().from(users)
        .where(and(eq(users.userId, userId), eq(users.tenantId, tenantId))).limit(1)
      if (!target || resetTarget(target, caller.userId, tenantId) === 'refused') {
        return c.json({ detail: 'User not found in this tenant' }, 404)
      }

      const [me] = await db.select().from(users).where(eq(users.userId, caller.userId)).limit(1)
      if (!me) return c.json({ detail: 'User not found' }, 404)
      const refused = await stepUp(c, db, me, { password, code })
      if (refused) return refused

      // One Neon HTTP transaction (db.batch): MFA off and the secret gone together.
      await db.batch([...mfaClearStatements(db, userId)])
      await audit(db, c, {
        userId: caller.userId, tenantId, actionType: 'user.mfa_reset', targetEntity: userId,
        previousState: { mfa_enabled: target.mfaEnabled },
      })
      await sendMail(c.env, {
        to: target.email, subject: 'Your MFA was reset',
        text: `Your MFA was reset by ${me.username} on ${new Date().toISOString().slice(0, 10)}. If you did not ask for this, contact them immediately.`,
      })
      return c.json({ ok: true })
    } catch (err) {
      console.error('mfa-reset error:', err)
      return c.json({ detail: 'Failed to reset MFA' }, 500)
    }
  }
)

// ── DELETE /:tenantId/users/:userId — Delete a user ────────────────
// The Tenant Superadmin of this tenant, for tenant users. Step-up: their password and current MFA
// code, plus the target's username typed exactly. The audit entry is written after the delete succeeds; audit rows of the
// user stay (user_id becomes NULL, actor_username keeps the username). A foreign key that refuses the delete
// (ownership history) gives 409.
const OWNERSHIP_HISTORY = "This account is part of the tenant's ownership history and cannot be deleted. Deactivate it instead."
router.delete(
  '/:tenantId/users/:userId',
  authMiddleware,
  requireTenantSuperadmin,
  zValidator('json', z.object({ password: z.string().optional(), code: z.string().optional(), confirm_username: z.string() })),
  async (c) => {
    try {
      const db = getDb(c.env.DATABASE_URL)
      const { tenantId, userId } = c.req.param()
      const { password, code, confirm_username } = c.req.valid('json')
      if (!z.string().uuid().safeParse(userId).success) return c.json({ detail: 'User not found in this tenant' }, 404)

      const caller = c.get('user')
      const [target] = await db.select().from(users)
        .where(and(eq(users.userId, userId), eq(users.tenantId, tenantId))).limit(1)
      if (!target || deleteTarget(caller, target, tenantId) === 'refused') {
        return c.json({ detail: 'User not found in this tenant' }, 404)
      }
      if (!confirmMatches(confirm_username, target.username)) {
        return c.json({ detail: 'Type the username exactly to confirm.' }, 400)
      }

      const [me] = await db.select().from(users).where(eq(users.userId, caller.userId)).limit(1)
      if (!me) return c.json({ detail: 'User not found' }, 404)
      const refused = await stepUp(c, db, me, { password, code })
      if (refused) return refused

      const previousState = { user_id: target.userId, username: target.username, email: target.email, actions: target.actions }
      try {
        // One Neon HTTP transaction (db.batch): the audit rows keep the username, then the user goes.
        const res = await db.batch([...deleteUserStatements(db, tenantId, userId, target.username, caller.userId)]) as unknown as unknown[][]
        if (res[1]!.length !== 1) return c.json({ detail: ACCOUNT_CHANGED }, 409)
      } catch (err) {
        if (isFkViolation(err)) {
          await audit(db, c, {
            userId: caller.userId, tenantId, actionType: 'user.delete_refused', targetEntity: userId, previousState,
          })
          return c.json({ detail: OWNERSHIP_HISTORY }, 409)
        }
        throw err
      }
      await audit(db, c, { userId: caller.userId, tenantId, actionType: 'user.delete', targetEntity: userId, previousState })
      return c.json({ ok: true })
    } catch (err) {
      console.error('delete user error:', err)
      return c.json({ detail: 'Failed to delete user' }, 500)
    }
  }
)

export default router
