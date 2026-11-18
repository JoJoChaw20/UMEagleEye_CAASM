// Inviting a tenant's Tenant Superadmin: the one code path behind the interim invite
// (POST /tenants/:tenantId/users/invite with as_tenant_superadmin) and the platform restore
// (POST /tenants/:tenantId/ownership/restore).
import type { Context } from 'hono'
import { and, eq, isNull, notExists, notInArray, or, sql, type SQL } from 'drizzle-orm'
import { alias } from 'drizzle-orm/pg-core'
import type { DB } from '../db/client'
import { tenants, users } from '../db/schema'
import { NO_PASSWORD_HASH } from '../lib/auth'
import { roleOf } from '../lib/accountRows'
import { addRefusal } from '../lib/userAdmin'
import { audit } from './audit'

export const OWNERSHIP_ONLY = 'The Tenant Superadmin can only change through an ownership transfer.'
export const ALREADY_OWNED = { detail: 'This tenant already has a Tenant Superadmin.' }

export type UserRow = typeof users.$inferSelect
type Caller = { userId: string; role: string; tenantId?: string | null }
export type InviteError = { detail: string; status: 403 | 404 | 409 }
export type OwnerInvitePlan = { ok: true; existing: UserRow | null; username: string } | { ok: false; error: InviteError }

/** Refusal texts when the Platform Superadmin invites. */
function refusalText(r: ReturnType<typeof addRefusal>): string {
  if (r === 'tenant_superadmin') return `That account is already a Tenant Superadmin. ${OWNERSHIP_ONLY}`
  if (r === 'other_tenant') return 'This account belongs to another tenant.'
  return 'The platform superadmin cannot be added to a tenant'
}

export function usernameFor(email: string, username?: string): string {
  return username ?? (email.split('@')[0] ?? email).toLowerCase().replace(/[^a-z0-9_]/g, '_')
}

/**
 * Checks an owner invite and finds the account it applies to (null = a new account will be created).
 * `replacingOwner` (restore) skips the "tenant already has an owner" refusal: the caller demotes the owner in the same batch.
 */
export async function planOwnerInvite(
  db: DB, caller: Caller, tenantId: string, email: string, username: string | undefined, replacingOwner: boolean,
): Promise<OwnerInvitePlan> {
  const [tenant] = await db.select({ tenantId: tenants.tenantId }).from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1)
  if (!tenant) return { ok: false, error: { detail: 'Tenant not found', status: 404 } }
  if (!replacingOwner) {
    const [owner] = await db.select({ userId: users.userId }).from(users)
      .where(and(eq(users.tenantId, tenantId), eq(users.role, 'tenant_superadmin'))).limit(1)
    if (owner) return { ok: false, error: { ...ALREADY_OWNED, status: 409 } }
  }
  const [existing] = await db.select().from(users).where(eq(users.email, email)).limit(1)
  if (existing) {
    const refusal = addRefusal(caller as never, { ...existing, role: roleOf(existing) } as never, tenantId)
    if (refusal) return { ok: false, error: { detail: refusalText(refusal), status: 403 } }
  }
  return { ok: true, existing: existing ?? null, username: usernameFor(email, username) }
}

/** SQL: the existing account may still be promoted (in this tenant or in none, not a superadmin of any kind, active, no due scheduled deactivation). */
export function candidateEligible(userId: string, tenantId: string): SQL {
  return sql`exists (select 1 from users where user_id = ${userId}::uuid
    and (tenant_id is null or tenant_id = ${tenantId}::uuid)
    and role not in ('superadmin', 'tenant_superadmin')
    and is_active = true and (scheduled_deactivation_at is null or scheduled_deactivation_at > now()))`
}

/**
 * The owner write as one builder (for db.batch, or awaited alone): promotes the existing account, or inserts a new one.
 * Both run only where the tenant has no Tenant Superadmin and `guard` holds. A failed promote returns 0 rows; a failed
 * insert raises NOT NULL (see below), so a surrounding batch rolls back and writes nothing. The unique index
 * uq_users_one_tenant_superadmin stays the final backstop.
 */
export function ownerInviteStatement(db: any, plan: Extract<OwnerInvitePlan, { ok: true }>, tenantId: string, email: string, guard?: SQL) {
  if (plan.existing) {
    const o = alias(users, 'o')
    return db.update(users).set({ tenantId, role: 'tenant_superadmin', actions: [] as string[], scheduledDeactivationAt: null }).where(and(
      eq(users.userId, plan.existing.userId), notInArray(users.role, ['superadmin', 'tenant_superadmin']),
      or(isNull(users.tenantId), eq(users.tenantId, tenantId)),
      eq(users.isActive, true), or(isNull(users.scheduledDeactivationAt), sql`${users.scheduledDeactivationAt} > now()`),
      notExists(db.select({ one: sql`1` }).from(o).where(and(eq(o.tenantId, tenantId), eq(o.role, 'tenant_superadmin')))),
      guard,
    )).returning({ userId: users.userId, username: users.username, email: users.email })
  }
  // Guarded insert: a column's value is a subquery that is NULL unless the guard holds (no Tenant Superadmin left
  // in the tenant, and `guard`). username is NOT NULL, so a failed guard raises (23502) and rolls the batch back:
  // nothing is written. (drizzle 0.36 insert().select() needs every table column, so the guard rides on a value.)
  const holds = and(
    sql`not exists (select 1 from users where tenant_id = ${tenantId}::uuid and role = 'tenant_superadmin')`, guard,
  )
  return db.insert(users).values({
    username: sql`(select ${plan.username}::varchar where ${holds})`,
    email, passwordHash: NO_PASSWORD_HASH, role: 'tenant_superadmin', actions: [] as string[], tenantId,
  }).returning({ userId: users.userId, username: users.username, email: users.email })
}

/** Audit of an owner invite, as the interim invite wrote it: user.assign for an existing account, user.invite for a new one. */
export async function auditOwnerInvite(
  db: DB, c: Context | null, caller: Caller, tenantId: string,
  plan: Extract<OwnerInvitePlan, { ok: true }>, added: { userId: string; username: string; email: string | null }, email: string,
) {
  if (plan.existing) {
    await audit(db, c, {
      userId: caller.userId, tenantId, actionType: 'user.assign', targetEntity: plan.existing.userId,
      previousState: { tenant_id: plan.existing.tenantId, role: plan.existing.role, actions: plan.existing.actions },
      newState: { tenant_id: tenantId, by: 'email', role: 'tenant_superadmin', actions: [] },
    })
  } else {
    await audit(db, c, {
      userId: caller.userId, tenantId, actionType: 'user.invite', targetEntity: added.userId,
      newState: { email, username: added.username, role: 'tenant_superadmin', actions: [] },
    })
  }
}
