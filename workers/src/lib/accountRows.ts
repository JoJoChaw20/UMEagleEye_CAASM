// How the routes read a stored users row. Until migration 0036 the table still holds legacy roles,
// so every role or action list taken from a row goes through normalizeAccount before it is
// compared, passed to decide, put in an AuthUser, or returned in JSON. Audit logs keep the raw
// stored values. Pure functions, so they are tested without a database (accountRows.test.ts).

import type { AuthUser } from '../types'
import { decide, normalizeAccount, type ActionKey, type Role } from './actions'

type StoredAccount = { role: string; actions: readonly string[] | null }

/** The signed-in user for the request (middleware/auth.ts). */
export function toAuthUser(
  userId: string, username: string,
  row: StoredAccount & { tenantId: string | null },
): AuthUser {
  const { role, actions } = normalizeAccount(row.role, row.actions)
  return { userId, role, username, tenantId: row.tenantId ?? undefined, actions }
}

/**
 * A sign-in (password, MFA verify, Google): the JWT claims and the role for the JSON response.
 * The token carries the STORED role, not the normalized one: the previous worker (main) trusts
 * payload.role, so after a rollback a legacy user's token must still name its old role. The new
 * middleware ignores the token's role and reads the row on every request. The response body
 * carries the normalized role.
 */
export function signIn(row: { userId: string; role: string; username: string; tenantId: string | null }) {
  return {
    claims: {
      sub: row.userId,
      role: row.role,
      username: row.username,
      tenant_id: row.tenantId ?? undefined,
    },
    role: roleOf(row),
  }
}

/** A row with its role and actions replaced by the normalized ones (GET /auth/me). */
export function withAccount<T extends StoredAccount>(row: T): Omit<T, 'role' | 'actions'> & { role: Role; actions: ActionKey[] } {
  return { ...row, ...normalizeAccount(row.role, row.actions) }
}

/** One row of GET /tenants/:tenantId/users. */
export function tenantUserItem(u: StoredAccount & {
  userId: string; username: string; email: string | null; isActive: boolean | null
  createdAt: Date | null; lastLogin: Date | null
}) {
  const { role, actions } = normalizeAccount(u.role, u.actions)
  return {
    user_id: u.userId,
    username: u.username,
    email: u.email,
    role,
    actions,
    is_active: u.isActive,
    created_at: u.createdAt,
    last_login: u.lastLogin,
  }
}

/** The tenant's members who may manage alerts (GET /events/assignees). */
export function assignableUsers(
  rows: readonly (StoredAccount & { userId: string; username: string })[],
  tenantId: string,
): { user_id: string; username: string; role: Role }[] {
  return rows.flatMap((u) => {
    const account = normalizeAccount(u.role, u.actions)
    return decide({ ...account, tenantId }, 'alert.manage').ok
      ? [{ user_id: u.userId, username: u.username, role: account.role }]
      : []
  })
}

/** Whether a user (looked up by id) may be assigned alerts. The tenant match is checked by the caller. */
export function canBeAssignedAlerts(row: (StoredAccount & { tenantId: string | null }) | undefined): boolean {
  if (!row) return false
  return decide({ ...normalizeAccount(row.role, row.actions), tenantId: row.tenantId }, 'alert.manage').ok
}

/**
 * PUT /tenants/:tenantId/users/:userId/actions: accepted for a tenant user, a legacy-role row
 * included. Only `actions` is written, so a legacy row keeps its stored role and old code still
 * works for it until migration 0036. `previous` is the list the user held (the converted set for
 * a legacy row never edited).
 */
export function planActionsUpdate(
  target: StoredAccount, next: ActionKey[],
): { previous: ActionKey[]; set: { actions: ActionKey[] } } | null {
  const account = normalizeAccount(target.role, target.actions)
  if (account.role !== 'tenant_user') return null
  return { previous: account.actions, set: { actions: next } }
}

/** A row's normalized role, for comparisons against 'superadmin' / 'tenant_superadmin'. */
export function roleOf(row: { role: string }): Role {
  return normalizeAccount(row.role, null).role
}

/**
 * The actions list to store with a role. A Tenant Superadmin ignores actions, so it is stored NULL:
 * if the previous worker demotes it to a legacy role, NULL reads as the converted set, not as zero
 * actions. A tenant user keeps its explicit list.
 */
export function storedActionsFor(role: Role, actions: string[]): string[] | null {
  return role === 'tenant_superadmin' ? null : actions
}
