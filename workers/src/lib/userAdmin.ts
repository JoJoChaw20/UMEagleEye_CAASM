// Who may add which user to a tenant (routes/tenants.ts: assign and invite). A tenant superadmin
// may add only accounts that belong to no tenant yet (or already to theirs), never the platform
// superadmin and never another tenant superadmin; only the platform superadmin moves accounts
// between tenants. Until 2026-11-09 any tenant superadmin could pull any account, the platform
// superadmin's included, into their tenant and then demote or deactivate it.

export interface Account { userId: string; role: string; tenantId?: string | null }

export type Refusal = 'superadmin' | 'other_tenant' | 'tenant_superadmin' | 'role'

/** Why `caller` may not add `target` to `tenantId` with `role` (undefined: keep its role); null = allowed. */
export function addRefusal(caller: Account, target: Account, tenantId: string, role?: string): Refusal | null {
  if (target.role === 'superadmin') return 'superadmin'
  if (caller.role === 'superadmin') return null
  const current = target.tenantId ?? null
  if (current !== null && current !== tenantId) return 'other_tenant'
  if (target.role === 'tenant_superadmin' && current !== tenantId) return 'tenant_superadmin'
  if (role === 'tenant_superadmin') return 'role'
  return null
}

/** Whether a tenant superadmin may give a new account this role (only the platform superadmin makes tenant superadmins). */
export function mayGrantRole(caller: Account, role: string): boolean {
  return caller.role === 'superadmin' || role !== 'tenant_superadmin'
}
