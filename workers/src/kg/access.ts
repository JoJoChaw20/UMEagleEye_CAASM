/**
 * kg/access.ts — who may see which nodes. Built on the server from the signed-in user; the
 * model never supplies any of it. Every graph read goes through accessSql.
 */
export interface Access {
  tenantId: string | null
  platform: boolean // UMEagleEye team only: code details and internal problems
  analyst: boolean  // false for business_owner: status and security score only
  none: boolean
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export function accessFor(user: { role: string; tenantId?: string | null }, pickedTenant?: string | null): Access {
  if (user.role === 'superadmin') {
    return { tenantId: pickedTenant && UUID.test(pickedTenant) ? pickedTenant : null, platform: true, analyst: true, none: false }
  }
  if (!user.tenantId) return { tenantId: null, platform: false, analyst: false, none: true }
  return { tenantId: user.tenantId, platform: false, analyst: user.role !== 'business_owner', none: false }
}

/** The WHERE condition for nodes aliased `alias`. Adds its one parameter to `params`. */
export function accessSql(a: Access, alias: string, params: unknown[]): string {
  if (a.none) return 'false'
  const scopes = [`(${alias}.tenant_id IS NULL AND ${alias}.visibility = 'all_staff')`]
  if (a.platform) scopes.push(`(${alias}.tenant_id IS NULL AND ${alias}.visibility = 'platform')`)
  if (a.tenantId) {
    params.push(a.tenantId)
    scopes.push(`${alias}.tenant_id = $${params.length}::uuid`)
  }
  return `((${scopes.join(' OR ')})${a.analyst ? '' : ` AND ${alias}.role_group = 'all'`})`
}
