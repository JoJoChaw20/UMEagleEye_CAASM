/**
 * kg/access.ts — who may see which nodes. Built on the server from the signed-in user; the
 * model never supplies any of it. Every graph read goes through accessSql.
 */
import { decide } from '../lib/actions'

export interface Access {
  tenantId: string | null
  platform: boolean // UMEagleEye team only: code details and internal problems
  analyst: boolean  // false without asset, alert, advisory and scan view: status and security score only
  none: boolean
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

type AccessUser = { role: string; tenantId?: string | null; actions: readonly string[] }

/**
 * True when the user may view assets, alerts, advisories and scans: the detail level the assistant needs.
 * scan.view is required as well because the migrated business_owner set (the viewer preset without
 * scan.view and relationship.view) holds the other three and must stay on status and score only.
 */
export function analystAccess(user: AccessUser): boolean {
  return (['asset.view', 'alert.view', 'advisory.view', 'scan.view'] as const).every(k => decide(user, k).ok)
}

export function accessFor(user: AccessUser, pickedTenant?: string | null): Access {
  if (user.role === 'superadmin') {
    return { tenantId: pickedTenant && UUID.test(pickedTenant) ? pickedTenant : null, platform: true, analyst: true, none: false }
  }
  if (!user.tenantId) return { tenantId: null, platform: false, analyst: false, none: true }
  return { tenantId: user.tenantId, platform: false, analyst: analystAccess(user), none: false }
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
