// Which actions a settings change needs, beyond the route's own guard (routes/agents.ts and
// routes/tenants.ts). Pure, so the rules are unit tested without a database.

import { decide, refusalMessage, type ActionKey } from './actions'
import { ROLE_KEYS } from './agentPolicy'

const ROLE_SETTING_KEYS: ReadonlySet<string> = new Set(Object.values(ROLE_KEYS).flat())

/**
 * Every action a PATCH /agents/:agentId/policy body needs. Switching a role on or off (directly,
 * or through one of its settings) needs "Assign agent roles"; turning on threat sightings reads
 * the computer's traffic, so it needs "Enable threat sightings on agents".
 */
export function policyChangeActions(body: { settings?: Record<string, unknown>; roles?: Record<string, boolean> }): ActionKey[] {
  const needed: ActionKey[] = ['agent.configure']
  const settingKeys = Object.keys(body.settings ?? {})
  if (Object.keys(body.roles ?? {}).length > 0 || settingKeys.some((k) => ROLE_SETTING_KEYS.has(k))) {
    needed.push('agent.roles.assign')
  }
  if (settingKeys.includes('sightings')) needed.push('agent.sightings.enable')
  return needed
}

/**
 * The actions a PATCH /tenants/:tenantId/agent-policy body needs beyond "Change default agent
 * settings": a tenant default reaches every agent of that kind without an override, so role and
 * sightings defaults need the same high-impact actions as the per-agent change. Catalog order.
 */
export function defaultsChangeActions(changes: Record<string, Record<string, unknown>>): ActionKey[] {
  const needed = new Set<ActionKey>()
  for (const settings of Object.values(changes)) {
    for (const key of policyChangeActions({ settings })) if (key !== 'agent.configure') needed.add(key)
  }
  return (['agent.roles.assign', 'agent.sightings.enable'] as const).filter((k) => needed.has(k))
}

type Caller = { role: string; tenantId?: string | null; actions: readonly string[] }
export type TenantPatch = {
  name?: string
  is_active?: boolean
  auto_investigate_new_devices?: boolean
  allow_local_scans?: boolean
}
export type PatchRefusal = { status: 403; detail: string; missing_action?: ActionKey }

/**
 * Why `user` may not apply `patch` to tenant `tenantId` (PATCH /tenants/:tenantId); null = allowed.
 * The Platform Superadmin may only switch the tenant on or off. Inside the tenant, only the Tenant
 * Superadmin renames it, and the scan policy needs "Change scan policy".
 */
export function tenantPatchRefusal(user: Caller, tenantId: string, patch: TenantPatch): PatchRefusal | null {
  const touchesScanPolicy = patch.auto_investigate_new_devices !== undefined || patch.allow_local_scans !== undefined
  if (user.role === 'superadmin') {
    if (touchesScanPolicy) return { status: 403, detail: refusalMessage('superadmin_read_only', 'settings.scan_policy.edit') }
    // A rename has no action of its own; the read-only refusal is the same for every key.
    if (patch.name !== undefined) return { status: 403, detail: refusalMessage('superadmin_read_only', 'settings.view') }
    return null
  }
  if (!user.tenantId || user.tenantId !== tenantId) return { status: 403, detail: 'You can only change your own tenant.' }
  if (patch.is_active !== undefined) return { status: 403, detail: 'Only the Platform Superadmin can do this.' }
  if (patch.name !== undefined && user.role !== 'tenant_superadmin') {
    return { status: 403, detail: 'Only the Tenant Superadmin can do this.' }
  }
  if (touchesScanPolicy) {
    const decision = decide(user, 'settings.scan_policy.edit')
    if (!decision.ok) {
      return { status: 403, detail: refusalMessage(decision.reason, 'settings.scan_policy.edit'), missing_action: 'settings.scan_policy.edit' }
    }
  }
  return null
}
