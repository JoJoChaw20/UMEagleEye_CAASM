// Who may add which user to a tenant (routes/tenants.ts: assign and invite), and the action lists
// a Tenant Superadmin grants. A tenant superadmin may add only accounts that belong to no tenant yet
// (or already to theirs), never the platform superadmin and never a tenant superadmin. Nobody takes
// an account from another tenant, the platform superadmin included. Until 2026-11-09 any tenant superadmin could
// pull any account, the platform superadmin's included, into their tenant and then demote or
// deactivate it.

import { isActionKey, withRequirements, type ActionKey } from './actions'

export interface Account { userId: string; role: string; tenantId?: string | null }

export type Refusal = 'superadmin' | 'other_tenant' | 'tenant_superadmin'

/** Why `caller` may not add `target` to `tenantId`; null = allowed. */
export function addRefusal(_caller: Account, target: Account, tenantId: string): Refusal | null {
  if (target.role === 'superadmin') return 'superadmin'
  const current = target.tenantId ?? null
  if (current !== null && current !== tenantId) return 'other_tenant'
  // A tenant superadmin changes only through an ownership transfer: adding one elsewhere would
  // leave its own tenant without one.
  if (target.role === 'tenant_superadmin') return 'tenant_superadmin'
  return null
}

/** A requested action list: an array of known action keys, closed over their requirements. Unknown keys are reported, not dropped. */
export function parseActionList(input: unknown): { ok: true; actions: ActionKey[] } | { ok: false; unknown: string[] } {
  const text = (x: unknown) => (typeof x === 'string' ? x : String(x))
  // Not a list at all (a bare key, say): the whole input is reported.
  if (!Array.isArray(input)) return { ok: false, unknown: [text(input)] }
  const unknown = input.filter((x) => typeof x !== 'string' || !isActionKey(x)).map(text)
  if (unknown.length) return { ok: false, unknown }
  return { ok: true, actions: withRequirements(input as string[]) }
}

/** What changed between two action lists, for the audit log. */
export function actionChanges(previous: readonly string[], next: readonly string[]): { added: string[]; removed: string[] } {
  return {
    added: next.filter((k) => !previous.includes(k)),
    removed: previous.filter((k) => !next.includes(k)),
  }
}
