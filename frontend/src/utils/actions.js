// Helpers over the action catalog served by GET /auth/actions. Mirrors workers/src/lib/actions.ts.

/** The given actions plus everything they require, transitively. Unknown keys dropped. Catalog order. */
export function withRequirements(keys, catalog) {
  const byKey = new Map((catalog?.actions || []).map((a) => [a.key, a]))
  const seen = new Set()
  const visit = (k) => {
    if (seen.has(k) || !byKey.has(k)) return
    seen.add(k)
    for (const r of byKey.get(k).requires || []) visit(r)
  }
  for (const k of keys || []) visit(k)
  return (catalog?.actions || []).map((a) => a.key).filter((k) => seen.has(k))
}

/** Every action whose closure contains `key`, excluding `key` itself. */
export function dependentsOf(key, catalog) {
  return (catalog?.actions || [])
    .map((a) => a.key)
    .filter((k) => k !== key && withRequirements([k], catalog).includes(key))
}

/** Key of the preset whose action set is exactly `keys` (any order), or null for a custom set. */
export function matchPreset(keys, catalog) {
  const given = new Set(keys || [])
  for (const p of catalog?.presets || []) {
    if (given.size === p.actions.length && p.actions.every((k) => given.has(k))) return p.key
  }
  return null
}

const ROLE_LABELS = {
  superadmin: 'Platform Superadmin',
  tenant_superadmin: 'Tenant Superadmin',
  tenant_user: 'Tenant user',
}

export function roleLabel(role) {
  return ROLE_LABELS[role] || (role ? role.replace(/_/g, ' ') : '')
}

/** Tooltip for a control the user may not use: names the missing action by its catalog label. */
export function requiresTitle(key, catalog) {
  const label = (catalog?.actions || []).find((a) => a.key === key)?.label || key
  return `Requires the "${label}" action.`
}
