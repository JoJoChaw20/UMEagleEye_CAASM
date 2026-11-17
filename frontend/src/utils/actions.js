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
export function actionLabel(key, catalog) {
  return (catalog?.actions || []).find((a) => a.key === key)?.label || key
}

export function requiresTitle(key, catalog) {
  return `Requires the "${actionLabel(key, catalog)}" action.`
}

/** Catalog keys in catalog order, keeping only those in `set`. */
function inCatalogOrder(set, catalog) {
  return (catalog?.actions || []).map((a) => a.key).filter((k) => set.has(k))
}

/**
 * Ticking `key`: the selection plus its closure. `added` lists what came along besides `key` itself,
 * so the picker can say "Also added: …".
 */
export function addAction(keys, key, catalog) {
  const before = new Set(keys || [])
  const next = withRequirements([...before, key], catalog)
  return { next, added: next.filter((k) => k !== key && !before.has(k)) }
}

/**
 * Unticking `key`: the selection without `key` and every selected action that needs it.
 * `removed` lists those selected dependents (empty when nothing else is affected).
 */
export function removeAction(keys, key, catalog) {
  const selected = new Set(keys || [])
  const removed = dependentsOf(key, catalog).filter((k) => selected.has(k))
  for (const k of [key, ...removed]) selected.delete(k)
  return { next: inCatalogOrder(selected, catalog), removed: inCatalogOrder(new Set(removed), catalog) }
}

/** The selection a preset button sets: the preset's actions closed over their requirements. */
export function presetActions(presetKey, catalog) {
  const p = (catalog?.presets || []).find((x) => x.key === presetKey)
  return p ? withRequirements(p.actions, catalog) : []
}

export function countActions(n) {
  return `${n} action${n === 1 ? '' : 's'}`
}

/**
 * "No access", "Matches: Analyst" or "Custom · 12 actions". With withCount, a preset match also
 * gives its size ("Matches: Analyst · 27 actions"), as the picker's summary line does.
 */
export function accessSummary(keys, catalog, { withCount = false } = {}) {
  const list = keys || []
  if (!list.length) return 'No access'
  const preset = matchPreset(list, catalog)
  if (preset) {
    const label = catalog.presets.find((p) => p.key === preset)?.label || preset
    return withCount ? `Matches: ${label} · ${countActions(list.length)}` : `Matches: ${label}`
  }
  return `Custom · ${countActions(list.length)}`
}

/** Catalog labels for keys, joined with commas. */
export function actionLabels(keys, catalog) {
  return (keys || []).map((k) => actionLabel(k, catalog)).join(', ')
}
