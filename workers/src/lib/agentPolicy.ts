// Agent policy: what an admin sets for agents from the dashboard, per tenant (defaults)
// and per agent (overrides). Pure functions; routes/agents.ts and routes/tenants.ts store
// and serve it, the heartbeat delivers it, and job creation checks it.
//
// A setting resolves as: this agent's override > the tenant's default > the agent's own
// setting (what it reports in its heartbeat). Only overrides and defaults are stored, so
// a setting nobody set stays the agent's own: upgrading changes nothing until an admin
// sets something. A set value is "managed": the agent applies it and its app shows it
// read-only.
//
// Roles are not stored; they are read from the settings: Inventory (inventory + SBOM of
// its own computer), Sensor (passive listening on its network), Scanner (runs scans the
// dashboard sends it). Switching a role on or off in the dashboard sets those settings.

export type PolicyValue = boolean | number | string
type Spec =
  | { type: 'bool' }
  | { type: 'int'; min: number; max: number }
  | { type: 'enum'; values: readonly string[] }

export const POLICY_SPECS = {
  scanner: { type: 'bool' },
  local_scans: { type: 'bool' },
  scan_engine: { type: 'enum', values: ['auto', 'own', 'compare'] },
  scan_ports: { type: 'enum', values: ['base', 'consumer', 'wide'] },
  passive: { type: 'bool' },
  passive_interval: { type: 'int', min: 10, max: 3600 },
  passive_backend: { type: 'enum', values: ['auto', 'npcap', 'native'] },
  inventory: { type: 'bool' },
  inventory_interval: { type: 'int', min: 300, max: 7 * 86400 },
  inventory_user_software: { type: 'bool' },
  inventory_admin_names: { type: 'bool' },
  sbom: { type: 'bool' },
  sbom_interval: { type: 'int', min: 3600, max: 30 * 86400 },
} as const satisfies Record<string, Spec>

export type PolicyKey = keyof typeof POLICY_SPECS
export const POLICY_KEYS = Object.keys(POLICY_SPECS) as PolicyKey[]

// Which settings each kind of agent has. Only "host" exists so far; the network agent
// (SNMP) will have its own list.
export const KIND_KEYS: Record<string, readonly PolicyKey[]> = { host: POLICY_KEYS }
export const AGENT_KINDS = Object.keys(KIND_KEYS)

export const ROLE_KEYS = {
  inventory: ['inventory', 'sbom'],
  sensor: ['passive'],
  scanner: ['scanner'],
} as const satisfies Record<string, readonly PolicyKey[]>
export type Role = keyof typeof ROLE_KEYS

// A setting an agent does not report (an agent before 2.4.0) whose behaviour is known:
// every agent runs the scans the dashboard sends it.
const ASSUMED: Partial<Record<PolicyKey, PolicyValue>> = { scanner: true }

export type Source = 'agent' | 'tenant' | 'local' | 'unknown'
export interface PolicyEntry {
  key: PolicyKey
  value: PolicyValue | null        // null: not known (the agent has not reported it)
  source: Source
  override: PolicyValue | null     // this agent's override
  tenant_default: PolicyValue | null
  local: PolicyValue | null        // the agent's own setting
  inherited: PolicyValue | null    // the value without this agent's override
}

export function kindKeys(kind: string | null | undefined): readonly PolicyKey[] {
  return KIND_KEYS[kind ?? 'host'] ?? POLICY_KEYS
}

/** The value of `raw` for `key`, or undefined when it does not fit the setting. */
export function coerce(key: PolicyKey, raw: unknown): PolicyValue | undefined {
  const spec: Spec = POLICY_SPECS[key]
  if (spec.type === 'bool') return typeof raw === 'boolean' ? raw : undefined
  if (spec.type === 'int') {
    return typeof raw === 'number' && Number.isInteger(raw) && raw >= spec.min && raw <= spec.max ? raw : undefined
  }
  return typeof raw === 'string' && spec.values.includes(raw) ? raw : undefined
}

/** Stored policy (agents.policy, tenants.agent_policy) with anything unknown or invalid
 *  dropped: what is read back from the database is never trusted blindly. */
export function cleanPolicy(raw: unknown, keys: readonly PolicyKey[] = POLICY_KEYS): Partial<Record<PolicyKey, PolicyValue>> {
  const out: Partial<Record<PolicyKey, PolicyValue>> = {}
  if (!raw || typeof raw !== 'object') return out
  for (const key of keys) {
    const value = coerce(key, (raw as Record<string, unknown>)[key])
    if (value !== undefined) out[key] = value
  }
  return out
}

/** Apply a change ({key: value, or null to remove}) to stored policy. Errors name each
 *  setting that is unknown for this kind of agent or has a value it cannot take. */
export function applyChange(
  current: unknown, change: Record<string, unknown>, keys: readonly PolicyKey[],
): { policy: Partial<Record<PolicyKey, PolicyValue>>; errors: string[] } {
  const policy = cleanPolicy(current, keys)
  const errors: string[] = []
  for (const [name, raw] of Object.entries(change)) {
    if (!(keys as readonly string[]).includes(name)) {
      errors.push(`${name}: not a setting of this agent`)
      continue
    }
    const key = name as PolicyKey
    if (raw === null) {
      delete policy[key]
      continue
    }
    const value = coerce(key, raw)
    if (value === undefined) errors.push(`${key}: ${describe(key)}`)
    else policy[key] = value
  }
  return { policy, errors }
}

function describe(key: PolicyKey): string {
  const spec: Spec = POLICY_SPECS[key]
  if (spec.type === 'bool') return 'must be true or false'
  if (spec.type === 'int') return `must be a whole number from ${spec.min} to ${spec.max}`
  return `must be one of ${spec.values.join(', ')}`
}

export interface ResolveInput {
  kind?: string | null
  overrides?: unknown                 // agents.policy
  tenantDefaults?: unknown            // tenants.agent_policy
  allowLocalScans?: boolean | null    // tenants.allow_local_scans: the tenant default of local_scans
  reported?: unknown                  // agents.reported.settings: the agent's own settings
}

export interface ResolvedPolicy {
  entries: PolicyEntry[]
  managed: Partial<Record<PolicyKey, PolicyValue>>   // what the agent must apply
  effective: Partial<Record<PolicyKey, PolicyValue>> // every known value
  roles: Record<Role, boolean | null>                // null: not known
  version: string                                    // changes when `managed` changes
}

export function resolvePolicy(input: ResolveInput): ResolvedPolicy {
  const keys = kindKeys(input.kind)
  const overrides = cleanPolicy(input.overrides, keys)
  const defaults = cleanPolicy(input.tenantDefaults, keys)
  if (keys.includes('local_scans') && typeof input.allowLocalScans === 'boolean') {
    defaults.local_scans = input.allowLocalScans      // kept in its own column (ScanPolicy, 2.3.0)
  }
  const local = cleanPolicy(input.reported, keys)
  const entries: PolicyEntry[] = []
  const managed: Partial<Record<PolicyKey, PolicyValue>> = {}
  const effective: Partial<Record<PolicyKey, PolicyValue>> = {}
  for (const key of keys) {
    // Without this agent's override: the tenant default, the agent's own, or what every
    // agent does (ASSUMED).
    let inherited: PolicyValue | null = null
    let inheritedFrom: Source = 'unknown'
    if (defaults[key] !== undefined) {
      inherited = defaults[key]!; inheritedFrom = 'tenant'
    } else if (local[key] !== undefined) {
      inherited = local[key]!; inheritedFrom = 'local'
    } else if (ASSUMED[key] !== undefined) {
      inherited = ASSUMED[key]!; inheritedFrom = 'local'
    }
    const overridden = overrides[key] !== undefined
    const value: PolicyValue | null = overridden ? overrides[key]! : inherited
    const source: Source = overridden ? 'agent' : inheritedFrom
    if (source === 'agent' || source === 'tenant') managed[key] = value!
    if (value !== null) effective[key] = value
    entries.push({
      key, value, source,
      override: overrides[key] ?? null, tenant_default: defaults[key] ?? null, local: local[key] ?? null, inherited,
    })
  }
  const roles = {} as Record<Role, boolean | null>
  for (const [role, roleKeys] of Object.entries(ROLE_KEYS) as [Role, readonly PolicyKey[]][]) {
    const values = roleKeys.filter((k) => keys.includes(k)).map((k) => effective[k])
    roles[role] = values.length === 0 || values.some((v) => v === undefined) ? null : values.some((v) => v === true)
  }
  return { entries, managed, effective, roles, version: policyVersion(managed) }
}

/** The settings a role sets: on switches them all on, off all off. */
export function roleChange(role: Role, on: boolean): Partial<Record<PolicyKey, boolean>> {
  return Object.fromEntries(ROLE_KEYS[role].map((k) => [k, on]))
}

/** A short, stable fingerprint of the managed settings (FNV-1a over sorted JSON), so the
 *  agent can tell it already applied this policy. */
export function policyVersion(managed: Partial<Record<PolicyKey, PolicyValue>>): string {
  const text = JSON.stringify(Object.keys(managed).sort().map((k) => [k, managed[k as PolicyKey]]))
  let h = 0x811c9dc5
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h.toString(16).padStart(8, '0')
}

/** Why the dashboard may not send this kind of job to an agent with this policy, or null.
 *  A value the agent has not reported does not block (an older agent decides itself). */
export function jobRefusal(effective: Partial<Record<PolicyKey, PolicyValue>>, job: 'active' | 'inventory' | 'sbom'): string | null {
  if (job === 'active' && effective.scanner === false) {
    return 'This agent does not run scans from the dashboard (its Scanner role is off).'
  }
  if (job === 'inventory' && effective.inventory === false) {
    return 'Endpoint inventory is switched off for this agent.'
  }
  if (job === 'sbom' && effective.sbom === false) {
    return 'The SBOM is switched off for this agent.'
  }
  return null
}

/** What an agent reports in its heartbeat about itself, kept within limits. */
export function cleanReport(raw: {
  kind?: unknown; settings?: unknown; capabilities?: unknown; policy_version?: unknown
}): { kind: string | null; settings: Partial<Record<PolicyKey, PolicyValue>>; capabilities: Record<string, string | number | boolean>; policyVersion: string | null } {
  const kind = typeof raw.kind === 'string' && AGENT_KINDS.includes(raw.kind) ? raw.kind : null
  const capabilities: Record<string, string | number | boolean> = {}
  if (raw.capabilities && typeof raw.capabilities === 'object') {
    for (const [k, v] of Object.entries(raw.capabilities as Record<string, unknown>).slice(0, 24)) {
      if (/^[a-z_]{1,40}$/.test(k) && (typeof v === 'boolean' || typeof v === 'number' || (typeof v === 'string' && v.length <= 80))) {
        capabilities[k] = v
      }
    }
  }
  const policyVersionRaw = typeof raw.policy_version === 'string' && /^[0-9a-f]{8}$/.test(raw.policy_version)
    ? raw.policy_version : null
  return { kind, settings: cleanPolicy(raw.settings, kindKeys(kind)), capabilities, policyVersion: policyVersionRaw }
}
