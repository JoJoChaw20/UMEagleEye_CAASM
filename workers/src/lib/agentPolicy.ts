// Agent policy: what an admin sets for agents from the dashboard, per tenant (defaults, kept
// apart for each kind of agent) and per agent (overrides). Pure functions; routes/agents.ts and routes/tenants.ts store
// and serve it, the heartbeat delivers it, and job creation checks it.
//
// A setting resolves as: this agent's override > the tenant's default > the built-in default
// (DEFAULTS). The dashboard is the only place settings are changed (2.6): the agent applies
// every resolved value (`managed` is the full set) and its app only shows them. Migration 0025
// turned what agents had chosen on their own computers into overrides, so nothing changed for
// them. How the agent scans and listens is not a setting: its own engine and the built-in
// capture (Nmap and Npcap remain command-line tools for evaluation).
//
// Roles are not stored; they are read from the settings: Inventory (inventory + SBOM of
// its own computer), Sensor (passive listening on its network), Scanner (runs scans the
// dashboard sends it), and for a network agent Collector (reads routers and switches over
// SNMP). Switching a role on or off in the dashboard sets those settings.

export type PolicyValue = boolean | number | string | string[]
type Spec =
  | { type: 'bool' }
  | { type: 'int'; min: number; max: number }
  | { type: 'enum'; values: readonly string[] }
  | { type: 'list'; item: 'ip' | 'cidr'; max: number }

export const POLICY_SPECS = {
  scanner: { type: 'bool' },
  scan_ports: { type: 'enum', values: ['base', 'consumer', 'wide'] },   // Scan depth
  passive: { type: 'bool' },
  passive_interval: { type: 'int', min: 10, max: 3600 },
  inventory: { type: 'bool' },
  inventory_interval: { type: 'int', min: 300, max: 7 * 86400 },
  // A phone's list of installed apps (personal: off unless set). A computer always reports its
  // software, per-user installs included; administrator accounts only as a count.
  inventory_user_software: { type: 'bool' },
  sbom: { type: 'bool' },
  sbom_interval: { type: 'int', min: 3600, max: 30 * 86400 },
  // The network agent (agent-gui/eagleeye/netagent): it reads the seed routers and switches,
  // then their CDP/LLDP neighbours inside the allowed ranges, up to network_depth hops away,
  // every network_interval seconds. Its SNMP credentials stay on the agent.
  network_poll: { type: 'bool' },
  network_seeds: { type: 'list', item: 'ip', max: 16 },
  network_ranges: { type: 'list', item: 'cidr', max: 32 },
  network_depth: { type: 'int', min: 0, max: 6 },
  network_interval: { type: 'int', min: 300, max: 86400 },
} as const satisfies Record<string, Spec>

export type PolicyKey = keyof typeof POLICY_SPECS
export const POLICY_KEYS = Object.keys(POLICY_SPECS) as PolicyKey[]

// Which settings each kind of agent has: a computer's own agent, the network agent, and the phone
// agent (mobile-agent/, Android): a phone only reports its own inventory (apps only when allowed).
const NETWORK_KEYS = ['network_poll', 'network_seeds', 'network_ranges', 'network_depth', 'network_interval'] as const
const MOBILE_KEYS = ['inventory', 'inventory_interval', 'inventory_user_software'] as const
const NOT_HOST: readonly string[] = [...NETWORK_KEYS, 'inventory_user_software']
export const KIND_KEYS: Record<string, readonly PolicyKey[]> = {
  host: POLICY_KEYS.filter((k) => !NOT_HOST.includes(k)),
  network: NETWORK_KEYS,
  mobile: MOBILE_KEYS,
}
export const AGENT_KINDS = Object.keys(KIND_KEYS)

/** The tenant defaults of one kind of agent. tenants.agent_policy keeps them apart per kind
 *  ({host: {...}, network: {...}, mobile: {...}}, migration 0031), so a phone default never
 *  changes the computers; a flat object (before 0031) is read as the defaults of every kind. */
export function tenantDefaultsFor(stored: unknown, kind: string | null | undefined): Partial<Record<PolicyKey, PolicyValue>> {
  const keys = kindKeys(kind)
  if (!stored || typeof stored !== 'object' || Array.isArray(stored)) return {}
  const byKind = stored as Record<string, unknown>
  if (!AGENT_KINDS.some((k) => k in byKind)) return cleanPolicy(stored, keys)
  return cleanPolicy(byKind[kind ?? 'host'], keys)
}

export const ROLE_KEYS = {
  inventory: ['inventory', 'sbom'],
  sensor: ['passive'],
  scanner: ['scanner'],
  collector: ['network_poll'],
} as const satisfies Record<string, readonly PolicyKey[]>
export type Role = keyof typeof ROLE_KEYS

// What an agent does when nobody set a value (the agent's own built-in defaults, config.py).
export const DEFAULTS: Record<PolicyKey, PolicyValue> = {
  scanner: true, scan_ports: 'base', passive: false, passive_interval: 300,
  inventory: true, inventory_interval: 21600, inventory_user_software: false,
  sbom: true, sbom_interval: 86400,
  network_poll: true, network_seeds: [], network_ranges: [], network_depth: 3, network_interval: 900,
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

/** An IPv4 address, or a CIDR range written as its network address ("10.10.0.0/16"); a
 *  range given by one of its addresses ("10.10.5.1/16") is moved to its network address. */
function listItem(item: 'ip' | 'cidr', raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined
  const text = raw.trim()
  if (item === 'ip') return IPV4.test(text) ? text : undefined
  const [ip, bits, extra] = text.split('/')
  const prefix = Number(bits)
  if (extra !== undefined || !ip || !IPV4.test(ip) || !/^\d{1,2}$/.test(bits ?? '') || prefix > 32) return undefined
  const n = ip.split('.').reduce((acc, part) => acc * 256 + Number(part), 0)
  const size = 2 ** (32 - prefix)
  const base = Math.floor(n / size) * size
  return [16777216, 65536, 256, 1].map((d) => Math.floor(base / d) % 256).join('.') + '/' + prefix
}

export type Source = 'agent' | 'tenant' | 'default'
export interface PolicyEntry {
  key: PolicyKey
  value: PolicyValue
  source: Source
  override: PolicyValue | null     // this agent's override
  tenant_default: PolicyValue | null
  inherited: PolicyValue           // the value without this agent's override
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
  if (spec.type === 'list') {
    if (!Array.isArray(raw) || raw.length > spec.max) return undefined
    const items = raw.map((r) => listItem(spec.item, r))
    if (items.some((i) => i === undefined)) return undefined
    return [...new Set(items as string[])]
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
  if (spec.type === 'list') {
    return `must be a list of at most ${spec.max} ${spec.item === 'ip' ? 'IPv4 addresses' : 'IPv4 ranges such as 10.0.0.0/8'}`
  }
  return `must be one of ${spec.values.join(', ')}`
}

export interface ResolveInput {
  kind?: string | null
  overrides?: unknown                 // agents.policy
  tenantDefaults?: unknown            // this kind's tenant defaults (tenantDefaultsFor)
}

export interface ResolvedPolicy {
  entries: PolicyEntry[]
  managed: Partial<Record<PolicyKey, PolicyValue>>   // what the agent applies: every setting of its kind
  effective: Partial<Record<PolicyKey, PolicyValue>> // the same values (kept for the job checks)
  roles: Partial<Record<Role, boolean>>              // this kind's roles
  version: string                                    // changes when `managed` changes
}

export function resolvePolicy(input: ResolveInput): ResolvedPolicy {
  const keys = kindKeys(input.kind)
  const overrides = cleanPolicy(input.overrides, keys)
  const defaults = cleanPolicy(input.tenantDefaults, keys)
  const entries: PolicyEntry[] = []
  const effective: Partial<Record<PolicyKey, PolicyValue>> = {}
  for (const key of keys) {
    const fromTenant = defaults[key] !== undefined
    const inherited = fromTenant ? defaults[key]! : DEFAULTS[key]
    const overridden = overrides[key] !== undefined
    const value = overridden ? overrides[key]! : inherited
    effective[key] = value
    entries.push({
      key, value, source: overridden ? 'agent' : fromTenant ? 'tenant' : 'default',
      override: overrides[key] ?? null, tenant_default: defaults[key] ?? null, inherited,
    })
  }
  const managed = { ...effective }
  const roles: Partial<Record<Role, boolean>> = {}
  for (const [role, roleKeys] of Object.entries(ROLE_KEYS) as [Role, readonly PolicyKey[]][]) {
    const values = roleKeys.filter((k) => keys.includes(k)).map((k) => effective[k])
    if (values.length === 0) continue                 // not a role of this kind of agent
    roles[role] = values.some((v) => v === true)
  }
  return { entries, managed, effective, roles, version: policyVersion(managed) }
}

/** An agent's own choices, adopted once at its first report (2.6): each one that differs from
 *  the built-in default becomes this agent's override, unless the agent or its tenant already
 *  set it. Install-time settings (EAGLEEYE_NETWORK_SEEDS, `config init --network-seed`, a value
 *  chosen in an older app) thus show on the dashboard and are changed there from then on.
 *  Migration 0025 did the same for the agents that existed. Returns the new overrides. */
export function adoptLocal(
  kind: string | null | undefined, reported: unknown, overrides: unknown, tenantDefaults: unknown,
): Partial<Record<PolicyKey, PolicyValue>> {
  const keys = kindKeys(kind)
  const local = cleanPolicy(reported, keys)
  const current = cleanPolicy(overrides, keys)
  const defaults = cleanPolicy(tenantDefaults, keys)
  for (const key of keys) {
    const value = local[key]
    if (value === undefined || current[key] !== undefined || defaults[key] !== undefined) continue
    if (JSON.stringify(value) !== JSON.stringify(DEFAULTS[key])) current[key] = value
  }
  return current
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
export function jobRefusal(effective: Partial<Record<PolicyKey, PolicyValue>>, job: 'active' | 'inventory' | 'sbom' | 'snmp'): string | null {
  if (job === 'active' && effective.scanner === false) {
    return 'This agent does not run scans from the dashboard (its Scanner role is off).'
  }
  if (job === 'inventory' && effective.inventory === false) {
    return 'Endpoint inventory is switched off for this agent.'
  }
  if (job === 'sbom' && effective.sbom === false) {
    return 'The SBOM is switched off for this agent.'
  }
  if (job === 'snmp' && effective.network_poll === false) {
    return 'This network agent does not read the network (its Collector role is off).'
  }
  return null
}

/** What an agent reports in its heartbeat about itself, kept within limits. */
export function cleanReport(raw: {
  kind?: unknown; settings?: unknown; capabilities?: unknown; policy_version?: unknown; networks?: unknown
}): { kind: string | null; settings: Partial<Record<PolicyKey, PolicyValue>>; capabilities: Record<string, string | number | boolean>; policyVersion: string | null; networks: string[] } {
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
  // The IPv4 networks it is directly on (2.5.1+), for routing scans to it.
  const networks = Array.isArray(raw.networks)
    ? raw.networks.filter((n): n is string => typeof n === 'string' && /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(n)).slice(0, 16)
    : []
  return { kind, settings: cleanPolicy(raw.settings, kindKeys(kind)), capabilities, policyVersion: policyVersionRaw, networks }
}
