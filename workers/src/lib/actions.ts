// Action catalog: every grantable action, its requirements, presets, and the single access decision.
// Labels, descriptions and impact levels are copied from the access-control spec, section 2.

export const ACTION_KEYS = [
  'dashboard.view',
  'asset.view', 'asset.create', 'asset.import', 'asset.edit', 'asset.delete', 'asset.merge',
  'asset.duplicate.dismiss', 'asset.rescore', 'asset.inventory.collect', 'asset.inventory.clear',
  'scan.view', 'scan.active.run', 'scan.passive.run', 'scan.cancel', 'scan.drift.run', 'scan.route.view',
  'sbom.view', 'sbom.download', 'sbom.scan', 'sbom.delete',
  'alert.view', 'alert.manage', 'alert.bulk_update',
  'advisory.view', 'advisory.generate', 'advisory.update', 'advisory.close_via_chat',
  'cti.view', 'ti_event.view', 'ti_event.create', 'ti_event.edit', 'ti_event.publish', 'ti_event.delete',
  'network.view', 'network.map.run', 'topology.edit', 'relationship.view', 'relationship.manage', 'relationship.delete',
  'report.view', 'report.download', 'report.generate', 'report.delete', 'report.snapshot',
  'agent.view', 'agent.installer.download', 'agent.enrol', 'agent.rename', 'agent.configure',
  'agent.roles.assign', 'agent.sightings.enable', 'agent.key.rotate', 'agent.remove',
  'settings.view', 'settings.scan_policy.edit', 'settings.agent_defaults.edit',
  'chatbot.use',
] as const

export type ActionKey = typeof ACTION_KEYS[number]

export const GROUPS = [
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'assets', label: 'Asset inventory' },
  { key: 'scans', label: 'Discovery and scanning' },
  { key: 'sbom', label: 'SBOM' },
  { key: 'alerts', label: 'Alerts' },
  { key: 'advisories', label: 'Advisories' },
  { key: 'threat_intel', label: 'Threat intelligence' },
  { key: 'network', label: 'Network map and relationships' },
  { key: 'reports', label: 'Reports' },
  { key: 'agents', label: 'Agents' },
  { key: 'settings', label: 'Tenant settings' },
  { key: 'assistant', label: 'AI assistant' },
] as const

export type GroupKey = typeof GROUPS[number]['key']
export type Impact = 'low' | 'medium' | 'high'

export type ActionDef = {
  key: ActionKey
  group: GroupKey
  label: string
  description: string
  impact: Impact
  requires: readonly ActionKey[]
  readOnly: boolean
}

type Row = [key: ActionKey, group: GroupKey, label: string, description: string, impact: Impact, requires: ActionKey[]]

const ROWS: Row[] = [
  ['dashboard.view', 'dashboard', 'View dashboard', 'Allows the user to see the security overview: posture score and its history, key figures, and notifications.', 'low', []],

  ['asset.view', 'assets', 'View assets', 'Allows the user to see all assets in the tenant: details, installed software, address history, risk score, baseline and possible duplicates.', 'low', []],
  ['asset.create', 'assets', 'Add assets', 'Allows the user to add an asset by hand.', 'medium', ['asset.view']],
  ['asset.import', 'assets', 'Import assets', 'Allows the user to upload a CSV file of assets. Matching existing assets are updated, not duplicated.', 'medium', ['asset.view']],
  ['asset.edit', 'assets', 'Edit assets', "Allows the user to change an asset's details and record its current state as the approved baseline.", 'medium', ['asset.view']],
  ['asset.delete', 'assets', 'Delete assets', 'Allows the user to permanently delete an asset, with its software list and history. This cannot be undone.', 'high', ['asset.view']],
  ['asset.merge', 'assets', 'Merge duplicate assets', 'Allows the user to combine assets that are the same device into one record. This cannot be undone.', 'high', ['asset.view']],
  ['asset.duplicate.dismiss', 'assets', 'Dismiss duplicate warnings', 'Allows the user to mark two assets as "not a duplicate", and to undo that decision.', 'medium', ['asset.view']],
  ['asset.rescore', 'assets', 'Recalculate risk scores', 'Allows the user to recalculate the risk score of one asset or of all assets.', 'medium', ['asset.view']],
  ['asset.inventory.collect', 'assets', 'Collect software inventory', "Allows the user to ask an asset's agent to report its installed software now.", 'medium', ['asset.view']],
  ['asset.inventory.clear', 'assets', 'Clear software inventory', "Allows the user to delete the recorded software list of an asset. It is rebuilt at the agent's next report.", 'high', ['asset.view']],

  ['scan.view', 'scans', 'View scans', 'Allows the user to see scan history, discovered networks and hosts, scan progress, and comparisons between scans.', 'low', []],
  ['scan.active.run', 'scans', 'Run active scans', 'Allows the user to start a scan that probes a network range to find devices and open ports. Active scans create network traffic and may be noticed by other security tools.', 'medium', ['scan.view']],
  ['scan.passive.run', 'scans', 'Run passive discovery', 'Allows the user to start passive listening, where an agent finds devices from network traffic without sending probes.', 'medium', ['scan.view']],
  ['scan.cancel', 'scans', 'Cancel scans', 'Allows the user to stop a scan that is waiting or running.', 'medium', ['scan.view']],
  ['scan.drift.run', 'scans', 'Run drift check', 'Allows the user to check now for changes from approved baselines and close outdated alerts. This normally runs every night.', 'medium', ['scan.view', 'alert.view']],
  ['scan.route.view', 'scans', 'Preview scan routing', 'Allows the user to see which agent would scan a given network, before starting a scan.', 'low', ['scan.view']],

  ['sbom.view', 'sbom', 'View SBOMs', 'Allows the user to see the software components of each computer, search packages across the tenant, and view dependency trees.', 'low', []],
  ['sbom.download', 'sbom', 'Download SBOMs', 'Allows the user to download SBOM files in standard formats.', 'low', ['sbom.view']],
  ['sbom.scan', 'sbom', 'Run SBOM scans', 'Allows the user to ask an agent to build a fresh SBOM for a computer.', 'medium', ['sbom.view', 'asset.view']],
  ['sbom.delete', 'sbom', 'Delete SBOMs', 'Allows the user to delete all SBOMs recorded for an asset. This cannot be undone.', 'high', ['sbom.view']],

  ['alert.view', 'alerts', 'View alerts', 'Allows the user to see alerts, their evidence, and related CVEs.', 'low', []],
  ['alert.manage', 'alerts', 'Manage alerts', 'Allows the user to acknowledge alerts, change their status, and assign them to people.', 'medium', ['alert.view']],
  ['alert.bulk_update', 'alerts', 'Bulk-update alerts', 'Allows the user to change the status or assignee of many alerts at once.', 'medium', ['alert.manage']],

  ['advisory.view', 'advisories', 'View advisories', 'Allows the user to see remediation advisories and their progress.', 'low', []],
  ['advisory.generate', 'advisories', 'Generate advisories', 'Allows the user to create a remediation advisory from an alert.', 'medium', ['advisory.view', 'alert.view']],
  ['advisory.update', 'advisories', 'Update advisories', "Allows the user to change an advisory's status (open, acknowledged, in progress, resolved) and its assignee.", 'medium', ['advisory.view']],
  ['advisory.close_via_chat', 'advisories', 'Close advisories from the assistant', 'Allows the user to confirm closing an advisory when the AI assistant proposes it.', 'medium', ['advisory.update', 'chatbot.use']],

  ['cti.view', 'threat_intel', 'View threat intelligence', 'Allows the user to see threat indicators, statistics, the MITRE ATT&CK matrix, indicator lookup, and "Seen in traffic" matches.', 'low', []],
  ['ti_event.view', 'threat_intel', 'View threat events', 'Allows the user to see the threat events recorded by the tenant and their indicators.', 'low', ['cti.view']],
  ['ti_event.create', 'threat_intel', 'Create threat events', 'Allows the user to record a new threat event.', 'medium', ['ti_event.view']],
  ['ti_event.edit', 'threat_intel', 'Edit threat events', 'Allows the user to change a threat event, and to add, edit or remove its indicators.', 'medium', ['ti_event.view']],
  ['ti_event.publish', 'threat_intel', 'Publish threat events', 'Allows the user to publish or unpublish a threat event. When published, its indicators are sent to agents for threat sightings.', 'medium', ['ti_event.view']],
  ['ti_event.delete', 'threat_intel', 'Delete threat events', 'Allows the user to permanently delete a threat event and its indicators. This cannot be undone.', 'high', ['ti_event.view']],

  ['network.view', 'network', 'View network map', 'Allows the user to see the network map, device links, and topology tree.', 'low', []],
  ['network.map.run', 'network', 'Map network devices', 'Allows the user to ask a network agent to read routers and switches (SNMP) and update the map.', 'medium', ['network.view']],
  ['topology.edit', 'network', 'Edit topology', 'Allows the user to add or remove topology nodes by hand, and to rebuild the topology from current assets.', 'medium', ['network.view']],
  ['relationship.view', 'network', 'View relationships', 'Allows the user to see how assets depend on each other, and the blast radius of an asset.', 'low', ['asset.view']],
  ['relationship.manage', 'network', 'Manage relationships', 'Allows the user to add relationships by hand and to detect them from current data.', 'medium', ['relationship.view']],
  ['relationship.delete', 'network', 'Delete relationships', 'Allows the user to remove a relationship between assets.', 'medium', ['relationship.view']],

  ['report.view', 'reports', 'View reports', 'Allows the user to see the list of reports and the data behind them.', 'low', []],
  ['report.download', 'reports', 'Download reports', 'Allows the user to download report files.', 'low', ['report.view']],
  ['report.generate', 'reports', 'Generate reports', 'Allows the user to create new reports and upload report files.', 'medium', ['report.view']],
  ['report.delete', 'reports', 'Delete reports', 'Allows the user to permanently delete report files.', 'high', ['report.view']],
  ['report.snapshot', 'reports', 'Take posture snapshots', 'Allows the user to record the current security posture as a fixed point for later comparison.', 'medium', ['report.view']],

  ['agent.view', 'agents', 'View agents', 'Allows the user to see agents, their status, roles and settings.', 'low', []],
  ['agent.installer.download', 'agents', 'Download agent installer', 'Allows the user to download the agent installer.', 'low', ['agent.view']],
  ['agent.enrol', 'agents', 'Enrol agents', 'Allows the user to register agents and to create, view and revoke enrolment tokens. Anyone holding a token can connect a computer to this tenant until it expires or is revoked.', 'high', ['agent.view']],
  ['agent.rename', 'agents', 'Rename agents', "Allows the user to change an agent's display name.", 'low', ['agent.view']],
  ['agent.configure', 'agents', 'Configure agents', "Allows the user to change an agent's settings, such as how often it reports and how deeply it scans.", 'medium', ['agent.view']],
  ['agent.roles.assign', 'agents', 'Assign agent roles', 'Allows the user to switch roles on or off per agent: Scanner (runs scans), Sensor (passive listening), Inventory (reports its own software and SBOM), Collector (reads network devices).', 'medium', ['agent.configure']],
  ['agent.sightings.enable', 'agents', 'Enable threat sightings on agents', "Allows the user to let agents check the computer's DNS lookups and outbound connections against the tenant's threat list. Only matches are sent. The privacy notice covers users of those computers.", 'high', ['agent.configure']],
  ['agent.key.rotate', 'agents', 'Replace agent keys', 'Allows the user to issue a new key to an agent. The old key stops working immediately, and the agent must be updated with the new key.', 'high', ['agent.view']],
  ['agent.remove', 'agents', 'Remove agents', 'Allows the user to remove an agent from the tenant. The computer stops reporting until it is enrolled again.', 'high', ['agent.view']],

  ['settings.view', 'settings', 'View tenant settings', "Allows the user to see the tenant's scan policy and default agent settings.", 'low', []],
  ['settings.scan_policy.edit', 'settings', 'Change scan policy', 'Allows the user to decide whether new devices are investigated automatically, and whether agents may run scans started on their own computer.', 'medium', ['settings.view']],
  ['settings.agent_defaults.edit', 'settings', 'Change default agent settings', 'Allows the user to set the default settings for each kind of agent (computer, network, phone). Agents without their own override follow these defaults.', 'medium', ['settings.view']],

  ['chatbot.use', 'assistant', 'Use AI assistant', "Allows the user to ask the assistant about the tenant's assets, alerts and advisories. The assistant only shows data the user can already view.", 'low', []],
]

const READ_ONLY_EXTRA: ReadonlySet<string> = new Set(['sbom.download', 'report.download', 'agent.installer.download', 'chatbot.use'])

export const ACTIONS: readonly ActionDef[] = ROWS.map(([key, group, label, description, impact, requires]) => ({
  key, group, label, description, impact, requires,
  readOnly: key.endsWith('.view') || READ_ONLY_EXTRA.has(key),
}))

export const ACTION_BY_KEY = Object.fromEntries(ACTIONS.map((a) => [a.key, a])) as Record<ActionKey, ActionDef>

const KEY_SET: ReadonlySet<string> = new Set(ACTION_KEYS)
export function isActionKey(s: string): s is ActionKey {
  return KEY_SET.has(s)
}

/** The given actions plus everything they require, transitively. Unknown keys are dropped. Catalog order. */
export function withRequirements(keys: readonly string[]): ActionKey[] {
  const seen = new Set<ActionKey>()
  const visit = (k: ActionKey) => {
    if (seen.has(k)) return
    seen.add(k)
    for (const r of ACTION_BY_KEY[k].requires) visit(r)
  }
  for (const k of keys) if (isActionKey(k)) visit(k)
  return ACTION_KEYS.filter((k) => seen.has(k))
}

/** Every action whose closure contains `key`, excluding `key` itself. */
export function dependentsOf(key: ActionKey): ActionKey[] {
  return ACTION_KEYS.filter((k) => k !== key && withRequirements([k]).includes(key))
}

const VIEWER: readonly ActionKey[] = [
  'dashboard.view', 'asset.view', 'scan.view', 'sbom.view', 'sbom.download', 'alert.view', 'advisory.view',
  'cti.view', 'ti_event.view', 'network.view', 'relationship.view', 'report.view', 'report.download',
  'agent.view', 'chatbot.use',
]
const ANALYST: readonly ActionKey[] = [
  ...VIEWER,
  'asset.duplicate.dismiss', 'scan.route.view', 'alert.manage', 'alert.bulk_update', 'advisory.generate',
  'advisory.update', 'advisory.close_via_chat', 'ti_event.create', 'ti_event.edit', 'ti_event.publish',
  'relationship.manage', 'report.generate',
]
const OPERATOR: readonly ActionKey[] = [
  ...ANALYST,
  'asset.create', 'asset.import', 'asset.edit', 'asset.rescore', 'asset.inventory.collect',
  'scan.active.run', 'scan.passive.run', 'scan.cancel', 'scan.drift.run', 'sbom.scan',
  'network.map.run', 'topology.edit', 'agent.installer.download', 'agent.rename', 'agent.configure',
  'agent.roles.assign', 'settings.view',
]

export type PresetKey = 'viewer' | 'analyst' | 'operator'

export const PRESETS: readonly { key: PresetKey; label: string; description: string; actions: readonly ActionKey[] }[] = [
  { key: 'viewer', label: 'Viewer', description: 'Sees everything, changes nothing.', actions: VIEWER },
  { key: 'analyst', label: 'Analyst', description: 'Investigates and responds.', actions: ANALYST },
  { key: 'operator', label: 'Operator', description: 'Runs scans and manages assets and agents.', actions: OPERATOR },
]

/** The preset whose action set is exactly `keys` (any order), or null for a custom set. */
export function matchPreset(keys: readonly string[]): PresetKey | null {
  const given = new Set(keys)
  for (const p of PRESETS) {
    if (given.size === p.actions.length && p.actions.every((k) => given.has(k))) return p.key
  }
  return null
}

const TENANT_ADMIN_NOT_GRANTED: readonly string[] = [
  'asset.delete', 'asset.merge', 'report.snapshot', 'settings.scan_policy.edit', 'settings.agent_defaults.edit',
]

/**
 * Actions given to converted accounts. The spec lists 8 extras for tenant_admin but states 53 in total
 * and names five ungranted actions; Clear software inventory is the ninth extra, so tenant_admin is
 * the whole catalog minus those five.
 */
export const MIGRATION_ACTIONS: { tenant_admin: readonly ActionKey[]; business_owner: readonly ActionKey[] } = {
  tenant_admin: ACTION_KEYS.filter((k) => !TENANT_ADMIN_NOT_GRANTED.includes(k)),
  business_owner: VIEWER.filter((k) => k !== 'scan.view' && k !== 'relationship.view'),
}

export type Decision =
  | { ok: true }
  | { ok: false; reason: 'superadmin_read_only' | 'missing_action' | 'not_tenant_member' }

export function decide(
  user: { role: string; tenantId?: string | null; actions: readonly string[] },
  key: ActionKey,
): Decision {
  if (user.role === 'superadmin') {
    return ACTION_BY_KEY[key].readOnly ? { ok: true } : { ok: false, reason: 'superadmin_read_only' }
  }
  if (!user.tenantId) return { ok: false, reason: 'not_tenant_member' }
  if (user.role === 'tenant_superadmin') return { ok: true }
  return user.actions.includes(key) ? { ok: true } : { ok: false, reason: 'missing_action' }
}

export function refusalMessage(reason: Exclude<Decision, { ok: true }>['reason'], key: ActionKey): string {
  switch (reason) {
    case 'superadmin_read_only':
      return 'The Platform Superadmin can view tenants but cannot make changes inside them.'
    case 'missing_action':
      return `You do not have the "${ACTION_BY_KEY[key].label}" action. Ask your Tenant Superadmin to grant it.`
    case 'not_tenant_member':
      return 'Your account is not part of an organisation yet. Ask your administrator to add you.'
  }
}

export function scanActionFor(scanType: 'active' | 'passive'): ActionKey {
  return scanType === 'active' ? 'scan.active.run' : 'scan.passive.run'
}
