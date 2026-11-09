/**
 * kg/extract.ts — turns one source row into graph nodes and edges. Pure functions.
 *
 * Each extractor reads only the fields named here, so a column added to a table later stays
 * out of the graph until someone adds it. Never read here: password hashes, TOTP secrets,
 * agent key hashes, enrolment tokens, raw scan output, audit logs. A row with no tenant
 * produces nothing, because a NULL tenant in kg_nodes means knowledge shared with everyone.
 */
import { containsSecret } from './redact'

export type Visibility = 'company' | 'all_staff' | 'platform'
export type RoleGroup = 'all' | 'analyst'

export interface KgNode {
  key: string
  tenantId: string | null
  visibility: Visibility
  roleGroup: RoleGroup
  type: string
  title: string
  body: string
  props: Record<string, unknown>
  sourceRef?: string
}
export interface KgEdge { from: string; to: string; relation: string; tenantId: string | null }
export interface GraphDelta { nodes: KgNode[]; edges: KgEdge[] }
export type Row = Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any

const EMPTY: GraphDelta = { nodes: [], edges: [] }

/** Replaces a lone surrogate (half an emoji) with U+FFFD: Postgres rejects it in text and jsonb. */
export const wellFormed = (s: string): string =>
  s.replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, '\ufffd')

export const clip = (v: unknown, max = 200): string => {
  if (v == null) return ''
  const s = wellFormed(String(v).replace(/\s+/g, ' ').trim())
  // A secret is checked in the whole field, before the cut: a value cut mid-way no longer matches
  // a pattern. Kept whole, the text still matches, so safeDelta blocks the node and nothing is stored.
  if (containsSecret(s)) return s
  if (s.length <= max) return s
  // Cut between characters, never inside an astral pair.
  const cut = /[\ud800-\udbff]/.test(s[max - 1] ?? '') ? max - 1 : max
  return `${s.slice(0, cut)}...`
}
const iso = (v: unknown): string | null => (v == null ? null : new Date(v as string).toISOString())

function node(tenantId: string, key: string, type: string, title: string, body: string, props: Record<string, unknown>, roleGroup: RoleGroup = 'analyst'): KgNode {
  return { key, tenantId, visibility: 'company', roleGroup, type, title: clip(title, 300) || key, body, props }
}

/** Drops anything that contains a secret. Returns the delta and how many nodes were blocked. */
export function safeDelta(d: GraphDelta): GraphDelta & { blocked: number } {
  const nodes = d.nodes.filter(n => !containsSecret(`${n.title}\n${n.body}\n${JSON.stringify(n.props)}`))
  const kept = new Set(nodes.map(n => n.key))
  const dropped = new Set(d.nodes.filter(n => !kept.has(n.key)).map(n => n.key))
  return {
    nodes,
    edges: d.edges.filter(e => !dropped.has(e.from) && !dropped.has(e.to)),
    blocked: dropped.size,
  }
}

const label = (r: Row) => r.hostname || r.ip_address || 'unknown device'

function servicesOf(osInfo: unknown): Array<{ port: number; service: string; product: string }> {
  const list = ((osInfo ?? {}) as Row).services
  if (!Array.isArray(list)) return []
  return list.slice(0, 40).map((s: Row) => ({
    port: Number(s?.port), service: clip(s?.service, 40), product: clip(`${s?.product ?? ''} ${s?.version ?? ''}`, 80),
  })).filter(s => Number.isFinite(s.port))
}

function osName(r: Row): string {
  const inv = (r.inv_os ?? {}) as Row
  if (inv.name) return clip(`${inv.name} ${inv.display_version ?? inv.version ?? ''}`, 100)
  const o = (r.os_info ?? {}) as Row
  return clip(`${o.name ?? o.os_name ?? ''} ${o.os_version ?? o.version ?? ''}`, 100)
}

export function extractAsset(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  const services = servicesOf(r.os_info)
  const internetFacing = r.internet_facing_override ?? r.is_internet_facing ?? false
  const os = osName(r)
  const body = [
    `Device ${label(r)}, IP ${r.ip_address}, type ${r.device_type}.`,
    r.mac_address ? `MAC ${r.mac_address}.` : '',
    os ? `Operating system: ${os}.` : 'Operating system unknown.',
    `Criticality ${r.criticality_score} out of 10.`,
    r.posture_score != null ? `Endpoint posture score ${r.posture_score} out of 100.` : 'Endpoint posture not assessed.',
    internetFacing ? 'Internet-facing.' : 'Not internet-facing.',
    r.in_my_assets ? 'Tracked in My Assets.' : 'Not in My Assets.',
    r.owner ? `Owner: ${clip(r.owner, 100)}.` : '',
    r.hardware_vendor ? `Vendor: ${clip(r.hardware_vendor, 100)}.` : '',
    `Last observed by: ${r.source}.`,
    r.last_scanned ? `Last scanned ${iso(r.last_scanned)}.` : 'Never scanned.',
    services.length ? `Open ports: ${services.map(s => `${s.port}${s.service ? ` (${s.service}${s.product ? `, ${s.product}` : ''})` : ''}`).join('; ')}.` : 'No open ports recorded.',
  ].filter(Boolean).join(' ')
  return {
    nodes: [node(r.tenant_id, `asset:${r.asset_id}`, 'asset', label(r), body, {
      assetId: r.asset_id, hostname: r.hostname ?? null, ip: r.ip_address, deviceType: r.device_type,
      os: os || null, criticality: r.criticality_score, postureScore: r.posture_score ?? null,
      internetFacing: Boolean(internetFacing), inMyAssets: Boolean(r.in_my_assets),
      ports: services.map(s => s.port), lastScanned: iso(r.last_scanned),
    })],
    edges: [],
  }
}

export function extractAddress(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  const key = `address:${r.address_id}`, current = r.ended_at == null
  return {
    nodes: [node(r.tenant_id, key, 'address', `${r.ip_address}`, `Address ${r.ip_address}${r.mac_address ? `, MAC ${r.mac_address}` : ''}, ${current ? 'current' : 'no longer in use'}.`, {
      ip: r.ip_address, current, firstSeen: iso(r.first_seen), lastSeen: iso(r.last_seen),
    })],
    edges: [{ from: key, to: `asset:${r.asset_id}`, relation: 'ADDRESS_OF', tenantId: r.tenant_id }],
  }
}

export function extractSoftware(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  const key = `software:${r.software_id}`
  return {
    nodes: [node(r.tenant_id, key, 'software', `${clip(r.name, 120)} ${clip(r.version, 40)}`.trim(),
      `Installed program ${clip(r.name, 120)}, version ${clip(r.version, 40) || 'unknown'}${r.publisher ? `, from ${clip(r.publisher, 100)}` : ''}, on ${label(r)}.`, {
        name: r.name, version: r.version ?? null, assetKey: `asset:${r.asset_id}`,
      })],
    edges: [{ from: key, to: `asset:${r.asset_id}`, relation: 'INSTALLED_ON', tenantId: r.tenant_id }],
  }
}

export function extractIdentifier(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  const key = `identifier:${r.identifier_id}`
  return {
    nodes: [node(r.tenant_id, key, 'identifier', `${r.kind} ${r.value}`, `Machine identifier of kind ${r.kind}: ${r.value}.`, { kind: r.kind, value: r.value })],
    edges: [{ from: key, to: `asset:${r.asset_id}`, relation: 'IDENTIFIES', tenantId: r.tenant_id }],
  }
}

export function extractRelationship(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  const key = `relationship:${r.relationship_id}`
  // Both ends must belong to this company: a label from another company's device must not enter its node.
  if (r.target_tenant_id !== undefined && r.target_tenant_id !== r.tenant_id) return EMPTY
  const src = r.source_label || 'unknown device', dst = r.target_label || 'unknown device'
  return {
    nodes: [node(r.tenant_id, key, 'relationship', `${src} ${r.relationship_type} ${dst}`,
      `${src} ${String(r.relationship_type).replace(/_/g, ' ')} ${dst}${r.confidence != null ? ` (confidence ${r.confidence})` : ''}.`, { relationshipType: r.relationship_type })],
    edges: [
      { from: key, to: `asset:${r.source_asset_id}`, relation: 'FROM_ASSET', tenantId: r.tenant_id },
      { from: key, to: `asset:${r.target_asset_id}`, relation: 'TO_ASSET', tenantId: r.tenant_id },
    ],
  }
}

export function extractSbom(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  const key = `sbom:${r.sbom_id}`
  return {
    nodes: [node(r.tenant_id, key, 'sbom', `SBOM of ${label(r)}`, `Software bill of materials of ${label(r)}, format ${r.format}, made by ${r.tool_used} on ${iso(r.generated_at)}. This device is checked for CVEs.`, {
      assetKey: `asset:${r.asset_id}`, generatedAt: iso(r.generated_at),
    })],
    edges: [{ from: key, to: `asset:${r.asset_id}`, relation: 'SBOM_OF', tenantId: r.tenant_id }],
  }
}

export function extractDependency(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  const key = `dependency:${r.dependency_id}`
  return {
    nodes: [node(r.tenant_id, key, 'dependency', `${clip(r.name, 120)} ${clip(r.version, 40)}`,
      `Package ${clip(r.name, 120)} version ${clip(r.version, 40)}${r.package_manager ? ` (${clip(r.package_manager, 30)})` : ''} on ${label(r)}.`, {
        name: r.name, version: r.version, assetKey: `asset:${r.asset_id}`,
      })],
    edges: [{ from: key, to: `asset:${r.asset_id}`, relation: 'PACKAGE_ON', tenantId: r.tenant_id }],
  }
}

const OPEN_EVENT = ['open', 'in_progress']
const FACT_KEYS = ['cve_id', 'package_name', 'package_version', 'fix_versions', 'cvss_base_score', 'epss_score', 'kev',
  'port', 'protocol', 'service', 'match_kind', 'indicator', 'missing_kb', 'exploited', 'product', 'changed_attribute',
  'from', 'to', 'package', 'old_value', 'new_value', 'description']

function eventFacts(details: unknown): string {
  const d = (details ?? {}) as Row
  const parts: string[] = []
  for (const k of FACT_KEYS) {
    const v = d[k]
    if (v === undefined || v === null || v === '') continue
    // Only scalars (and lists of scalars, like fix versions): an object under an allowed key
    // would carry subkeys nobody allowlisted.
    const scalar = (x: unknown) => ['string', 'number', 'boolean'].includes(typeof x)
    if (typeof v === 'object' && !(Array.isArray(v) && v.every(scalar))) continue
    parts.push(`${k.replace(/_/g, ' ')}: ${clip(Array.isArray(v) ? v.join(', ') : v, k === 'description' ? 300 : 120)}`)
  }
  return parts.join('; ')
}

export function extractEvent(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  const key = `event:${r.event_id}`, d = (r.details ?? {}) as Row
  const open = OPEN_EVENT.includes(r.status)
  const cve = typeof d.cve_id === 'string' && /^CVE-\d{4}-\d+$/i.test(d.cve_id) ? d.cve_id.toUpperCase() : null
  const facts = eventFacts(d)
  const nodes: KgNode[] = [node(r.tenant_id, key, 'event',
    `${r.severity} ${r.event_type}${cve ? ` ${cve}` : ''} on ${label(r)}`,
    `Alert ${r.event_type}, severity ${r.severity}, status ${r.status}, on ${label(r)} (${r.ip_address}). Raised ${iso(r.timestamp)}, seen ${r.occurrences ?? 1} time(s).${r.composite_risk_score != null ? ` Risk score ${r.composite_risk_score}.` : ''}${facts ? ` ${facts}.` : ''}`, {
      eventId: r.event_id, eventType: r.event_type, severity: r.severity, status: r.status, open,
      cve, assetKey: `asset:${r.asset_id}`, timestamp: iso(r.timestamp),
    })]
  const edges: KgEdge[] = [{ from: key, to: `asset:${r.asset_id}`, relation: 'ALERT_ON', tenantId: r.tenant_id }]
  if (cve) {
    const cveKey = `cve:${r.tenant_id}:${cve}`
    nodes.push(node(r.tenant_id, cveKey, 'cve', cve, `Vulnerability ${cve}, found in this company.${d.cvss_base_score != null ? ` CVSS ${d.cvss_base_score}.` : ''}`, { cve }))
    edges.push({ from: key, to: cveKey, relation: 'ABOUT_CVE', tenantId: r.tenant_id })
  }
  for (const i of (Array.isArray(r.indicators) ? r.indicators : []) as Row[]) {
    const iKey = `indicator:${r.tenant_id}:${i.indicator_id}`
    nodes.push(node(r.tenant_id, iKey, 'indicator', `${i.indicator_type} ${clip(i.value, 120)}`,
      `Threat indicator ${clip(i.value, 200)} of type ${i.indicator_type}, from ${clip(i.source, 60)}${i.malware_family ? `, malware family ${clip(i.malware_family, 80)}` : ''}.`, {
        indicatorType: i.indicator_type, value: i.value,
      }))
    edges.push({ from: key, to: iKey, relation: 'MATCHED_INDICATOR', tenantId: r.tenant_id })
  }
  return { nodes, edges }
}

const ACTIVE_ADVISORY = ['open', 'acknowledged', 'in_progress']

export function extractAdvisory(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  const key = `advisory:${r.advisory_id}`, shortId = String(r.advisory_id).slice(0, 8)
  return {
    nodes: [node(r.tenant_id, key, 'advisory', `Advisory ${shortId}: ${clip(r.summary, 120)}`,
      `Advisory ${shortId}, status ${r.status}, for a ${r.severity} ${r.event_type} on ${label(r)} (${r.ip_address}). Summary: ${clip(r.summary, 600)} Recommended action: ${clip(r.recommended_action, 1200)}`, {
        advisoryId: r.advisory_id, shortId, status: r.status, active: ACTIVE_ADVISORY.includes(r.status),
        severity: r.severity, assetKey: `asset:${r.asset_id}`, createdAt: iso(r.created_at),
      })],
    edges: [{ from: key, to: `event:${r.event_id}`, relation: 'ADVISES_ON', tenantId: r.tenant_id }],
  }
}

export function extractTiEvent(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  return {
    nodes: [node(r.tenant_id, `ti_event:${r.ti_event_id}`, 'ti_event', clip(r.title, 200),
      `Threat-intelligence event "${clip(r.title, 200)}", threat level ${r.threat_level}, status ${r.status}.${r.malware_family ? ` Malware family ${clip(r.malware_family, 80)}.` : ''} ${clip(r.description, 800)}`, {
        threatLevel: r.threat_level, status: r.status,
      })],
    edges: [],
  }
}

export function extractAgent(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  const key = `agent:${r.agent_id}`
  return {
    nodes: [node(r.tenant_id, key, 'agent', `Agent ${clip(r.name, 100)}`,
      `EagleEye ${r.kind} agent ${clip(r.name, 100)}, status ${r.retired_at ? 'retired' : r.status}, version ${r.version ?? 'unknown'}.${r.gateway_ip ? ` Gateway ${r.gateway_ip}.` : ''}`, {
        agentId: r.agent_id, name: r.name, kind: r.kind, status: r.status, retired: r.retired_at != null, version: r.version ?? null,
      })],
    edges: r.host_asset_id ? [{ from: key, to: `asset:${r.host_asset_id}`, relation: 'RUNS_ON', tenantId: r.tenant_id }] : [],
  }
}

export function extractTopology(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  const key = `topology:${r.node_id}`
  const edges: KgEdge[] = []
  if (r.asset_id) edges.push({ from: key, to: `asset:${r.asset_id}`, relation: 'TOPOLOGY_OF', tenantId: r.tenant_id })
  if (r.parent_node_id) edges.push({ from: key, to: `topology:${r.parent_node_id}`, relation: 'CHILD_OF', tenantId: r.tenant_id })
  return {
    nodes: [node(r.tenant_id, key, 'topology', clip(r.label, 100) || `${r.node_type} node`, `Network topology ${r.node_type} ${clip(r.label, 100)}, layer ${r.layer}.`, { nodeType: r.node_type })],
    edges,
  }
}

export function extractLink(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  const key = `link:${r.link_id}`
  const edges: KgEdge[] = []
  if (r.a_asset_id) edges.push({ from: key, to: `asset:${r.a_asset_id}`, relation: 'CABLE_END', tenantId: r.tenant_id })
  if (r.b_asset_id) edges.push({ from: key, to: `asset:${r.b_asset_id}`, relation: 'CABLE_END', tenantId: r.tenant_id })
  return {
    nodes: [node(r.tenant_id, key, 'link', `${clip(r.a_name, 80)} to ${clip(r.b_name, 80)}`, `Network cable from ${clip(r.a_name, 80)} port ${clip(r.a_port, 40)} to ${clip(r.b_name, 80)} port ${clip(r.b_port, 40)}.`, {})],
    edges,
  }
}

export function extractScan(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  const key = `scan:${r.scan_id}`
  return {
    nodes: [node(r.tenant_id, key, 'scan', `${r.scan_type} scan ${r.status}${r.subnet ? ` of ${r.subnet}` : ''}`,
      `A ${r.scan_type} scan${r.subnet ? ` of ${r.subnet}` : ''}, status ${r.status}, found ${r.hosts_discovered} host(s), started ${iso(r.started_at)}.${r.failure_reason ? ` Failure reason: ${clip(r.failure_reason, 400)}.` : ''}`, {
        scanType: r.scan_type, status: r.status, agentKey: r.agent_id ? `agent:${r.agent_id}` : null, startedAt: iso(r.started_at),
      })],
    edges: r.agent_id ? [{ from: key, to: `agent:${r.agent_id}`, relation: 'RUN_BY', tenantId: r.tenant_id }] : [],
  }
}

export function extractPosture(r: Row): GraphDelta {
  if (!r.tenant_id) return EMPTY
  return {
    nodes: [node(r.tenant_id, `posture:${r.tenant_id}`, 'posture', 'Security posture',
      `Security posture score ${r.overall_score} out of 100, measured ${iso(r.timestamp)}, across ${r.total_assets} assets, ${r.total_critical_assets} of them critical, with ${r.open_critical_events} open critical alerts.`, {
        score: r.overall_score, totalAssets: r.total_assets, criticalAssets: r.total_critical_assets, openCritical: r.open_critical_events, measuredAt: iso(r.timestamp),
      }, 'all')],
    edges: [],
  }
}
