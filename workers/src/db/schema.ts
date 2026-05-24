import {
  pgTable, pgEnum, uuid, varchar, text, boolean, integer,
  smallint, timestamp, jsonb, numeric, index, uniqueIndex,
  primaryKey
} from 'drizzle-orm/pg-core'
import { sql } from 'drizzle-orm'

// ─── Helpers ───────────────────────────────────────────────────
const now = () => sql`now()`
const newUuid = () => sql`gen_random_uuid()`

// ─── Enums ─────────────────────────────────────────────────────
export const deviceTypeEnum = pgEnum('device_type', [
  'server', 'workstation', 'network', 'iot', 'unknown'
])
export const severityEnum = pgEnum('severity', [
  'low', 'medium', 'high', 'critical'
])
export const eventTypeEnum = pgEnum('event_type', [
  'port_opened', 'port_closed', 'version_downgrade', 'version_upgrade',
  'cve_detected', 'new_device', 'config_change', 'new_package',
  'removed_package', 'cti_match'
])
export const indicatorTypeEnum = pgEnum('indicator_type', [
  'ip', 'domain', 'hash', 'url', 'email'
])
export const advisoryStatusEnum = pgEnum('advisory_status', [
  'open', 'acknowledged', 'in_progress', 'resolved'
])
export const userRoleEnum = pgEnum('user_role', [
  'ops_lead', 'security_engineer', 'business_owner', 'mssp_analyst', 'superadmin'
])
export const relationshipTypeEnum = pgEnum('relationship_type', [
  'connects_to', 'depends_on', 'same_subnet', 'authenticates_to', 'exposes_service'
])
export const sbomFormatEnum = pgEnum('sbom_format', ['cyclonedx', 'spdx'])
export const agentStatusEnum = pgEnum('agent_status', ['online', 'offline', 'degraded'])
export const assetSourceEnum = pgEnum('asset_source', ['manual', 'scan_active', 'scan_passive'])
export const topologyNodeTypeEnum = pgEnum('topology_node_type', [
  'gateway', 'router', 'switch', 'access_point', 'host'
])

// ─── Table 1: Tenants ───────────────────────────────────────────
export const tenants = pgTable('tenants', {
  tenantId: uuid('tenant_id').primaryKey().default(newUuid()),
  name: varchar('name', { length: 100 }).notNull(),
  slug: varchar('slug', { length: 50 }).notNull().unique(),
  isActive: boolean('is_active').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now()),
}, (t) => [uniqueIndex('idx_tenants_slug').on(t.slug)])

// ─── Table 2: Users ─────────────────────────────────────────────
export const users = pgTable('users', {
  userId: uuid('user_id').primaryKey().default(newUuid()),
  username: varchar('username', { length: 100 }).notNull().unique(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  passwordHash: varchar('password_hash', { length: 512 }).notNull(),
  role: userRoleEnum('role').notNull().default('business_owner'),
  tenantId: uuid('tenant_id').references(() => tenants.tenantId, { onDelete: 'set null' }),
  googleId: varchar('google_id', { length: 255 }).unique(),
  totpSecret: varchar('totp_secret', { length: 64 }),
  mfaEnabled: boolean('mfa_enabled').notNull().default(false),
  isActive: boolean('is_active').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now()),
  lastLogin: timestamp('last_login', { withTimezone: true }),
  telegramChatId: varchar('telegram_chat_id', { length: 64 }),
}, (t) => [
  index('idx_users_username').on(t.username),
  index('idx_users_tenant').on(t.tenantId),
])

// ─── Table 3: Assets ────────────────────────────────────────────
export const assets = pgTable('assets', {
  assetId: uuid('asset_id').primaryKey().default(newUuid()),
  tenantId: uuid('tenant_id').references(() => tenants.tenantId, { onDelete: 'cascade' }),
  hostname: varchar('hostname', { length: 255 }),
  ipAddress: varchar('ip_address', { length: 45 }).notNull(),
  macAddress: varchar('mac_address', { length: 17 }),
  owner: varchar('owner', { length: 255 }),
  deviceType: deviceTypeEnum('device_type').notNull().default('unknown'),
  hardwareVendor: varchar('hardware_vendor', { length: 255 }),
  osInfo: jsonb('os_info').default({}),
  criticalityScore: smallint('criticality_score').notNull().default(5),
  baselineState: jsonb('baseline_state'),
  isInternetFacing: boolean('is_internet_facing').notNull().default(false),
  source: assetSourceEnum('source').notNull().default('manual'),
  lastScanned: timestamp('last_scanned', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now()),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now()),
}, (t) => [
  index('idx_assets_ip').on(t.ipAddress),
  index('idx_assets_tenant').on(t.tenantId),
])

// ─── Table 4: SBOMs ─────────────────────────────────────────────
export const sboms = pgTable('sboms', {
  sbomId: uuid('sbom_id').primaryKey().default(newUuid()),
  assetId: uuid('asset_id').notNull().references(() => assets.assetId, { onDelete: 'cascade' }),
  format: sbomFormatEnum('format').notNull().default('cyclonedx'),
  formatVersion: varchar('format_version', { length: 10 }).notNull().default('1.5'),
  rawData: jsonb('raw_data').notNull().default({}),
  generatedAt: timestamp('generated_at', { withTimezone: true }).notNull().default(now()),
  toolUsed: varchar('tool_used', { length: 50 }).notNull().default('syft'),
  r2Path: varchar('r2_path', { length: 500 }),
})

// ─── Table 5: Dependencies ──────────────────────────────────────
export const dependencies = pgTable('dependencies', {
  dependencyId: uuid('dependency_id').primaryKey().default(newUuid()),
  assetId: uuid('asset_id').notNull().references(() => assets.assetId, { onDelete: 'cascade' }),
  sbomId: uuid('sbom_id').references(() => sboms.sbomId, { onDelete: 'cascade' }),
  name: varchar('name', { length: 255 }).notNull(),
  version: varchar('version', { length: 100 }).notNull(),
  packageManager: varchar('package_manager', { length: 50 }),
  purl: varchar('purl', { length: 500 }),
  licenses: jsonb('licenses'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now()),
}, (t) => [index('idx_deps_name').on(t.name)])

// ─── Table 6: Events ────────────────────────────────────────────
export const events = pgTable('events', {
  eventId: uuid('event_id').primaryKey().default(newUuid()),
  assetId: uuid('asset_id').notNull().references(() => assets.assetId, { onDelete: 'cascade' }),
  eventType: eventTypeEnum('event_type').notNull(),
  severity: severityEnum('severity').notNull(),
  details: jsonb('details').notNull().default({}),
  compositeRiskScore: numeric('composite_risk_score', { precision: 8, scale: 2 }),
  timestamp: timestamp('timestamp', { withTimezone: true }).notNull().default(now()),
}, (t) => [index('idx_events_timestamp').on(t.timestamp)])

// ─── Table 7: CTI Indicators ────────────────────────────────────
export const ctiIndicators = pgTable('cti_indicators', {
  indicatorId: uuid('indicator_id').primaryKey().default(newUuid()),
  source: varchar('source', { length: 100 }).notNull().default('MyCERT'),
  indicatorType: indicatorTypeEnum('indicator_type').notNull(),
  value: varchar('value', { length: 512 }).notNull().unique(),
  confidenceScore: numeric('confidence_score', { precision: 3, scale: 2 }),
  attackTactic: varchar('attack_tactic', { length: 100 }),
  attackTechnique: varchar('attack_technique', { length: 100 }),
  firstSeen: timestamp('first_seen', { withTimezone: true }).notNull().default(now()),
  lastSeen: timestamp('last_seen', { withTimezone: true }).notNull().default(now()),
}, (t) => [index('idx_cti_value').on(t.value)])

// ─── Table 8: Advisories ────────────────────────────────────────
export const advisories = pgTable('advisories', {
  advisoryId: uuid('advisory_id').primaryKey().default(newUuid()),
  eventId: uuid('event_id').notNull().references(() => events.eventId, { onDelete: 'cascade' }),
  summary: text('summary').notNull(),
  recommendedAction: text('recommended_action').notNull(),
  status: advisoryStatusEnum('status').notNull().default('open'),
  assignedTo: uuid('assigned_to').references(() => users.userId, { onDelete: 'set null' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now()),
  resolvedAt: timestamp('resolved_at', { withTimezone: true }),
})

// ─── Table 9: Posture Metrics ────────────────────────────────────
export const postureMetrics = pgTable('posture_metrics', {
  snapshotId: uuid('snapshot_id').primaryKey().default(newUuid()),
  tenantId: uuid('tenant_id').references(() => tenants.tenantId, { onDelete: 'cascade' }),
  overallScore: smallint('overall_score').notNull(),
  totalAssets: integer('total_assets').notNull().default(0),
  totalCriticalAssets: integer('total_critical_assets').notNull().default(0),
  openCriticalEvents: integer('open_critical_events').notNull().default(0),
  topRisks: jsonb('top_risks'),
  timestamp: timestamp('timestamp', { withTimezone: true }).notNull().default(now()),
}, (t) => [index('idx_posture_timestamp').on(t.timestamp)])

// ─── Table 10: Asset Relationships ──────────────────────────────
export const assetRelationships = pgTable('asset_relationships', {
  relationshipId: uuid('relationship_id').primaryKey().default(newUuid()),
  sourceAssetId: uuid('source_asset_id').notNull().references(() => assets.assetId, { onDelete: 'cascade' }),
  targetAssetId: uuid('target_asset_id').notNull().references(() => assets.assetId, { onDelete: 'cascade' }),
  relationshipType: relationshipTypeEnum('relationship_type').notNull(),
  metadataJson: jsonb('metadata_json'),
  confidence: numeric('confidence', { precision: 3, scale: 2 }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now()),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now()),
}, (t) => [
  index('idx_rel_source').on(t.sourceAssetId),
  index('idx_rel_target').on(t.targetAssetId),
  uniqueIndex('idx_rel_unique').on(t.sourceAssetId, t.targetAssetId, t.relationshipType),
])

// ─── Table 11: Audit Logs ────────────────────────────────────────
export const auditLogs = pgTable('audit_logs', {
  logId: uuid('log_id').primaryKey().default(newUuid()),
  userId: uuid('user_id').notNull().references(() => users.userId, { onDelete: 'cascade' }),
  tenantId: uuid('tenant_id').references(() => tenants.tenantId),
  actionType: varchar('action_type', { length: 100 }).notNull(),
  targetEntity: varchar('target_entity', { length: 255 }),
  previousState: jsonb('previous_state'),
  newState: jsonb('new_state'),
  timestamp: timestamp('timestamp', { withTimezone: true }).notNull().default(now()),
}, (t) => [index('idx_audit_timestamp').on(t.timestamp)])

// ─── Table 14: Bridges (relay for isolated networks) ─────────────
export const bridges = pgTable('bridges', {
  bridgeId: uuid('bridge_id').primaryKey().default(newUuid()),
  tenantId: uuid('tenant_id').references(() => tenants.tenantId, { onDelete: 'set null' }),
  name: varchar('name', { length: 100 }).notNull(),
  apiKeyHash: varchar('api_key_hash', { length: 512 }).notNull(),
  mode: varchar('mode', { length: 20 }).notNull().default('relay'),
  status: agentStatusEnum('status').notNull().default('offline'),
  lastHeartbeat: timestamp('last_heartbeat', { withTimezone: true }),
  bridgeIp: varchar('bridge_ip', { length: 45 }),
  version: varchar('version', { length: 20 }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now()),
}, (t) => [index('idx_bridges_tenant').on(t.tenantId)])

// ─── Table 12: Agents (EagleEye scanning agents) ─────────────────
export const agents = pgTable('agents', {
  agentId: uuid('agent_id').primaryKey().default(newUuid()),
  tenantId: uuid('tenant_id').references(() => tenants.tenantId, { onDelete: 'cascade' }),
  name: varchar('name', { length: 100 }).notNull(),
  apiKeyHash: varchar('api_key_hash', { length: 512 }).notNull(),
  status: agentStatusEnum('status').notNull().default('offline'),
  lastHeartbeat: timestamp('last_heartbeat', { withTimezone: true }),
  gatewayIp: varchar('gateway_ip', { length: 45 }),
  version: varchar('version', { length: 20 }),
  config: jsonb('config').notNull().default({}),
  bridgeId: uuid('bridge_id').references(() => bridges.bridgeId, { onDelete: 'set null' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now()),
}, (t) => [index('idx_agents_tenant').on(t.tenantId)])

// ─── Table 13: Topology Nodes ────────────────────────────────────
export const topologyNodes = pgTable('topology_nodes', {
  nodeId: uuid('node_id').primaryKey().default(newUuid()),
  assetId: uuid('asset_id').references(() => assets.assetId, { onDelete: 'cascade' }),
  tenantId: uuid('tenant_id').references(() => tenants.tenantId, { onDelete: 'cascade' }),
  parentNodeId: uuid('parent_node_id'),  // self-reference handled in app logic
  nodeType: topologyNodeTypeEnum('node_type').notNull().default('host'),
  layer: smallint('layer').notNull().default(4),
  label: varchar('label', { length: 100 }),
  metadata: jsonb('metadata').notNull().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now()),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now()),
}, (t) => [index('idx_topology_tenant').on(t.tenantId)])

// ─── Junction: event_cti_indicators ─────────────────────────────
export const eventCtiIndicators = pgTable('event_cti_indicators', {
  eventId: uuid('event_id').notNull().references(() => events.eventId, { onDelete: 'cascade' }),
  indicatorId: uuid('indicator_id').notNull().references(() => ctiIndicators.indicatorId, { onDelete: 'cascade' }),
}, (t) => [primaryKey({ columns: [t.eventId, t.indicatorId] })])

// ─── Scan results (pushed by agents) ────────────────────────────
export const scanResults = pgTable('scan_results', {
  scanId: uuid('scan_id').primaryKey().default(newUuid()),
  agentId: uuid('agent_id').references(() => agents.agentId, { onDelete: 'cascade' }),
  tenantId: uuid('tenant_id').references(() => tenants.tenantId, { onDelete: 'cascade' }),
  scanType: varchar('scan_type', { length: 20 }).notNull().default('active'),
  subnet: varchar('subnet', { length: 50 }),
  status: varchar('status', { length: 20 }).notNull().default('completed'),
  hostsDiscovered: integer('hosts_discovered').notNull().default(0),
  rawResults: jsonb('raw_results').notNull().default([]),
  startedAt: timestamp('started_at', { withTimezone: true }).notNull().default(now()),
  completedAt: timestamp('completed_at', { withTimezone: true }),
}, (t) => [index('idx_scans_tenant').on(t.tenantId)])
