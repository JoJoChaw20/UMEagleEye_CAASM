-- Knowledge graph behind the chatbot (workers/src/kg). See docs/superpowers/specs/2026-11-09-knowledge-graph-chatbot-design.md.
-- Not mapped in src/db/schema.ts: the graph is read and written with raw SQL (vector, tsvector).
CREATE EXTENSION IF NOT EXISTS vector;
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS kg_nodes (
  key text PRIMARY KEY,
  tenant_id uuid REFERENCES tenants(tenant_id) ON DELETE CASCADE,
  visibility text NOT NULL CHECK (visibility IN ('company', 'all_staff', 'platform')),
  role_group text NOT NULL DEFAULT 'analyst' CHECK (role_group IN ('all', 'analyst')),
  type text NOT NULL,
  title text NOT NULL,
  body text NOT NULL DEFAULT '',
  props jsonb NOT NULL DEFAULT '{}',
  source_ref text,
  embedding vector(768),
  tsv tsvector GENERATED ALWAYS AS (to_tsvector('simple', title || ' ' || body)) STORED,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((visibility = 'company') = (tenant_id IS NOT NULL))
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS idx_kg_nodes_scope ON kg_nodes (tenant_id, type);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS idx_kg_nodes_tsv ON kg_nodes USING gin (tsv);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS idx_kg_nodes_props ON kg_nodes USING gin (props jsonb_path_ops);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS idx_kg_nodes_unembedded ON kg_nodes (updated_at) WHERE embedding IS NULL;
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS kg_edges (
  from_key text NOT NULL,
  to_key text NOT NULL,
  relation text NOT NULL,
  tenant_id uuid REFERENCES tenants(tenant_id) ON DELETE CASCADE,
  PRIMARY KEY (from_key, to_key, relation)
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS idx_kg_edges_to ON kg_edges (to_key);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS kg_outbox (
  table_name text NOT NULL,
  row_pk text NOT NULL,
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (table_name, row_pk)
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS idx_kg_outbox_changed ON kg_outbox (changed_at);
--> statement-breakpoint
-- TG_ARGV[0]: the row's id column. TG_ARGV[1], optional: record this table instead of the one changed.
CREATE OR REPLACE FUNCTION kg_capture() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  rec jsonb := to_jsonb(CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END);
BEGIN
  INSERT INTO kg_outbox (table_name, row_pk, changed_at)
  VALUES (COALESCE(TG_ARGV[1], TG_TABLE_NAME), rec ->> TG_ARGV[0], clock_timestamp())
  ON CONFLICT (table_name, row_pk) DO UPDATE SET changed_at = EXCLUDED.changed_at;
  RETURN NULL;
END $$;
--> statement-breakpoint
CREATE TRIGGER kg_assets AFTER INSERT OR UPDATE OR DELETE ON assets FOR EACH ROW EXECUTE FUNCTION kg_capture('asset_id');
--> statement-breakpoint
CREATE TRIGGER kg_advisories AFTER INSERT OR UPDATE OR DELETE ON advisories FOR EACH ROW EXECUTE FUNCTION kg_capture('advisory_id');
--> statement-breakpoint
CREATE TRIGGER kg_relationships AFTER INSERT OR UPDATE OR DELETE ON asset_relationships FOR EACH ROW EXECUTE FUNCTION kg_capture('relationship_id');
--> statement-breakpoint
CREATE TRIGGER kg_sboms AFTER INSERT OR UPDATE OR DELETE ON sboms FOR EACH ROW EXECUTE FUNCTION kg_capture('sbom_id');
--> statement-breakpoint
CREATE TRIGGER kg_ti_events AFTER INSERT OR UPDATE OR DELETE ON ti_events FOR EACH ROW EXECUTE FUNCTION kg_capture('ti_event_id');
--> statement-breakpoint
CREATE TRIGGER kg_topology AFTER INSERT OR UPDATE OR DELETE ON topology_nodes FOR EACH ROW EXECUTE FUNCTION kg_capture('node_id');
--> statement-breakpoint
CREATE TRIGGER kg_links AFTER INSERT OR UPDATE OR DELETE ON network_links FOR EACH ROW EXECUTE FUNCTION kg_capture('link_id');
--> statement-breakpoint
-- High-churn tables: only changes that alter what the graph says (last_seen and heartbeats do not).
CREATE TRIGGER kg_software AFTER INSERT OR DELETE ON asset_software FOR EACH ROW EXECUTE FUNCTION kg_capture('software_id');
--> statement-breakpoint
CREATE TRIGGER kg_dependencies AFTER INSERT OR DELETE ON dependencies FOR EACH ROW EXECUTE FUNCTION kg_capture('dependency_id');
--> statement-breakpoint
CREATE TRIGGER kg_identifiers AFTER INSERT OR DELETE ON asset_identifiers FOR EACH ROW EXECUTE FUNCTION kg_capture('identifier_id');
--> statement-breakpoint
CREATE TRIGGER kg_posture AFTER INSERT ON posture_metrics FOR EACH ROW EXECUTE FUNCTION kg_capture('snapshot_id');
--> statement-breakpoint
CREATE TRIGGER kg_event_cti AFTER INSERT OR DELETE ON event_cti_indicators FOR EACH ROW EXECUTE FUNCTION kg_capture('event_id', 'events');
--> statement-breakpoint
CREATE TRIGGER kg_events_write AFTER INSERT OR DELETE ON events FOR EACH ROW EXECUTE FUNCTION kg_capture('event_id');
--> statement-breakpoint
CREATE TRIGGER kg_events_change AFTER UPDATE ON events FOR EACH ROW
  WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.severity IS DISTINCT FROM NEW.severity OR OLD.details IS DISTINCT FROM NEW.details OR OLD.composite_risk_score IS DISTINCT FROM NEW.composite_risk_score)
  EXECUTE FUNCTION kg_capture('event_id');
--> statement-breakpoint
CREATE TRIGGER kg_agents_write AFTER INSERT OR DELETE ON agents FOR EACH ROW EXECUTE FUNCTION kg_capture('agent_id');
--> statement-breakpoint
CREATE TRIGGER kg_agents_change AFTER UPDATE ON agents FOR EACH ROW
  WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.name IS DISTINCT FROM NEW.name OR OLD.version IS DISTINCT FROM NEW.version OR OLD.retired_at IS DISTINCT FROM NEW.retired_at OR OLD.host_asset_id IS DISTINCT FROM NEW.host_asset_id)
  EXECUTE FUNCTION kg_capture('agent_id');
--> statement-breakpoint
CREATE TRIGGER kg_addresses_write AFTER INSERT OR DELETE ON asset_addresses FOR EACH ROW EXECUTE FUNCTION kg_capture('address_id');
--> statement-breakpoint
CREATE TRIGGER kg_addresses_change AFTER UPDATE ON asset_addresses FOR EACH ROW
  WHEN (OLD.ended_at IS DISTINCT FROM NEW.ended_at OR OLD.ip_address IS DISTINCT FROM NEW.ip_address)
  EXECUTE FUNCTION kg_capture('address_id');
--> statement-breakpoint
CREATE TRIGGER kg_scans_write AFTER INSERT OR DELETE ON scan_results FOR EACH ROW EXECUTE FUNCTION kg_capture('scan_id');
--> statement-breakpoint
CREATE TRIGGER kg_scans_change AFTER UPDATE ON scan_results FOR EACH ROW
  WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.failure_reason IS DISTINCT FROM NEW.failure_reason OR OLD.hosts_discovered IS DISTINCT FROM NEW.hosts_discovered)
  EXECUTE FUNCTION kg_capture('scan_id');
--> statement-breakpoint
-- First fill: every existing row is queued once and applied by the sync in batches.
INSERT INTO kg_outbox (table_name, row_pk)
  SELECT 'assets', asset_id::text FROM assets
  UNION ALL SELECT 'asset_addresses', address_id::text FROM asset_addresses
  UNION ALL SELECT 'asset_software', software_id::text FROM asset_software
  UNION ALL SELECT 'asset_identifiers', identifier_id::text FROM asset_identifiers
  UNION ALL SELECT 'asset_relationships', relationship_id::text FROM asset_relationships
  UNION ALL SELECT 'sboms', sbom_id::text FROM sboms
  UNION ALL SELECT 'dependencies', dependency_id::text FROM dependencies
  UNION ALL SELECT 'events', event_id::text FROM events
  UNION ALL SELECT 'advisories', advisory_id::text FROM advisories
  UNION ALL SELECT 'ti_events', ti_event_id::text FROM ti_events
  UNION ALL SELECT 'agents', agent_id::text FROM agents
  UNION ALL SELECT 'topology_nodes', node_id::text FROM topology_nodes
  UNION ALL SELECT 'network_links', link_id::text FROM network_links
  UNION ALL SELECT 'scan_results', scan_id::text FROM scan_results
  UNION ALL (SELECT DISTINCT ON (tenant_id) 'posture_metrics', snapshot_id::text FROM posture_metrics WHERE tenant_id IS NOT NULL ORDER BY tenant_id, timestamp DESC)
ON CONFLICT DO NOTHING;
