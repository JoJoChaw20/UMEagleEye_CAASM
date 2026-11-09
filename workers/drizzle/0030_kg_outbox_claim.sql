-- Knowledge graph outbox, part 2. 0029 is already applied, so everything new is here.
--
-- claimed_until: rows being applied are claimed for 90 seconds, so concurrent drains split the work.
-- attempts: counted at each claim; a row that reaches 5 is set aside (excluded from claims) until a
--   new change to the same row resets it, so one bad row cannot loop the queue.
-- tenant_id: the company a change belongs to, resolved when it is captured, so a company's chat can
--   apply its own changes first. NULL means not resolved; the global drain handles those. No foreign
--   key: a tenant delete must never be blocked by the outbox.
ALTER TABLE kg_outbox ADD COLUMN IF NOT EXISTS claimed_until timestamptz;
--> statement-breakpoint
ALTER TABLE kg_outbox ADD COLUMN IF NOT EXISTS attempts integer NOT NULL DEFAULT 0;
--> statement-breakpoint
ALTER TABLE kg_outbox ADD COLUMN IF NOT EXISTS tenant_id uuid;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS idx_kg_outbox_tenant ON kg_outbox (tenant_id, changed_at);
--> statement-breakpoint
-- Same trigger function as 0029, now recording the company. The lookup can never fail or block the
-- business write: any error leaves the tenant NULL. A newer change keeps a known tenant, resets the
-- attempts and releases the claim (a drain still working on the old version leaves the entry alone,
-- because its changed_at no longer matches).
CREATE OR REPLACE FUNCTION kg_capture() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  rec jsonb := to_jsonb(CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END);
  tid uuid;
BEGIN
  BEGIN
    tid := NULLIF(rec ->> 'tenant_id', '')::uuid;
    IF tid IS NULL AND rec ->> 'asset_id' IS NOT NULL THEN
      SELECT a.tenant_id INTO tid FROM assets a WHERE a.asset_id = (rec ->> 'asset_id')::uuid;
    END IF;
    IF tid IS NULL AND rec ->> 'source_asset_id' IS NOT NULL THEN
      SELECT a.tenant_id INTO tid FROM assets a WHERE a.asset_id = (rec ->> 'source_asset_id')::uuid;
    END IF;
    IF tid IS NULL AND rec ->> 'event_id' IS NOT NULL THEN
      SELECT a.tenant_id INTO tid FROM events e JOIN assets a ON a.asset_id = e.asset_id WHERE e.event_id = (rec ->> 'event_id')::uuid;
    END IF;
  EXCEPTION WHEN OTHERS THEN
    tid := NULL;
  END;
  INSERT INTO kg_outbox (table_name, row_pk, changed_at, tenant_id)
  VALUES (COALESCE(TG_ARGV[1], TG_TABLE_NAME), rec ->> TG_ARGV[0], clock_timestamp(), tid)
  ON CONFLICT (table_name, row_pk) DO UPDATE SET
    changed_at = EXCLUDED.changed_at,
    tenant_id = COALESCE(EXCLUDED.tenant_id, kg_outbox.tenant_id),
    attempts = 0,
    claimed_until = NULL;
  RETURN NULL;
END $$;
--> statement-breakpoint
-- An alert moved to another device (asset merge) must requeue its advisories: they name the device.
CREATE OR REPLACE FUNCTION kg_capture_event_advisories() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO kg_outbox (table_name, row_pk, changed_at, tenant_id)
  SELECT 'advisories', v.advisory_id::text, clock_timestamp(), (SELECT a.tenant_id FROM assets a WHERE a.asset_id = NEW.asset_id)
  FROM advisories v WHERE v.event_id = NEW.event_id
  ON CONFLICT (table_name, row_pk) DO UPDATE SET
    changed_at = EXCLUDED.changed_at,
    tenant_id = COALESCE(EXCLUDED.tenant_id, kg_outbox.tenant_id),
    attempts = 0,
    claimed_until = NULL;
  RETURN NULL;
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END $$;
--> statement-breakpoint
-- Asset merge moves rows with UPDATE of asset_id (routes/assets.ts): software, dependencies,
-- identifiers, addresses, alerts. SBOMs, relationships, topology nodes and agents already capture every update.
DROP TRIGGER IF EXISTS kg_software_move ON asset_software;
--> statement-breakpoint
CREATE TRIGGER kg_software_move AFTER UPDATE ON asset_software FOR EACH ROW
  WHEN (OLD.asset_id IS DISTINCT FROM NEW.asset_id) EXECUTE FUNCTION kg_capture('software_id');
--> statement-breakpoint
DROP TRIGGER IF EXISTS kg_dependencies_move ON dependencies;
--> statement-breakpoint
CREATE TRIGGER kg_dependencies_move AFTER UPDATE ON dependencies FOR EACH ROW
  WHEN (OLD.asset_id IS DISTINCT FROM NEW.asset_id) EXECUTE FUNCTION kg_capture('dependency_id');
--> statement-breakpoint
DROP TRIGGER IF EXISTS kg_identifiers_move ON asset_identifiers;
--> statement-breakpoint
CREATE TRIGGER kg_identifiers_move AFTER UPDATE ON asset_identifiers FOR EACH ROW
  WHEN (OLD.asset_id IS DISTINCT FROM NEW.asset_id) EXECUTE FUNCTION kg_capture('identifier_id');
--> statement-breakpoint
-- Alerts: also when the device changes or the occurrence count moves (the node body shows it).
DROP TRIGGER IF EXISTS kg_events_change ON events;
--> statement-breakpoint
CREATE TRIGGER kg_events_change AFTER UPDATE ON events FOR EACH ROW
  WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.severity IS DISTINCT FROM NEW.severity OR OLD.details IS DISTINCT FROM NEW.details
        OR OLD.composite_risk_score IS DISTINCT FROM NEW.composite_risk_score OR OLD.occurrences IS DISTINCT FROM NEW.occurrences
        OR OLD.asset_id IS DISTINCT FROM NEW.asset_id)
  EXECUTE FUNCTION kg_capture('event_id');
--> statement-breakpoint
DROP TRIGGER IF EXISTS kg_events_move_advisories ON events;
--> statement-breakpoint
CREATE TRIGGER kg_events_move_advisories AFTER UPDATE ON events FOR EACH ROW
  WHEN (OLD.asset_id IS DISTINCT FROM NEW.asset_id) EXECUTE FUNCTION kg_capture_event_advisories();
--> statement-breakpoint
-- Agents: also the gateway address.
DROP TRIGGER IF EXISTS kg_agents_change ON agents;
--> statement-breakpoint
CREATE TRIGGER kg_agents_change AFTER UPDATE ON agents FOR EACH ROW
  WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.name IS DISTINCT FROM NEW.name OR OLD.version IS DISTINCT FROM NEW.version
        OR OLD.retired_at IS DISTINCT FROM NEW.retired_at OR OLD.host_asset_id IS DISTINCT FROM NEW.host_asset_id
        OR OLD.gateway_ip IS DISTINCT FROM NEW.gateway_ip)
  EXECUTE FUNCTION kg_capture('agent_id');
--> statement-breakpoint
-- Addresses: also the MAC address and a move to another device.
DROP TRIGGER IF EXISTS kg_addresses_change ON asset_addresses;
--> statement-breakpoint
CREATE TRIGGER kg_addresses_change AFTER UPDATE ON asset_addresses FOR EACH ROW
  WHEN (OLD.ended_at IS DISTINCT FROM NEW.ended_at OR OLD.ip_address IS DISTINCT FROM NEW.ip_address
        OR OLD.mac_address IS DISTINCT FROM NEW.mac_address OR OLD.asset_id IS DISTINCT FROM NEW.asset_id)
  EXECUTE FUNCTION kg_capture('address_id');
