-- The bridge (HTTP relay of the retired 1.x agent, agent/bridge.py) is removed:
-- 0 bridges on staging and production (2026-10-15). Foreign key first, then the
-- column, then the table; no CASCADE, so anything unexpected that depends on the
-- table stops the migration instead of being dropped silently.
ALTER TABLE "agents" DROP CONSTRAINT IF EXISTS "agents_bridge_id_bridges_bridge_id_fk";--> statement-breakpoint
ALTER TABLE "agents" DROP COLUMN IF EXISTS "bridge_id";--> statement-breakpoint
DROP TABLE IF EXISTS "bridges";
