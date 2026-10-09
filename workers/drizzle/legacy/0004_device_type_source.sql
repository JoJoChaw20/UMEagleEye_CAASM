-- 0004_device_type_source.sql
-- Track whether an asset's device_type was set by a user (manual) or inferred by a
-- scan (auto). A 'manual' type is NEVER changed by a scan; an 'auto' type may be
-- corrected by a later ACTIVE scan that infers a different non-unknown type.
-- See lib/ingest-plan.ts resolveIngestDeviceType.
--
-- HAND-AUTHORED for manual review/apply. NOT registered in drizzle/meta/_journal.json
-- (same convention as 0002_in_my_assets.sql / 0003_topology_nodes_asset_unique.sql).
-- Additive + idempotent: safe to run once or re-run.
--
-- DEPLOY ORDER: apply this migration FIRST, then deploy the worker. If the worker is
-- deployed BEFORE the migration, every write that sets device_type_source (scan ingest,
-- POST /assets, PATCH, CSV import, merge) fails with "column device_type_source does
-- not exist" (HTTP 500) until the column exists. Reads are unaffected.

-- 1. Column. Default 'auto' for any future row the code forgets to set (the worker now
--    sets it explicitly on every insert/update; this is only a safety net).
ALTER TABLE assets ADD COLUMN IF NOT EXISTS device_type_source text NOT NULL DEFAULT 'auto';

-- 2. Backfill EXISTING rows to 'manual' to PROTECT everything already in the inventory
--    — overwriting a user's confirmed type is worse than leaving a wrong auto guess.
--    Run BEFORE the worker starts writing, so there are no genuinely-new 'auto' rows yet.
--    The reset SQL below (run separately, after review) re-opens suspect rows.
UPDATE assets SET device_type_source = 'manual' WHERE device_type_source = 'auto';

-- ─────────────────────────────────────────────────────────────────────────────
-- OWNER SQL (NOT part of the migration — run manually after review)
--
-- (a) Suspect list: device_type='network' assets whose IP ends in .1/.254 and whose
--     port data shows NO real network evidence (no router/switch/SNMP product text).
--     These were likely promoted by the old positional guess.
--
--   SELECT a.asset_id, a.hostname, a.ip_address, a.device_type, a.device_type_source
--   FROM assets a
--   WHERE a.device_type = 'network'
--     AND split_part(a.ip_address, '.', 4) IN ('1','254')
--     AND NOT EXISTS (
--       SELECT 1 FROM jsonb_array_elements(COALESCE(a.os_info->'services','[]'::jsonb)) s
--       WHERE lower(COALESCE(s->>'product','') || ' ' || COALESCE(s->>'service',''))
--             ~ '(busybox|router|cisco|juniper|aruba|mikrotik|ubiquiti|fortigate|panos|snmp)'
--     );
--
-- (b) Reset template (NOT run) — after reviewing (a), set the chosen ids back to
--     unknown/auto so the next ACTIVE scan reclassifies them from real evidence:
--
--   UPDATE assets
--   SET device_type = 'unknown', device_type_source = 'auto'
--   WHERE asset_id IN ('<id1>', '<id2>' /* , … reviewed ids only */);
-- ─────────────────────────────────────────────────────────────────────────────
