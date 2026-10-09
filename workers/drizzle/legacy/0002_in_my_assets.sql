-- 0002_in_my_assets.sql
-- My Assets membership as an explicit boolean, decoupled from `source`.
-- Previously membership was inferred from source = 'manual', kept sticky by a CASE
-- in the scan upsert. That lost the original observation method and made "remove
-- from My Assets" impossible to express. `source` now means only the LAST
-- observation method; `in_my_assets` carries membership.
--
-- HAND-AUTHORED for manual review/apply. NOT registered in drizzle/meta/_journal.json.
-- Additive + idempotent: safe to run once or re-run. DO NOT truncate.

-- 1. Membership flag. Default false = not in My Assets.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS in_my_assets boolean NOT NULL DEFAULT false;

-- 2. Partial index for the My Assets list filter and relationship-graph scope.
CREATE INDEX IF NOT EXISTS idx_assets_in_my_assets ON assets (tenant_id) WHERE in_my_assets;

-- 3. Backfill: every asset currently flagged manual becomes a My Assets member.
--    Idempotent — only flips rows not already true, so re-running is a no-op.
UPDATE assets SET in_my_assets = true WHERE source = 'manual' AND in_my_assets = false;
