-- 0003_topology_nodes_asset_unique.sql
-- Enforce one topology node per asset (topology_nodes.asset_id) — the invariant the
-- merge planner and the criticality topology-layer lookup both assume. Partial, so
-- hand-authored nodes with no asset_id (asset_id IS NULL) are unaffected.
--
-- HAND-AUTHORED for manual review/apply. NOT registered in drizzle/meta/_journal.json.
-- NOT APPLIED by this change. Create it only after the preflight returns zero rows.
--
-- Preflight — must return NO rows before applying (the owner's check showed none):
--   SELECT asset_id, COUNT(*)
--   FROM topology_nodes
--   WHERE asset_id IS NOT NULL
--   GROUP BY asset_id
--   HAVING COUNT(*) > 1;
--
-- After applying: POST /topology/nodes that inserts a SECOND node for an asset_id
-- which already has one will be REJECTED (unique violation) — see the code report.
-- POST /topology/infer stays safe: it deletes the tenant's nodes before re-inserting
-- one per asset, so it never trips the index.

CREATE UNIQUE INDEX IF NOT EXISTS idx_topology_nodes_asset_unique
  ON topology_nodes (asset_id)
  WHERE asset_id IS NOT NULL;
