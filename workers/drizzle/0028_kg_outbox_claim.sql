-- Rows being applied to the graph are claimed for 90 seconds, so concurrent drains split the work.
-- No index: the claim query orders by changed_at (idx_kg_outbox_changed) and the outbox is small.
ALTER TABLE kg_outbox ADD COLUMN IF NOT EXISTS claimed_until timestamptz;
