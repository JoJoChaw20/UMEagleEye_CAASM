-- 0044: an index for looking indicators up by type and value across feeds and events (threat-intel matching:
-- services/threatIntel.ts refreshCveIntel, services/iocMatch.ts, routes/sightings.ts). The two partial indexes
-- on value serve only feed rows or only event rows, so these lookups read the whole table each time.
CREATE INDEX IF NOT EXISTS "idx_cti_type_value" ON "cti_indicators" USING btree ("indicator_type","value");
