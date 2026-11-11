ALTER TABLE "assets" ADD COLUMN "ports_seen_at" timestamp with time zone;--> statement-breakpoint
-- Until now a port alert counted any sighting, a passive upload too (it moves last_scanned but
-- sees no ports). Each device's ports were last checked by its last completed active scan that
-- found it at its address; a device never actively scanned stays NULL (its port alerts wait).
UPDATE "assets" AS a
SET "ports_seen_at" = s.seen
FROM (
  SELECT a2."asset_id", max(COALESCE(r."completed_at", r."started_at")) AS seen
  FROM "assets" AS a2
  JOIN "scan_results" AS r
    ON r."tenant_id" IS NOT DISTINCT FROM a2."tenant_id"
   AND r."scan_type" = 'active' AND r."status" = 'completed'
   AND r."raw_results" @> jsonb_build_array(jsonb_build_object('ip', a2."ip_address"))
  GROUP BY a2."asset_id"
) AS s
WHERE a."asset_id" = s."asset_id";
