-- 0048: MyCERT advisories as platform threat-intel events (services/mycert.ts). Additive only: which
-- publisher an event came from and its id there (one event per advisory), the CVEs it says are
-- exploited in the wild, and what else it says (link, rating, kind, affected products).
ALTER TABLE "ti_events" ADD COLUMN "origin" varchar(20);--> statement-breakpoint
ALTER TABLE "ti_events" ADD COLUMN "external_id" varchar(40);--> statement-breakpoint
ALTER TABLE "ti_events" ADD COLUMN "exploited_cves" text[];--> statement-breakpoint
ALTER TABLE "ti_events" ADD COLUMN "source_meta" jsonb;--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_ti_events_origin" ON "ti_events" USING btree ("origin","external_id") WHERE "ti_events"."origin" IS NOT NULL;