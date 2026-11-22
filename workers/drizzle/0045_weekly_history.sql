-- 0045: weekly history (services/weekly.ts). One record per tenant per week (Monday, Malaysia time), and the
-- week a tenant compares against. New only: no existing data changes. Past weeks are filled in by the nightly job.
CREATE TABLE IF NOT EXISTS "weekly_snapshots" (
	"snapshot_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"week_start" date NOT NULL,
	"metrics" jsonb NOT NULL,
	"backfilled" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "baseline_week" date;--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "weekly_snapshots" ADD CONSTRAINT "weekly_snapshots_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_weekly_tenant_week" ON "weekly_snapshots" USING btree ("tenant_id","week_start");