CREATE TABLE IF NOT EXISTS "duplicate_dismissals" (
	"dismissal_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid,
	"asset_a" uuid NOT NULL,
	"asset_b" uuid NOT NULL,
	"reasons" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"dismissed_by" uuid,
	"dismissed_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "assets" ALTER COLUMN "criticality_model" SET DEFAULT 2;--> statement-breakpoint
ALTER TABLE "tenants" ALTER COLUMN "criticality_model" SET DEFAULT 2;--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "duplicate_dismissals" ADD CONSTRAINT "duplicate_dismissals_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "duplicate_dismissals" ADD CONSTRAINT "duplicate_dismissals_asset_a_assets_asset_id_fk" FOREIGN KEY ("asset_a") REFERENCES "public"."assets"("asset_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "duplicate_dismissals" ADD CONSTRAINT "duplicate_dismissals_asset_b_assets_asset_id_fk" FOREIGN KEY ("asset_b") REFERENCES "public"."assets"("asset_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "duplicate_dismissals" ADD CONSTRAINT "duplicate_dismissals_dismissed_by_users_user_id_fk" FOREIGN KEY ("dismissed_by") REFERENCES "public"."users"("user_id") ON DELETE set null ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_dismissal_pair" ON "duplicate_dismissals" USING btree ("asset_a","asset_b");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_dismissal_tenant" ON "duplicate_dismissals" USING btree ("tenant_id");--> statement-breakpoint
-- Hand-written: every tenant scores with criticality v2 (no more per-tenant switch).
-- Stored scores still from v1 are rewritten by the next rescore.
UPDATE "tenants" SET "criticality_model" = 2 WHERE "criticality_model" <> 2;--> statement-breakpoint
-- Hand-written: empty tables left by the retired FastAPI backend (0 rows on staging and
-- production, 2026-10-13). No CASCADE: the migration fails if anything depends on them.
DROP TABLE IF EXISTS "chat_sessions";--> statement-breakpoint
DROP TABLE IF EXISTS "playbook_chunks";
