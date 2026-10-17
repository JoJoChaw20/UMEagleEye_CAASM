CREATE TYPE "public"."ti_distribution" AS ENUM('organisation', 'all_tenants', 'platform');--> statement-breakpoint
CREATE TYPE "public"."ti_event_status" AS ENUM('draft', 'published');--> statement-breakpoint
CREATE TYPE "public"."ti_threat_level" AS ENUM('low', 'medium', 'high');--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "ti_events" (
	"ti_event_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid,
	"title" varchar(200) NOT NULL,
	"description" text,
	"threat_level" "ti_threat_level" DEFAULT 'medium' NOT NULL,
	"status" "ti_event_status" DEFAULT 'draft' NOT NULL,
	"distribution" "ti_distribution" DEFAULT 'organisation' NOT NULL,
	"tags" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"published_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "cti_indicators" DROP CONSTRAINT "cti_indicators_value_unique";--> statement-breakpoint
ALTER TABLE "cti_indicators" ADD COLUMN "tenant_id" uuid;--> statement-breakpoint
ALTER TABLE "cti_indicators" ADD COLUMN "ti_event_id" uuid;--> statement-breakpoint
ALTER TABLE "cti_indicators" ADD COLUMN "to_ids" boolean DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE "cti_indicators" ADD COLUMN "comment" text;--> statement-breakpoint
ALTER TABLE "cti_indicators" ADD COLUMN "warning" varchar(60);--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "ti_events" ADD CONSTRAINT "ti_events_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "ti_events" ADD CONSTRAINT "ti_events_created_by_users_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("user_id") ON DELETE set null ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_ti_events_tenant" ON "ti_events" USING btree ("tenant_id","status");--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "cti_indicators" ADD CONSTRAINT "cti_indicators_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "cti_indicators" ADD CONSTRAINT "cti_indicators_ti_event_id_ti_events_ti_event_id_fk" FOREIGN KEY ("ti_event_id") REFERENCES "public"."ti_events"("ti_event_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_cti_feed_value" ON "cti_indicators" USING btree ("value") WHERE "cti_indicators"."ti_event_id" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_cti_event_value" ON "cti_indicators" USING btree ("ti_event_id","value") WHERE "cti_indicators"."ti_event_id" IS NOT NULL;