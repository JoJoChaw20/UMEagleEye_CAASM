ALTER TABLE "assets" ADD COLUMN "criticality_model" smallint DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "posture_score" smallint;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "posture_model" smallint;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "posture_assessed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "posture_checks" jsonb;--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "criticality_model" smallint DEFAULT 1 NOT NULL;