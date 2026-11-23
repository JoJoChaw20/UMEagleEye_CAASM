-- 0046: security baseline (lib/baseline.ts, services/securityBaseline.ts). Additive only: a new alert
-- type, the score per computer (filled from its next inventory, or the nightly job), and the tenant's
-- target (95% unless changed). Not the drift baseline (assets.baseline_state).
ALTER TYPE "public"."event_type" ADD VALUE 'security_baseline';--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "security_baseline_percent" numeric(4, 1);--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "security_baseline" jsonb;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "security_baseline_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "security_baseline_target" smallint DEFAULT 95 NOT NULL;
