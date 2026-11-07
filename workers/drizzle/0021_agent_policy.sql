ALTER TABLE "agents" ADD COLUMN "kind" varchar(20) DEFAULT 'host' NOT NULL;--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "policy" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "reported" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "agent_policy" jsonb DEFAULT '{}'::jsonb NOT NULL;