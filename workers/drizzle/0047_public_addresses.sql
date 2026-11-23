-- 0047: the organisation's public addresses (D4, docs/plans/2026-11-23-public-addresses.md). Additive
-- only: a table of addresses agents connect from or admins add, each agent's current public address,
-- and the tenant's switch for the Shodan InternetDB check (on unless turned off).
CREATE TABLE IF NOT EXISTS "public_addresses" (
	"public_address_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"ip" varchar(45) NOT NULL,
	"source" varchar(16) DEFAULT 'agent' NOT NULL,
	"status" varchar(16) DEFAULT 'unconfirmed' NOT NULL,
	"note" varchar(200),
	"first_seen" timestamp with time zone,
	"last_seen" timestamp with time zone,
	"last_agent_id" uuid,
	"blocklists" jsonb,
	"checked_at" timestamp with time zone,
	"internetdb" jsonb,
	"internetdb_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "public_ip" varchar(45);--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "public_ip_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "public_address_lookup" boolean DEFAULT true NOT NULL;--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "public_addresses" ADD CONSTRAINT "public_addresses_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "public_addresses" ADD CONSTRAINT "public_addresses_last_agent_id_agents_agent_id_fk" FOREIGN KEY ("last_agent_id") REFERENCES "public"."agents"("agent_id") ON DELETE set null ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_public_addr_tenant_ip" ON "public_addresses" USING btree ("tenant_id","ip");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_public_addr_ip" ON "public_addresses" USING btree ("ip");