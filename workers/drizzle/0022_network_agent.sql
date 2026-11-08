CREATE TABLE IF NOT EXISTS "network_links" (
	"link_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"agent_id" uuid,
	"a_name" varchar(255) NOT NULL,
	"a_port" varchar(64) NOT NULL,
	"a_asset_id" uuid,
	"b_name" varchar(255) NOT NULL,
	"b_port" varchar(64) NOT NULL,
	"b_asset_id" uuid,
	"protocols" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"first_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "network_device" jsonb;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "network_location" jsonb;--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "network_links" ADD CONSTRAINT "network_links_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "network_links" ADD CONSTRAINT "network_links_agent_id_agents_agent_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("agent_id") ON DELETE set null ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "network_links" ADD CONSTRAINT "network_links_a_asset_id_assets_asset_id_fk" FOREIGN KEY ("a_asset_id") REFERENCES "public"."assets"("asset_id") ON DELETE set null ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "network_links" ADD CONSTRAINT "network_links_b_asset_id_assets_asset_id_fk" FOREIGN KEY ("b_asset_id") REFERENCES "public"."assets"("asset_id") ON DELETE set null ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_links_ends" ON "network_links" USING btree ("tenant_id","a_name","a_port","b_name","b_port");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_links_a_asset" ON "network_links" USING btree ("a_asset_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_links_b_asset" ON "network_links" USING btree ("b_asset_id");