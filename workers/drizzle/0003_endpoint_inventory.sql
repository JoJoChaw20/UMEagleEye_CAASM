ALTER TYPE "public"."asset_source" ADD VALUE 'agent';--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "asset_software" (
	"software_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid NOT NULL,
	"name" varchar(255) NOT NULL,
	"version" varchar(100),
	"publisher" varchar(255),
	"install_date" varchar(10),
	"scope" varchar(16),
	"arch" varchar(16),
	"source" varchar(32) DEFAULT 'agent' NOT NULL,
	"first_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "host_asset_id" uuid;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "endpoint_inventory" jsonb;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "inventory_collected_at" timestamp with time zone;--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "asset_software" ADD CONSTRAINT "asset_software_asset_id_assets_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("asset_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_software_asset" ON "asset_software" USING btree ("asset_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_software_name" ON "asset_software" USING btree ("name");--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "agents" ADD CONSTRAINT "agents_host_asset_id_assets_asset_id_fk" FOREIGN KEY ("host_asset_id") REFERENCES "public"."assets"("asset_id") ON DELETE set null ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
