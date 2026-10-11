CREATE TABLE IF NOT EXISTS "asset_identifiers" (
	"identifier_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid NOT NULL,
	"tenant_id" uuid,
	"kind" varchar(16) NOT NULL,
	"value" varchar(64) NOT NULL,
	"source" varchar(16) DEFAULT 'agent' NOT NULL,
	"first_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "asset_identifiers" ADD CONSTRAINT "asset_identifiers_asset_id_assets_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("asset_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "asset_identifiers" ADD CONSTRAINT "asset_identifiers_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_identifier_asset_kind_value" ON "asset_identifiers" USING btree ("asset_id","kind","value");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_identifier_lookup" ON "asset_identifiers" USING btree ("tenant_id","kind","value");