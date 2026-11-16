CREATE TABLE IF NOT EXISTS "cve_findings" (
	"finding_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"event_id" uuid NOT NULL,
	"asset_id" uuid NOT NULL,
	"cve_id" varchar(40) NOT NULL,
	"advisory_id" varchar(64),
	"package_type" varchar(40),
	"package_name" varchar(255) NOT NULL,
	"package_version" varchar(100) DEFAULT '' NOT NULL,
	"severity" "severity" NOT NULL,
	"cvss" numeric(3, 1) DEFAULT '0' NOT NULL,
	"epss" numeric(6, 5) DEFAULT '0' NOT NULL,
	"fix_versions" text[] DEFAULT '{}'::text[] NOT NULL,
	"cwe_ids" text[] DEFAULT '{}'::text[] NOT NULL,
	"description" varchar(500) DEFAULT '' NOT NULL,
	"kev" boolean DEFAULT false NOT NULL,
	"has_cti_match" boolean DEFAULT false NOT NULL,
	"ti_event_titles" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"dismissed" boolean DEFAULT false NOT NULL,
	"first_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"fixed_at" timestamp with time zone
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "cve_findings" ADD CONSTRAINT "cve_findings_event_id_events_event_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."events"("event_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "cve_findings" ADD CONSTRAINT "cve_findings_asset_id_assets_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("asset_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "uq_cve_findings_key" ON "cve_findings" USING btree ("asset_id","cve_id","package_name","package_version");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_cve_findings_event" ON "cve_findings" USING btree ("event_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_cve_findings_cve" ON "cve_findings" USING btree ("cve_id");