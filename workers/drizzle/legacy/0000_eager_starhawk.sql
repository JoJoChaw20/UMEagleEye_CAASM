CREATE TYPE "public"."advisory_status" AS ENUM('open', 'acknowledged', 'in_progress', 'resolved');--> statement-breakpoint
CREATE TYPE "public"."agent_status" AS ENUM('online', 'offline', 'degraded');--> statement-breakpoint
CREATE TYPE "public"."asset_source" AS ENUM('manual', 'scan_active', 'scan_passive');--> statement-breakpoint
CREATE TYPE "public"."device_type" AS ENUM('server', 'workstation', 'network', 'iot', 'unknown');--> statement-breakpoint
CREATE TYPE "public"."event_type" AS ENUM('port_opened', 'port_closed', 'version_downgrade', 'version_upgrade', 'cve_detected', 'new_device', 'config_change', 'new_package', 'removed_package', 'cti_match');--> statement-breakpoint
CREATE TYPE "public"."indicator_type" AS ENUM('ip', 'domain', 'hash', 'url', 'email');--> statement-breakpoint
CREATE TYPE "public"."relationship_type" AS ENUM('connects_to', 'depends_on', 'same_subnet', 'authenticates_to', 'exposes_service');--> statement-breakpoint
CREATE TYPE "public"."sbom_format" AS ENUM('cyclonedx', 'spdx');--> statement-breakpoint
CREATE TYPE "public"."severity" AS ENUM('low', 'medium', 'high', 'critical');--> statement-breakpoint
CREATE TYPE "public"."topology_node_type" AS ENUM('gateway', 'router', 'switch', 'access_point', 'host');--> statement-breakpoint
CREATE TYPE "public"."user_role" AS ENUM('superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner');--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "advisories" (
	"advisory_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"event_id" uuid NOT NULL,
	"summary" text NOT NULL,
	"recommended_action" text NOT NULL,
	"status" "advisory_status" DEFAULT 'open' NOT NULL,
	"assigned_to" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"resolved_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "agents" (
	"agent_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid,
	"name" varchar(100) NOT NULL,
	"api_key_hash" varchar(512) NOT NULL,
	"status" "agent_status" DEFAULT 'offline' NOT NULL,
	"last_heartbeat" timestamp with time zone,
	"gateway_ip" varchar(45),
	"version" varchar(20),
	"config" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"bridge_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "asset_relationships" (
	"relationship_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"source_asset_id" uuid NOT NULL,
	"target_asset_id" uuid NOT NULL,
	"relationship_type" "relationship_type" NOT NULL,
	"metadata_json" jsonb,
	"confidence" numeric(3, 2),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "assets" (
	"asset_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid,
	"hostname" varchar(255),
	"ip_address" varchar(45) NOT NULL,
	"mac_address" varchar(17),
	"owner" varchar(255),
	"device_type" "device_type" DEFAULT 'unknown' NOT NULL,
	"hardware_vendor" varchar(255),
	"os_info" jsonb DEFAULT '{}'::jsonb,
	"criticality_score" smallint DEFAULT 5 NOT NULL,
	"baseline_state" jsonb,
	"is_internet_facing" boolean DEFAULT false NOT NULL,
	"source" "asset_source" DEFAULT 'manual' NOT NULL,
	"last_scanned" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "audit_logs" (
	"log_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"tenant_id" uuid,
	"action_type" varchar(100) NOT NULL,
	"target_entity" varchar(255),
	"previous_state" jsonb,
	"new_state" jsonb,
	"timestamp" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "bridges" (
	"bridge_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid,
	"name" varchar(100) NOT NULL,
	"api_key_hash" varchar(512) NOT NULL,
	"mode" varchar(20) DEFAULT 'relay' NOT NULL,
	"status" "agent_status" DEFAULT 'offline' NOT NULL,
	"last_heartbeat" timestamp with time zone,
	"bridge_ip" varchar(45),
	"version" varchar(20),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "cti_indicators" (
	"indicator_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"source" varchar(100) DEFAULT 'MyCERT' NOT NULL,
	"indicator_type" "indicator_type" NOT NULL,
	"value" varchar(512) NOT NULL,
	"confidence_score" numeric(3, 2),
	"attack_tactic" varchar(100),
	"attack_technique" varchar(100),
	"first_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "cti_indicators_value_unique" UNIQUE("value")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "dependencies" (
	"dependency_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid NOT NULL,
	"sbom_id" uuid,
	"name" varchar(255) NOT NULL,
	"version" varchar(100) NOT NULL,
	"package_manager" varchar(50),
	"purl" varchar(500),
	"licenses" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "event_cti_indicators" (
	"event_id" uuid NOT NULL,
	"indicator_id" uuid NOT NULL,
	CONSTRAINT "event_cti_indicators_event_id_indicator_id_pk" PRIMARY KEY("event_id","indicator_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "events" (
	"event_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid NOT NULL,
	"event_type" "event_type" NOT NULL,
	"severity" "severity" NOT NULL,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"composite_risk_score" numeric(8, 2),
	"timestamp" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "posture_metrics" (
	"snapshot_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid,
	"overall_score" smallint NOT NULL,
	"total_assets" integer DEFAULT 0 NOT NULL,
	"total_critical_assets" integer DEFAULT 0 NOT NULL,
	"open_critical_events" integer DEFAULT 0 NOT NULL,
	"top_risks" jsonb,
	"timestamp" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "sboms" (
	"sbom_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid NOT NULL,
	"format" "sbom_format" DEFAULT 'cyclonedx' NOT NULL,
	"format_version" varchar(10) DEFAULT '1.5' NOT NULL,
	"raw_data" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"generated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"tool_used" varchar(50) DEFAULT 'syft' NOT NULL,
	"r2_path" varchar(500)
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "scan_results" (
	"scan_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"agent_id" uuid,
	"tenant_id" uuid,
	"scan_type" varchar(20) DEFAULT 'active' NOT NULL,
	"subnet" varchar(50),
	"status" varchar(20) DEFAULT 'completed' NOT NULL,
	"hosts_discovered" integer DEFAULT 0 NOT NULL,
	"raw_results" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "tenants" (
	"tenant_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(100) NOT NULL,
	"slug" varchar(50) NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenants_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "topology_nodes" (
	"node_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid,
	"tenant_id" uuid,
	"parent_node_id" uuid,
	"node_type" "topology_node_type" DEFAULT 'host' NOT NULL,
	"layer" smallint DEFAULT 4 NOT NULL,
	"label" varchar(100),
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "users" (
	"user_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"username" varchar(100) NOT NULL,
	"email" varchar(255) NOT NULL,
	"password_hash" varchar(512) NOT NULL,
	"role" "user_role" DEFAULT 'business_owner' NOT NULL,
	"tenant_id" uuid,
	"google_id" varchar(255),
	"totp_secret" varchar(64),
	"mfa_enabled" boolean DEFAULT false NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_login" timestamp with time zone,
	"telegram_chat_id" varchar(64),
	CONSTRAINT "users_username_unique" UNIQUE("username"),
	CONSTRAINT "users_email_unique" UNIQUE("email"),
	CONSTRAINT "users_google_id_unique" UNIQUE("google_id")
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "advisories" ADD CONSTRAINT "advisories_event_id_events_event_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."events"("event_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "advisories" ADD CONSTRAINT "advisories_assigned_to_users_user_id_fk" FOREIGN KEY ("assigned_to") REFERENCES "public"."users"("user_id") ON DELETE set null ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "agents" ADD CONSTRAINT "agents_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "agents" ADD CONSTRAINT "agents_bridge_id_bridges_bridge_id_fk" FOREIGN KEY ("bridge_id") REFERENCES "public"."bridges"("bridge_id") ON DELETE set null ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "asset_relationships" ADD CONSTRAINT "asset_relationships_source_asset_id_assets_asset_id_fk" FOREIGN KEY ("source_asset_id") REFERENCES "public"."assets"("asset_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "asset_relationships" ADD CONSTRAINT "asset_relationships_target_asset_id_assets_asset_id_fk" FOREIGN KEY ("target_asset_id") REFERENCES "public"."assets"("asset_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "assets" ADD CONSTRAINT "assets_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_user_id_users_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("user_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "bridges" ADD CONSTRAINT "bridges_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE set null ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "dependencies" ADD CONSTRAINT "dependencies_asset_id_assets_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("asset_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "dependencies" ADD CONSTRAINT "dependencies_sbom_id_sboms_sbom_id_fk" FOREIGN KEY ("sbom_id") REFERENCES "public"."sboms"("sbom_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "event_cti_indicators" ADD CONSTRAINT "event_cti_indicators_event_id_events_event_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."events"("event_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "event_cti_indicators" ADD CONSTRAINT "event_cti_indicators_indicator_id_cti_indicators_indicator_id_fk" FOREIGN KEY ("indicator_id") REFERENCES "public"."cti_indicators"("indicator_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "events" ADD CONSTRAINT "events_asset_id_assets_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("asset_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "posture_metrics" ADD CONSTRAINT "posture_metrics_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "sboms" ADD CONSTRAINT "sboms_asset_id_assets_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("asset_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_agent_id_agents_agent_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("agent_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "topology_nodes" ADD CONSTRAINT "topology_nodes_asset_id_assets_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("asset_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "topology_nodes" ADD CONSTRAINT "topology_nodes_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "users" ADD CONSTRAINT "users_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE set null ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_agents_tenant" ON "agents" USING btree ("tenant_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_rel_source" ON "asset_relationships" USING btree ("source_asset_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_rel_target" ON "asset_relationships" USING btree ("target_asset_id");--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_rel_unique" ON "asset_relationships" USING btree ("source_asset_id","target_asset_id","relationship_type");--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_assets_ip_tenant" ON "assets" USING btree ("ip_address","tenant_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_assets_tenant" ON "assets" USING btree ("tenant_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_audit_timestamp" ON "audit_logs" USING btree ("timestamp");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_bridges_tenant" ON "bridges" USING btree ("tenant_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_cti_value" ON "cti_indicators" USING btree ("value");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_deps_name" ON "dependencies" USING btree ("name");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_events_timestamp" ON "events" USING btree ("timestamp");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_posture_timestamp" ON "posture_metrics" USING btree ("timestamp");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_scans_tenant" ON "scan_results" USING btree ("tenant_id");--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_tenants_slug" ON "tenants" USING btree ("slug");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_topology_tenant" ON "topology_nodes" USING btree ("tenant_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_users_username" ON "users" USING btree ("username");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_users_tenant" ON "users" USING btree ("tenant_id");