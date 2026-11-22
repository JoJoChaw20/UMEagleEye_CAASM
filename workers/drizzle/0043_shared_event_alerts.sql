-- 0043: alerts from threat-intel events other tenants share with all tenants are opt-in for the receiving tenant.
--   tenants.shared_event_alerts   the tenant's default for every shared event (off: shared events are read-only context)
--   ti_event_alert_choices        its choice for one shared event, overriding that default
-- No behaviour changes for existing data: shared events alerted only their own tenant before, and still do until opted in.
CREATE TABLE IF NOT EXISTS "ti_event_alert_choices" (
	"tenant_id" uuid NOT NULL,
	"ti_event_id" uuid NOT NULL,
	"alerts" boolean NOT NULL,
	"set_by" uuid,
	"set_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ti_event_alert_choices_tenant_id_ti_event_id_pk" PRIMARY KEY("tenant_id","ti_event_id")
);
--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "shared_event_alerts" boolean DEFAULT false NOT NULL;--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "ti_event_alert_choices" ADD CONSTRAINT "ti_event_alert_choices_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "ti_event_alert_choices" ADD CONSTRAINT "ti_event_alert_choices_ti_event_id_ti_events_ti_event_id_fk" FOREIGN KEY ("ti_event_id") REFERENCES "public"."ti_events"("ti_event_id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "ti_event_alert_choices" ADD CONSTRAINT "ti_event_alert_choices_set_by_users_user_id_fk" FOREIGN KEY ("set_by") REFERENCES "public"."users"("user_id") ON DELETE set null ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
