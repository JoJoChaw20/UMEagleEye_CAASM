CREATE TABLE "ownership_recoveries" (
	"recovery_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"successor_id" uuid NOT NULL,
	"former_owner_id" uuid NOT NULL,
	"reason" varchar(16) NOT NULL,
	"status" varchar(20) DEFAULT 'awaiting_approval' NOT NULL,
	"approver1_at" timestamp with time zone,
	"approver2_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"hold_until" timestamp with time zone,
	"completed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "ownership_transfers" (
	"transfer_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"from_user_id" uuid NOT NULL,
	"to_user_id" uuid NOT NULL,
	"after_mode" varchar(16) NOT NULL,
	"after_actions" text[] DEFAULT '{}'::text[] NOT NULL,
	"deactivate_on" timestamp with time zone,
	"status" varchar(16) DEFAULT 'pending' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"decided_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "tenant_notices" (
	"notice_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid,
	"kind" varchar(32) NOT NULL,
	"body" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	"dismissed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "tenant_recovery_plans" (
	"tenant_id" uuid PRIMARY KEY NOT NULL,
	"successor_id" uuid,
	"approver1_id" uuid,
	"approver2_id" uuid,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "scheduled_deactivation_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "ownership_recoveries" ADD CONSTRAINT "ownership_recoveries_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "ownership_recoveries" ADD CONSTRAINT "ownership_recoveries_successor_id_users_user_id_fk" FOREIGN KEY ("successor_id") REFERENCES "public"."users"("user_id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "ownership_recoveries" ADD CONSTRAINT "ownership_recoveries_former_owner_id_users_user_id_fk" FOREIGN KEY ("former_owner_id") REFERENCES "public"."users"("user_id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "ownership_transfers" ADD CONSTRAINT "ownership_transfers_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "ownership_transfers" ADD CONSTRAINT "ownership_transfers_from_user_id_users_user_id_fk" FOREIGN KEY ("from_user_id") REFERENCES "public"."users"("user_id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "ownership_transfers" ADD CONSTRAINT "ownership_transfers_to_user_id_users_user_id_fk" FOREIGN KEY ("to_user_id") REFERENCES "public"."users"("user_id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "tenant_notices" ADD CONSTRAINT "tenant_notices_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "tenant_notices" ADD CONSTRAINT "tenant_notices_user_id_users_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("user_id") ON DELETE set null ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "tenant_recovery_plans" ADD CONSTRAINT "tenant_recovery_plans_tenant_id_tenants_tenant_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("tenant_id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "tenant_recovery_plans" ADD CONSTRAINT "tenant_recovery_plans_successor_id_users_user_id_fk" FOREIGN KEY ("successor_id") REFERENCES "public"."users"("user_id") ON DELETE set null ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "tenant_recovery_plans" ADD CONSTRAINT "tenant_recovery_plans_approver1_id_users_user_id_fk" FOREIGN KEY ("approver1_id") REFERENCES "public"."users"("user_id") ON DELETE set null ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "tenant_recovery_plans" ADD CONSTRAINT "tenant_recovery_plans_approver2_id_users_user_id_fk" FOREIGN KEY ("approver2_id") REFERENCES "public"."users"("user_id") ON DELETE set null ON UPDATE no action;
--> statement-breakpoint
CREATE UNIQUE INDEX "uq_ownership_recoveries_one_open" ON "ownership_recoveries" USING btree ("tenant_id") WHERE "ownership_recoveries"."status" in ('awaiting_approval', 'on_hold');--> statement-breakpoint
CREATE UNIQUE INDEX "uq_ownership_transfers_one_pending" ON "ownership_transfers" USING btree ("tenant_id") WHERE "ownership_transfers"."status" = 'pending';