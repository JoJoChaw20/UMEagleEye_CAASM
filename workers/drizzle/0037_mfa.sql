-- 0037: mandatory MFA (additive only: two new tables, three nullable columns on users).
CREATE TABLE "mfa_recovery_codes" (
	"code_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"code_hash" char(64) NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "platform_mfa_resets" (
	"reset_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"secret_hash" char(64) NOT NULL,
	"confirm_hash" char(64) NOT NULL,
	"cancel_hash" char(64) NOT NULL,
	"status" varchar(16) DEFAULT 'requested' NOT NULL,
	"requested_at" timestamp with time zone DEFAULT now() NOT NULL,
	"confirmed_at" timestamp with time zone,
	"effective_at" timestamp with time zone,
	"completed_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "mfa_pending_secret" varchar(64);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "totp_last_step" bigint;
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "sessions_valid_after" timestamp with time zone;
--> statement-breakpoint
ALTER TABLE "mfa_recovery_codes" ADD CONSTRAINT "mfa_recovery_codes_user_id_users_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("user_id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "platform_mfa_resets" ADD CONSTRAINT "platform_mfa_resets_user_id_users_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("user_id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
CREATE UNIQUE INDEX "uq_mfa_recovery_user_hash" ON "mfa_recovery_codes" USING btree ("user_id","code_hash");
--> statement-breakpoint
CREATE UNIQUE INDEX "uq_platform_mfa_resets_secret" ON "platform_mfa_resets" USING btree ("secret_hash");
