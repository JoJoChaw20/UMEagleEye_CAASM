-- Remove the three legacy user_role values (ops_lead, security_engineer, mssp_analyst).
-- Postgres cannot drop enum values, so the type is rebuilt. users.role is the only column
-- that uses it. Aborts (and rolls back) if any user still holds a legacy role.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM users WHERE role::text IN ('ops_lead', 'security_engineer', 'mssp_analyst')) THEN
    RAISE EXCEPTION 'users still hold a legacy role; remap them before running this migration';
  END IF;
END $$;--> statement-breakpoint
ALTER TYPE "public"."user_role" RENAME TO "user_role_old";--> statement-breakpoint
CREATE TYPE "public"."user_role" AS ENUM ('superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner');--> statement-breakpoint
ALTER TABLE "users" ALTER COLUMN "role" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "users" ALTER COLUMN "role" TYPE "public"."user_role" USING "role"::text::"public"."user_role";--> statement-breakpoint
ALTER TABLE "users" ALTER COLUMN "role" SET DEFAULT 'business_owner';--> statement-breakpoint
DROP TYPE "public"."user_role_old";
