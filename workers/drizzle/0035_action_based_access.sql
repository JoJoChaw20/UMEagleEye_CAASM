-- Action-based access, step 1 of 2 (expand): additive only, safe while old code is still running.
-- The destructive role conversion is a later migration (0036). See spec section 8.1.
ALTER TYPE "public"."user_role" ADD VALUE IF NOT EXISTS 'tenant_user';--> statement-breakpoint
ALTER TABLE users ADD COLUMN IF NOT EXISTS actions text[];
