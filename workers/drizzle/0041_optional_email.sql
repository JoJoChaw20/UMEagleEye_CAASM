-- 0041: accounts without an email (created with a username and starting password), and the flag that makes
-- the owner choose their own password at first sign-in. Additive: no rows change; existing accounts keep their email.
ALTER TABLE "users" ALTER COLUMN "email" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "password_change_required" boolean DEFAULT false NOT NULL;
