-- 0038: audit history survives deleting a user. The user FK changes from ON DELETE cascade to
-- ON DELETE set null; no rows are touched. The old constraint is dropped and recreated (expected here).
-- The new FK is added NOT VALID, then validated as its own statement. Note: drizzle-kit migrate runs all
-- pending migrations in one transaction, so the DROP CONSTRAINT lock is still held while VALIDATE scans;
-- audit_logs is small, so the scan is short. Run by hand in separate transactions to shorten the lock.
-- actor_username keeps the username of a deleted user on their audit rows (set by the delete, in the same transaction).
ALTER TABLE "audit_logs" ADD COLUMN "actor_username" varchar(100);
--> statement-breakpoint
ALTER TABLE "audit_logs" DROP CONSTRAINT "audit_logs_user_id_users_user_id_fk";
--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_user_id_users_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("user_id") ON DELETE set null ON UPDATE no action NOT VALID;
--> statement-breakpoint
ALTER TABLE "audit_logs" VALIDATE CONSTRAINT "audit_logs_user_id_users_user_id_fk";
