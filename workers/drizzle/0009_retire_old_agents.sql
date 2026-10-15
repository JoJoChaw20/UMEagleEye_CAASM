ALTER TABLE "agents" ADD COLUMN "retired_at" timestamp with time zone;--> statement-breakpoint
-- Hand-written: retire the 1.x agents (eagleeye_agent.py). Their API key is replaced by
-- a value no key can hash to, so they can no longer connect; the records and their
-- Discovery history stay, and the Agents page shows them as retired.
UPDATE "agents" SET "retired_at" = now(), "api_key_hash" = 'retired', "status" = 'offline'
WHERE "version" LIKE '1.%' AND "retired_at" IS NULL;
