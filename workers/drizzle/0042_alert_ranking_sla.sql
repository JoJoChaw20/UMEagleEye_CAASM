-- 0042: alert ranking and fix-time targets (lib/alertRank.ts, lib/priority.ts), and EPSS that can be "not checked yet".
--   tenants.sla_policy        a tenant's own targets in hours ({} = the defaults)
--   events.reopened_at        when a closed alert last became open again: the fix-time clock restarts there
--   events.reopen_count       how many times it reopened
--   events_reopen trigger     sets both, whichever producer reopened the alert (iocMatch, drift, exposure...)
--   cve_findings.epss         nullable: NULL until FIRST.org is asked (services/epss.ts refreshes it nightly)
-- Data: an EPSS of exactly 0 was what ingest wrote for CVEs it never looked up (300 per upload), so those become
-- NULL ("not checked yet") and the nightly refresh asks for them. Scores treat NULL as 0, so no score changes.
ALTER TABLE "cve_findings" ALTER COLUMN "epss" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "cve_findings" ALTER COLUMN "epss" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "cve_findings" ADD COLUMN "epss_checked_at" timestamp with time zone;--> statement-breakpoint
UPDATE "cve_findings" SET "epss" = NULL WHERE "epss" = 0;--> statement-breakpoint
ALTER TABLE "events" ADD COLUMN "reopened_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "events" ADD COLUMN "reopen_count" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "sla_policy" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
CREATE OR REPLACE FUNCTION events_mark_reopen() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.reopened_at := now();
  NEW.reopen_count := OLD.reopen_count + 1;
  RETURN NEW;
END $$;--> statement-breakpoint
CREATE TRIGGER events_reopen BEFORE UPDATE OF status ON events FOR EACH ROW
  WHEN (OLD.status IN ('resolved', 'false_positive', 'accepted_risk') AND NEW.status IN ('open', 'in_progress'))
  EXECUTE FUNCTION events_mark_reopen();
