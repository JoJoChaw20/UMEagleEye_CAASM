ALTER TABLE "cti_indicators" ADD COLUMN "malware_family" varchar(120);--> statement-breakpoint
ALTER TABLE "cti_indicators" ADD COLUMN "attack_software" varchar(12);--> statement-breakpoint
ALTER TABLE "cti_indicators" ADD COLUMN "attack_techniques" text[];