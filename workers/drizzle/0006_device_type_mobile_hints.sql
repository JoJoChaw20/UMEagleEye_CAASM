ALTER TYPE "public"."device_type" ADD VALUE 'mobile';--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "device_type_hint" jsonb;