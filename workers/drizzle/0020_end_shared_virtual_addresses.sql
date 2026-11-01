-- Data only. A shared/virtual MAC (KM-TEST loopback, VMware host adapters, VRRP, HSRP,
-- GLBP, MS NLB; lib/identity.ts SHARED_VIRTUAL_PATTERNS) is the same on many machines,
-- so an address row carrying one says nothing about where a device is. Agents before
-- 2.3.0 reported such adapters (a laptop's GNS3 loopback, 142.19.0.1 / 02:00:4c:4f:4f:50),
-- and nothing ever ends those rows. End the current ones, at the time they were last seen.
UPDATE "asset_addresses"
SET "ended_at" = "last_seen"
WHERE "ended_at" IS NULL
  AND "mac_address" ~ '^(02:00:4c:4f:4f:50|00:50:56:c0:00:0[0-9a-f]|00:00:5e:00:0[12]:[0-9a-f]{2}|00:00:0c:07:ac:[0-9a-f]{2}|00:00:0c:9f:f[0-9a-f]:[0-9a-f]{2}|00:05:73:a0:0[0-9a-f]:[0-9a-f]{2}|00:07:b4:0[0-3]:[0-9a-f]{2}:[0-9a-f]{2}|02:bf:.*)$';
