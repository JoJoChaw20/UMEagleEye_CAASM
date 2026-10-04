-- 0001_asset_identity.sql
-- Asset identity: device/address split + ordered matching.
-- HAND-AUTHORED for manual review/apply (includes a custom backfill drizzle-kit
-- cannot generate). NOT registered in drizzle/meta/_journal.json — apply manually.
-- Safe to run once; the backfill is idempotent (NOT EXISTS guard). DO NOT truncate.

-- 1. assets.host_key (SMB computer name / SNMP sysName, lowercased) + lookup index
ALTER TABLE assets ADD COLUMN IF NOT EXISTS host_key varchar(255);
CREATE INDEX IF NOT EXISTS idx_assets_host_key ON assets (tenant_id, host_key);

-- 1b. scan_results.network_info: stores the agent's {subnet,gateway_ip,gateway_mac}
--     for reference. NOT used for identity (the network key is the host IP /24).
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS network_info jsonb;

-- 2. Identity is no longer IP-keyed: replace the UNIQUE (ip_address, tenant_id)
--    index with a plain lookup index (tenant_id, ip_address). Non-unique: one IP
--    may now map to several assets over time.
DROP INDEX IF EXISTS idx_assets_ip_tenant;
CREATE INDEX IF NOT EXISTS idx_assets_ip_tenant ON assets (tenant_id, ip_address);

-- 3. asset_addresses: historical + current addresses per device.
CREATE TABLE IF NOT EXISTS asset_addresses (
  address_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id    uuid NOT NULL REFERENCES assets(asset_id)  ON DELETE CASCADE,
  tenant_id   uuid          REFERENCES tenants(tenant_id) ON DELETE CASCADE,
  network_key varchar(64),                 -- NULL = unscoped (manual/CSV)
  ip_address  varchar(45) NOT NULL,
  mac_address varchar(17),                 -- normalized, NULL if none/invalid
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  ended_at    timestamptz                  -- NULL = current address
);

CREATE INDEX IF NOT EXISTS idx_addr_tenant_mac ON asset_addresses (tenant_id, mac_address);

-- Partial UNIQUE: at most one CURRENT scoped address per (tenant, network, ip).
-- This is what makes the resolver's check-then-insert race harmless — a losing
-- concurrent insert raises a unique violation the app catches and retries as an
-- UPDATE. Unscoped rows (network_key NULL) are intentionally excluded, so manual/
-- CSV addresses are never blocked.
CREATE UNIQUE INDEX IF NOT EXISTS idx_addr_current
  ON asset_addresses (tenant_id, network_key, ip_address)
  WHERE ended_at IS NULL AND network_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_addr_asset ON asset_addresses (asset_id);

-- 4. Idempotent backfill: one CURRENT address per existing asset that has none.
--    network_key: /24 for scanned IPv4 assets, NULL for source='manual'.
--    mac_address: normalized (dash/dot -> colon, lowercased); NULL if blank or
--    not a well-formed 48-bit MAC (Invalid class left for the resolver to ignore).
--    first_seen = created_at, last_seen = last_scanned (fallbacks when NULL).
--    The NOT EXISTS guard makes re-running safe (no duplicate address rows).
--    Relies on the pre-migration UNIQUE (ip_address, tenant_id) having prevented
--    duplicate current (tenant, /24, ip) rows; tenant_id NULL rows are distinct
--    under the partial unique index, so they cannot collide either.
INSERT INTO asset_addresses (asset_id, tenant_id, network_key, ip_address, mac_address, first_seen, last_seen)
SELECT
  a.asset_id,
  a.tenant_id,
  CASE
    WHEN a.source = 'manual' THEN NULL
    WHEN a.ip_address ~ '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
      THEN split_part(a.ip_address, '.', 1) || '.' ||
           split_part(a.ip_address, '.', 2) || '.' ||
           split_part(a.ip_address, '.', 3) || '.0/24'
    ELSE NULL
  END,
  a.ip_address,
  CASE
    WHEN a.mac_address IS NULL OR btrim(a.mac_address) = '' THEN NULL
    WHEN lower(replace(replace(a.mac_address, '-', ':'), '.', ':')) ~ '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
      THEN lower(replace(replace(a.mac_address, '-', ':'), '.', ':'))
    ELSE NULL
  END,
  COALESCE(a.created_at, now()),
  COALESCE(a.last_scanned, a.created_at, now())
FROM assets a
WHERE NOT EXISTS (
  SELECT 1 FROM asset_addresses x WHERE x.asset_id = a.asset_id
);
