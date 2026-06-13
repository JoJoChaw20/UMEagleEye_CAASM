-- RBAC 4-Role Migration
-- Migrates user_role enum from:
--   ops_lead | security_engineer | business_owner | mssp_analyst | superadmin
-- to:
--   superadmin | tenant_superadmin | tenant_admin | business_owner
--
-- Role mapping:
--   ops_lead          → tenant_superadmin
--   security_engineer → tenant_admin
--   mssp_analyst      → tenant_admin
--   business_owner    → business_owner  (unchanged)
--   superadmin        → superadmin      (unchanged)
--
-- Run this BEFORE deploying new code.

BEGIN;

-- Step 1: Convert the column to plain text so we can change the enum safely
ALTER TABLE users ALTER COLUMN role TYPE text;

-- Step 2: Remap old values to new values
UPDATE users SET role = 'tenant_superadmin' WHERE role = 'ops_lead';
UPDATE users SET role = 'tenant_admin'      WHERE role = 'security_engineer';
UPDATE users SET role = 'tenant_admin'      WHERE role = 'mssp_analyst';
-- business_owner and superadmin keep their current values

-- Step 3: Drop the old enum type
DROP TYPE IF EXISTS user_role;

-- Step 4: Create the new enum type
CREATE TYPE user_role AS ENUM ('superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner');

-- Step 5: Restore the column type using the new enum
ALTER TABLE users ALTER COLUMN role TYPE user_role USING role::user_role;

-- Step 6: Restore the default
ALTER TABLE users ALTER COLUMN role SET DEFAULT 'business_owner';

COMMIT;
