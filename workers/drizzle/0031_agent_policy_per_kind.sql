-- Tenant default agent settings are kept apart per kind of agent (lib/agentPolicy.ts
-- tenantDefaultsFor): {host: {...}, network: {...}, mobile: {...}}, so a phone default no longer
-- changes the computers. Each kind gets the flat defaults it had, except a phone's app list:
-- inventory_user_software set for the computers (their per-user installs) is not a phone setting.
UPDATE "tenants" AS t
SET "agent_policy" = jsonb_build_object(
  'host', COALESCE((SELECT jsonb_object_agg(e.key, e.value) FROM jsonb_each(t."agent_policy") AS e
    WHERE e.key IN ('scanner', 'scan_ports', 'passive', 'passive_interval', 'inventory', 'inventory_interval', 'sbom', 'sbom_interval')), '{}'::jsonb),
  'network', COALESCE((SELECT jsonb_object_agg(e.key, e.value) FROM jsonb_each(t."agent_policy") AS e
    WHERE e.key IN ('network_poll', 'network_seeds', 'network_ranges', 'network_depth', 'network_interval')), '{}'::jsonb),
  'mobile', COALESCE((SELECT jsonb_object_agg(e.key, e.value) FROM jsonb_each(t."agent_policy") AS e
    WHERE e.key IN ('inventory', 'inventory_interval')), '{}'::jsonb)
)
WHERE jsonb_typeof(t."agent_policy") = 'object'
  AND t."agent_policy" <> '{}'::jsonb
  AND NOT (t."agent_policy" ?| ARRAY['host', 'network', 'mobile']);--> statement-breakpoint
-- A computer always reports its software (per-user installs included) and only the number of
-- administrator accounts: those two settings are gone from computers; a phone keeps its app list.
UPDATE "agents"
SET "policy" = "policy" - 'inventory_admin_names' - CASE WHEN "kind" = 'mobile' THEN '' ELSE 'inventory_user_software' END
WHERE "policy" ?| ARRAY['inventory_admin_names', 'inventory_user_software'];
