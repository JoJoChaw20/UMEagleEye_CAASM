-- 2.6: the dashboard is the only place agent settings are set (lib/agentPolicy.ts). Until now a
-- setting nobody set on the dashboard was the agent's own choice (made in its app, reported in
-- its heartbeat). So that no agent changes behaviour, each own choice that differs from the
-- built-in default becomes an override of that agent, unless the agent or its tenant already
-- set that setting (those already won). Engine, capture and agent-started scans are dropped.
UPDATE "agents" AS a
SET "policy" = a."policy" || own.add
FROM (
  SELECT g."agent_id", jsonb_object_agg(d.key, g."reported"->'settings'->d.key) AS add
  FROM "agents" AS g
  LEFT JOIN "tenants" AS t ON t."tenant_id" = g."tenant_id"
  CROSS JOIN (VALUES
    ('host', 'scan_ports', '"base"'::jsonb), ('host', 'passive', 'false'::jsonb), ('host', 'passive_interval', '300'::jsonb),
    ('host', 'inventory', 'true'::jsonb), ('host', 'inventory_interval', '21600'::jsonb),
    ('host', 'inventory_user_software', 'false'::jsonb), ('host', 'inventory_admin_names', 'false'::jsonb),
    ('host', 'sbom', 'true'::jsonb), ('host', 'sbom_interval', '86400'::jsonb),
    ('network', 'network_poll', 'true'::jsonb), ('network', 'network_seeds', '[]'::jsonb),
    ('network', 'network_ranges', '[]'::jsonb), ('network', 'network_depth', '3'::jsonb),
    ('network', 'network_interval', '900'::jsonb)
  ) AS d(kind, key, builtin)
  WHERE g."kind" = d.kind
    AND g."retired_at" IS NULL
    AND jsonb_typeof(g."reported"->'settings') = 'object'
    AND (g."reported"->'settings') ? d.key
    AND g."reported"->'settings'->d.key <> d.builtin
    AND NOT (g."policy" ? d.key)
    AND NOT (COALESCE(t."agent_policy", '{}'::jsonb) ? d.key)
  GROUP BY g."agent_id"
) AS own
WHERE a."agent_id" = own."agent_id";--> statement-breakpoint
UPDATE "agents" SET "policy" = "policy" - 'scan_engine' - 'passive_backend' - 'local_scans';--> statement-breakpoint
-- Adopted: a setting the admin clears later is not taken from the agent again (the heartbeat
-- adopts an agent's own choices once, for agents that report them for the first time).
UPDATE "agents" SET "config" = "config" || '{"adopted_local": true}'::jsonb
WHERE jsonb_typeof("reported"->'settings') = 'object';--> statement-breakpoint
UPDATE "tenants" SET "agent_policy" = "agent_policy" - 'scan_engine' - 'passive_backend' - 'local_scans';
