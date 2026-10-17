// Read-only data report for the legacy cleanup (Phase D0). Prints counts only (no hostnames,
// IPs, emails or secrets), as Markdown tables, so the output can be reviewed and shared.
//
//   node scripts/db/report.mjs <staging|production>
//
// Every query runs inside one READ ONLY transaction, so this script cannot change data even
// if a query were wrong. Credentials come from workers/.env.<target> (DB_TARGET guard).
import { neon } from '@neondatabase/serverless'
import { die, loadEnvFile, describe } from './lib.mjs'

const TARGETS = ['staging', 'production']
const target = process.argv[2]
if (!TARGETS.includes(target)) die('usage: report.mjs <staging|production>')

// Tables the Worker schema (src/db/schema.ts) defines. Anything else in the database came
// from an earlier version (FastAPI backend, hand-applied SQL) or a tool.
const SCHEMA_TABLES = new Set([
  'tenants', 'users', 'assets', 'asset_addresses', 'sboms', 'dependencies', 'events',
  'cti_indicators', 'advisories', 'posture_metrics', 'asset_relationships', 'audit_logs',
  'agents', 'asset_software', 'asset_identifiers', 'topology_nodes',
  'event_cti_indicators', 'scan_results', 'duplicate_dismissals', 'ti_events',
])

// Age bucket of a timestamp column, as a SQL expression.
const age = col => `case when ${col} is null then 'never'
  when ${col} > now() - interval '30 days' then '< 30 d'
  when ${col} > now() - interval '90 days' then '30-90 d'
  when ${col} > now() - interval '365 days' then '90-365 d'
  else '> 1 y' end`
const day = col => `to_char(${col}, 'YYYY-MM-DD')`
const tenantName = alias => `coalesce((select t.name from tenants t where t.tenant_id = ${alias}.tenant_id), '(no tenant)')`

const SECTIONS = [
  ['Database size', `select pg_size_pretty(pg_database_size(current_database())) as size`],

  ['All tables (rows and size)', `
    select c.relname as table,
           (xpath('/row/n/text()', query_to_xml(format('select count(*) as n from public.%I', c.relname), false, true, '')))[1]::text::bigint as rows,
           pg_size_pretty(pg_total_relation_size(c.oid)) as size
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind = 'r'
    order by pg_total_relation_size(c.oid) desc`],

  ['Tenants', `
    select t.name as tenant, t.slug, t.is_active as active, ${day('t.created_at')} as created,
           t.criticality_model as formula,
           (select count(*) from users u where u.tenant_id = t.tenant_id)::int as users,
           (select count(*) from assets a where a.tenant_id = t.tenant_id)::int as assets,
           (select count(*) from assets a where a.tenant_id = t.tenant_id and a.in_my_assets)::int as my_assets,
           (select count(*) from agents g where g.tenant_id = t.tenant_id)::int as agents,
           (select count(*) from scan_results s where s.tenant_id = t.tenant_id)::int as scans,
           (select ${day('max(s.started_at)')} from scan_results s where s.tenant_id = t.tenant_id) as last_scan,
           (select count(*) from events e join assets a on a.asset_id = e.asset_id where a.tenant_id = t.tenant_id)::int as events
    from tenants t order by t.created_at`],

  ['Assets by tenant, source and last scan', `
    select ${tenantName('a')} as tenant, a.source::text as source, ${age('a.last_scanned')} as last_scanned,
           count(*)::int as assets,
           count(*) filter (where a.in_my_assets)::int as my_assets,
           count(*) filter (where a.endpoint_inventory is not null)::int as with_inventory,
           count(*) filter (where exists (select 1 from sboms s where s.asset_id = a.asset_id))::int as with_sbom,
           count(*) filter (where a.device_type = 'unknown')::int as unknown_type
    from assets a group by 1, 2, 3 order by 1, 2, 3`],

  ['Users by tenant and role (no names)', `
    select ${tenantName('u')} as tenant, u.role::text as role,
           count(*)::int as users,
           count(*) filter (where u.is_active)::int as active,
           count(*) filter (where u.last_login > now() - interval '90 days')::int as login_90d,
           count(*) filter (where u.last_login is null)::int as never_logged_in
    from users u group by 1, 2 order by 1, 2`],

  ['Agents', `
    select ${tenantName('g')} as tenant, g.name, coalesce(g.version, '?') as version,
           -- Same rule as the app (routes/agents.ts computeStatus): the stored status column
           -- is only ever set to 'online', so status comes from the last heartbeat.
           case when g.last_heartbeat > now() - interval '2 minutes' then 'online'
                when g.last_heartbeat > now() - interval '10 minutes' then 'degraded'
                else 'offline' end as status,
           ${day('g.last_heartbeat')} as last_heartbeat, ${day('g.created_at')} as created,
           g.retired_at is not null as retired, g.host_asset_id is not null as bound_to_host,
           (select count(*) from scan_results s where s.agent_id = g.agent_id)::int as scans,
           (select count(*) from scan_results s where s.agent_id = g.agent_id and s.scan_type = 'sbom')::int as sbom_scans
    from agents g order by 1, g.created_at`],

  ['Scans by tenant, type, status and age', `
    select ${tenantName('s')} as tenant, s.scan_type as type, s.status, ${age('s.started_at')} as age,
           count(*)::int as scans, pg_size_pretty(sum(pg_column_size(s.raw_results))) as raw_results_size
    from scan_results s group by 1, 2, 3, 4 order by 1, 2, 3, 4`],

  ['SBOM data by tenant', `
    select ${tenantName('a')} as tenant,
           count(distinct s.sbom_id)::int as sboms,
           (select count(*) from dependencies d join assets a2 on a2.asset_id = d.asset_id where a2.tenant_id is not distinct from a.tenant_id)::int as dependencies,
           ${day('max(s.generated_at)')} as newest, ${day('min(s.generated_at)')} as oldest,
           pg_size_pretty(sum(pg_column_size(s.raw_data))) as raw_size
    from sboms s join assets a on a.asset_id = s.asset_id group by a.tenant_id order by 1`],

  ['Events by tenant, type and status', `
    select ${tenantName('a')} as tenant, e.event_type::text as type, e.status::text as status,
           count(*)::int as events, ${day('min(e.timestamp)')} as oldest, ${day('max(e.last_seen)')} as newest
    from events e join assets a on a.asset_id = e.asset_id group by 1, 2, 3 order by 1, 2, 3`],

  ['Advisories by status', `
    select a.status::text as status, ${age('a.created_at')} as age, count(*)::int as advisories
    from advisories a group by 1, 2 order by 1, 2`],

  ['Threat intel', `
    select c.source, c.indicator_type::text as type, ${age('c.last_seen')} as last_seen, count(*)::int as indicators,
           count(*) filter (where exists (select 1 from event_cti_indicators x where x.indicator_id = c.indicator_id))::int as linked_to_events
    from cti_indicators c group by 1, 2, 3 order by 1, 2, 3`],

  ['Posture snapshots, audit log, graph (by tenant)', `
    select t.name as tenant,
           (select count(*) from posture_metrics p where p.tenant_id = t.tenant_id)::int as posture_snapshots,
           (select ${day('min(p.timestamp)')} from posture_metrics p where p.tenant_id = t.tenant_id) as posture_oldest,
           (select count(*) from audit_logs l where l.tenant_id = t.tenant_id)::int as audit_logs,
           (select ${day('min(l.timestamp)')} from audit_logs l where l.tenant_id = t.tenant_id) as audit_oldest,
           (select count(*) from asset_relationships r join assets a on a.asset_id = r.source_asset_id where a.tenant_id = t.tenant_id)::int as relationships,
           (select count(*) from topology_nodes n where n.tenant_id = t.tenant_id)::int as topology_nodes,
           (select count(*) from asset_software w join assets a on a.asset_id = w.asset_id where a.tenant_id = t.tenant_id)::int as software_rows,
           (select count(*) from asset_identifiers i where i.tenant_id = t.tenant_id)::int as identifiers
    from tenants t
    union all
    -- The posture cron writes platform-wide snapshots (tenant_id NULL) by design.
    select '(platform-wide)', (select count(*) from posture_metrics p where p.tenant_id is null)::int,
           (select ${day('min(p.timestamp)')} from posture_metrics p where p.tenant_id is null),
           null, null, null, null, null, null
    order by 1`],

  ['Rows without a tenant or owner (orphans)', `
    select 'assets without tenant' as what, count(*)::int as n from assets where tenant_id is null
    union all select 'users without tenant (excl. superadmin)', count(*)::int from users where tenant_id is null and role <> 'superadmin'
    union all select 'agents without tenant', count(*)::int from agents where tenant_id is null
    union all select 'scans without tenant', count(*)::int from scan_results where tenant_id is null
    union all select 'scans without agent', count(*)::int from scan_results where agent_id is null
    union all select 'sbom scans whose asset is gone', count(*)::int from scan_results s where s.scan_type = 'sbom'
      and not exists (select 1 from assets a where a.asset_id::text = s.subnet)
    union all select 'audit logs without tenant', count(*)::int from audit_logs where tenant_id is null
    union all select 'topology nodes without asset', count(*)::int from topology_nodes where asset_id is null
    union all select 'topology nodes with a missing parent', count(*)::int from topology_nodes n
      where n.parent_node_id is not null and not exists (select 1 from topology_nodes p where p.node_id = n.parent_node_id)
    union all select 'dependencies without sbom', count(*)::int from dependencies where sbom_id is null`],
]

function cell(v) {
  if (v === null || v === undefined) return ''
  if (v instanceof Date) return v.toISOString().slice(0, 10)
  return String(v).replace(/\|/g, '\\|').replace(/\s+/g, ' ')
}

function markdown(rows) {
  if (!rows.length) return '_(none)_'
  const cols = Object.keys(rows[0])
  return [
    `| ${cols.join(' | ')} |`,
    `|${cols.map(() => '---').join('|')}|`,
    ...rows.map(r => `| ${cols.map(c => cell(r[c])).join(' | ')} |`),
  ].join('\n')
}

const vars = loadEnvFile(target)
const sql = neon(vars.DATABASE_URL)
const results = await sql.transaction(SECTIONS.map(([, q]) => sql(q)), { readOnly: true })
  .catch(e => die(e.message))

console.log(`# Data report: ${target.toUpperCase()} (${describe(vars.DATABASE_URL)})`)
console.log(`Generated ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC. Read-only; counts only.\n`)
SECTIONS.forEach(([title], i) => {
  let rows = results[i]
  if (title.startsWith('All tables')) {
    rows = rows.map(r => ({ ...r, in_worker_schema: SCHEMA_TABLES.has(r.table) ? 'yes' : 'NO (legacy?)' }))
  }
  console.log(`## ${title}\n${markdown(rows)}\n`)
})
