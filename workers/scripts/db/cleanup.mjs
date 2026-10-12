// One-off legacy data cleanup (Phase D0), approved item by item on 2026-10-13:
//   1. scans stuck in pending/running for over 90 days      -> marked failed
//   2. SBOM scan jobs whose asset no longer exists          -> deleted
//   3. discovered assets not seen by a scan for over 90 days -> deleted
//      (never: My Assets, manual/agent assets, assets with an SBOM, CVE alerts, an
//       endpoint inventory or a bound agent; SBOM/CVE data waits for the D1 decision)
//   5. business-owner accounts without a tenant              -> deleted, except KEEP_USER_ID
// Tenants are kept (item 4); the two empty legacy tables are dropped by a migration (item 6).
//
//   node scripts/db/cleanup.mjs <staging|production>           dry run: counts and the accounts
//   node scripts/db/cleanup.mjs <staging|production> --apply   write (production asks to type its name)
//
// Everything runs in ONE transaction: either all items apply or none. Take a fresh pg_dump
// of production first.
import { createInterface } from 'node:readline/promises'
import { neon } from '@neondatabase/serverless'
import { die, loadEnvFile, describe } from './lib.mjs'

const KEEP_USER_ID = '7c4d1d2b-8539-494d-8dca-49d112b62d97'
const STALE_DAYS = 90

const [target, ...flags] = process.argv.slice(2)
if (!['staging', 'production'].includes(target)) die('usage: cleanup.mjs <staging|production> [--apply]')
const apply = flags.includes('--apply')

// ── Selections (shared by the dry run and the writes, so they always match) ──
const STUCK_SCANS = `select scan_id from scan_results
  where status in ('pending', 'running') and started_at < now() - interval '${STALE_DAYS} days'`

const STALE_ASSETS = `select a.asset_id from assets a
  where not a.in_my_assets
    and a.source in ('scan_active', 'scan_passive')
    and a.last_scanned < now() - interval '${STALE_DAYS} days'
    and a.endpoint_inventory is null
    and not exists (select 1 from sboms s where s.asset_id = a.asset_id)
    and not exists (select 1 from events e where e.asset_id = a.asset_id and e.event_type = 'cve_detected')
    and not exists (select 1 from agents g where g.host_asset_id = a.asset_id)`

// Run after the asset delete, so jobs of the assets just removed are included too.
const ORPHAN_SBOM_SCANS = `select s.scan_id from scan_results s
  where s.scan_type = 'sbom' and not exists (select 1 from assets a where a.asset_id::text = s.subnet)`
const ORPHAN_SBOM_SCANS_AFTER = `select s.scan_id from scan_results s
  where s.scan_type = 'sbom' and (
    not exists (select 1 from assets a where a.asset_id::text = s.subnet)
    or s.subnet in (select asset_id::text from (${STALE_ASSETS}) x))`

const TENANTLESS_USERS = `select user_id from users
  where tenant_id is null and role = 'business_owner' and user_id <> '${KEEP_USER_ID}'`

const vars = loadEnvFile(target)
const host = describe(vars.DATABASE_URL)
console.log(`\nTarget : ${target.toUpperCase()}\nDatabase: ${host}\n`)
const sql = neon(vars.DATABASE_URL)

// ── Dry run (always shown) ──
const [counts, assetBreakdown, userRows, kept] = await sql.transaction([
  sql(`select
    (select count(*) from (${STUCK_SCANS}) x)::int as stuck_scans_to_fail,
    (select count(*) from (${ORPHAN_SBOM_SCANS_AFTER}) x)::int as sbom_scan_jobs_to_delete,
    (select count(*) from (${STALE_ASSETS}) x)::int as assets_to_delete,
    (select count(*) from events where asset_id in (${STALE_ASSETS}))::int as their_events,
    (select count(*) from asset_relationships where source_asset_id in (${STALE_ASSETS}) or target_asset_id in (${STALE_ASSETS}))::int as their_relationships,
    (select count(*) from topology_nodes where asset_id in (${STALE_ASSETS}))::int as their_topology_nodes,
    (select count(*) from (${TENANTLESS_USERS}) x)::int as users_to_delete,
    (select count(*) from audit_logs where user_id in (${TENANTLESS_USERS}))::int as their_audit_logs`),
  sql(`select coalesce(t.name, '(no tenant)') as tenant, a.source::text as source, a.device_type::text as type, count(*)::int as assets
       from assets a left join tenants t on t.tenant_id = a.tenant_id
       where a.asset_id in (${STALE_ASSETS}) group by 1, 2, 3 order by 1, 2, 3`),
  sql(`select user_id, username, email, to_char(created_at, 'YYYY-MM-DD') as created,
              coalesce(to_char(last_login, 'YYYY-MM-DD'), 'never') as last_login
       from users where user_id in (${TENANTLESS_USERS}) order by created_at`),
  sql(`select username, role::text as role, tenant_id is null as no_tenant from users where user_id = '${KEEP_USER_ID}'`),
], { readOnly: true }).catch(e => die(e.message))

console.log('Would change:')
console.table(counts)
console.log('Assets to delete, by tenant, source and type:')
console.table(assetBreakdown)
console.log('Accounts to delete (check these before --apply):')
console.table(userRows)
console.log(kept.length
  ? `Kept account ${KEEP_USER_ID}: ${kept[0].username} (${kept[0].role}${kept[0].no_tenant ? ', no tenant' : ''})`
  : `Note: the kept account ${KEEP_USER_ID} does not exist in this database.`)

if (!apply) {
  console.log('\nDry run only. Nothing was changed. Re-run with --apply to write.')
  process.exit(0)
}

if (target === 'production') {
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  const answer = await rl.question(`\nThis DELETES data in PRODUCTION (${host}). Type "production" to continue: `)
  rl.close()
  if (answer.trim() !== 'production') die('Not confirmed. Nothing was changed.')
}

const results = await sql.transaction([
  // 1. Stuck scans can never finish; keep them as history, marked failed.
  sql(`update scan_results set status = 'failed', completed_at = coalesce(completed_at, now()),
         failure_reason = 'Never finished; marked failed by the legacy data cleanup on ${new Date().toISOString().slice(0, 10)}'
       where scan_id in (${STUCK_SCANS}) returning scan_id`),
  // 3. Same as DELETE /assets/:id: detach child topology nodes first (parent_node_id has
  //    no FK), then the delete cascades to addresses, events, relationships and nodes.
  sql(`update topology_nodes set parent_node_id = null
       where parent_node_id in (select node_id from topology_nodes where asset_id in (${STALE_ASSETS})) returning node_id`),
  sql(`delete from assets where asset_id in (${STALE_ASSETS}) returning asset_id`),
  // 2. SBOM scan jobs pointing at an asset that no longer exists (incl. the ones just removed).
  sql(`delete from scan_results where scan_id in (${ORPHAN_SBOM_SCANS}) returning scan_id`),
  // 5. Business-owner accounts that never got a tenant, except the one kept.
  sql(`delete from users where user_id in (${TENANTLESS_USERS}) returning user_id`),
]).catch(e => die(`${e.message}\nThe transaction was rolled back. Nothing was changed.`))

const [failed, detached, deletedAssets, deletedScans, deletedUsers] = results
console.log('\nDone (one transaction):')
console.table([{
  scans_marked_failed: failed.length,
  topology_nodes_detached: detached.length,
  assets_deleted: deletedAssets.length,
  sbom_scan_jobs_deleted: deletedScans.length,
  users_deleted: deletedUsers.length,
}])
