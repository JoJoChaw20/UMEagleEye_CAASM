// Read-only pre-check for migration 0036 (drop the legacy roles). SELECT only; writes nothing.
//
//   node scripts/db/check-0036.mjs <staging|production>
//
// Prints users per role, the legacy-role users with NULL actions (they get the converted set; the
// others keep the actions already stored), and every tenant with more than one Tenant Superadmin, showing which
// account the migration keeps (active first, then oldest, then lowest user_id) and which become full-access users,
// and flags every tenant whose kept Tenant Superadmin is inactive.
import { neon } from '@neondatabase/serverless'
import { die, loadEnvFile, describe } from './lib.mjs'

const target = process.argv[2]
if (!['staging', 'production'].includes(target)) die('usage: check-0036.mjs <staging|production>')
const { DATABASE_URL } = loadEnvFile(target)
const sql = neon(DATABASE_URL)
console.log(`Target: ${target} (${describe(DATABASE_URL)})  [read-only]\n`)

const roles = await sql(`select role::text as role, count(*)::int as n from users group by role order by role`)
console.log('Users per role:')
for (const r of roles) console.log(`  ${r.role.padEnd(20)} ${r.n}`)

// role::text: the comparison stays valid if 0036 has already removed these enum values.
const [{ n: legacyNull }] = await sql(`select count(*)::int as n from users where role::text in ('tenant_admin', 'business_owner') and actions is null`)
console.log(`\nLegacy-role users with NULL actions (get the converted set): ${legacyNull}`)

const [{ n: orphans }] = await sql(`select count(*)::int as n from users where role = 'tenant_superadmin' and tenant_id is null`)
console.log(`\nTenant Superadmins with no tenant (become users with no actions): ${orphans}`)

const rows = await sql(`
  select t.name as tenant, u.username, u.is_active, u.created_at,
         row_number() over (partition by u.tenant_id order by u.is_active desc, u.created_at asc, u.user_id asc) as rn,
         count(*) over (partition by u.tenant_id) as total
  from users u join tenants t on t.tenant_id = u.tenant_id
  where u.role = 'tenant_superadmin'
  order by t.name, rn`)
const multi = rows.filter((r) => Number(r.total) > 1)
if (!multi.length) {
  console.log('\nNo tenant has more than one Tenant Superadmin.')
} else {
  console.log('\nTenants with more than one Tenant Superadmin:')
  let current = null
  for (const r of multi) {
    if (r.tenant !== current) { current = r.tenant; console.log(`  ${r.tenant} (${r.total})`) }
    const fate = Number(r.rn) === 1 ? 'KEPT as Tenant Superadmin' : 'becomes tenant_user with all actions'
    console.log(`    ${r.username}  active=${r.is_active}  created=${new Date(r.created_at).toISOString()}  -> ${fate}`)
  }
}

// The kept Tenant Superadmin is the active one when there is one; a tenant whose kept owner is
// still inactive has none of its Tenant Superadmins active, so nobody can run it after the migration.
const inactiveKept = rows.filter((r) => Number(r.rn) === 1 && !r.is_active)
if (!inactiveKept.length) {
  console.log('\nEvery kept Tenant Superadmin is active.')
} else {
  console.log('\nTenants whose kept Tenant Superadmin is inactive:')
  for (const r of inactiveKept) console.log(`  ${r.tenant}: ${r.username}  -> kept owner inactive — fix by hand`)
}
