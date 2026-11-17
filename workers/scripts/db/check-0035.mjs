// Read-only pre-check for migration 0035 (action-based access). SELECT only; writes nothing.
//
//   node scripts/db/check-0035.mjs <staging|production>
//
// Prints users per role, and every tenant with more than one Tenant Superadmin, showing which
// account the migration keeps (active first, then oldest, then lowest user_id) and which become full-access users.
import { neon } from '@neondatabase/serverless'
import { die, loadEnvFile, describe } from './lib.mjs'

const target = process.argv[2]
if (!['staging', 'production'].includes(target)) die('usage: check-0035.mjs <staging|production>')
const { DATABASE_URL } = loadEnvFile(target)
const sql = neon(DATABASE_URL)
console.log(`Target: ${target} (${describe(DATABASE_URL)})  [read-only]\n`)

const roles = await sql(`select role::text as role, count(*)::int as n from users group by role order by role`)
console.log('Users per role:')
for (const r of roles) console.log(`  ${r.role.padEnd(20)} ${r.n}`)

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
