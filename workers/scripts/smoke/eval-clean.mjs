// Cleans up after an interrupted advisory-eval run: the same steps as its finally block.
import { neon } from '@neondatabase/serverless'
import { loadEnvFile } from '../db/lib.mjs'
const sql = neon(loadEnvFile('staging').DATABASE_URL)
const P = 'adveval_'
const tenants = (await sql("select tenant_id::text t from tenants where name like 'ADVEVAL-%'")).map(r => r.t)
console.log('tenants found', tenants.length)
for (const t of tenants) await sql('delete from audit_logs where tenant_id = $1', [t])
await sql(`delete from audit_logs where actor_username like '${P}%' or user_id in (select user_id from users where username like '${P}%')`)
await sql(`delete from users where username like '${P}%'`)
for (const t of tenants) await sql('delete from tenants where tenant_id = $1', [t])
const left = await sql(`select (select count(*) from users where username like '${P}%')::int u, (select count(*) from tenants where name like 'ADVEVAL-%')::int t, (select count(*) from assets where hostname like '%-eval-%')::int a, (select count(*) from cve_findings where cve_id in ('CVE-2099-1111','CVE-2099-2222'))::int c, (select count(*) from agents where name like '${P}%')::int g`)
console.log('cleanup left', JSON.stringify(left[0]))
