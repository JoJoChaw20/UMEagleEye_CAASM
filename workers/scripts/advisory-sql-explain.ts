/**
 * advisory-sql-explain.ts — asks Postgres to PLAN (EXPLAIN, never ANALYZE) every advisory
 * statement added for tenant scoping, so syntax and type errors show up without running
 * anything: EXPLAIN without ANALYZE does not execute the statement, nothing is written.
 * Run from workers/:
 *   npx esbuild scripts/advisory-sql-explain.ts --bundle --platform=node --format=cjs --outfile=.x.cjs
 *   node --env-file=../.env .x.cjs     (DATABASE_URL; the postgresql+asyncpg:// prefix is rewritten)
 */
import { neon } from '@neondatabase/serverless'
import { PgDialect } from 'drizzle-orm/pg-core'
import { and, inArray, lt, eq } from 'drizzle-orm'
import { getDb } from '../src/db/client'
import { advisories } from '../src/db/schema'
import {
  ACTIVE_ADVISORY_STATUSES, advisoryInTenant, advisoryScope, insertAdvisoryIfNoneSql, liveAdvisoryOf, resolveClosedSql,
} from '../src/lib/advisoryScope'

const url = (process.env.DATABASE_URL ?? '')
  .replace(/^postgresql\+asyncpg:\/\//, 'postgresql://').replace(/([?&])ssl=require/, '$1sslmode=require')
if (!url) throw new Error('DATABASE_URL missing')
const client = neon(url)
const db = getDb(url)
const dialect = new PgDialect()
const T = '00000000-0000-0000-0000-0000000000aa'
const E = '00000000-0000-0000-0000-0000000000bb'

const cases: Array<[string, { sql: string; params: unknown[] }]> = [
  ['resolve closed: by alerts', dialect.sqlToQuery(resolveClosedSql({ eventIds: [E, T] }))],
  ['resolve closed: tenant sweep', dialect.sqlToQuery(resolveClosedSql({ tenantId: T }))],
  ['resolve closed: global sweep', dialect.sqlToQuery(resolveClosedSql({}))],
  ['insert if none', dialect.sqlToQuery(insertAdvisoryIfNoneSql(E, 'summary', 'text'))],
  ['live advisory select', db.select({ id: advisories.advisoryId }).from(advisories).where(liveAdvisoryOf(E)).toSQL()],
  ['tenant list', db.select({ id: advisories.advisoryId }).from(advisories)
    .where(and(inArray(advisories.status, [...ACTIVE_ADVISORY_STATUSES]), advisoryInTenant(db, T))).toSQL()],
  ['sla breach count', db.select({ id: advisories.advisoryId }).from(advisories)
    .where(and(eq(advisories.status, 'open'), lt(advisories.createdAt, new Date()), advisoryScope(db, { role: 'tenant_admin', tenantId: T }))).toSQL()],
]

async function main() {
  let fail = 0
  for (const [label, q] of cases) {
    try {
      await (client as unknown as (s: string, p: unknown[]) => Promise<unknown>)(`EXPLAIN ${q.sql}`, q.params)
      console.log(`PASS  ${label}`)
    } catch (err) {
      fail++
      console.log(`FAIL  ${label}: ${(err as Error).message}`)
    }
  }
  console.log(fail ? `\n${fail} failed` : '\nall statements plan')
  process.exit(fail ? 1 : 0)
}
void main()
