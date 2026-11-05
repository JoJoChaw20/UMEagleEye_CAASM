/**
 * advisory-scope-demo.ts — checks the advisory tenant scoping, id parsing and the AI draft guard.
 * No database: the SQL is rendered, not run.
 * Run: npx esbuild scripts/advisory-scope-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.r.cjs && node .r.cjs
 */
import { PgDialect } from 'drizzle-orm/pg-core'
import { getDb } from '../src/db/client'
import { advisories } from '../src/db/schema'
import { advisoryIdPrefix, advisoryInTenant, advisoryScope, advisoryIdStartsWith } from '../src/lib/advisoryScope'
import { cveIdsIn, parseAiDraft, type AdvisoryDraft } from '../src/lib/advisoryKit'

let pass = 0, fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `  got=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

// ── ids typed in the chat ──
check('full uuid accepted', advisoryIdPrefix('3F2A91C0-1111-2222-3333-444455556666'), '3f2a91c0-1111-2222-3333-444455556666')
check('8-char prefix accepted', advisoryIdPrefix(' 3f2a91c0 '), '3f2a91c0')
check('% wildcard refused', advisoryIdPrefix('%'), null)
check('_ wildcard refused', advisoryIdPrefix('3f2a_'), null)
check('too short refused', advisoryIdPrefix('3f2'), null)
check('sql text refused', advisoryIdPrefix("3f2a' OR 1=1"), null)

// ── rendered SQL ──
const db = getDb('postgresql://user:pass@localhost/db')
const dialect = new PgDialect()
const q = db.select({ id: advisories.advisoryId }).from(advisories)
  .where(advisoryInTenant(db, '00000000-0000-0000-0000-0000000000aa')).toSQL()
check('tenant scope is a subquery through events and assets',
  /"advisories"\."event_id" in \(select "events"\."event_id" from "events" inner join "assets" on "events"\."asset_id" = "assets"\."asset_id" where "assets"\."tenant_id" = \$1\)/.test(q.sql), true)
check('tenant id is a parameter', q.params, ['00000000-0000-0000-0000-0000000000aa'])
check('superadmin, no tenant picked: no filter', advisoryScope(db, { role: 'superadmin' }), undefined)
check('tenant admin without tenant: sees nothing',
  dialect.sqlToQuery(advisoryScope(db, { role: 'tenant_admin', tenantId: null })!).sql, 'false')
const like = dialect.sqlToQuery(advisoryIdStartsWith('3f2a91c0'))
check('prefix match is parameterised', [like.sql.includes('LIKE $1'), like.params], [true, ['3f2a91c0%']])

// ── AI draft guard ──
const fallback: AdvisoryDraft = {
  summary: 'rule summary', steps: ['rule step'], whyNow: null, verify: null, rollback: null,
  confidence: { level: 'Low', reason: 'no fixed version known' },
}
const ai = (o: unknown) => JSON.stringify(o)
const good = parseAiDraft(ai({ summary: 'CVE-2024-1234 affects openssl here.', steps: ['Upgrade openssl.'], confidence: 'high' }), fallback, ['CVE-2024-1234'])
check('known CVE accepted', good?.summary, 'CVE-2024-1234 affects openssl here.')
check('confidence stays rule-based', good?.confidence, fallback.confidence)
check('invented CVE rejected',
  parseAiDraft(ai({ summary: 'CVE-2024-1234 and CVE-2023-9999 affect it.', steps: ['Upgrade.'] }), fallback, ['CVE-2024-1234']), null)
check('invented CVE in a step rejected',
  parseAiDraft(ai({ summary: 'Upgrade needed.', steps: ['See cve-2020-0001.'] }), fallback, []), null)
check('urls stripped', parseAiDraft(ai({ summary: 'Read https://evil.example/x now.', steps: ['Upgrade.'] }), fallback)?.summary, 'Read now.')
check('cveIdsIn dedupes and upper-cases', cveIdsIn('cve-2024-1234 CVE-2024-1234 CVE-2021-44228'), ['CVE-2024-1234', 'CVE-2021-44228'])

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
