/**
 * Staging smoke test: malicious packages (services/maliciousPackages.ts) against the real OSV API and the
 * staging database. Temporary tenant MALTEST-smoke with one device whose SBOM holds @ctrl/tinycolor 4.1.1
 * (OSV MAL-2025-47141, the Sept 2025 "Shai-Hulud" worm) and lodash 4.17.20 (flawed, not malware), and a
 * Grype finding for ua-parser-js 0.7.29 marked CWE-506. Then the package goes away and comes back.
 * Removed at the end.
 *
 *   npx esbuild scripts/smoke/malpkg-smoke.ts --bundle --platform=node --format=esm --outfile=scripts/smoke/.malpkg-smoke.mjs \
 *     "--banner:js=import { createRequire as __cr } from 'module'; const require = __cr(import.meta.url);"
 *   node scripts/smoke/.malpkg-smoke.mjs
 */
import { neon } from '@neondatabase/serverless'
import { getDb } from '../../src/db/client'
import { checkMaliciousPackages } from '../../src/services/maliciousPackages'
// @ts-expect-error plain .mjs helper
import { loadEnvFile } from '../db/lib.mjs'

const url = loadEnvFile('staging').DATABASE_URL as string
const sql = neon(url)
const db = getDb(url)
const store = new Map<string, string>()
const kv = {
  get: async (k: string) => store.get(k) ?? null,
  put: async (k: string, v: string) => { store.set(k, v) },
} as unknown as KVNamespace

const results: Array<[string, string]> = []
const check = (name: string, ok: boolean, info = '') => { results.push([ok ? 'PASS' : 'FAIL', name]); console.log(ok ? 'PASS' : 'FAIL', name, info) }
const alerts = async (asset: string) => await sql(
  "select status, severity, details from events where asset_id=$1 and event_type='cti_match' and details->>'match_kind'='malicious_package' order by details->>'indicator_value'", [asset]) as Array<{ status: string; severity: string; details: Record<string, unknown> }>

const [{ tenant_id: T }] = await sql("insert into tenants (name, slug) values ('MALTEST-smoke','maltest-smoke') returning tenant_id") as Array<{ tenant_id: string }>
try {
  const [{ asset_id: A }] = await sql("insert into assets (tenant_id, ip_address, hostname) values ($1, '10.97.0.5', 'maltest-dev') returning asset_id", [T]) as Array<{ asset_id: string }>
  const [{ sbom_id: S }] = await sql("insert into sboms (asset_id, format, raw_data) values ($1, 'cyclonedx', '{}'::jsonb) returning sbom_id", [A]) as Array<{ sbom_id: string }>
  const dep = (name: string, version: string, purl: string) => sql(
    "insert into dependencies (asset_id, sbom_id, name, version, package_manager, purl) values ($1,$2,$3,$4,'npm',$5)", [A, S, name, version, purl])
  await dep('@ctrl/tinycolor', '4.1.1', 'pkg:npm/%40ctrl/tinycolor@4.1.1')
  await dep('lodash', '4.17.20', 'pkg:npm/lodash@4.17.20')
  const [{ event_id: E }] = await sql("insert into events (asset_id, event_type, severity, details) values ($1, 'cve_detected', 'high', '{\"shape\":\"package\",\"package_name\":\"ua-parser-js\"}'::jsonb) returning event_id", [A]) as Array<{ event_id: string }>
  await sql("insert into cve_findings (event_id, asset_id, cve_id, advisory_id, package_type, package_name, package_version, severity, cwe_ids, description) values ($1,$2,'CVE-2021-4229','GHSA-pjwm-rvh2-c87w','npm','ua-parser-js','0.7.29','high',ARRAY['CWE-506','CWE-912'],'Embedded malware in ua-parser-js')", [E, A])

  let r = await checkMaliciousPackages(db, kv, { assetId: A })
  let a = await alerts(A)
  check('2 packages asked, 2 malicious (OSV + the advisory), 2 alerts', r.checked === 2 && r.malicious === 2 && r.created === 2, JSON.stringify(r))
  const tiny = a.find((x) => String(x.details.package_name) === '@ctrl/tinycolor')
  const ua = a.find((x) => String(x.details.package_name) === 'ua-parser-js')
  check('tinycolor: critical, OSV MAL-2025-47141, with summary', tiny?.severity === 'critical' && JSON.stringify(tiny?.details.advisory_ids) === '["MAL-2025-47141"]' && /tinycolor/.test(String(tiny?.details.summary)), String(tiny?.details.summary))
  check('ua-parser-js: from the CWE-506 advisory', ua?.status === 'open' && (ua?.details.sources as string[])?.[0] === 'Advisory: embedded malicious code' && JSON.stringify(ua?.details.advisory_ids) === '["GHSA-pjwm-rvh2-c87w"]')
  check('lodash (flawed, not malware): no alert', !a.some((x) => x.details.package_name === 'lodash'))

  r = await checkMaliciousPackages(db, kv, { assetId: A })
  check('a second run changes nothing', r.created === 0 && r.reopened === 0 && r.resolved === 0, JSON.stringify(r))

  await sql("delete from dependencies where asset_id=$1 and name='@ctrl/tinycolor'", [A])
  r = await checkMaliciousPackages(db, kv, { assetId: A })
  a = await alerts(A)
  check('package removed: its alert resolves, the other stays', r.resolved === 1 && a.find((x) => x.details.package_name === '@ctrl/tinycolor')?.status === 'resolved' && a.find((x) => x.details.package_name === 'ua-parser-js')?.status === 'open', JSON.stringify(r))

  await dep('@ctrl/tinycolor', '4.1.1', 'pkg:npm/%40ctrl/tinycolor@4.1.1')
  r = await checkMaliciousPackages(db, kv, { assetId: A })
  a = await alerts(A)
  const [re] = await sql("select reopen_count from events where asset_id=$1 and details->>'package_name'='@ctrl/tinycolor'", [A]) as Array<{ reopen_count: number }>
  check('back again: reopened (trigger counted it)', r.reopened === 1 && a.find((x) => x.details.package_name === '@ctrl/tinycolor')?.status === 'open' && re?.reopen_count === 1, JSON.stringify(r))

  // A record covering every version of a name (a squat): a name match, reviewed, not a compromise
  await dep('vscode-bicep', '0.30.3', 'pkg:npm/vscode-bicep@0.30.3')
  r = await checkMaliciousPackages(db, kv, { assetId: A })
  a = await alerts(A)
  const bicep = a.find((x) => x.details.package_name === 'vscode-bicep')
  check('vscode-bicep (MAL-2022-6972, any version): medium, a name match', bicep?.severity === 'medium' && bicep?.details.match_scope === 'name', `${bicep?.severity} ${bicep?.details.match_scope}`)
  check('tinycolor stays a listed release: critical', a.find((x) => x.details.package_name === '@ctrl/tinycolor')?.details.match_scope === 'version')

  // The nightly run pages through every device's packages (other staging devices may have some too)
  const before = (await alerts(A)).length
  r = await checkMaliciousPackages(db, kv, { nightly: true })
  check('nightly run: asks every package, no duplicate alerts here', r.checked > 3 && (await alerts(A)).length === before, JSON.stringify(r))
  const [tier] = await sql("select count(*)::int n from events where asset_id=$1 and event_type='cti_match' and status='open' and severity='critical'", [A]) as Array<{ n: number }>
  check('2 open critical threat-intel alerts (tier 1: investigate in 24 h)', tier?.n === 2)
} finally {
  await sql('delete from audit_logs where tenant_id=$1', [T])
  await sql('delete from tenants where tenant_id=$1', [T])
  await sql('delete from kg_outbox where tenant_id=$1', [T])
  await sql("delete from kg_outbox where tenant_id is null and changed_at > now() - interval '10 minutes' and table_name in ('events','assets')")
  console.log('cleanup left:', (await sql("select count(*)::int n from tenants where name='MALTEST-smoke'"))[0]!.n)
  console.log(`SUMMARY: ${results.filter((x) => x[0] === 'PASS').length} pass, ${results.filter((x) => x[0] === 'FAIL').length} fail`)
}
