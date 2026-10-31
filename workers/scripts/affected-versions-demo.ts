/**
 * affected-versions-demo.ts — CVE alerts with several installed versions of a package
 * (lib/affectedVersions.ts): every affected version kept, the oldest named, and the other
 * versions of a fix group listed with their own upgrade. PURE (no DB).
 * Run: npx esbuild scripts/affected-versions-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.affected-versions-demo.cjs && node .affected-versions-demo.cjs
 */
import { alsoAffected, collectAffectedVersions, MAX_AFFECTED_VERSIONS } from '../src/lib/affectedVersions'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

// pgAdmin 4 on the staging PC, 31 Oct: one CVE reported for three installed versions.
const findings = [
  { cve_id: 'CVE-2026-33750', package_name: 'brace-expansion', package_version: '2.0.2', fix_versions: ['2.0.3'] },
  { cve_id: 'CVE-2026-33750', package_name: 'brace-expansion', package_version: '1.1.11', fix_versions: ['1.1.13', '2.0.3'] },
  { cve_id: 'CVE-2026-33750', package_name: 'brace-expansion', package_version: '1.1.12', fix_versions: ['1.1.13'] },
  { cve_id: 'CVE-2026-33750', package_name: 'brace-expansion', package_version: '1.1.11', fix_versions: ['1.1.12'] },  // a second copy
  { cve_id: 'CVE-2021-3807', package_name: 'ansi-regex', package_version: '3.0.0', fix_versions: ['3.0.1'] },
  { cve_id: 'CVE-2099-0001', package_name: 'nover', package_version: null, fix_versions: [] },
]
const byKey = collectAffectedVersions(findings)
check('every affected version, oldest first, fixes of copies merged', byKey.get('CVE-2026-33750::brace-expansion'), [
  { version: '1.1.11', fix_versions: ['1.1.13', '2.0.3', '1.1.12'] },
  { version: '1.1.12', fix_versions: ['1.1.13'] },
  { version: '2.0.2', fix_versions: ['2.0.3'] },
])
check('the oldest is the one the alert names (stable whichever copy came first)', byKey.get('CVE-2026-33750::brace-expansion')?.[0]?.version, '1.1.11')
check('a single version stays a single entry', byKey.get('CVE-2021-3807::ansi-regex'), [{ version: '3.0.0', fix_versions: ['3.0.1'] }])
check('a finding without a version adds nothing', byKey.has('CVE-2099-0001::nover'), false)
const many = Array.from({ length: 30 }, (_, i) => ({ cve_id: 'CVE-1', package_name: 'p', package_version: `1.0.${i}`, fix_versions: [] }))
check(`at most ${MAX_AFFECTED_VERSIONS} versions kept, oldest first`, [collectAffectedVersions(many).get('CVE-1::p')?.length, collectAffectedVersions(many).get('CVE-1::p')?.[0]?.version], [MAX_AFFECTED_VERSIONS, '1.0.0'])

// The fix group "upgrade brace-expansion 1.1.11": its alerts' affected versions.
const lists = [
  byKey.get('CVE-2026-33750::brace-expansion'),
  [{ version: '1.1.11', fix_versions: ['1.1.14'] }, { version: '2.0.2', fix_versions: ['2.0.5'] }],   // another CVE
]
check('the group lists the other versions, each with the upgrade that fixes all its CVEs', alsoAffected('1.1.11', lists), [
  { version: '1.1.12', to: '1.1.13' },
  { version: '2.0.2', to: '2.0.5' },
])
check('no other version: nothing listed', alsoAffected('3.0.0', [byKey.get('CVE-2021-3807::ansi-regex')]), [])
check('alerts from before affected_versions existed: nothing listed', alsoAffected('1.0.0', [null, undefined]), [])
check('a version with no published fix says so (to: null)', alsoAffected('1.0', [[{ version: '1.0' }, { version: '2.0', fix_versions: [] }]]), [{ version: '2.0', to: null }])

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
