/**
 * windows-patch-demo.ts — Windows patch level from Microsoft's fixed builds (lib/windowsPatch.ts):
 * which version a machine runs, which months of fixes it is missing, the grace period, out of
 * support, severity. PURE (no DB). With MSRC_INDEX=<index.json from build-msrc.mjs> it also
 * runs a few machines against real data.
 * Run: npx esbuild scripts/windows-patch-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.windows-patch-demo.cjs && node .windows-patch-demo.cjs
 */
import { readFileSync } from 'node:fs'
import { assessPatch, patchSeverity, productFor, windowsOs, type MsrcIndex } from '../src/lib/windowsPatch'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

const fix = (ubr: number, cves: number, critical = 0, exploited = 0, kb = `KB${ubr}`, build = 26200) =>
  ({ fixed_build: `10.0.${build}.${ubr}`, kb, cves, critical, exploited })
const index: MsrcIndex = {
  generated: '2026-10-27T00:00:00Z',
  months: [
    { id: '2026-Jul', released: '2026-07-14T07:00:00Z', revised: '2026-07-14T07:00:00Z' },
    { id: '2026-Aug', released: '2026-08-11T07:00:00Z', revised: '2026-08-11T07:00:00Z' },
    { id: '2026-Sep', released: '2026-09-08T07:00:00Z', revised: '2026-09-08T07:00:00Z' },
    { id: '2026-Oct', released: '2026-10-13T07:00:00Z', revised: '2026-10-13T07:00:00Z' },
  ],
  products: {
    // 24H2 and 25H2 share fixes; 24H2 lists both builds
    'Windows 11 Version 24H2 for x64-based Systems': { server: false, core: false, arch: 'x64', builds: [26100, 26200], months: {
      '2026-Aug': [fix(8875, 200, 5, 0, 'KB1', 26100), fix(8875, 200, 5, 0, 'KB1')],
      '2026-Sep': [fix(9445, 600, 50, 1, 'KB2', 26100), fix(9445, 600, 50, 1, 'KB2')],
      '2026-Oct': [fix(9711, 1000, 25, 1, 'KB3', 26100), fix(9711, 1000, 25, 1, 'KB3')],
    } },
    'Windows 11 Version 25H2 for x64-based Systems': { server: false, core: false, arch: 'x64', builds: [26200], months: {
      '2026-Aug': [fix(8875, 200, 5, 0, 'KB1')],
      // October also lists 10 CVEs whose fix shipped in September's build
      '2026-Sep': [fix(9445, 600, 50, 1, 'KB2')],
      '2026-Oct': [fix(9711, 1000, 25, 1, 'KB3'), fix(9445, 10, 1, 0, 'KB2')],
    } },
    'Windows 11 Version 25H2 for ARM64-based Systems': { server: false, core: false, arch: 'arm64', builds: [26200], months: {
      '2026-Oct': [fix(9711, 990, 25, 1, 'KB3')],
    } },
    'Windows Server 2025': { server: true, core: false, arch: 'x64', builds: [26100], months: {
      '2026-Oct': [fix(9711, 1050, 30, 1, 'KB4', 26100)],
    } },
    'Windows Server 2025 (Server Core installation)': { server: true, core: true, arch: 'x64', builds: [26100], months: {
      '2026-Oct': [fix(9711, 1050, 30, 1, 'KB4', 26100)],
    } },
    // Last listed in July: out of support once three releases pass without it
    'Windows 11 Version 22H2 for x64-based Systems': { server: false, core: false, arch: 'x64', builds: [22621, 22631], months: {
      '2026-Jul': [fix(6000, 50, 1, 0, 'KB5', 22621)],
    } },
  },
}
const inv = (os: Record<string, unknown>, platform = 'windows') => ({ platform, os })
const pc = (ubr: number, over: Record<string, unknown> = {}) =>
  windowsOs(inv({ build: '26200', ubr, architecture: '64-bit', product_type: 1, display_version: '25H2', ...over }))
const NOW = new Date('2026-10-27T00:00:00Z')

// ── reading the inventory ──
check('a Windows inventory gives build, patch number, arch, workstation',
  pc(9711), { build: 26200, ubr: 9711, arch: 'x64', server: false, displayVersion: '25H2' })
check('ARM and server are recognised', [windowsOs(inv({ build: 26200, ubr: 1, architecture: 'ARM 64-bit Processor', product_type: 1 }))?.arch,
  windowsOs(inv({ build: 26100, ubr: 1, architecture: '64-bit', product_type: 3 }))?.server], ['arm64', true])
check('a Linux inventory, or one without a patch number, is not assessed',
  [windowsOs(inv({ build: '6.8', ubr: 1 }, 'linux')), windowsOs(inv({ build: '26200' }))], [null, null])

// ── which version ──
check('25H2 picks the 25H2 product, not 24H2 which shares its build', productFor(pc(1)!, index), 'Windows 11 Version 25H2 for x64-based Systems')
check('without a display version the build still finds a product', productFor(pc(1, { display_version: null })!, index) !== null, true)
check('ARM64 machine gets the ARM64 product', productFor(pc(1, { architecture: 'ARM 64-bit Processor' })!, index), 'Windows 11 Version 25H2 for ARM64-based Systems')
check('a server gets the full installation, not Server Core', productFor(windowsOs(inv({ build: 26100, ubr: 1, architecture: '64-bit', product_type: 3 }))!, index), 'Windows Server 2025')
check('the registry\'s "Windows 10" name does not matter: only the build is used',
  productFor(windowsOs(inv({ name: 'Windows 10 Home', build: '26200', ubr: 1, architecture: '64-bit', product_type: 1, display_version: '25H2' }))!, index),
  'Windows 11 Version 25H2 for x64-based Systems')

// ── missing fixes ──
const cur = assessPatch(pc(9711), index, NOW)
check('fully patched: current, nothing missing, latest is its own build', [cur.status, cur.missing.length, cur.latest], ['current', 0, { fixed_build: '10.0.26200.9711', kb: 'KB3' }])
const sep = assessPatch(pc(9445), index, NOW)
check('September build: missing October only', [sep.status, sep.missing.map(m => m.month), sep.cves, sep.critical, sep.exploited], ['behind', ['2026-Oct'], 1000, 25, 1])
check('…and the fix to install is October\'s KB', sep.latest?.kb, 'KB3')
const aug = assessPatch(pc(8875), index, NOW)
check('August build: misses September, October, and October\'s late-listed September fixes',
  [aug.missing.map(m => `${m.month}:${m.kb}`), aug.cves], [['2026-Sep:KB2', '2026-Oct:KB2', '2026-Oct:KB3'], 1610])
check('a build newer than every fix (preview update) is current', assessPatch(pc(9800), index, NOW).status, 'current')
check('a fix released under 7 days ago is not missing yet', assessPatch(pc(9445), index, new Date('2026-10-16T00:00:00Z')).status, 'current')

// ── support ──
const w22 = assessPatch(windowsOs(inv({ build: 22621, ubr: 6000, architecture: '64-bit', product_type: 1, display_version: '22H2' })), index, NOW)
check('a version Microsoft dropped (not in the last 3 releases) is out of support', [w22.status, w22.product], ['unsupported', 'Windows 11 Version 22H2 for x64-based Systems'])
check('a build older than every listed version is out of support', assessPatch(windowsOs(inv({ build: 19041, ubr: 1, architecture: '64-bit', product_type: 1 })), index, NOW).status, 'unsupported')
check('a build newer than every listed version (Insider) is unknown', assessPatch(windowsOs(inv({ build: 27000, ubr: 1, architecture: '64-bit', product_type: 1 })), index, NOW).status, 'unknown')
check('no patch data loaded: unknown, never "current"', assessPatch(pc(1), null, NOW).status, 'unknown')

// ── severity ──
check('exploited fix missing = critical; critical fixes = high; else medium; unsupported = high',
  [patchSeverity(sep), patchSeverity({ ...sep, exploited: 0 }), patchSeverity({ ...sep, exploited: 0, critical: 0 }), patchSeverity(w22)],
  ['critical', 'high', 'medium', 'high'])

// ── real data (optional) ──
if (process.env.MSRC_INDEX) {
  const real = JSON.parse(readFileSync(process.env.MSRC_INDEX, 'utf8')) as MsrcIndex
  console.log(`\nReal data: ${Object.keys(real.products).length} versions, ${real.months.map(m => m.id).join(' ')}`)
  for (const [label, os] of [
    ['this PC (25H2, Oct patch)', pc(9711)],
    ['25H2, Sep patch', pc(9445)],
    ['24H2 x64, Sep patch', windowsOs(inv({ build: 26100, ubr: 9445, architecture: '64-bit', product_type: 1, display_version: '24H2' }))],
    ['Windows 10 22H2, Oct 2025 (no ESU)', windowsOs(inv({ build: 19045, ubr: 6456, architecture: '64-bit', product_type: 1, display_version: '22H2' }))],
    ['Windows 11 22H2', windowsOs(inv({ build: 22621, ubr: 5000, architecture: '64-bit', product_type: 1, display_version: '22H2' }))],
    ['Server 2022, Oct patch', windowsOs(inv({ build: 20348, ubr: 99999, architecture: '64-bit', product_type: 3 }))],
  ] as const) {
    const a = assessPatch(os, real, NOW)
    console.log(`  ${label}: ${a.status} | ${a.product} | missing ${a.missing.length} months, ${a.cves} CVEs (${a.critical} critical, ${a.exploited} exploited) | latest ${a.latest?.fixed_build} ${a.latest?.kb ?? ''}`)
  }
}

console.log(`\n${pass} passed, ${fail} failed`)
if (fail) process.exit(1)
