/**
 * packages-known-demo.ts — PASS/FAIL for the packages_known baseline work.
 * Run: npx esbuild scripts/packages-known-demo.ts --bundle --platform=node \
 *        --format=cjs --outfile=.pk.cjs && node .pk.cjs
 *
 * Mirrors ports_known: a baseline captured before any SBOM has unknown packages,
 * the first real SBOM completes it (same atomic jsonb ||-merge the ingest batches
 * with the scan-complete write), and the drift audit skips the package comparison
 * while the baseline packages are unknown or there is no current package data — so
 * the first SBOM never looks like every package is new/removed.
 */
import {
  buildBaseline, buildManualBaseline, baselinePackagesKnown,
  buildPackageMap, planPackageBaselineCompletion, detectDrift,
} from '../src/services/drift'

let pass = 0, fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  got=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`)
  ok ? pass++ : fail++
}

// Minimal asset row for detectDrift (demo isn't typechecked — tsconfig excludes scripts).
const asset = (osInfo: Record<string, unknown>, over: Record<string, unknown> = {}): any =>
  ({ assetId: 'A', hostname: 'h', macAddress: null, isInternetFacing: false, deviceType: 'server', osInfo, ...over })
// Only the package-related drift findings.
const pkgDrifts = (baseline: any, osInfo: Record<string, unknown>) =>
  detectDrift(baseline, asset(osInfo)).filter(d =>
    d.type === 'new_package' || d.type === 'removed_package' ||
    (d.details as any)?.changed_attribute === 'package_version')
// Shallow merge == the top-level jsonb `||` semantics used by the SBOM ingest.
const applyPatch = (bl: any, patch: any) => ({ ...bl, ...patch })

const comps = [{ name: 'nginx', version: '1.24.0' }, { name: 'openssl', version: '3.0.2' }]
const pkgMap = buildPackageMap(comps)

// ── (a) manual asset (no packages key): first SBOM completes it, zero drift ──
console.log('=== (a) manual baseline → first SBOM completes packages ===')
{
  const manual = buildManualBaseline({ hostname: 'h', deviceType: 'server', isInternetFacing: false })
  check('(a) packages unknown before SBOM', baselinePackagesKnown(manual), false)
  const patch = planPackageBaselineCompletion(manual, pkgMap)
  check('(a) first SBOM yields a completion patch', patch !== null, true)
  check('(a) patch.packages_known=true', patch?.packages_known, true)
  check('(a) patch.packages == ingested map', patch?.packages, pkgMap)
  const completed = applyPatch(manual, patch)
  check('(a) completed baseline now known', baselinePackagesKnown(completed), true)
  check('(a) audit: zero new_package (current matches completed baseline)', pkgDrifts(completed, { packages: pkgMap }).length, 0)
  check('(a) audit: zero new_package (os_info carries no packages)', pkgDrifts(completed, {}).length, 0)
}

// ── (b) scan-created legacy baseline with packages:{} → same ─────────────────
console.log('\n=== (b) legacy packages:{} baseline → completed by first SBOM ===')
{
  const legacy: any = { ports: [22], packages: {}, hostname: 'h', is_internet_facing: false, device_type: 'server' } // no packages_known
  check('(b) legacy empty map counts as unknown', baselinePackagesKnown(legacy), false)
  check('(b) audit: unknown legacy baseline → zero package drift even with current pkgs', pkgDrifts(legacy, { packages: pkgMap }).length, 0)
  const patch = planPackageBaselineCompletion(legacy, pkgMap)
  check('(b) first SBOM completes it', patch?.packages_known, true)
  check('(b) audit: zero drift after completion', pkgDrifts(applyPatch(legacy, patch), { packages: pkgMap }).length, 0)
}

// ── (c) baseline already known: add / remove / version bump all raise drift ──
console.log('\n=== (c) known baseline raises real package drift ===')
{
  const known: any = { packages: { nginx: '1.24.0', openssl: '3.0.2' }, packages_known: true, hostname: 'h', is_internet_facing: false, device_type: 'server' }
  check('(c) added package → new_package', pkgDrifts(known, { packages: { nginx: '1.24.0', openssl: '3.0.2', curl: '8.0.0' } }).map(d => [d.type, (d.details as any).package]), [['new_package', 'curl']])
  check('(c) removed package → removed_package', pkgDrifts(known, { packages: { nginx: '1.24.0' } }).map(d => [d.type, (d.details as any).package]), [['removed_package', 'openssl']])
  check('(c) version bump → version_upgrade', pkgDrifts(known, { packages: { nginx: '1.25.0', openssl: '3.0.2' } }).map(d => [d.type, (d.details as any).package]), [['version_upgrade', 'nginx']])
  check('(c) version drop → version_downgrade', pkgDrifts(known, { packages: { nginx: '1.23.0', openssl: '3.0.2' } }).map(d => d.type), ['version_downgrade'])
}

// ── (d) second identical SBOM changes nothing ────────────────────────────────
console.log('\n=== (d) second identical SBOM is a no-op ===')
{
  const completed: any = applyPatch(buildManualBaseline({ hostname: 'h', deviceType: 'server', isInternetFacing: false }), planPackageBaselineCompletion(buildManualBaseline({ hostname: 'h', deviceType: 'server', isInternetFacing: false }), pkgMap))
  check('(d) no completion patch when already known', planPackageBaselineCompletion(completed, pkgMap), null)
  check('(d) identical current packages → zero drift', pkgDrifts(completed, { packages: pkgMap }).length, 0)
}

// ── (e) unknown baseline + empty SBOM result stays unknown ───────────────────
console.log('\n=== (e) empty SBOM result never marks known ===')
{
  const manual = buildManualBaseline({ hostname: 'h', deviceType: 'server', isInternetFacing: false })
  check('(e) buildPackageMap([]) is empty', Object.keys(buildPackageMap([])).length, 0)
  check('(e) empty SBOM → no completion (stays unknown)', planPackageBaselineCompletion(manual, buildPackageMap([])), null)
  check('(e) non-array components → empty map', Object.keys(buildPackageMap(undefined)).length, 0)
}

// ── (f) detectDrift skips packages while unknown, even with current packages ─
console.log('\n=== (f) unknown baseline suppresses the comparison ===')
{
  const manual = buildManualBaseline({ hostname: 'h', deviceType: 'server', isInternetFacing: false })
  check('(f) unknown baseline + current packages present → zero package drift', pkgDrifts(manual, { packages: { nginx: '1.0.0', foo: '2.0.0' } }).length, 0)
  const scanBaseline = buildBaseline({ ports: [22], osInfo: { ports: ['22/tcp'] }, hostname: 'h', macAddress: null, isInternetFacing: false, deviceType: 'server' })
  check('(f) scan baseline (no SBOM) is unknown → zero package drift', [baselinePackagesKnown(scanBaseline), pkgDrifts(scanBaseline, { packages: { a: '1' } }).length], [false, 0])
}

// ── (g) Set Baseline (buildBaseline) packages_known reflects SBOM presence ───
console.log('\n=== (g) Set Baseline reflects whether package data exists ===')
{
  const noSbom = buildBaseline({ ports: [80], osInfo: { ports: ['80/tcp'] }, hostname: 'h', macAddress: null, isInternetFacing: false, deviceType: 'server' })
  check('(g) no package data → packages_known false', noSbom.packages_known, false)
  check('(g) no package data → no packages key', 'packages' in noSbom, false)
  const withSbom = buildBaseline({ ports: [80], osInfo: { ports: ['80/tcp'], packages: { nginx: '1.24.0' } }, hostname: 'h', macAddress: null, isInternetFacing: false, deviceType: 'server' })
  check('(g) with package data → packages_known true', withSbom.packages_known, true)
  check('(g) with package data → packages captured', withSbom.packages, { nginx: '1.24.0' })
}

// ── (h)(i) completion is a single partial ||-merge; other keys untouched ─────
console.log('\n=== (h)(i) partial, atomic completion patch ===')
{
  const rich: any = { ports: [22, 443], ports_known: true, hostname: 'web', mac_address: 'aa:bb:cc:dd:ee:ff', os_version: '22.04', device_type: 'server', is_internet_facing: false }
  const patch = planPackageBaselineCompletion(rich, pkgMap)!
  check('(h) patch touches ONLY packages & packages_known', Object.keys(patch).sort(), ['packages', 'packages_known'])
  const after = applyPatch(rich, patch)
  check('(h) ports untouched', after.ports, [22, 443])
  check('(h) hostname untouched', after.hostname, 'web')
  check('(h) mac untouched', after.mac_address, 'aa:bb:cc:dd:ee:ff')
  check('(h) os_version untouched', after.os_version, '22.04')
  // (i) one JSON-serializable object → one `baseline_state || $1::jsonb` statement,
  //     batched with the scan-complete UPDATE in sbom.ts (one db.batch = one subrequest).
  check('(i) patch is a single JSON-serializable object', typeof JSON.stringify(patch), 'string')
  check('(i) ||-merge installs the ingested package map', after.packages, pkgMap)
}

// ── (j) null-baseline asset: no completion, no throw ─────────────────────────
console.log('\n=== (j) null baseline is left alone (audit skips it) ===')
{
  check('(j) null baseline → no completion patch', planPackageBaselineCompletion(null, pkgMap), null)
  check('(j) undefined baseline → no completion patch, no throw', planPackageBaselineCompletion(undefined, pkgMap), null)
}

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail === 0 ? 0 : 1)
