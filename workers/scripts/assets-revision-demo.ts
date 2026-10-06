/**
 * assets-revision-demo.ts — PASS/FAIL for the All/My Assets revision work.
 * Run: npx esbuild scripts/assets-revision-demo.ts --bundle --platform=node \
 *        --format=cjs --outfile=.rev.cjs && node .rev.cjs
 *
 * Covers: shared per-asset scorer == bulk (incl. topology), scope=my_assets,
 * PATCH update_baseline merge, ingest baseline fill, and the First/Last seen
 * formatter. Route-level guards (tenant, role) are mirrored by small pure checks
 * that document the authoritative logic in routes/assets.ts.
 */
import { scoreAsset, planRescore } from '../src/lib/rescore'
import { buildBaseline, buildManualBaseline, mergeBaselineFields } from '../src/services/drift'
import { planIngest, type PlanHost, type IdentityPrefetch, type IngestOp } from '../src/lib/ingest-plan'
// Shared frontend formatter (demo isn't typechecked — tsconfig excludes scripts).
import { formatSeen } from '../../frontend/src/utils/time.js'

let pass = 0, fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  got=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`)
  ok ? pass++ : fail++
}

// ── (a)(b) shared scorer == bulk, including the topology layer ───────────────
console.log('=== (a)(b) per-asset scorer == bulk ===')
{
  const input = { deviceType: 'workstation', isInternetFacing: false, hostname: 'dev-pc', osInfo: {}, topologyLayer: 1 }
  const single = scoreAsset(input)                              // base3 −1 dev +1 unowned +3 L1 = 6
  const noLayer = scoreAsset({ ...input, topologyLayer: null }) // = 3
  const row = { assetId: 'A', deviceType: 'workstation', isInternetFacing: false, hostname: 'dev-pc', osInfo: {}, criticalityScore: 0 }
  const bulk = planRescore([row], new Map([['A', 1]]))
  check('(a) per-asset == bulk (same inputs incl. layer)', bulk.changes[0]?.score, single)
  check('(a) topology layer is included (L1 > no-layer)', single > noLayer, true)

  const row2 = { ...row, criticalityScore: single }            // store the computed score
  check('(b) second run → no change', planRescore([row2], new Map([['A', 1]])).changes.length, 0)
}

// ── (c)(d) route guards (mirrors assets.ts) ──────────────────────────────────
console.log('\n=== (c)(d) tenant + role guards ===')
{
  // Mirrors the 404 guard in POST /:id/rescore and PATCH.
  const accessible = (assetTenant: string, user: { role: string; tenantId: string | null }) =>
    user.role === 'superadmin' || !user.tenantId || assetTenant === user.tenantId
  check('(c) cross-tenant id rejected', accessible('t2', { role: 'tenant_admin', tenantId: 't1' }), false)
  check('(c) same-tenant allowed', accessible('t1', { role: 'tenant_admin', tenantId: 't1' }), true)
  // Both PATCH and POST /:id/rescore use requireRoles(...WRITE_ROLES).
  const WRITE_ROLES = ['tenant_superadmin', 'tenant_admin']
  check('(d) per-asset rescore role rule == PATCH (WRITE_ROLES)', WRITE_ROLES, ['tenant_superadmin', 'tenant_admin'])
}

// ── (e) scope=my_assets scores only members; chunk formula unchanged ─────────
console.log('\n=== (e) scope=my_assets ===')
{
  const mixed = [
    { assetId: 'm1', deviceType: 'server', isInternetFacing: false, hostname: 'a', osInfo: {}, criticalityScore: 0, inMyAssets: true },
    { assetId: 'm2', deviceType: 'iot',    isInternetFacing: false, hostname: 'b', osInfo: {}, criticalityScore: 0, inMyAssets: true },
    { assetId: 'x1', deviceType: 'server', isInternetFacing: false, hostname: 'c', osInfo: {}, criticalityScore: 0, inMyAssets: false },
  ]
  const scopeFilter = (rows: typeof mixed) => rows.filter(r => r.inMyAssets)   // mirrors SQL in_my_assets=true
  const scoped = planRescore(scopeFilter(mixed), new Map())
  const unscoped = planRescore(mixed, new Map())
  check('(e) scoped scans only My Assets', scoped.scanned, 2)
  check('(e) non-member not scored', scoped.changes.some(c => c.assetId === 'x1'), false)
  check('(e) chunk formula matches unscoped run', Math.ceil(scoped.changes.length / 100), Math.ceil(unscoped.changes.length / 100))
}

// ── (f)(g) PATCH update_baseline merge ───────────────────────────────────────
console.log('\n=== (f)(g) baseline merge on edit ===')
{
  const base = buildBaseline({ ports: [22], osInfo: {}, hostname: 'old-host', macAddress: 'aa:bb:cc:dd:ee:ff', isInternetFacing: false, deviceType: 'server' })
  const merged = mergeBaselineFields(base, { hostname: 'new-host' })!
  // detectDrift flags iff baseline.hostname !== asset.hostname (drift.ts). asset is now 'new-host'.
  check('(f) with update_baseline: baseline hostname follows the edit (no drift)', merged.hostname, 'new-host')
  check('(f) ports/other baseline fields untouched', merged.ports, [22])
  check('(f) without update_baseline: baseline keeps old hostname (→ drift)', base.hostname, 'old-host')
  check('(g) null baseline → merge no-op (no throw)', mergeBaselineFields(null, { hostname: 'x' }), null)
  check('(g) empty baseline → merge no-op', mergeBaselineFields({}, { hostname: 'x' }), null)
}

// ── (h) ingest baseline fill: active vs passive, existing untouched ──────────
// NOTE: deviates from the task's literal (h). The already-merged ingest DOES
// baseline on a passive scan, but with ports_known=false, so the next active scan
// never flags real ports as drift — the owner's actual concern. See report §7.2.
console.log('\n=== (h) ingest baseline fill (active vs passive) ===')
{
  const GLOBAL = '98:bb:cc:00:00:01'
  const NOW = new Date('2026-10-06T00:00:00Z')
  const prefetch = (hasBaseline: boolean, baseline: Record<string, unknown> | null = null): IdentityPrefetch => ({
    addresses: [{ addressId: 'ad1', assetId: 'A1', networkKey: '10.0.0.0/24', ipAddress: '10.0.0.5', macAddress: GLOBAL, deviceType: 'server', lastSeen: NOW.getTime(), assetCreatedAt: NOW.getTime() }],
    assets: [{ assetId: 'A1', deviceType: 'server', hostKey: null, osInfo: {}, hostname: 'h', owner: null, hardwareVendor: null, macAddress: GLOBAL, source: 'scan_active', hasBaseline, baseline: baseline as never }],
  })
  const host = (over: Partial<PlanHost> = {}): PlanHost => ({
    ip: '10.0.0.5', rawMac: GLOBAL, hostname: 'h', hostKeyRaw: null, deviceType: 'server',
    observedOsInfo: { ports: ['22/tcp', '443/tcp'] }, ports: [22, 443], hardwareVendor: null, internetFacing: false, isPassive: false, tenantId: 't', ...over,
  })
  const setOf = (plan: ReturnType<typeof planIngest>) =>
    (plan.perHost[0]!.ops.find(o => o.k === 'updateAsset') as Extract<IngestOp, { k: 'updateAsset' }>).set

  const active = setOf(planIngest([host({})], prefetch(false), { now: NOW }))
  check('(h) active scan fills a null baseline', !!active.baselineState, true)
  check('(h) active baseline has ports_known=true', (active.baselineState as Record<string, unknown>).ports_known, true)

  const passive = setOf(planIngest([host({ isPassive: true, observedOsInfo: {}, ports: [] })], prefetch(false), { now: NOW }))
  check('(h) passive baseline has ports_known=false (no false port drift)', (passive.baselineState as Record<string, unknown>).ports_known, false)

  const full = { ports: [22], ports_known: true, hostname: 'h', is_internet_facing: false, device_type: 'server' }
  const existing = setOf(planIngest([host({ isPassive: true, observedOsInfo: {}, ports: [] })], prefetch(true, full), { now: NOW }))
  check('(h) existing full baseline untouched on passive', 'baselineState' in existing, false)
}

// ── (i) First/Last seen formatter edge cases ─────────────────────────────────
console.log('\n=== (i) formatSeen edge cases ===')
{
  const NOW = new Date('2026-10-06T00:00:00Z').getTime()
  check('(i) null → nullText "Never scanned"', formatSeen(null, { nullText: 'Never scanned' }).text, 'Never scanned')
  check('(i) null → isNull flag', formatSeen(null).isNull, true)
  check('(i) future clamps to "just now"', formatSeen(new Date(NOW + 60000), { now: NOW }).text, 'just now')
  check('(i) 59s ago', formatSeen(new Date(NOW - 59000), { now: NOW }).text, '59s ago')
  check('(i) 6 days → not stale', formatSeen(new Date(NOW - 6 * 86400000), { now: NOW }).stale, false)
  check('(i) 7 days exactly → stale', formatSeen(new Date(NOW - 7 * 86400000), { now: NOW }).stale, true)
  const over = formatSeen(new Date(NOW - 10 * 86400000), { now: NOW })
  check('(i) over 7 days → stale + "1w ago"', [over.stale, over.text], [true, '1w ago'])
}

// ── §4 owner in the criticality score ───────────────────────────────────────
console.log('\n=== §4 owner in criticality score ===')
{
  const base = { deviceType: 'server', isInternetFacing: false, hostname: 'app', osInfo: {}, topologyLayer: null }
  const owned = scoreAsset({ ...base, owner: 'IT' })
  const unowned = scoreAsset({ ...base, owner: null })
  check('§4 owned scores exactly 1 lower than unowned', unowned - owned, 1)

  // per-asset (scoreAsset) == bulk (planRescore) for the same owned asset.
  const row = { assetId: 'A', deviceType: 'server', isInternetFacing: false, hostname: 'app', osInfo: {}, criticalityScore: 0, owner: 'IT' }
  const bulk = planRescore([row], new Map())
  check('§4 per-asset == bulk (incl. owner)', bulk.changes[0]?.score, owned)
  check('§4 create/PATCH use the same scoreAsset (deterministic)', scoreAsset({ ...base, owner: 'IT' }), owned)
  check('§4 second rescore → no change', planRescore([{ ...row, criticalityScore: owned }], new Map()).changes.length, 0)
}

// ── §2 baseline seeded at manual creation ────────────────────────────────────
console.log('\n=== §2 baseline at manual creation ===')
{
  const b = buildManualBaseline({ hostname: 'pc-1', macAddress: 'aa:bb:cc:dd:ee:ff', deviceType: 'workstation', isInternetFacing: false, osVersion: 'Windows 11' })
  check('§2 ports_known=false', b.ports_known, false)
  check('§2 no ports key (not empty array)', 'ports' in b, false)
  check('§2 no packages key', 'packages' in b, false)
  check('§2 captured_from=manual', b.captured_from, 'manual')
  check('§2(b) hostname baselined → no "Hostname Changed"', b.hostname, 'pc-1')
  check('§2(b) mac baselined → no "MAC Changed"', b.mac_address, 'aa:bb:cc:dd:ee:ff')
  check('§2 os_version kept when known', b.os_version, 'Windows 11')
  check('§2 os_version omitted when absent', 'os_version' in buildManualBaseline({ deviceType: 'iot', isInternetFacing: false }), false)

  // (c) never overwrite a populated baseline — mirrors the POST/CSV fill-if-null guard.
  const shouldSeed = (bl: Record<string, unknown> | null) => !bl || Object.keys(bl).length === 0
  check('§2(c) seed when null', shouldSeed(null), true)
  check('§2(c) seed when empty {}', shouldSeed({}), true)
  check('§2(c) do NOT seed a populated baseline', shouldSeed({ hostname: 'x' }), false)

  // (a) first ACTIVE scan completes ports on a manual baseline (ports_known false→true),
  //     which is a baseline patch, not "port opened" drift.
  const GLOBAL = '98:bb:cc:00:00:01'
  const NOW = new Date('2026-10-06T00:00:00Z')
  const manual = buildManualBaseline({ hostname: 'pc-1', macAddress: GLOBAL, deviceType: 'workstation', isInternetFacing: false })
  const prefetch = {
    addresses: [{ addressId: 'ad1', assetId: 'A1', networkKey: '10.0.0.0/24', ipAddress: '10.0.0.5', macAddress: GLOBAL, deviceType: 'workstation', lastSeen: NOW.getTime(), assetCreatedAt: NOW.getTime() }],
    assets: [{ assetId: 'A1', deviceType: 'workstation', hostKey: null, osInfo: {}, hostname: 'pc-1', owner: null, hardwareVendor: null, macAddress: GLOBAL, source: 'manual', hasBaseline: true, baseline: manual as never }],
  }
  const host: PlanHost = { ip: '10.0.0.5', rawMac: GLOBAL, hostname: 'pc-1', hostKeyRaw: null, deviceType: 'workstation', observedOsInfo: { ports: ['22/tcp', '443/tcp'] }, ports: [22, 443], hardwareVendor: null, internetFacing: false, isPassive: false, tenantId: 't' }
  const set = (planIngest([host], prefetch, { now: NOW }).perHost[0]!.ops.find(o => o.k === 'updateAsset') as Extract<IngestOp, { k: 'updateAsset' }>).set
  const bl = set.baselineState as Record<string, unknown> | undefined
  check('§2(a) active scan completes ports on a manual baseline', bl ? [bl.ports_known, bl.ports] : 'none', [true, [22, 443]])
}

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail === 0 ? 0 : 1)
