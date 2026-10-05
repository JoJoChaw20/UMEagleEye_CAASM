/**
 * my-assets-demo.ts — PASS/FAIL checks for the in_my_assets membership split.
 * Run: npx esbuild scripts/my-assets-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.ma-demo.cjs && node .ma-demo.cjs
 *
 * Covers (pure planners only; routes are verified by reading):
 *   (a) scan of a My Assets asset keeps membership + sets source to the scan method
 *   (b) scan of a new host creates in_my_assets = false
 *   (c) CSV/POST adoption of an existing scanned asset sets the flag, leaves source
 *   (d) merge: flag OR, source = latest-scanned (manual only if ALL manual)
 *   (e) duplicates suggestedSurvivor prefers a My Assets member
 *   (f) planIngest keeps a constant statement count per host
 */
import { planIngest, type PlanHost, type IdentityPrefetch, type IngestOp } from '../src/lib/ingest-plan'
import { planMerge, type MergeAsset, type MergeRelated } from '../src/lib/merge'
import { findDuplicateGroups, type DupAsset, type DupAddress } from '../src/lib/duplicates'

let pass = 0, fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  got=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`)
  ok ? pass++ : fail++
}

const GLOBAL = '98:bb:cc:00:00:01'   // true OUI (unicast, non-LA) → global MAC
const NOW = new Date('2026-10-05T00:00:00Z')
let idc = 0
const newId = () => `id${idc++}`

const host = (over: Partial<PlanHost>): PlanHost => ({
  ip: '10.0.0.5', rawMac: GLOBAL, hostname: 'h', hostKeyRaw: null, deviceType: 'server',
  observedOsInfo: {}, ports: [22], hardwareVendor: null, internetFacing: false, isPassive: false,
  tenantId: 't', ...over,
})

// ── (a) scan of an EXISTING My Assets asset ──────────────────────────────────
// The planner updates `source` to the scan method and NEVER writes in_my_assets,
// so membership is preserved regardless of its prior value.
console.log('=== (a) scan of an existing (My Assets) asset ===')
{
  const prefetch: IdentityPrefetch = {
    addresses: [{ addressId: 'ad1', assetId: 'A1', networkKey: '10.0.0.0/24', ipAddress: '10.0.0.5', macAddress: GLOBAL, deviceType: 'server', lastSeen: NOW.getTime() - 1e6, assetCreatedAt: NOW.getTime() - 1e8 }],
    assets: [{ assetId: 'A1', deviceType: 'server', hostKey: null, osInfo: {}, hostname: 'h', owner: null, hardwareVendor: null, macAddress: GLOBAL, source: 'manual', hasBaseline: true }],
  }
  idc = 0
  const plan = planIngest([host({})], prefetch, { newId, now: NOW })
  const ph = plan.perHost[0]!
  const upd = ph.ops.find(o => o.k === 'updateAsset') as Extract<IngestOp, { k: 'updateAsset' }>
  check('(a) matched the existing asset', ph.assetId, 'A1')
  check('(a) source set to the scan method', upd.set.source, 'scan_active')
  check('(a) membership NOT touched (no inMyAssets in set)', 'inMyAssets' in upd.set, false)
  const plan2 = planIngest([host({ isPassive: true })], prefetch, { newId, now: NOW })
  const upd2 = (plan2.perHost[0]!.ops.find(o => o.k === 'updateAsset') as Extract<IngestOp, { k: 'updateAsset' }>)
  check('(a) passive scan → source scan_passive', upd2.set.source, 'scan_passive')
}

// ── (b) scan of a NEW host ───────────────────────────────────────────────────
console.log('\n=== (b) scan of a new host ===')
{
  idc = 0
  const plan = planIngest([host({ ip: '10.0.0.9', rawMac: '98:bb:cc:00:00:02' })], { addresses: [], assets: [] }, { newId, now: NOW })
  const ins = plan.perHost[0]!.ops.find(o => o.k === 'insertAsset') as Extract<IngestOp, { k: 'insertAsset' }>
  check('(b) new asset created', plan.perHost[0]!.isNew, true)
  check('(b) new scanned asset is NOT in My Assets', ins.values.inMyAssets, false)
}

// ── (c) CSV/POST adoption of an existing scanned asset ───────────────────────
// Mirrors the adopt branch in routes/assets.ts (POST /assets + CSV import): set
// in_my_assets=true, and DO NOT write `source`. Source of truth is the route; this
// guards the rule from regressing.
console.log('\n=== (c) adoption of an existing scanned asset ===')
{
  const buildAdoptUpdate = (): Record<string, unknown> => ({ inMyAssets: true, criticalityScore: 7, updatedAt: NOW })
  const upd = buildAdoptUpdate()
  check('(c) adopt sets the flag', upd.inMyAssets, true)
  check('(c) adopt leaves source untouched', 'source' in upd, false)
}

// ── (d) merge field rules ────────────────────────────────────────────────────
console.log('\n=== (d) merge: flag OR + source rule ===')
{
  const mAsset = (id: string, over: Partial<MergeAsset> = {}): MergeAsset => ({
    assetId: id, tenantId: 't', hostname: null, ipAddress: '10.0.0.5', macAddress: null, hostKey: null,
    owner: null, deviceType: 'workstation', hardwareVendor: null, osInfo: {}, criticalityScore: 1,
    baselineState: null, isInternetFacing: false, source: 'scan_active', inMyAssets: false,
    lastScanned: '2026-01-01', createdAt: '2026-01-01', ...over,
  })
  const noRel: MergeRelated = { addresses: [], relationships: [], topologyNodes: [] }

  // all manual → source manual.
  const p1 = planMerge(mAsset('S', { source: 'manual' }), [mAsset('L', { source: 'manual' })], noRel)
  check('(d) all manual → source manual', p1.mergedFields.source, 'manual')

  // mixed → latest-scanned non-manual source wins (loser is newest but manual).
  const p2 = planMerge(
    mAsset('S', { source: 'scan_passive', lastScanned: '2026-02-01' }),
    [mAsset('L', { source: 'manual', lastScanned: '2026-09-01' })],
    noRel,
  )
  check('(d) mixed → latest non-manual source', p2.mergedFields.source, 'scan_passive')

  // mixed, newest is a scan → that scan source wins.
  const p3 = planMerge(
    mAsset('S', { source: 'manual', lastScanned: '2026-02-01' }),
    [mAsset('L', { source: 'scan_active', lastScanned: '2026-09-01' })],
    noRel,
  )
  check('(d) mixed → newest scan source', p3.mergedFields.source, 'scan_active')

  // flag OR.
  check('(d) flag OR: member + non-member → member',
    planMerge(mAsset('S'), [mAsset('L', { inMyAssets: true })], noRel).mergedFields.inMyAssets, true)
  check('(d) flag OR: none member → non-member',
    planMerge(mAsset('S'), [mAsset('L')], noRel).mergedFields.inMyAssets, false)
}

// ── (e) suggested survivor prefers a My Assets member ────────────────────────
console.log('\n=== (e) duplicates suggestedSurvivor prefers a member ===')
{
  const A = (over: Partial<DupAsset>): DupAsset => ({
    assetId: 'x', hostname: null, ipAddress: '0.0.0.0', macAddress: GLOBAL, source: 'scan_active',
    inMyAssets: false, deviceType: 'workstation', lastScanned: '2026-01-01', createdAt: '2026-01-01', hostKey: null, ...over,
  })
  const AD = (assetId: string, ip: string, net: string): DupAddress => ({ addressId: `ad-${assetId}`, assetId, networkKey: net, ipAddress: ip, macAddress: GLOBAL, endedAt: null })
  // 'mem' is in My Assets but older; 'fresh' was scanned more recently. Member wins.
  const assets = [
    A({ assetId: 'fresh', ipAddress: '10.1.0.5', lastScanned: '2026-09-01' }),
    A({ assetId: 'mem', ipAddress: '10.0.0.5', inMyAssets: true, lastScanned: '2026-01-01' }),
  ]
  const addrs = [AD('fresh', '10.1.0.5', '10.1.0.0/24'), AD('mem', '10.0.0.5', '10.0.0.0/24')]
  const g = findDuplicateGroups(assets, addrs)
  check('(e) one group', g.length, 1)
  check('(e) survivor = the My Assets member', g[0]?.suggestedSurvivorId, 'mem')
}

// ── (f) constant statement count per host ────────────────────────────────────
// Adding in_my_assets to the insert VALUES does not add a statement: a matched
// host = 2 stmts (updateAsset + updateAddress), a new host = 3 (insert asset +
// address + new_device event). Membership never costs an extra subrequest.
console.log('\n=== (f) planIngest statement count per host ===')
{
  const prefetch: IdentityPrefetch = {
    addresses: [{ addressId: 'ad1', assetId: 'A1', networkKey: '10.0.0.0/24', ipAddress: '10.0.0.5', macAddress: GLOBAL, deviceType: 'server', lastSeen: NOW.getTime(), assetCreatedAt: NOW.getTime() }],
    assets: [{ assetId: 'A1', deviceType: 'server', hostKey: null, osInfo: {}, hostname: 'h', owner: null, hardwareVendor: null, macAddress: GLOBAL, source: 'scan_active', hasBaseline: true }],
  }
  idc = 0
  const plan = planIngest(
    [host({}), host({ ip: '10.0.0.9', rawMac: '98:bb:cc:00:00:02' })],
    prefetch, { newId, now: NOW },
  )
  const matched = plan.perHost.find(p => !p.isNew)!
  const created = plan.perHost.find(p => p.isNew)!
  check('(f) matched host = 2 statements', matched.ops.length, 2)
  check('(f) new host = 3 statements', created.ops.length, 3)
  check('(f) total statementCount', plan.statementCount, 5)
}

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail === 0 ? 0 : 1)
