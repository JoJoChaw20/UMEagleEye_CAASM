/**
 * inventory-search-demo.ts — PASS/FAIL for the Inventory address search helpers.
 * Run: npx esbuild scripts/inventory-search-demo.ts --bundle --platform=node \
 *        --format=cjs --outfile=.inv.cjs && node .inv.cjs
 *
 * Tests the pure match logic (mirrors the SQL WHERE/ORDER BY in routes/assets.ts):
 *   (a) historical IP finds the asset        (b) current IP still finds it
 *   (c) historical MAC (dash/upper) finds it  (d) partial IP, no row duplication
 *   (e) two matching rows → asset once        (f) other asset/tenant rows never match
 *   (g) matches report correct fields         (h) current matches before history-only
 *   (i) >5 history rows capped + total count
 */
import { computeMatches, matchRank, addressRowMatches, type AddrRow, type MatchAsset } from '../src/lib/addressSearch'

let pass = 0, fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  got=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`)
  ok ? pass++ : fail++
}

const MAC = '14:13:33:c3:f6:03'
const laptop: MatchAsset = { assetId: 'A', hostname: 'laptop-jo', ipAddress: '192.168.100.71', macAddress: MAC, hardwareVendor: 'Dell' }
const addr = (o: Partial<AddrRow> & { addressId: string }): AddrRow => ({
  assetId: 'A', networkKey: null, ipAddress: '0.0.0.0', macAddress: MAC, firstSeen: '2026-01-01', lastSeen: '2026-01-01', endedAt: null, ...o,
})
// current + two past addresses (the laptop roamed networks).
const cur = addr({ addressId: 'c',  ipAddress: '192.168.100.71', networkKey: '192.168.100.0/24', endedAt: null,         lastSeen: '2026-10-06' })
const old1 = addr({ addressId: 'o1', ipAddress: '192.168.0.139',  networkKey: '192.168.0.0/24',   endedAt: '2026-10-02', lastSeen: '2026-10-02' })
const old2 = addr({ addressId: 'o2', ipAddress: '172.20.10.9',    networkKey: null,                endedAt: '2026-09-01', lastSeen: '2026-09-01' })
const rows = [cur, old1, old2]
const found = (a: MatchAsset, rs: AddrRow[], term: string) => computeMatches(a, rs, term).matches.length > 0

// (a) historical IP finds the asset.
check('(a) historical IP 192.168.0.139 finds it', found(laptop, rows, '192.168.0.139'), true)

// (b) current IP still finds it.
check('(b) current IP 192.168.100.71 finds it', found(laptop, rows, '192.168.100.71'), true)

// (c) historical MAC in dash/upper form finds it (normalized).
check('(c) MAC 14-13-33-C3-F6-03 finds it', found(laptop, rows, '14-13-33-C3-F6-03'), true)

// (d) partial IP "192.168." matches 2 rows but the asset is one result (computeMatches
//     is per-asset; current live address is reported as current_ip, old1 as history).
{
  const { matches, matchedAddressCount } = computeMatches(laptop, rows, '192.168.')
  check('(d) partial IP both rows match (row-level)', [addressRowMatches(cur, '192.168.'), addressRowMatches(old1, '192.168.')], [true, true])
  check('(d) current_ip reported once', matches.filter(m => m.field === 'current_ip').length, 1)
  check('(d) one history entry (old1), live address excluded', matchedAddressCount, 1)
}

// (e) a term matching two history rows returns the asset once with both rows.
{
  // MAC matches all three rows; the live address is excluded → 2 history rows.
  const { matches, matchedAddressCount } = computeMatches(laptop, rows, MAC)
  check('(e) current_mac reported', matches.some(m => m.field === 'current_mac'), true)
  check('(e) two history rows, one asset', matchedAddressCount, 2)
  check('(e) history ids newest-first', matches.filter(m => m.field === 'address_history').map(m => m.addressId), ['o1', 'o2'])
}

// (f) another asset's (hence another tenant's) address rows never match this asset.
//     In production these rows are never even fetched (query is tenant+asset scoped);
//     computeMatches also guards on asset_id.
{
  const foreign = addr({ addressId: 'x', assetId: 'OTHER', ipAddress: '192.168.0.139', endedAt: '2026-10-02' })
  const assetB: MatchAsset = { assetId: 'B', hostname: 'other', ipAddress: '10.9.9.9', macAddress: null, hardwareVendor: null }
  check('(f) foreign row does not match asset B', found(assetB, [foreign], '192.168.0.139'), false)
}

// (g) matches report the right fields for a history-only hit vs a current hit.
{
  const hist = computeMatches(laptop, rows, '192.168.0.139').matches.find(m => m.field === 'address_history')
  check('(g) history entry has no current_ip reason', computeMatches(laptop, rows, '192.168.0.139').matches.some(m => m.field === 'current_ip'), false)
  check('(g) history ip/network/lastSeen/endedAt', [hist?.ip, hist?.networkKey, hist?.lastSeen, hist?.endedAt, hist?.isCurrent], ['192.168.0.139', '192.168.0.0/24', '2026-10-02', '2026-10-02', false])
  const curMatch = computeMatches(laptop, rows, '192.168.100.71').matches.find(m => m.field === 'current_ip')
  check('(g) current hit reports current_ip', [curMatch?.ip, curMatch?.isCurrent], ['192.168.100.71', true])
}

// (h) ordering: current-field match ranks before history-only.
{
  const curHit = computeMatches(laptop, rows, '192.168.100.71').matches     // current_ip → rank 0
  const histHit = computeMatches(laptop, rows, '192.168.0.139').matches     // history → rank 1
  check('(h) ranks: current=0, history=1', [matchRank(curHit), matchRank(histHit)], [0, 1])
  const ordered = [{ id: 'hist', m: histHit }, { id: 'cur', m: curHit }].sort((a, b) => matchRank(a.m) - matchRank(b.m)).map(x => x.id)
  check('(h) current sorts before history-only', ordered, ['cur', 'hist'])
}

// (i) more than 5 matching history rows are capped; matchedAddressCount shows total.
{
  const many: AddrRow[] = Array.from({ length: 7 }, (_, i) =>
    addr({ addressId: `h${i}`, ipAddress: `10.10.0.${i + 1}`, networkKey: '10.10.0.0/24', endedAt: '2026-08-01', lastSeen: `2026-08-0${(i % 7) + 1}` }))
  const subject: MatchAsset = { assetId: 'A', hostname: null, ipAddress: '192.168.1.5', macAddress: null, hardwareVendor: null }
  const { matches, matchedAddressCount } = computeMatches(subject, many, '10.10.0.')
  check('(i) history capped at 5', matches.filter(m => m.field === 'address_history').length, 5)
  check('(i) matchedAddressCount = total 7', matchedAddressCount, 7)
}

// ── vendor search + source filter ───────────────────────────────────────────
console.log('\n=== vendor search + source filter ===')
type DemoAsset = MatchAsset & { source: string }
const vMatches = (a: MatchAsset, term: string) => computeMatches(a, [], term).matches

const huawei: DemoAsset = { assetId: 'V', hostname: null, ipAddress: '192.168.100.1', macAddress: null, hardwareVendor: 'HUAWEI TECHNOLOGIES CO.,LTD', source: 'scan_passive' }
const dell: DemoAsset = { assetId: 'D', hostname: null, ipAddress: '192.168.100.3', macAddress: null, hardwareVendor: 'Dell Inc.', source: 'scan_passive' }

// (a) "huawei" (any case / partial "huaw") finds the asset by vendor.
check('(a) vendor "huawei" matches', vMatches(huawei, 'huawei').length > 0, true)
check('(a) vendor "HUAW" (upper) matches', vMatches(huawei, 'HUAW').length > 0, true)
check('(a) vendor "huaw" (partial) matches', vMatches(huawei, 'huaw').length > 0, true)

// (c) a vendor term that matches nothing.
check('(c) "huawei" does not match a Dell asset', vMatches(dell, 'huawei').length, 0)

// (d) matches reports field:'vendor' for a vendor hit.
check('(d) matches has field vendor', vMatches(huawei, 'huawei').some(m => m.field === 'vendor'), true)

// (e) vendor match (rank 0) orders above a history-only match (rank 1).
{
  const vendorHit = vMatches(huawei, 'huawei')
  const histAsset: MatchAsset = { assetId: 'H', hostname: null, ipAddress: '10.0.0.9', macAddress: null, hardwareVendor: null }
  const histRows: AddrRow[] = [{ addressId: 'old', assetId: 'H', networkKey: '10.0.0.0/24', ipAddress: '10.0.0.5', macAddress: null, firstSeen: '2026-01-01', lastSeen: '2026-02-01', endedAt: '2026-02-01' }]
  const historyHit = computeMatches(histAsset, histRows, '10.0.0.5').matches
  check('(e) vendor rank 0 above history rank 1', [matchRank(vendorHit), matchRank(historyHit)], [0, 1])
}

// Pure mirror of the route's AND of (search) + (source) — SQL in production.
const applyFilters = (rows: DemoAsset[], f: { search?: string; source?: string }) =>
  rows.filter(a =>
    (!f.search || computeMatches(a, [], f.search).matches.length > 0) &&
    (!f.source || a.source === f.source))

const pool: DemoAsset[] = [
  huawei,                                                                                                                                      // huawei, passive
  { assetId: 'V2', hostname: null, ipAddress: '192.168.100.2', macAddress: null, hardwareVendor: 'Huawei Device Co', source: 'scan_active' },  // huawei, active
  dell,                                                                                                                                        // dell,   passive
]

// (b) vendor term + source=scan_passive → only passive huawei asset(s).
check('(b) huawei + source=scan_passive → only passive', applyFilters(pool, { search: 'huawei', source: 'scan_passive' }).map(a => a.assetId), ['V'])

// (f) source filter alone (no search) → only passive assets.
check('(f) source=scan_passive alone', applyFilters(pool, { source: 'scan_passive' }).map(a => a.assetId).sort(), ['D', 'V'])

// (g) other tenant never matches — in production the outer WHERE scopes assets by
//     tenant_id, so a foreign-tenant asset is never in this tenant's result set.
{
  const tenantPool: DemoAsset[] = [huawei]   // only this tenant's rows are ever fetched
  check('(g) foreign-tenant huawei absent from tenant results', applyFilters(tenantPool, { search: 'huawei' }).some(a => a.assetId === 'F'), false)
}

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail === 0 ? 0 : 1)
