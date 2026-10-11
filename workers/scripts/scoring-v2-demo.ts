/**
 * scoring-v2-demo.ts — Phase C2: criticality v2 (importance only, sources, confidence),
 * endpoint posture (weakness, unassessed when unknown), coverage aggregates, model-aware
 * rescore/ingest and merge. PURE (no DB).
 * Run: npx esbuild scripts/scoring-v2-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.scoring-v2-demo.cjs && node .scoring-v2-demo.cjs
 */
import { computeCriticality } from '../src/lib/criticality'
import { computeCriticalityV2 } from '../src/lib/criticalityV2'
import { evaluatePosture, postureColumns, MIN_ASSESSED_WEIGHT } from '../src/lib/endpointPosture'
import { summarizeCoverage, type CoverageAsset } from '../src/lib/coverage'
import { planRescore, scoreAsset, scoreDetail, scoreInputOf, agentRoleOf } from '../src/lib/rescore'
import { planIngest, type PlanHost } from '../src/lib/ingest-plan'
import { planMerge, type MergeAsset } from '../src/lib/merge'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

// ── 1. Criticality v2 ──
console.log('\n── criticality v2: importance only, with sources ──')
const base = { deviceType: 'server', isInternetFacing: false, hostname: 'app01', osInfo: { ports: [22, 443] } as Record<string, unknown> }
check('v1 unchanged: unowned server = 5 + 1', computeCriticality({ ...base, owner: null }).score, 6)
check('v2: owner does not matter (importance only)', computeCriticalityV2(base).score, 5)
check('v2 type source in the label: agent', computeCriticalityV2({ ...base, deviceTypeSource: 'agent' }).details[0], { label: 'Server (confirmed by agent)', points: 5, source: 'agent' })
check('v2 type source in the label: manual', computeCriticalityV2({ ...base, deviceTypeSource: 'manual' }).details[0]!.label, 'Server (set by hand)')
check('v2 type source in the label: scans', computeCriticalityV2({ ...base, deviceTypeSource: 'auto' }).details[0]!.label, 'Server (inferred from scans)')
check('domain controller reported by agent: +2', computeCriticalityV2({ ...base, agentRole: 'domain_controller' }).breakdown.role, 2)
check('agentless DC (Kerberos + LDAP seen by scan) scores the same', computeCriticalityV2({ ...base, osInfo: { ports: [53, 88, 389, 445] } }).breakdown.role, 2)
check('Kerberos alone is not a directory service', computeCriticalityV2({ ...base, osInfo: { ports: [88] } }).breakdown.role, 0)
check('internet-facing confirmed by analyst vs inferred',
  [computeCriticalityV2({ ...base, isInternetFacing: true, internetFacingOverride: true }).details[1]!.source,
   computeCriticalityV2({ ...base, isInternetFacing: true }).details[1]!.source], ['analyst', 'inferred'])
check('same port weights as v1 (RDP, SMB, DB, breadth)',
  computeCriticalityV2({ ...base, osInfo: { ports: [3389, 445, 5432, 1, 2, 3, 4, 5, 6, 7] } }).breakdown.portRisk,
  computeCriticality({ ...base, osInfo: { ports: [3389, 445, 5432, 1, 2, 3, 4, 5, 6, 7] }, owner: 'x' }).breakdown.portRisk)
check('"22/tcp" and { port } entries are read', computeCriticalityV2({ ...base, osInfo: { ports: ['3389/tcp', { port: 23 }] } }).breakdown.portRisk, 2)
const rdpOnlyInside = scoreInputOf({ deviceType: 'server', deviceTypeSource: 'agent', isInternetFacing: false, internetFacingOverride: null,
  hostname: 'app01', osInfo: { ports: [] }, owner: null,
  endpointInventory: { os: { role: 'server' }, network: { listening: [{ port: 3389, protocol: 'tcp', address: '0.0.0.0' }] } } })
check('only scan-seen ports count: RDP the agent lists (not seen by a scan) adds nothing',
  (scoreDetail(rdpOnlyInside, 2) as { breakdown: { portRisk: number } }).breakdown.portRisk, 0)
const passive = computeCriticalityV2({ ...base, osInfo: {} })
check('never port-scanned: low confidence, reported as unknown', [passive.confidence, passive.unknowns], ['low', ['open ports (no active scan yet)']])
check('unknown type: low confidence', computeCriticalityV2({ ...base, deviceType: 'unknown' }).confidence, 'low')
check('agent-confirmed type + scanned ports: high confidence', computeCriticalityV2({ ...base, deviceTypeSource: 'agent' }).confidence, 'high')
check('scan-inferred type: medium confidence', computeCriticalityV2(base).confidence, 'medium')
check('hostname hints kept (−1 test)', computeCriticalityV2({ ...base, hostname: 'test-db' }).breakdown.hostnameHints, 0)
check('clamped to 1..10', computeCriticalityV2({ deviceType: 'network', isInternetFacing: true, hostname: 'prod-core-db', agentRole: 'domain_controller', osInfo: { ports: [3389, 445, 5432, 88, 389, 1, 2, 3, 4, 5] } }).score, 10)
check('factors text carries the points', computeCriticalityV2(base).factors, ['Server (inferred from scans) (+5)'])

// ── 2. Single entry point ──
console.log('\n── scoreAsset(model) ──')
const input = { ...base, owner: null, deviceTypeSource: 'agent' }
check('model 1 = v1, model 2 = v2', [scoreAsset(input, 1), scoreAsset(input, 2)], [6, 5])
check('default model is 1 (unchanged callers)', scoreAsset(input), 6)
check('scoreDetail(…, 2) is the v2 result', (scoreDetail(input, 2) as { model?: number }).model, 2)
check('agent role read from a stored inventory', [agentRoleOf({ os: { role: 'domain_controller' } }), agentRoleOf(null), agentRoleOf({ os: {} })], ['domain_controller', null, null])

// ── 3. Endpoint posture ──
console.log('\n── endpoint posture (weakness; unknown never counts as good) ──')
const secure = {
  security: {
    firewall_all_enabled: true, firewall: [{ profile: 'Domain', enabled: true }],
    antivirus: [{ name: 'Defender', enabled: true, up_to_date: true }],
    bitlocker: [{ drive: 'C:', protection: 'On' }], secure_boot: true, tpm: { present: true, ready: true },
    uac_enabled: true, rdp_enabled: false, smb1_enabled: false, local_admin_count: 1,
  },
  patches: { days_since_last_patch: 5, pending_reboot: false },
}
check('fully protected machine: 100', evaluatePosture(secure).score, 100)
const firewallOff = { ...secure, security: { ...secure.security, firewall_all_enabled: false } }
check('firewall off: 15 of 105 lost -> 86', evaluatePosture(firewallOff).score, 86)
check('antivirus off = at risk, out of date = review',
  [evaluatePosture({ ...secure, security: { ...secure.security, antivirus: [{ name: 'X', enabled: false }] } }).checks.find(c => c.id === 'antivirus')!.state,
   evaluatePosture({ ...secure, security: { ...secure.security, antivirus: [{ name: 'X', enabled: true, up_to_date: false }] } }).checks.find(c => c.id === 'antivirus')!.state,
   evaluatePosture({ ...secure, security: { ...secure.security, antivirus: [{ name: 'X', enabled: true }] } }).checks.find(c => c.id === 'antivirus')!.state],
  ['bad', 'warn', 'warn'])
const upd = (days: number | null, pending = false) => evaluatePosture({ ...secure, patches: { days_since_last_patch: days, pending_reboot: pending } }).checks.find(c => c.id === 'updates')!.state
check('updates: ≤30 good, 31-60 review, >60 at risk, unknown', [upd(30), upd(31), upd(61), upd(null)], ['good', 'warn', 'bad', 'unknown'])
check('recent updates but restart pending: review', upd(3, true), 'warn')
const notAdmin = { ...secure, unavailable: ['bitlocker', 'tpm', 'smb1'], security: { ...secure.security, bitlocker: null, tpm: null, smb1_enabled: null } }
const na = evaluatePosture(notAdmin)
check('without Administrator: those checks are "admin", left out, not passed',
  [na.checks.filter(c => c.state === 'admin').map(c => c.id), na.assessedWeight, na.score], [['disk_encryption', 'smb1', 'tpm'], 75, 100])
check('nothing readable: unassessed (null), not 100', evaluatePosture({}).score, null)
check('too little readable (firewall only): unassessed', evaluatePosture({ security: { firewall_all_enabled: true } }).score, null)
check(`threshold is ${MIN_ASSESSED_WEIGHT} of readable weight`, evaluatePosture({ security: { firewall_all_enabled: true, antivirus: [{ name: 'D', enabled: true, up_to_date: true }], uac_enabled: true } }).score, 100)
check('platform-neutral disk_encryption list accepted (Linux/macOS collectors)',
  evaluatePosture({ ...secure, security: { ...secure.security, bitlocker: undefined, disk_encryption: [{ volume: '/', protection: 'off' }] } }).checks.find(c => c.id === 'disk_encryption')!.state, 'bad')
check('postureColumns(null) clears everything', postureColumns(null, null), { postureScore: null, postureModel: null, postureAssessedAt: null, postureChecks: null })
check('postureColumns keeps the collection time', postureColumns(secure, new Date('2026-10-11T00:00:00Z')).postureAssessedAt, new Date('2026-10-11T00:00:00Z'))

// ── 4. Coverage ──
console.log('\n── coverage: aggregates say what they cover ──')
const cov = (o: Partial<CoverageAsset> & { asset_id: string }): CoverageAsset => ({
  hostname: null, ip: '10.0.0.1', device_type: 'workstation', criticality: 3, inventory_at: null, posture_score: null, posture_checks: null, ...o,
})
const summary = summarizeCoverage([
  cov({ asset_id: 'pc1', inventory_at: '2026-10-11', posture_score: 80, posture_checks: evaluatePosture(firewallOff).checks }),
  cov({ asset_id: 'pc2', inventory_at: '2026-10-11', posture_score: 100, posture_checks: evaluatePosture(secure).checks }),
  cov({ asset_id: 'pc3', inventory_at: '2026-10-11', posture_score: null }),            // agent, too few checks
  cov({ asset_id: 'srv', device_type: 'server', criticality: 7 }),                      // no agent
  cov({ asset_id: 'ws', criticality: 2 }),                                              // no agent
  cov({ asset_id: 'rtr', device_type: 'network' }),
  cov({ asset_id: 'cam', device_type: 'iot' }),
  cov({ asset_id: 'unk', device_type: 'unknown' }),
])
check('average only over assessed machines (80, 100 -> 90), unassessed counted apart',
  [summary.posture.average, summary.posture.assessed, summary.posture.unassessed], [90, 2, 3])
check('agent coverage: 3 with agent, 2 of 5 servers/PCs without, 2 n/a, 1 unidentified',
  [summary.with_agent, summary.no_agent.count, summary.agent_capable, summary.not_applicable, summary.unidentified], [3, 2, 5, 2, 1])
check('"No agent" list: most critical first', summary.no_agent.items.map(a => a.asset_id), ['srv', 'ws'])
check('failing checks: firewall at risk on 1 machine', summary.posture.failing.map(f => [f.id, f.bad, f.warn]), [['firewall', 1, 0]])
check('no assessed machines: average is null, not 0 or 100', summarizeCoverage([cov({ asset_id: 'x' })]).posture.average, null)

// ── 5. Rescore with a model ──
console.log('\n── model-aware rescore ──')
const row = { assetId: 'a', deviceType: 'server', isInternetFacing: false, hostname: 'app01', osInfo: { ports: [22] }, owner: null, criticalityScore: 6, criticalityModel: 1 }
check('v1 tenant: nothing to change', planRescore([row], 1).changes, [])
check('switch to v2: score and model written', planRescore([row], 2).changes, [{ assetId: 'a', score: 5, model: 2 }])
check('same score but stored under v1: model still updated', planRescore([{ ...row, owner: 'IT', criticalityScore: 5 }], 2).changes.map(c => [c.score, c.model]), [[5, 2]])
const withInv = { ...row, endpointInventory: secure, inventoryCollectedAt: new Date('2026-10-10T00:00:00Z'), postureModel: null }
const pc = planRescore([withInv], 1).changes[0]
check('agent asset without posture: rescore fills it (assessed at collection time)', [pc?.posture?.postureScore, pc?.posture?.postureAssessedAt], [100, new Date('2026-10-10T00:00:00Z')])
check('posture already current: untouched', planRescore([{ ...withInv, postureModel: 1 }], 1).changes, [])

// ── 6. Ingest uses the tenant model ──
console.log('\n── scan ingest scores with the tenant model ──')
const host: PlanHost = { ip: '10.0.0.5', rawMac: 'A4:BB:CC:DD:EE:01', hostname: 'app01', hostKeyRaw: null, deviceType: 'server',
  observedOsInfo: { ports: [22] }, ports: [22], hardwareVendor: null, internetFacing: false, isPassive: false, tenantId: 't' }
const vals = (m?: 1 | 2) => {
  const p = planIngest([host], { addresses: [], assets: [] }, { newId: () => 'id', criticalityModel: m })
  const op = p.perHost[0]!.ops.find(o => o.k === 'insertAsset') as { values: Record<string, unknown> }
  return [op.values.criticalityScore, op.values.criticalityModel]
}
check('new asset under v1 (default): 6, model 1', vals(), [6, 1])
check('new asset under v2: 5, model 2', vals(2), [5, 2])
const updPlan = planIngest([host], {
  addresses: [{ addressId: 'ad', assetId: 'x', networkKey: '10.0.0.0/24', ipAddress: '10.0.0.5', macAddress: 'a4:bb:cc:dd:ee:01', deviceType: 'server', lastSeen: 1, assetCreatedAt: 1 }],
  assets: [{ assetId: 'x', deviceType: 'server', deviceTypeSource: 'agent', hostKey: null, osInfo: {}, hostname: 'app01', owner: null, hardwareVendor: null,
    macAddress: 'a4:bb:cc:dd:ee:01', source: 'agent', hasBaseline: true, baseline: null, internetFacingOverride: null, agentRole: 'domain_controller' }],
}, { newId: () => 'id', criticalityModel: 2 })
const set = (updPlan.perHost[0]!.ops[0] as { set: Record<string, unknown> }).set
check('existing DC keeps its agent role in v2 on a scan (no flip)', [set.criticalityScore, set.criticalityModel], [7, 2])

// ── 7. Merge ──
console.log('\n── merge carries posture with the newest inventory ──')
const mAsset = (assetId: string, o: Partial<MergeAsset> = {}): MergeAsset => ({
  assetId, tenantId: 't', hostname: null, ipAddress: '10.0.0.1', macAddress: null, hostKey: null, owner: null, deviceType: 'workstation',
  deviceTypeSource: 'auto', hardwareVendor: null, osInfo: {}, criticalityScore: 3, baselineState: null, isInternetFacing: false,
  source: 'scan_active', inMyAssets: false, lastScanned: null, createdAt: null, ...o,
})
const m = planMerge(mAsset('s', { criticalityScore: 4, criticalityModel: 2 }),
  [mAsset('l', { endpointInventory: secure, inventoryCollectedAt: '2026-10-11', postureScore: 100, postureModel: 1, postureChecks: [], postureAssessedAt: '2026-10-11', criticalityScore: 3, criticalityModel: 1 })],
  { addresses: [], relationships: [], topologyNodes: [] })
check('posture follows the inventory', [m.mergedFields.postureScore, m.mergedFields.postureModel], [100, 1])
check('kept score keeps its formula', [m.mergedFields.criticalityScore, m.mergedFields.criticalityModel], [4, 2])

console.log(`\n${pass} passed, ${fail} failed`)
if (fail > 0) process.exit(1)
