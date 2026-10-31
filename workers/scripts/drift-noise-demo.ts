/**
 * drift-noise-demo.ts — the drift rules that keep alerts quiet (services/drift.ts):
 * no port_closed alerts, no port judgement on a scan that saw no open port, an agent's own
 * adapters are not a MAC change, OS upgrades are not alerts; re-checks are not sightings,
 * unseen devices raise nothing, rule changes and generic names move the baseline. PURE (no DB).
 * Run: npx esbuild scripts/drift-noise-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.drift-noise-demo.cjs && node .drift-noise-demo.cjs
 */
import { baselineMoves, detectDrift, frozenOnUnreliablePorts, isUnseen, lastObservedAt, openAlertAction, portsUnreliable, RULE_VERSIONS, shouldReopen } from '../src/services/drift'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

const asset = (osInfo: Record<string, unknown>, over: Record<string, unknown> = {}): any =>
  ({ assetId: 'A', hostname: 'h', macAddress: '00:1b:63:00:00:01', isInternetFacing: false, deviceType: 'workstation', osInfo, ...over })
const base: any = { ports: [80, 445], ports_known: true, hostname: 'h', mac_address: '00:1b:63:00:00:01', os_version: '10.0.19045', is_internet_facing: false, device_type: 'workstation' }
const types = (d: Array<{ type: string; details: Record<string, unknown> }>) => d.map(x => `${x.type}${x.details.port != null ? `:${x.details.port}` : ''}${x.details.changed_attribute ? `:${x.details.changed_attribute}` : ''}`)

// ── ports ──
check('a new risky port alerts (high on an internal host)', detectDrift(base, asset({ ports: ['80/tcp', '445/tcp', '3389/tcp'] })).map(d => [d.type, d.details.port, d.severity]), [['port_opened', 3389, 'high']])
check('a closed port raises nothing', types(detectDrift(base, asset({ ports: ['80/tcp'] }))), [])
check('a scan that saw no open port is unreliable', portsUnreliable(base, { ports: [] }), true)
check('…and is not judged (no port drift)', types(detectDrift(base, asset({ ports: [] }))), [])
check('a scan with ports is reliable', portsUnreliable(base, { ports: ['80/tcp'] }), false)
check('no port data at all (passive) is not "unreliable", just skipped', [portsUnreliable(base, {}), types(detectDrift(base, asset({})))], [false, []])
check('such a scan freezes port_opened alerts but lets old port_closed alerts resolve', [frozenOnUnreliablePorts('port_opened'), frozenOnUnreliablePorts('port_closed')], [true, false])
check('a host with no baseline ports that shows none is fine', portsUnreliable({ ...base, ports: [] }, { ports: [] }), false)

// ── MAC ──
const swapped = asset({ ports: ['80/tcp', '445/tcp'] }, { macAddress: '00-1B-63-00-00-02' })
check('another MAC alerts as a MAC change', types(detectDrift(base, swapped)), ['config_change:mac_address'])
check("…unless it is one of the machine's own adapters (agent-reported)", types(detectDrift(base, swapped, { agentMacs: new Set(['00:1b:63:00:00:02']) })), [])
check('a MAC the agent never reported still alerts', types(detectDrift(base, swapped, { agentMacs: new Set(['00:1b:63:00:00:09']) })), ['config_change:mac_address'])

// ── OS version (runDriftAudit turns version_upgrade into a baseline move, no alert) ──
check('an OS upgrade is reported as version_upgrade (low)', detectDrift(base, asset({ ports: ['80/tcp', '445/tcp'], os_version: '10.0.22631' })).map(d => [d.type, d.severity]), [['version_upgrade', 'low']])
check('an OS downgrade alerts high', detectDrift(base, asset({ ports: ['80/tcp', '445/tcp'], os_version: '10.0.17763' })).map(d => [d.type, d.severity]), [['version_downgrade', 'high']])

// ── re-checking stored data is not a sighting (prod 28 Oct: x459 on lab VMs gone for weeks) ──
const t = (iso: string) => new Date(iso)
check('observed after the alert was last seen: counted again', openAlertAction(t('2026-10-28T10:00Z'), t('2026-10-28T09:00Z'), false), 'bump')
check('not observed since: nothing written', openAlertAction(t('2026-10-07T12:00Z'), t('2026-10-28T09:00Z'), false), 'none')
check('…unless its severity or detail changed', openAlertAction(t('2026-10-07T12:00Z'), t('2026-10-28T09:00Z'), true), 'update')
check('never observed: nothing counted', openAlertAction(null, t('2026-10-28T09:00Z'), false), 'none')
check('last observed = newest of scan and inventory', lastObservedAt({ lastScanned: t('2026-10-01T00:00Z'), inventoryCollectedAt: t('2026-10-05T00:00Z') })?.toISOString(), '2026-10-05T00:00:00.000Z')
check('a resolved alert reopens only when the device was seen after it was resolved',
  [shouldReopen(t('2026-10-29T00:00Z'), t('2026-10-28T00:00Z')), shouldReopen(t('2026-10-27T00:00Z'), t('2026-10-28T00:00Z')), shouldReopen(null, t('2026-10-28T00:00Z'))], [true, false, false])

// ── devices not seen for 14 days raise nothing and their alerts close unreviewed ──
const now = t('2026-10-31T00:00Z')
check('seen 13 days ago: still audited', isUnseen(t('2026-10-18T01:00Z'), null, now), false)
check('seen 14+ days ago: unseen', isUnseen(t('2026-10-07T12:00Z'), null, now), true)
check('never seen: counted from creation', [isUnseen(null, t('2026-10-30T00:00Z'), now), isUnseen(null, t('2026-06-01T00:00Z'), now)], [false, true])

// ── detection-rule changes move the baseline instead of alerting ──
const oldRule = { ...base, is_internet_facing: true }                     // captured before rule v2
check('exposure captured under an older rule is not compared', types(detectDrift(oldRule, asset({ ports: ['80/tcp', '445/tcp'] }))), [])
check('…the baseline moves to the current value and records the rule version',
  baselineMoves(oldRule, asset({ ports: ['80/tcp', '445/tcp'] }), null),
  { patch: { is_internet_facing: false, rule_versions: { internet_facing: RULE_VERSIONS.internet_facing } }, ruleRefreshed: ['internet_facing'] })
const newRule = { ...base, is_internet_facing: true, rule_versions: { ...RULE_VERSIONS } }
check('captured under the current rule: a real exposure change still alerts', types(detectDrift(newRule, asset({ ports: ['80/tcp', '445/tcp'] }))), ['config_change:internet_facing'])
check('…and nothing moves', baselineMoves(newRule, asset({ ports: ['80/tcp', '445/tcp'] }), null), { patch: null, ruleRefreshed: [] })

// ── generic names (platform defaults, UUIDs) are never a rename ──
const uuidBase = { ...newRule, is_internet_facing: false, hostname: 'bec1b98f-82d4-47be-a770-05c7d0a9fcd2' }
const docker = asset({ ports: ['80/tcp', '445/tcp'] }, { hostname: 'host.docker.internal' })
check('a UUID baseline name replaced by a real one: no alert', types(detectDrift(uuidBase, docker)), [])
check('…the baseline takes the real name', baselineMoves(uuidBase, docker, null).patch, { hostname: 'host.docker.internal' })
check('a real name seen as a platform default: no alert', types(detectDrift({ ...newRule, is_internet_facing: false, hostname: 'Jojos-iPad' }, asset({ ports: ['80/tcp', '445/tcp'] }, { hostname: 'iPad' }))), [])
check('a real rename still alerts', types(detectDrift({ ...newRule, is_internet_facing: false, hostname: 'pc-01' }, asset({ ports: ['80/tcp', '445/tcp'] }, { hostname: 'pc-02' }))), ['config_change:hostname'])

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
