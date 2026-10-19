/**
 * drift-noise-demo.ts — the drift rules that keep alerts quiet (services/drift.ts):
 * no port_closed alerts, no port judgement on a scan that saw no open port, an agent's own
 * adapters are not a MAC change, OS upgrades are not alerts. PURE (no DB).
 * Run: npx esbuild scripts/drift-noise-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.drift-noise-demo.cjs && node .drift-noise-demo.cjs
 */
import { detectDrift, frozenOnUnreliablePorts, portsUnreliable } from '../src/services/drift'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

const asset = (osInfo: Record<string, unknown>, over: Record<string, unknown> = {}): any =>
  ({ assetId: 'A', hostname: 'h', macAddress: 'aa:bb:cc:00:00:01', isInternetFacing: false, deviceType: 'workstation', osInfo, ...over })
const base: any = { ports: [80, 445], ports_known: true, hostname: 'h', mac_address: 'aa:bb:cc:00:00:01', os_version: '10.0.19045', is_internet_facing: false, device_type: 'workstation' }
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
const swapped = asset({ ports: ['80/tcp', '445/tcp'] }, { macAddress: 'AA-BB-CC-00-00-02' })
check('another MAC alerts as a MAC change', types(detectDrift(base, swapped)), ['config_change:mac_address'])
check("…unless it is one of the machine's own adapters (agent-reported)", types(detectDrift(base, swapped, { agentMacs: new Set(['aa:bb:cc:00:00:02']) })), [])
check('a MAC the agent never reported still alerts', types(detectDrift(base, swapped, { agentMacs: new Set(['aa:bb:cc:00:00:09']) })), ['config_change:mac_address'])

// ── OS version (runDriftAudit turns version_upgrade into a baseline move, no alert) ──
check('an OS upgrade is reported as version_upgrade (low)', detectDrift(base, asset({ ports: ['80/tcp', '445/tcp'], os_version: '10.0.22631' })).map(d => [d.type, d.severity]), [['version_upgrade', 'low']])
check('an OS downgrade alerts high', detectDrift(base, asset({ ports: ['80/tcp', '445/tcp'], os_version: '10.0.17763' })).map(d => [d.type, d.severity]), [['version_downgrade', 'high']])

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
