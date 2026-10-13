/**
 * device-type-reset-demo.ts — "Automatic" device type (lib/deviceClassify.ts):
 * what an asset's type becomes when an analyst hands it back to the system,
 * recomputed from the facts already stored on the asset. PURE (no DB).
 * Run: npx esbuild scripts/device-type-reset-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.device-type-reset-demo.cjs && node .device-type-reset-demo.cjs
 */
import { automaticDeviceType, inferDeviceType, storedPorts, type AutomaticTypeInput } from '../src/lib/deviceClassify'
import { inferDeviceType as fromScansRoute } from '../src/routes/scans'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}

const asset = (over: Partial<AutomaticTypeInput> = {}): AutomaticTypeInput => ({
  ipAddress: '192.168.1.20', hostname: null, macAddress: null, hardwareVendor: null,
  osInfo: {}, endpointInventory: null, isInternetFacing: false, internetFacingOverride: null, ...over,
})
const typeOf = (over: Partial<AutomaticTypeInput>) => {
  const r = automaticDeviceType(asset(over))
  return [r.deviceType, r.deviceTypeSource]
}

console.log('\n── the scan classifier moved, behaviour unchanged ──')
check('routes/scans re-exports the same function', fromScansRoute === inferDeviceType, true)

console.log('\n── 1. the machine itself (agent) ──')
check('agent role server', typeOf({ endpointInventory: { os: { role: 'server' } } }), ['server', 'agent'])
check('agent laptop chassis', typeOf({ endpointInventory: { os: {}, hardware: { form_factor: 'laptop' } } }), ['workstation', 'agent'])
check('agent with nothing usable falls through to scans',
  typeOf({ endpointInventory: { os: {} }, osInfo: { services: [{ port: 22, service: 'ssh' }] } }), ['server', 'auto'])

console.log('\n── 2. stored scan facts ──')
check('RDP seen by a scan -> workstation', typeOf({ osInfo: { services: [{ port: 3389, service: 'ms-wbt-server' }] } }), ['workstation', 'auto'])
check('router product -> network', typeOf({ osInfo: { services: [{ port: 80, service: 'http', product: 'MikroTik router config' }] } }), ['network', 'auto'])
check('only port strings stored (no services) still classify', typeOf({ osInfo: { ports: ['22/tcp', '80/tcp'] } }), ['server', 'auto'])
check('storedPorts reads services first', storedPorts({ services: [{ port: 443, product: 'nginx' }], ports: ['22/tcp'] }), [{ port: 443, product: 'nginx' }])
check('inferred exposure = it was the gateway -> network',
  typeOf({ isInternetFacing: true, internetFacingOverride: null, osInfo: { services: [{ port: 443 }] } }), ['network', 'auto'])
check('analyst-confirmed exposure is not the gateway signal',
  typeOf({ isInternetFacing: true, internetFacingOverride: true, osInfo: { services: [{ port: 443 }] } }), ['server', 'auto'])
check('SNMP sysDescr of a switch -> network', typeOf({ osInfo: { snmp_sysdescr: 'Cisco IOS Software, C2960' } }), ['network', 'auto'])
check('DHCP/OS hint android -> mobile', typeOf({ osInfo: { dhcp_device_hint: 'Android' } }), ['mobile', 'auto'])

console.log('\n── 3. classifier v2 hint for a type still unknown ──')
const ipad = automaticDeviceType(asset({ hostname: 'Jojos-iPad' }))
check('the device\'s own name (high confidence) fills it', [ipad.deviceType, ipad.deviceTypeSource], ['mobile', 'auto'])
check('the hint is returned for the asset page', ipad.hint?.type, 'mobile')
const privateMac = automaticDeviceType(asset({ macAddress: '4a:15:f7:3b:8c:29' }))
check('a low-confidence hint does not fill it', privateMac.deviceType, 'unknown')
check('nothing known -> unknown', typeOf({}), ['unknown', 'auto'])
check('a scan type is not overridden by a hint', typeOf({ hostname: 'Jojos-iPad', osInfo: { services: [{ port: 22 }] } }), ['server', 'auto'])

console.log(`\n${pass} passed, ${fail} failed`)
if (fail > 0) process.exit(1)
