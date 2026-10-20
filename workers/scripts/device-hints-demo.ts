/**
 * device-hints-demo.ts — classifier v2 hints (lib/deviceHints.ts) and how ingest,
 * rescore and criticality v2 use them. PURE (no DB). Vendor strings are the ones the
 * MAC-vendor lookup actually stored on staging.
 * Run: npx esbuild scripts/device-hints-demo.ts --bundle --platform=node --format=cjs \
 *        --outfile=.device-hints-demo.cjs && node .device-hints-demo.cjs
 */
import { applyHint, deviceTypeHint, type HintInput } from '../src/lib/deviceHints'
import { planRescore, scoreDetail } from '../src/lib/rescore'
import { planIngest, type PlanHost } from '../src/lib/ingest-plan'
import type { ScoringResultV2 } from '../src/lib/criticalityV2'

let pass = 0
let fail = 0
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      got=${JSON.stringify(actual)}\n      expected=${JSON.stringify(expected)}`}`)
  ok ? pass++ : fail++
}
const h = (o: Partial<HintInput>) => deviceTypeHint({ hostname: null, mac: null, vendor: null, osInfo: {}, ...o })
const brief = (o: Partial<HintInput>) => { const r = h(o); return r && [r.type, r.rule, r.confidence, r.auto] }

console.log('\n── high confidence: the device names itself (automatic) ──')
check('mDNS name Jojos-iPad', brief({ osInfo: { mdns_name: 'Jojos-iPad' } }), ['mobile', 'device_name', 'high', true])
check('hostname Jos-iPhone', brief({ hostname: 'Jos-iPhone' }), ['mobile', 'device_name', 'high', true])
check('Galaxy-S23 / Pixel-8 / Redmi-Note', [brief({ hostname: 'Galaxy-S23' })?.[0], brief({ hostname: 'Pixel-8' })?.[0], brief({ hostname: 'Redmi-Note-12' })?.[0]], ['mobile', 'mobile', 'mobile'])
check('Android default DHCP hostname android-1a2b3c4d', brief({ osInfo: { dhcp_hostname: 'android-1a2b3c4d5e' } }), ['mobile', 'device_name', 'high', true])
check('MacBook-Pro -> workstation', brief({ osInfo: { mdns_name: 'Jos-MacBook-Pro' } }), ['workstation', 'device_name', 'high', true])
check('Android DHCP vendor class', brief({ osInfo: { dhcp_vendor_class: 'android-dhcp-13' } }), ['mobile', 'dhcp_vendor_class', 'high', true])
check('evidence names the source and value', h({ osInfo: { mdns_name: 'Jojos-iPad' } })?.evidence, 'mDNS name "Jojos-iPad"')
check('not fooled: "pixelhub", "galaxyserver" (no word boundary)', [h({ hostname: 'pixelhub' }), h({ hostname: 'galaxyserver' })], [null, null])
check('Windows PC name gives nothing', h({ hostname: 'HMSB-P1SV010507' }), null)

console.log('\n── medium / low: suggestions only ──')
check('Apple-only mDNS services: Apple device, type left open',
  brief({ mac: '06:00:59:e5:9a:c6', osInfo: { mdns_services: ['_airplay._tcp', '_companion-link._tcp', '_rdlink._tcp'] } }), [null, 'apple_services', 'medium', false])
check('AirPlay / Google Cast lookups alone say nothing (any OS makes them)', h({ osInfo: { mdns_services: ['_airplay._tcp', '_googlecast._tcp'] } }), null)
check('OPPO MAC (staging vendor string)', brief({ vendor: 'GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD' }), ['mobile', 'mobile_maker', 'medium', false])
check('Bilian Wi-Fi module (staging string, full-width comma)', brief({ vendor: 'SHENZHEN BILIAN ELECTRONIC CO.，LTD' }), ['iot', 'iot_module_maker', 'low', false])
check('Espressif module: IoT, medium', brief({ vendor: 'Espressif Inc.' }), ['iot', 'iot_module_maker', 'medium', false])
check('Huawei is ambiguous (phones, routers, laptops): no hint', h({ vendor: 'HUAWEI TECHNOLOGIES CO.,LTD' }), null)
check('AzureWave (a PC Wi-Fi card maker): no hint', h({ vendor: 'AzureWave Technology Inc.' }), null)
check('private MAC + scanned with no open ports: likely mobile, low',
  brief({ mac: '4a:15:f7:3b:8c:29', osInfo: { ports: [] } }), ['mobile', 'private_mac_no_ports', 'low', false])
check('private MAC but never port-scanned: nothing (unknown is not "closed")', h({ mac: '4a:15:f7:3b:8c:29', osInfo: {} }), null)
check('burned-in MAC with no open ports: nothing', h({ mac: '00:9b:08:76:46:57', osInfo: { ports: [] } }), null)
check('Fingerbank phone result: medium suggestion', brief({ osInfo: { fingerbank_device: 'Samsung Android', fingerbank_score: 70 } }), ['mobile', 'dhcp_fingerprint', 'medium', false])

console.log('\n── the LLM description is only a low-confidence suggestion ──')
check('AI "Apple Mac Desktop" -> workstation suggestion, never automatic',
  brief({ osInfo: { ai_description: 'Apple Mac Desktop' } }), ['workstation', 'ai_guess', 'low', false])
check('AI "Samsung Android Phone" -> mobile suggestion', brief({ osInfo: { ai_description: 'Samsung Android Phone' } })?.slice(0, 2), ['mobile', 'ai_guess'])
check('AI "TP-Link Home Router" -> network suggestion', brief({ osInfo: { ai_description: 'TP-Link Home Router' } })?.[0], 'network')
check('AI text naming no type gives nothing', h({ osInfo: { ai_description: 'Unknown Apple device' } }), null)
check('stronger evidence wins over the AI guess (Apple services, medium)',
  brief({ vendor: 'Apple, Inc.', osInfo: { ai_description: 'Apple Mac Desktop', mdns_services: ['_companion-link._tcp'] } })?.[1], 'apple_services')
check('the AI guess outranks the other low rules (it saw all the facts)',
  brief({ mac: '4a:15:f7:3b:8c:29', osInfo: { ports: [], ai_description: 'Apple iPhone' } })?.[1], 'ai_guess')
check('label and evidence say it is an AI guess', [h({ osInfo: { ai_description: 'Apple Mac Desktop' } })?.label, h({ osInfo: { ai_description: 'Apple Mac Desktop' } })?.evidence],
  ['Apple Mac Desktop (AI guess)', 'AI description "Apple Mac Desktop"'])

console.log('\n── applying a hint ──')
const auto = h({ hostname: 'Jos-iPhone' })
const weak = h({ mac: '4a:15:f7:3b:8c:29', osInfo: { ports: [] } })
check('fills an unknown type', applyHint({ deviceType: 'unknown', deviceTypeSource: 'auto' }, auto), { deviceType: 'mobile', deviceTypeSource: 'auto', changed: true })
check('never changes a known type', applyHint({ deviceType: 'workstation', deviceTypeSource: 'auto' }, auto).changed, false)
check('never over an agent-confirmed type', applyHint({ deviceType: 'unknown', deviceTypeSource: 'agent' }, auto).changed, false)
check('a manual "unknown" is filled (it was not a real choice)', applyHint({ deviceType: 'unknown', deviceTypeSource: 'manual' }, auto), { deviceType: 'mobile', deviceTypeSource: 'auto', changed: true })
check('a low-confidence hint never sets the type', applyHint({ deviceType: 'unknown', deviceTypeSource: 'auto' }, weak).changed, false)

console.log('\n── rescore applies hints to existing assets ──')
const row = (o: Record<string, unknown>) => ({
  assetId: 'a', deviceType: 'unknown', deviceTypeSource: 'auto', isInternetFacing: false, hostname: null, owner: null,
  osInfo: { ports: [] }, criticalityScore: 4, criticalityModel: 1, macAddress: '0e:18:7c:8f:fd:91', hardwareVendor: null,
  deviceTypeHint: null, baselineState: { auto_set: true, device_type: 'unknown', ports: [] }, ...o,
})
const ipad = planRescore([row({ hostname: 'Jojos-iPad' })], 1).changes[0]
check('iPad: type filled, hint stored, auto baseline moved with it (no drift)',
  [ipad?.deviceType, ipad?.hint?.rule, (ipad?.baselineState as Record<string, unknown>)?.device_type], ['mobile', 'device_name', 'mobile'])
const priv = planRescore([row({ macAddress: '4a:15:f7:3b:8c:29' })], 1).changes[0]
check('private-MAC phone: only a suggestion is stored, type stays unknown', [priv?.deviceType, priv?.hint?.rule], [undefined, 'private_mac_no_ports'])
check('second rescore: nothing left to change', planRescore([row({ macAddress: '4a:15:f7:3b:8c:29', deviceTypeHint: priv?.hint })], 1).changes, [])
// Postgres jsonb returns keys in its own order (by length, then name), not ours.
const jsonbOrder = (o: Record<string, unknown>) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => a.length - b.length || (a < b ? -1 : 1)))
check('(the stored order really differs)', JSON.stringify(jsonbOrder(priv!.hint as never)) !== JSON.stringify(priv!.hint), true)
check('second rescore with the hint as jsonb returns it: nothing to change',
  planRescore([row({ macAddress: '4a:15:f7:3b:8c:29', deviceTypeHint: jsonbOrder(priv!.hint as never), criticalityModel: 2, criticalityScore: 3 })]).changes, [])
check('user-confirmed baseline is not moved', planRescore([row({ hostname: 'Jojos-iPad', baselineState: { auto_set: false, device_type: 'unknown' } })], 1).changes[0]?.baselineState, undefined)
check('mobile scores like a workstation in v1 (3, no +1 over unknown)',
  planRescore([row({ hostname: 'Jojos-iPad', owner: 'IT' })], 1).changes[0]?.score, 3)

console.log('\n── criticality v2 explains it ──')
const v2 = scoreDetail({ deviceType: 'mobile', deviceTypeSource: 'auto', isInternetFacing: false, hostname: 'Jojos-iPad', owner: null,
  osInfo: { ports: [] }, deviceTypeHint: h({ hostname: 'Jojos-iPad' }) }, 2) as ScoringResultV2
check('type label names the evidence', v2.details[0]!.label, 'Mobile device (inferred from hostname "Jojos-iPad")')
check('mobile base in v2 equals workstation and unknown (3): filing a phone never raises it',
  ['mobile', 'workstation', 'unknown'].map(t => (scoreDetail({ deviceType: t, isInternetFacing: false, hostname: null, owner: null, osInfo: { ports: [] } }, 2) as ScoringResultV2).breakdown.base),
  [3, 3, 3])
const v2u = scoreDetail({ deviceType: 'unknown', deviceTypeSource: 'auto', isInternetFacing: false, hostname: null, owner: null,
  osInfo: { ports: [] }, deviceTypeHint: weak }, 2) as ScoringResultV2
check('unknown type shows the pending suggestion', v2u.unknowns, ['device type (suggested: Likely mobile device, low confidence)'])

console.log('\n── ingest: a passive mDNS name classifies a known unknown ──')
const host = (o: Partial<PlanHost>): PlanHost => ({ ip: '192.168.100.186', rawMac: '0e:18:7c:8f:fd:91', hostname: 'Jojos-iPad', hostKeyRaw: null,
  deviceType: 'unknown', observedOsInfo: { mdns_name: 'Jojos-iPad', mdns_services: ['_companion-link._tcp'] }, ports: [], hardwareVendor: null,
  internetFacing: false, isPassive: true, tenantId: 't', ...o })
const plan = planIngest([host({})], {
  addresses: [{ addressId: 'ad', assetId: 'x', networkKey: '192.168.100.0/24', ipAddress: '192.168.100.186', macAddress: '0e:18:7c:8f:fd:91', deviceType: 'unknown', lastSeen: 1, assetCreatedAt: 1 }],
  assets: [{ assetId: 'x', deviceType: 'unknown', deviceTypeSource: 'auto', hostKey: null, osInfo: { ports: [] }, hostname: null, owner: null, hardwareVendor: null,
    macAddress: '0e:18:7c:8f:fd:91', source: 'scan_active', hasBaseline: true, baseline: { auto_set: true, device_type: 'unknown' } as never, internetFacingOverride: null }],
}, { newId: () => 'n' })
const set = (plan.perHost[0]!.ops[0] as { set: Record<string, unknown> }).set
check('passive scan fills the type and keeps the baseline in step',
  [set.deviceType, (set.deviceTypeHint as { rule: string }).rule, (set.baselineState as { device_type: string }).device_type], ['mobile', 'device_name', 'mobile'])
const emptyName = planIngest([host({})], {
  addresses: [{ addressId: 'ad', assetId: 'x', networkKey: '192.168.100.0/24', ipAddress: '192.168.100.186', macAddress: '0e:18:7c:8f:fd:91', deviceType: 'mobile', lastSeen: 1, assetCreatedAt: 1 }],
  assets: [{ assetId: 'x', deviceType: 'mobile', deviceTypeSource: 'manual', hostKey: null, osInfo: {}, hostname: '', owner: null, hardwareVendor: null,
    macAddress: '0e:18:7c:8f:fd:91', source: 'scan_passive', hasBaseline: true, baseline: null, internetFacingOverride: null }],
}, { newId: () => 'n3' })
check('an empty stored hostname (saved from an empty Edit field) is filled by the mDNS name',
  (emptyName.perHost[0]!.ops[0] as { set: Record<string, unknown> }).set.hostname, 'Jojos-iPad')
const created = planIngest([host({ ip: '192.168.100.40', rawMac: 'c4:fe:5b:a9:44:05', hostname: null, observedOsInfo: {}, hardwareVendor: 'GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD' })],
  { addresses: [], assets: [] }, { newId: () => 'n2' })
const ins = (created.perHost[0]!.ops.find(o => o.k === 'insertAsset') as { values: Record<string, unknown> }).values
check('new OPPO device: stays unknown, carries the medium suggestion', [ins.deviceType, (ins.deviceTypeHint as { rule: string }).rule], ['unknown', 'mobile_maker'])

console.log('\n── SSDP/UPnP and announced mDNS services (agent 2.2.0) ──')
check('UPnP Internet gateway → router, automatic', brief({ osInfo: { ssdp_types: ['device:InternetGatewayDevice:1'], ssdp_server: 'miniupnpd/2.1' } }), ['network', 'ssdp_device_type', 'high', true])
check('UPnP MediaRenderer → smart TV, suggestion', brief({ osInfo: { ssdp_types: ['device:MediaRenderer:1'] } }), ['iot', 'ssdp_device_type', 'medium', false])
check('DIAL (cast target) → smart TV', brief({ osInfo: { ssdp_types: ['dial-multiscreen-org:service:dial:1'] } })?.[0], 'iot')
check('UPnP printer', brief({ osInfo: { ssdp_types: ['device:Printer:1'] } })?.[0], 'iot')
check('MediaServer alone (Windows media sharing) says nothing', h({ osInfo: { ssdp_types: ['device:MediaServer:1'] } }), null)
check('SSDP server Roku → smart TV', brief({ osInfo: { ssdp_server: 'Roku/12.0 UPnP/1.0' } }), ['iot', 'ssdp_server', 'medium', false])
check('SSDP server miniupnpd → router (suggestion without the IGD type)', brief({ osInfo: { ssdp_server: 'Linux miniupnpd/2.2' } }), ['network', 'ssdp_server', 'medium', false])
check('Hue bridge', h({ osInfo: { ssdp_server: 'Linux/3.14.0 UPnP/1.0 IpBridge/1.65.0' } })?.label, 'Philips Hue bridge')
check('announces _googlecast → Chromecast', brief({ osInfo: { mdns_offered: ['_googlecast._tcp'] } }), ['iot', 'mdns_offered_service', 'medium', false])
check('announces _ipp → printer', h({ osInfo: { mdns_offered: ['_ipp._tcp'] } })?.label, 'Network printer or scanner')
check('only LOOKS for _googlecast (a phone) → no Chromecast hint', h({ osInfo: { mdns_services: ['_googlecast._tcp'] } }), null)
check('a device name still wins over SSDP', brief({ hostname: 'Jos-iPhone', osInfo: { ssdp_types: ['device:MediaRenderer:1'] } })?.[0], 'mobile')
check('Windows PC looking for _companion-link (Phone Link) is not an Apple device',
  h({ vendor: 'AzureWave Technology Inc.', mac: 'a4:42:3b:11:22:33', osInfo: { mdns_services: ['_companion-link._tcp', '_dosvc._tcp'] } }), null)
check('…but an announced _companion-link is', brief({ vendor: 'AzureWave Technology Inc.', osInfo: { mdns_offered: ['_companion-link._tcp'] } })?.[1], 'apple_services')
check('…and a private-MAC device looking for it (an iPhone) still counts', brief({ mac: '0e:18:7c:8f:fd:91', osInfo: { mdns_services: ['_companion-link._tcp'] } })?.[1], 'apple_services')
check('IGD wins over a weaker medium rule', brief({ vendor: 'Espressif Inc.', osInfo: { ssdp_types: ['device:InternetGatewayDevice:1'] } })?.[0], 'network')

console.log(`\n${pass} passed, ${fail} failed`)
if (fail > 0) process.exit(1)
