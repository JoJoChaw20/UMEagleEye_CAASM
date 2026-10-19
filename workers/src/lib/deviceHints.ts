/**
 * Device-type hints (classifier v2) — PURE (no DB). Tested by scripts/device-hints-demo.ts.
 *
 * For assets the port/OS classifier (scans.ts inferDeviceType) cannot place, mostly
 * phones and IoT that block every port, these rules look at other facts: the device's
 * own name (mDNS / NetBIOS / DHCP option 12), what it announces over mDNS and SSDP/UPnP,
 * its DHCP fingerprint, the MAC manufacturer and whether its MAC is a private (randomized) one.
 *
 * Every hint carries its rule, evidence and a confidence, and only HIGH-confidence rules
 * (a default device name, Android's DHCP vendor class) may set the type automatically —
 * and only on an asset whose type is still unknown. Everything weaker is a SUGGESTION
 * the analyst confirms with one click (which makes the type "set by hand"). The rules
 * and their thresholds should be re-checked against a labelled set
 * (scripts/evaluate-classifier.ts) before any is promoted to automatic.
 */
import { classifyMac } from './identity'

export const HINT_MODEL = 1
export type HintType = 'mobile' | 'workstation' | 'iot' | 'server' | 'network'
export type HintConfidence = 'high' | 'medium' | 'low'

export interface DeviceTypeHint {
  model: number
  /** Suggested type; null = we know something (e.g. "Apple device") but not the type. */
  type: HintType | null
  label: string
  rule: string
  confidence: HintConfidence
  /** True when the rule may set the type on an unknown asset without confirmation. */
  auto: boolean
  evidence: string
}

export interface HintInput {
  hostname: string | null | undefined
  mac: string | null | undefined
  vendor: string | null | undefined
  osInfo: Record<string, unknown> | null | undefined
}

// Default device names that state the device itself. Users can rename devices, which is
// why these are "high", not certain.
const MOBILE_NAME = /(iphone|ipad|ipod)|(^|[^a-z])(galaxy|pixel|redmi|oneplus|poco)([^a-z]|$)|^android-[0-9a-f]{6,}$/i
const MAC_NAME = /(^|[^a-z])(macbook|imac|mac-?mini|mac-?pro|mac-?studio)([^a-z]|$)/i
// mDNS services only Apple's own OSes use (Continuity, remote device link).
const APPLE_ONLY_SERVICES = ['_companion-link._tcp', '_rdlink._tcp']
// MAC manufacturers that, on Wi-Fi, are almost always phones.
const MOBILE_MAKERS = /\b(oppo|vivo mobile|realme|oneplus|honor device|motorola mobility|nothing technology)\b/i
// Wi-Fi module makers found in smart plugs, cameras and TV boxes (also in some PC dongles).
const IOT_MAKERS_MEDIUM = /\b(espressif|tuya)\b/i
const IOT_MAKERS_LOW = /\b(bilian)\b/i

// mDNS service types a device ANNOUNCES (os_info.mdns_offered, agent 2.2.0+) that say what
// it is. Only announced ones count: a phone looking for a Chromecast is not one.
const OFFERED_SERVICES: Array<[RegExp, HintType, string]> = [
  [/^_googlecast\._tcp$/, 'iot', 'Chromecast, Google TV or Nest speaker'],
  [/^_androidtvremote2?\._tcp$/, 'iot', 'Android TV / Google TV'],
  [/^_amzn-wplay\._tcp$/, 'iot', 'Amazon Fire TV or Echo'],
  [/^_(ipp|ipps|pdl-datastream|printer|uscan|uscans)\._tcp$/, 'iot', 'Network printer or scanner'],
  [/^_hap\._(tcp|udp)$/, 'iot', 'HomeKit accessory'],
  [/^_matterc?\._(tcp|udp)$/, 'iot', 'Matter smart-home device'],
]
// UPnP device/service types a device provides (os_info.ssdp_types, from SSDP). MediaServer
// is left out: Windows PCs sharing media announce it too.
const SSDP_TYPES: Array<[RegExp, HintType, string, HintConfidence]> = [
  [/^device:InternetGatewayDevice:/i, 'network', 'Router (UPnP Internet gateway)', 'high'],
  [/^device:WFADevice:/i, 'network', 'Wi-Fi router or access point', 'medium'],
  [/^device:MediaRenderer:|^dial-multiscreen-org:/i, 'iot', 'Smart TV or media player', 'medium'],
  [/^device:Printer:|^service:PrintBasic:/i, 'iot', 'Network printer', 'medium'],
]
// The SSDP SERVER header names the device's software.
const SSDP_SERVERS: Array<[RegExp, HintType, string]> = [
  [/\b(miniupnpd|RouterOS|OpenWrt|DD-WRT|AsusWRT)\b/i, 'network', 'Router'],
  [/\b(Roku|webOS|Tizen|SmartTV|BRAVIA|Chromecast|AppleTV|Fire ?TV)\b/i, 'iot', 'Smart TV or media player'],
  [/\bIpBridge\b/i, 'iot', 'Philips Hue bridge'],
]

const str = (v: unknown): string => (typeof v === 'string' ? v : '')
const strList = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : [])

/** Type named in the LLM's free-text description (os_info.ai_description). The same
 *  keyword mapping the ingest used before Phase C, plus phones; an unverified guess. */
export function aiDescriptionType(description: string): HintType | null {
  const d = description.toLowerCase()
  if (/iphone|ipad|smartphone|\bphone\b|tablet|android/.test(d)) return 'mobile'
  if (/workstation|laptop|desktop|windows pc|macbook|imac/.test(d)) return 'workstation'
  if (/server/.test(d)) return 'server'
  if (/router|gateway|switch|access.point/.test(d)) return 'network'
  if (/iot|camera|printer|sensor/.test(d)) return 'iot'
  return null
}

function names(input: HintInput): { name: string; source: string }[] {
  const os = input.osInfo ?? {}
  return [
    { name: str(os['mdns_name']), source: 'mDNS name' },
    { name: str(os['netbios_name']), source: 'NetBIOS name' },
    { name: str(os['dhcp_hostname']), source: 'DHCP hostname' },
    { name: str(input.hostname), source: 'hostname' },
  ].filter(n => n.name)
}

function hint(type: HintType | null, label: string, rule: string, confidence: HintConfidence, evidence: string): DeviceTypeHint {
  return { model: HINT_MODEL, type, label, rule, confidence, auto: confidence === 'high' && type !== null, evidence }
}

/** The best hint for this asset, or null when nothing points anywhere. */
export function deviceTypeHint(input: HintInput): DeviceTypeHint | null {
  const os = input.osInfo ?? {}

  // ── High: the device names itself ──
  for (const n of names(input)) {
    if (MOBILE_NAME.test(n.name)) return hint('mobile', 'Mobile device', 'device_name', 'high', `${n.source} "${n.name}"`)
    if (MAC_NAME.test(n.name)) return hint('workstation', 'Mac computer', 'device_name', 'high', `${n.source} "${n.name}"`)
  }
  const vendorClass = str(os['dhcp_vendor_class'])
  if (/^android-dhcp/i.test(vendorClass)) return hint('mobile', 'Android device', 'dhcp_vendor_class', 'high', `DHCP vendor class "${vendorClass}"`)
  const dhcpHint = str(os['dhcp_device_hint'])
  if (/^Apple (iPhone|iPad)$/.test(dhcpHint)) return hint('mobile', dhcpHint, 'dhcp_vendor_class', 'high', `DHCP vendor class "${vendorClass}"`)

  // ── SSDP/UPnP: what the device provides (high for an Internet gateway, else medium) ──
  const ssdpTypes = strList(os['ssdp_types'])
  const ssdpServer = str(os['ssdp_server'])
  let ssdpMedium: DeviceTypeHint | null = null
  for (const [re, type, label, confidence] of SSDP_TYPES) {
    const t = ssdpTypes.find(x => re.test(x))
    if (!t) continue
    const h = hint(type, label, 'ssdp_device_type', confidence, `SSDP ${t}${ssdpServer ? ` (server "${ssdpServer}")` : ''}`)
    if (confidence === 'high') return h
    ssdpMedium ??= h
  }

  // ── Medium: strong but not conclusive ──
  const fingerbank = str(os['fingerbank_device'])
  if (fingerbank && /phone|android|ipad|tablet|ios/i.test(fingerbank)) {
    return hint('mobile', fingerbank, 'dhcp_fingerprint', 'medium', `Fingerbank "${fingerbank}" (score ${os['fingerbank_score'] ?? '?'})`)
  }
  if (ssdpMedium) return ssdpMedium
  for (const [re, type, label] of SSDP_SERVERS) {
    if (re.test(ssdpServer)) return hint(type, label, 'ssdp_server', 'medium', `SSDP server "${ssdpServer}"`)
  }
  const offered = strList(os['mdns_offered'])
  for (const [re, type, label] of OFFERED_SERVICES) {
    const svc = offered.find(x => re.test(x))
    if (svc) return hint(type, label, 'mdns_offered_service', 'medium', `announces mDNS ${svc}`)
  }
  const services = Array.isArray(os['mdns_services']) ? (os['mdns_services'] as unknown[]).map(String) : []
  const apple = services.filter(s => APPLE_ONLY_SERVICES.includes(s))
  if (apple.length) {
    return hint(null, 'Apple device (iPhone, iPad, Mac or Apple TV)', 'apple_services', 'medium', `mDNS ${apple.join(', ')}`)
  }
  const vendor = str(input.vendor)
  if (MOBILE_MAKERS.test(vendor)) return hint('mobile', 'Mobile device', 'mobile_maker', 'medium', `MAC manufacturer ${vendor}`)
  if (IOT_MAKERS_MEDIUM.test(vendor)) return hint('iot', 'IoT device', 'iot_module_maker', 'medium', `MAC manufacturer ${vendor}`)

  // ── Low: weak signals ──
  // The LLM's guess sees every fact above, but it is unverified and unexplained, so it is
  // only ever a suggestion (its precision is measured like any other rule).
  const ai = str(os['ai_description'])
  const aiType = ai ? aiDescriptionType(ai) : null
  if (aiType) return hint(aiType, `${ai} (AI guess)`, 'ai_guess', 'low', `AI description "${ai}"`)
  if (IOT_MAKERS_LOW.test(vendor)) return hint('iot', 'IoT device', 'iot_module_maker', 'low', `MAC manufacturer ${vendor} (also used in PC Wi-Fi dongles)`)
  const { macClass } = classifyMac(input.mac)
  const ports = os['ports']
  const scannedClosed = Array.isArray(ports) && ports.length === 0
  if (macClass === 'local' && scannedClosed && !names(input).length) {
    return hint('mobile', 'Likely mobile device', 'private_mac_no_ports', 'low', 'private (randomized) MAC address and no open ports')
  }
  return null
}

/** Type after the hint: only an automatic hint, only on an unknown type, never over a
 *  type set by hand or confirmed by the agent. */
export function applyHint(
  current: { deviceType: string; deviceTypeSource: string | null },
  h: DeviceTypeHint | null,
): { deviceType: string; deviceTypeSource: string; changed: boolean } {
  const source = current.deviceTypeSource ?? 'auto'
  if (current.deviceType !== 'unknown' || !h?.auto || !h.type || source === 'agent') {
    return { deviceType: current.deviceType, deviceTypeSource: source, changed: false }
  }
  return { deviceType: h.type, deviceTypeSource: 'auto', changed: true }
}
