/**
 * Device type from observed facts (PURE, no DB).
 *
 *  - inferDeviceType / isNetworkBySnmp: the scan-time classifier (moved unchanged from
 *    routes/scans.ts, which re-exports inferDeviceType).
 *  - automaticDeviceType: what an asset's type is when nobody has set it by hand,
 *    recomputed from what is already stored on the asset. Used when an analyst switches
 *    a type back to "Automatic", so the asset shows a type straight away instead of
 *    waiting for the next scan. Same precedence as live data: the machine's own agent,
 *    then the scan classifier (ports/products, gateway, SNMP, DHCP/OS hints), then a
 *    high-confidence classifier v2 hint for a type that is still unknown.
 */
import { deviceTypeFor, type InventoryPayload } from './endpointInventory'
import { applyHint, deviceTypeHint, type DeviceTypeHint } from './deviceHints'

export type NmapPort = { port: number; protocol?: string; service?: string; product?: string; version?: string }
export type InferredDeviceType = 'server' | 'workstation' | 'network' | 'iot' | 'mobile' | 'unknown'

// SNMP sysDescr substrings that identify a host as a router/switch/network device.
const NETWORK_DEVICE_SIGNATURES = [
  'cisco ios', 'cisco nx-os', 'cisco adaptive security appliance', 'cisco asa',
  'junos', 'arista networks eos', 'mikrotik routeros', 'fortigate', 'pan-os',
  'arubaos', 'aruba networks',
]

// A host is a NETWORK device when its SNMP sysDescr matches a known router/switch
// signature, or when SNMP returned a non-empty interface table (ifDescr).
export function isNetworkBySnmp(snmpSysDescr?: string | null, snmpInterfaces?: string[] | null): boolean {
  if (snmpSysDescr) {
    const text = snmpSysDescr.toLowerCase()
    if (NETWORK_DEVICE_SIGNATURES.some(sig => text.includes(sig))) return true
  }
  if (snmpInterfaces && snmpInterfaces.length > 0) return true
  return false
}

export function inferDeviceType(
  ports: NmapPort[],
  ip?: string,
  os?: Record<string, unknown> | null,
  defaultGateway?: string,
): InferredDeviceType {
  // Only a real signal makes a device 'network': the agent-reported default gateway
  // is evidence; a bare .1/.254 position is NOT (it made ordinary hosts look like
  // gateways — removed). Port/product/SNMP/OS rules below carry the real evidence.
  if (ip && defaultGateway && ip === defaultGateway) return 'network'
  const text = ports.map(p => `${p.product ?? ''} ${p.service ?? ''}`).join(' ').toLowerCase()
  if (/busybox|router|cisco|juniper|aruba|mikrotik|ubiquiti|fortigate|panos|snmp/.test(text)) return 'network'
  if (/rdp|remote.desktop/.test(text) || ports.some(p => p.port === 3389)) return 'workstation'
  // SMB-only profile (139/445 without server ports) is characteristic of a Windows workstation
  if (ports.some(p => [139, 445].includes(p.port)) && !ports.some(p => [22, 80, 443, 3306, 5432, 8080, 8443, 6379, 27017, 1433].includes(p.port))) return 'workstation'
  if (ports.some(p => [22, 80, 443, 3306, 5432, 8080, 8443, 6379, 27017, 1433].includes(p.port))) return 'server'

  // OS-based fallback when no port signal is available
  if (os) {
    const hint = String(os.dhcp_device_hint ?? os.name ?? os.fingerbank_device ?? '').toLowerCase()
    if (/windows|macos|darwin|desktop|workstation|laptop/.test(hint)) return 'workstation'
    if (/android|iphone|ipad|mobile/.test(hint)) return 'mobile'
    if (/server/.test(hint) || (/linux|ubuntu|debian|centos|rhel/.test(hint) && !/desktop/.test(hint))) return 'server'
    if (/cisco|router|switch|ap |access.point|aruba|ubiquiti/.test(hint)) return 'network'
  }

  return 'unknown'
}

/** The ports a scan stored on an asset (os_info.services, else os_info.ports), as NmapPort. */
export function storedPorts(osInfo: Record<string, unknown> | null | undefined): NmapPort[] {
  const services = osInfo?.['services']
  if (Array.isArray(services)) {
    return services
      .filter((s): s is Record<string, unknown> => typeof s === 'object' && s !== null && Number.isFinite(Number(s['port'])))
      .map(s => ({
        port: Number(s['port']),
        protocol: typeof s['protocol'] === 'string' ? s['protocol'] : undefined,
        service: typeof s['service'] === 'string' ? s['service'] : undefined,
        product: typeof s['product'] === 'string' ? s['product'] : undefined,
      }))
  }
  const ports = osInfo?.['ports']
  if (!Array.isArray(ports)) return []
  return ports.map(p => parseInt(String(typeof p === 'object' && p !== null ? (p as Record<string, unknown>)['port'] : p), 10))
    .filter(n => Number.isFinite(n) && n > 0).map(port => ({ port }))
}

export interface AutomaticTypeInput {
  ipAddress: string
  hostname: string | null
  macAddress: string | null
  hardwareVendor: string | null
  osInfo: Record<string, unknown> | null
  endpointInventory: unknown
  isInternetFacing: boolean
  internetFacingOverride: boolean | null
}

export interface AutomaticType {
  deviceType: InferredDeviceType
  /** 'agent' when the machine's own agent decided it, else 'auto' (scans / hints). */
  deviceTypeSource: 'agent' | 'auto'
  hint: DeviceTypeHint | null
}

export function automaticDeviceType(a: AutomaticTypeInput): AutomaticType {
  const osInfo = a.osInfo ?? {}
  const hint = deviceTypeHint({ hostname: a.hostname, mac: a.macAddress, vendor: a.hardwareVendor, osInfo })

  // 1. The machine itself, when an agent reported its role or chassis.
  if (a.endpointInventory != null) {
    const own = deviceTypeFor(a.endpointInventory as InventoryPayload)
    if (own !== 'unknown') return { deviceType: own, deviceTypeSource: 'agent', hint }
  }

  // 2. The scan classifier on the stored scan facts. Exposure that was inferred (not
  //    confirmed by an analyst) only ever comes from "this host is the agent's default
  //    gateway" (lib/exposure.ts), which is the classifier's gateway signal.
  const gateway = a.isInternetFacing && a.internetFacingOverride == null ? a.ipAddress : undefined
  let type = inferDeviceType(storedPorts(osInfo), a.ipAddress, osInfo, gateway)
  if (type === 'unknown') {
    const ifaces = osInfo['snmp_interfaces']
    if (isNetworkBySnmp(typeof osInfo['snmp_sysdescr'] === 'string' ? osInfo['snmp_sysdescr'] : null,
      Array.isArray(ifaces) ? ifaces.map(String) : null)) type = 'network'
  }

  // 3. A high-confidence hint fills a type that is still unknown (same rule as ingest).
  const typed = applyHint({ deviceType: type, deviceTypeSource: 'auto' }, hint)
  return { deviceType: typed.deviceType as InferredDeviceType, deviceTypeSource: 'auto', hint }
}
