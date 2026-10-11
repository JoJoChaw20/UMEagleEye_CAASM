/**
 * Machine identity — PURE helpers (no DB) for the identifiers an agent reports about
 * the machine it runs on (stored in asset_identifiers).
 *
 *   hardware_uuid  SMBIOS system UUID (Windows Win32_ComputerSystemProduct.UUID, Linux
 *                  /sys/class/dmi/id/product_uuid) or macOS IOPlatformUUID. Identifies
 *                  the (virtual) hardware; a cloned VM gets a new one.
 *   os_install_id  Windows MachineGuid or Linux /etc/machine-id. Identifies one OS
 *                  installation; a cloned VM keeps it, a reinstall changes it.
 *   mac            burned-in MAC of every physical NIC.
 *
 * Firmware often ships placeholder UUIDs; those are dropped so they can never tie two
 * machines together. Tested by scripts/machine-identity-demo.ts.
 */
import { classifyMac } from './identity'
import type { InventoryPayload } from './endpointInventory'

export type IdentifierKind = 'hardware_uuid' | 'os_install_id' | 'mac'
export interface MachineIdentifier { kind: IdentifierKind; value: string }

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

// Placeholder SMBIOS UUIDs shipped by firmware vendors ("To be filled by O.E.M."
// boards and some VM templates). Any UUID made of one repeated hex digit is junk too.
const JUNK_HARDWARE_UUIDS = new Set([
  '03000200-0400-0500-0006-000700080009',
  '00020003-0004-0005-0006-000700080009',
  '12345678-1234-5678-90ab-cddeefaabbcc',
  '4c4c4544-0000-0000-0000-000000000000',
])

/** Lowercase, braces stripped, valid UUID, not a known placeholder; else null. */
export function normalizeHardwareUuid(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const v = raw.trim().toLowerCase().replace(/^\{|\}$/g, '')
  if (!UUID_RE.test(v)) return null
  const hex = v.replace(/-/g, '')
  if (/^(.)\1+$/.test(hex)) return null                     // 0000…, ffff…
  if (JUNK_HARDWARE_UUIDS.has(v)) return null
  return v
}

/** Windows MachineGuid (a GUID) or Linux machine-id (32 hex chars); else null. */
export function normalizeOsInstallId(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const v = raw.trim().toLowerCase().replace(/^\{|\}$/g, '')
  const hex = UUID_RE.test(v) ? v.replace(/-/g, '') : /^[0-9a-f]{32}$/.test(v) ? v : null
  if (!hex || /^(.)\1+$/.test(hex)) return null
  return v
}

/** Burned-in MACs of the physical NICs (same rule as binding: global, physical). */
export function physicalMacs(inv: InventoryPayload): string[] {
  const out = new Set<string>()
  for (const nic of inv.network.interfaces ?? []) {
    if (!nic.physical) continue
    const { mac, macClass } = classifyMac(nic.mac)
    if (mac && macClass === 'global') out.add(mac)
  }
  return [...out]
}

/** Every identifier this inventory proves about its machine. */
export function machineIdentifiers(inv: InventoryPayload): MachineIdentifier[] {
  const id = inv.identity as Record<string, unknown>
  const out: MachineIdentifier[] = []
  const hw = normalizeHardwareUuid(id['smbios_uuid'] ?? id['hardware_uuid'])
  if (hw) out.push({ kind: 'hardware_uuid', value: hw })
  const os = normalizeOsInstallId(id['machine_guid'] ?? id['machine_id'])
  if (os) out.push({ kind: 'os_install_id', value: os })
  for (const mac of physicalMacs(inv)) out.push({ kind: 'mac', value: mac })
  return out
}

/**
 * Two machines are provably different when both have a known hardware UUID and the
 * sets don't overlap. Used as the VM-clone guard: a clone keeps its OS install id,
 * hostname and (unless regenerated) MACs, but never its hardware UUID.
 * Unknown on either side (no agent, or a placeholder UUID) proves nothing.
 */
export function differentHardware(a: readonly string[] | undefined, b: readonly string[] | undefined): boolean {
  if (!a?.length || !b?.length) return false
  return !a.some(x => b.includes(x))
}
