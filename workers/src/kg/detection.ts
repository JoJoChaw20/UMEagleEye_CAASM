/**
 * kg/detection.ts: is the problem behind an advisory still detected?
 *
 * Closing an advisory records that its problem is fixed. Scans decide whether that is true: a
 * drift, exposure, patch or indicator check closes its alert when the problem is no longer
 * found, and reopens or raises it again when it returns. So an advisory may be closed from the
 * chat only when no alert for the same problem on the same device is still open. Both the
 * proposal (agent.ts) and the Confirm click (confirm.ts) use this one check.
 */

/** Alert statuses that mean the problem was last seen as present. */
export const OPEN_ALERT_STATUSES = ['open', 'in_progress'] as const

// The details that tell one problem from another of the same type on one device: the port of
// a port or exposure alert, the CVE, the exposure rule, the changed setting, the package, the
// indicator, the service key. A type without these (new_device, os_patch_missing) is one problem per device.
const IDENTITY_KEYS = ['port', 'cve_id', 'rule', 'changed_attribute', 'package_name', 'indicator_value', 'key'] as const

/**
 * SQL: alert `o` is open and is the same problem as alert `e` (same device, type and identifying
 * details). Includes `e` itself while it is open, and catches a newer duplicate that `e` was merged into.
 */
export function sameProblemOpen(o: string, e: string): string {
  return [
    `${o}.asset_id = ${e}.asset_id`,
    `${o}.event_type = ${e}.event_type`,
    `${o}.status::text IN (${OPEN_ALERT_STATUSES.map(s => `'${s}'`).join(', ')})`,
    ...IDENTITY_KEYS.map(k => `(${o}.details->>'${k}') IS NOT DISTINCT FROM (${e}.details->>'${k}')`),
  ].join(' AND ')
}

/** SQL column: when the device's newest software list (SBOM) was made. CVE alerts follow it. */
export function lastSbomColumn(a: string): string {
  return `(SELECT max(sb.generated_at) FROM sboms sb WHERE sb.asset_id = ${a}.asset_id) AS last_sbom`
}

export interface DetectionFacts {
  hostname?: unknown
  ip_address?: unknown
  last_scanned?: unknown
  last_sbom?: unknown
  alert_type?: unknown
  port?: unknown
}

function utc(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null
  const d = new Date(value as string)
  return Number.isNaN(d.getTime()) ? null : `${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`
}

const THEN_CLOSE = 'Then close the advisory.'

/** The refusal shown when the problem is still detected. Built from database values only. */
export function stillDetectedMessage(f: DetectionFacts): string {
  const device = String(f.hostname ?? '').trim() || String(f.ip_address ?? '').trim() || 'the device'
  const type = String(f.alert_type ?? '')
  // A new device is not found by a scan: its alert closes when someone deals with the device (alertHygiene.ts).
  if (type === 'new_device') {
    return `Not closed: the new-device alert for ${device} is still open. It closes when the device is added to My Assets, given an owner, or runs an EagleEye agent. ${THEN_CLOSE}`
  }
  // CVE alerts follow the software list the agent reports (routes/sbom.ts), not the network scan.
  if (type === 'cve_detected') {
    const sbom = utc(f.last_sbom)
    return [
      `Not closed: this CVE is still detected on ${device}.`,
      sbom ? `Its alert is still open after the device's latest software scan (SBOM), on ${sbom}.` : 'Its alert is still open, and the device has no software scan (SBOM) on record.',
      `Fix it, then run a new software scan from the EagleEye agent: the alert closes when the scan no longer finds the CVE. ${THEN_CLOSE}`,
    ].join(' ')
  }
  const port = String(f.port ?? '').trim()
  const what = /^\d+$/.test(port) && /^port_|^exposure$|^vulnerable_service$/.test(type) ? `Port ${port}` : 'This problem'
  const scanned = utc(f.last_scanned)
  return [
    `Not closed: ${what} is still detected on ${device}.`,
    scanned ? `Its alert is still open after the last scan of the device, on ${scanned}.` : 'Its alert is still open, and the device has no recorded scan.',
    `Fix it and scan the device again: the alert closes when a scan no longer finds the problem. ${THEN_CLOSE}`,
  ].join(' ')
}
