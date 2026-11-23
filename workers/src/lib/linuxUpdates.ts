/**
 * Linux security updates: the Linux side of the "OS updates missing" alert (event type os_patch_missing,
 * one per machine; Windows: lib/windowsPatch.ts against Microsoft's fixes). The agent lists the packages
 * its distribution's security channel has newer versions of (inventory.baseline.security_update_packages:
 * apt-get -s, or dnf updateinfo --security). One alert while any are waiting, listing them; it closes at
 * the next inventory with none. The SBOM's per-package CVE alerts for the same packages close with it,
 * since one upgrade fixes both.
 */

type Rec = Record<string, unknown>
const rec = (v: unknown): Rec => (v && typeof v === 'object' && !Array.isArray(v) ? v as Rec : {})

export interface LinuxUpdatePackage { name: string; installed: string | null; available: string | null; advisory?: string; severity?: string }
export interface LinuxUpdateFacts {
  status: 'unknown' | 'current' | 'behind'
  product: string | null
  updates: number
  packages: LinuxUpdatePackage[]
  restart_pending: boolean | null
}

export function linuxUpdateFacts(inventory: unknown): LinuxUpdateFacts | null {
  const inv = rec(inventory)
  if (inv['platform'] !== 'linux') return null
  const b = rec(inv['baseline'])
  const n = typeof b['security_updates'] === 'number' ? b['security_updates'] as number : null
  const packages = (Array.isArray(b['security_update_packages']) ? b['security_update_packages'] as unknown[] : [])
    .map(rec).filter(p => typeof p['name'] === 'string')
    .map(p => ({
      name: String(p['name']).slice(0, 200),
      installed: typeof p['installed'] === 'string' ? p['installed'].slice(0, 100) : null,
      available: typeof p['available'] === 'string' ? p['available'].slice(0, 100) : null,
      ...(typeof p['advisory'] === 'string' ? { advisory: p['advisory'].slice(0, 40) } : {}),
      ...(typeof p['severity'] === 'string' ? { severity: p['severity'].slice(0, 20) } : {}),
    }))
  const pending = rec(inv['patches'])['pending_reboot']
  return {
    status: n == null ? 'unknown' : n === 0 ? 'current' : 'behind',
    product: typeof rec(inv['os'])['name'] === 'string' ? rec(inv['os'])['name'] as string : null,
    updates: n ?? 0,
    packages,
    restart_pending: typeof pending === 'boolean' ? pending : null,
  }
}

export type LinuxUpdatePlan =
  | { kind: 'none' } | { kind: 'suppressed' }
  | { kind: 'open'; details: Rec } | { kind: 'update'; eventId: string; details: Rec }
  | { kind: 'resolve'; eventId: string; note: string }

/** Open while updates wait, resolve when none do; unknown (no apt/dnf answer) changes nothing. Closed as
 *  false positive / accepted risk: quiet until a package not waiting then is waiting now. */
export function planLinuxUpdateAlert(
  f: LinuxUpdateFacts | null, open: { eventId: string } | null, lastClosed: { status: string; details: unknown } | null,
): LinuxUpdatePlan {
  if (!f || f.status === 'unknown') return { kind: 'none' }
  if (f.status === 'current') {
    return open ? { kind: 'resolve', eventId: open.eventId, note: 'Auto-resolved: no security updates waiting' } : { kind: 'none' }
  }
  const details = {
    platform: 'linux', patch_status: 'behind', product: f.product, updates: f.updates, packages: f.packages,
    restart_pending: f.restart_pending, cves: 0, critical: 0, exploited: 0, kb: null,
  }
  if (open) return { kind: 'update', eventId: open.eventId, details }
  if (lastClosed && (lastClosed.status === 'false_positive' || lastClosed.status === 'accepted_risk')) {
    const before = new Set((Array.isArray(rec(lastClosed.details)['packages']) ? rec(lastClosed.details)['packages'] as unknown[] : [])
      .map(p => String(rec(p)['name'])))
    if (f.packages.every(p => before.has(p.name))) return { kind: 'suppressed' }
  }
  return { kind: 'open', details }
}
