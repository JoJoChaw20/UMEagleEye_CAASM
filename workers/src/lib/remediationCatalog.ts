/**
 * remediationCatalog.ts - PURE. The fixed set of automatic remediation actions, their risk,
 * and the lists of things automation must never touch. The model never picks from here;
 * only the step mapper (advisoryContent.ts) does.
 */

export type RemediationActionKey =
  | 'pkg.upgrade' | 'os.updates.apply' | 'service.stop_disable' | 'firewall.block_port'
  | 'app.uninstall' | 'check.version' | 'check.port' | 'check.service'

export const REMEDIATION_ACTIONS: Record<RemediationActionKey, {
  label: string; risk: 'low' | 'medium' | 'high'; rollback: 'auto' | 'none'; needsReboot: boolean
}> = {
  'pkg.upgrade':          { label: 'Upgrade a package',          risk: 'low',    rollback: 'auto', needsReboot: false },
  'os.updates.apply':     { label: 'Install Windows updates',    risk: 'medium', rollback: 'none', needsReboot: true },
  'service.stop_disable': { label: 'Stop and disable a service', risk: 'high',   rollback: 'auto', needsReboot: false },
  'firewall.block_port':  { label: 'Block an inbound port',      risk: 'medium', rollback: 'auto', needsReboot: false },
  'app.uninstall':        { label: 'Uninstall an application',   risk: 'high',   rollback: 'none', needsReboot: false },
  'check.version':        { label: 'Check a package version',    risk: 'low',    rollback: 'none', needsReboot: false },
  'check.port':           { label: 'Check a port',               risk: 'low',    rollback: 'none', needsReboot: false },
  'check.service':        { label: 'Check a service',            risk: 'low',    rollback: 'none', needsReboot: false },
}

export const PROTECTED_SERVICES: readonly string[] = [
  'eagleeye', 'EagleEyeAgent', 'MsMpEng', 'WinDefend', 'mpssvc', 'EventLog', 'wuauserv', 'sshd',
  'TermService', 'ufw', 'firewalld', 'auditd', 'rsyslog', 'systemd-journald', 'DNS', 'named', 'dhcpd', 'NTDS',
]
export const PROTECTED_PORTS: readonly number[] = [22, 3389, 53, 67, 68, 88, 389, 636, 443]
export const PROTECTED_APP_PATTERNS: readonly string[] = [
  'defender', 'antivirus', 'eagleeye', 'crowdstrike', 'sentinel', 'sophos', 'malwarebytes',
]

const PROTECTED_SERVICES_LC = new Set(PROTECTED_SERVICES.map(s => s.toLowerCase()))

export function isProtectedService(name: unknown): boolean {
  return PROTECTED_SERVICES_LC.has(String(name ?? '').trim().toLowerCase())
}
export function isProtectedPort(port: unknown): boolean {
  return PROTECTED_PORTS.includes(Number(port))
}
export function isProtectedApp(name: unknown): boolean {
  const s = String(name ?? '').toLowerCase()
  return PROTECTED_APP_PATTERNS.some(p => s.includes(p))
}

/** SBOM packageType -> package manager. Windows apps have no reliable mapping in this round. */
export const PACKAGE_MANAGER_FOR: Record<string, 'apt' | 'dnf' | 'apk' | 'pip' | 'npm' | 'winget'> = {
  deb: 'apt', rpm: 'dnf', apk: 'apk', python: 'pip', npm: 'npm',
}
