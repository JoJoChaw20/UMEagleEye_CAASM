/**
 * Security baseline: 30 checks per operating system, in the same eight areas, after the CIS
 * Benchmarks (Level 1: Windows 11 Enterprise, Ubuntu / Red Hat family). The agent reports raw
 * facts (inventory.baseline, plus the security and patches sections it already sends); this
 * module decides pass or fail, so a rule can be corrected without an agent release.
 * Plan: docs/plans/2026-11-23-security-baseline.md.
 *
 * Each check is pass, fail, na (does not apply here), unknown (not reported) or admin (needs the
 * agent to run as Administrator / root). Only pass and fail are judged: percent = passed / judged.
 * Fewer than MIN_READABLE readable checks (pass, fail or na) leaves the device not assessed.
 * The same rules as the device score (endpointPosture.ts): unreadable is never a pass.
 *
 * The CIS references are the recommendation titles, cited, not copied text; their numbers are
 * added once checked against the benchmark documents. UMEagleEye does not claim CIS certification.
 * Pure; tested by baseline.test.ts with facts recorded on the lab machines.
 */

export const BASELINE_MODEL = 1
export const CHECKS_PER_OS = 30
export const MIN_READABLE = 24
export const DEFAULT_TARGET = 95

export type BaselineState = 'pass' | 'fail' | 'na' | 'unknown' | 'admin'
export type BaselineArea = 'updates' | 'accounts' | 'firewall' | 'disk' | 'remote' | 'hardening' | 'integrity' | 'logging'
export const AREAS: Record<BaselineArea, string> = {
  updates: 'Updates', accounts: 'Accounts and passwords', firewall: 'Firewall', disk: 'Disk and boot',
  remote: 'Remote access and network', hardening: 'System hardening', integrity: 'Malware and integrity',
  logging: 'Logging and time',
}
export type BaselineOs = 'windows' | 'linux' | 'macos'

export interface BaselineCheck {
  id: string
  area: BaselineArea
  label: string
  /** What passes, in words. */
  expected: string
  /** What the agent found, in words (null when not reported). */
  found: string | null
  state: BaselineState
  cis: string
  fix: string
}
export interface BaselineResult {
  model: number
  os: BaselineOs
  /** passed / judged, rounded DOWN to one decimal (94.96 must not show as the 95 target); null when not assessed. */
  percent: number | null
  passed: number
  failed: number
  judged: number
  /** pass + fail + na */
  readable: number
  total: number
  assessed: boolean
  checks: BaselineCheck[]
}

type Rec = Record<string, unknown>
const rec = (v: unknown): Rec => (v && typeof v === 'object' && !Array.isArray(v) ? v as Rec : {})
const list = (v: unknown): Rec[] => (Array.isArray(v) ? v.filter(x => x && typeof x === 'object') as Rec[] : [])
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)
const bool = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null)
const str = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null)
const plural = (n: number, w: string) => `${n} ${n === 1 ? w : w === 'try' ? 'tries' : `${w}s`}`
const octal = (n: number) => n.toString(8).padStart(4, '0')

// ── supported operating system versions (vendor lifecycle pages, checked November 2026) ──
interface Support { until: string; name: string }
/** Windows by build: [Home/Pro, Enterprise/Education], end of servicing. */
const WINDOWS_CLIENT: Record<string, [string, string, string]> = {
  '19045': ['Windows 10 22H2', '2025-10-14', '2025-10-14'],
  '22000': ['Windows 11 21H2', '2023-10-10', '2024-10-08'],
  '22621': ['Windows 11 22H2', '2024-10-08', '2025-10-14'],
  '22631': ['Windows 11 23H2', '2025-11-11', '2026-11-10'],
  '26100': ['Windows 11 24H2', '2026-10-13', '2027-10-12'],
  '26200': ['Windows 11 25H2', '2027-10-12', '2028-10-10'],
}
/** Long-term servicing (edition EnterpriseS / IoTEnterpriseS). */
const WINDOWS_LTSC: Record<string, Support> = {
  '17763': { name: 'Windows 10 LTSC 2019', until: '2029-01-09' },
  '19044': { name: 'Windows 10 LTSC 2021', until: '2027-01-12' },
  '26100': { name: 'Windows 11 LTSC 2024', until: '2029-10-09' },
}
const WINDOWS_SERVER: Record<string, Support> = {
  '14393': { name: 'Windows Server 2016', until: '2027-01-12' },
  '17763': { name: 'Windows Server 2019', until: '2029-01-09' },
  '20348': { name: 'Windows Server 2022', until: '2031-10-14' },
  '26100': { name: 'Windows Server 2025', until: '2034-11-14' },
}
/** Linux by distribution id and version: end of security updates from the vendor (Debian: LTS). */
const LINUX: Record<string, Record<string, string>> = {
  ubuntu: { '20.04': '2025-05-31', '22.04': '2027-06-30', '24.04': '2029-05-31', '24.10': '2025-07-10',
    '25.04': '2026-01-15', '25.10': '2026-07-09', '26.04': '2031-05-31' },
  debian: { '11': '2026-08-31', '12': '2028-06-30', '13': '2030-06-30' },
  rhel: { '8': '2029-05-31', '9': '2032-05-31', '10': '2035-05-31' },
}
for (const twin of ['rocky', 'almalinux', 'centos']) LINUX[twin] = LINUX['rhel']!

export function windowsSupport(os: Rec): Support | null {
  const build = String(os['build'] ?? '').split('.')[0] ?? ''
  const edition = String(os['edition'] ?? '')
  if (os['role'] === 'server') return WINDOWS_SERVER[build] ?? null
  if (/EnterpriseS/i.test(edition)) return WINDOWS_LTSC[build] ?? null
  const row = WINDOWS_CLIENT[build]
  // A build newer than every listed release came out after this table: it is current. Not given a
  // date (until '') rather than one guessed from Microsoft's servicing policy.
  if (!row) return Number(build) > Math.max(...Object.keys(WINDOWS_CLIENT).map(Number)) ? { name: `Windows build ${build}`, until: '' } : null
  const enterprise = /^(Enterprise|Education|IoTEnterprise)/i.test(edition)
  return { name: row[0], until: enterprise ? row[2] : row[1] }
}

/** macOS by major version. Apple publishes no end dates; in practice it fixes the current macOS and
 *  the two before it, so a major is dropped when the third one after it ships (these dates). */
const MACOS_ENDED: Record<number, [string, string]> = {
  11: ['macOS Big Sur', '2023-09-26'], 12: ['macOS Monterey', '2024-09-16'], 13: ['macOS Ventura', '2025-09-15'],
}
const MACOS_CURRENT: Record<number, string> = { 14: 'macOS Sonoma', 15: 'macOS Sequoia', 26: 'macOS Tahoe' }

export function macosSupport(os: Rec): Support | null {
  const major = Number(String(os['version'] ?? '').split('.')[0])
  if (!Number.isFinite(major) || major <= 0) return null
  if (MACOS_ENDED[major]) return { name: MACOS_ENDED[major][0], until: MACOS_ENDED[major][1] }
  if (MACOS_CURRENT[major]) return { name: MACOS_CURRENT[major], until: '' }
  if (major > 26) return { name: `macOS ${major}`, until: '' }
  return { name: `macOS ${os['version']}`, until: '2023-09-26' }    // older than Big Sur
}

export function linuxSupport(os: Rec): Support | null {
  const name = String(os['name'] ?? '').toLowerCase()
  const id = Object.keys(LINUX).find(k => name.includes(k === 'rhel' ? 'red hat' : k)) ?? null
  const version = String(os['version'] ?? '')
  if (!id) return null
  const table = LINUX[id]!
  const until = table[version] ?? table[version.split('.')[0] ?? ''] ?? null
  return until ? { name: String(os['name'] ?? `${id} ${version}`), until } : null
}

// ── the checks ──
interface Ctx { inv: Rec; sec: Rec; facts: Rec; patches: Rec; os: Rec; admin: boolean; now: Date }
type Verdict = [BaselineState, string | null]
interface Rule {
  id: string; area: BaselineArea; label: string; expected: string; cis: string; fix: string
  judge: (c: Ctx) => Verdict
}

/** Not readable: 'admin' when the agent lacked the rights to read it, else 'unknown'. */
const unread = (c: Ctx, needsAdmin = true): Verdict => [needsAdmin && !c.admin ? 'admin' : 'unknown', null]
const yes = (found: string | null = null): Verdict => ['pass', found]
const no = (found: string | null = null): Verdict => ['fail', found]
const passIf = (ok: boolean, found: string | null): Verdict => [ok ? 'pass' : 'fail', found]

function supportVerdict(s: Support | null, now: Date): Verdict {
  if (!s) return ['unknown', null]
  if (!s.until) return yes(s.name.startsWith('macOS') ? `${s.name}: still getting security updates` : `${s.name}: newer than every release in the lifecycle table`)
  const ends = new Date(`${s.until}T23:59:59Z`)
  return passIf(ends >= now, `${s.name}: security updates ${ends >= now ? 'until' : 'ended'} ${s.until}`)
}

const updatesRecent = (c: Ctx): Verdict => {
  const d = num(c.patches['days_since_last_patch'])
  return d == null ? unread(c, false) : passIf(d <= 30, `last update ${plural(d, 'day')} ago`)
}

const WINDOWS: Rule[] = [
  { id: 'win.updates_recent', area: 'updates', label: 'Updates installed recently', expected: 'an update installed in the last 30 days',
    cis: 'Windows Update: keep the system current', fix: 'Run Windows Update and restart.', judge: updatesRecent },
  { id: 'win.auto_updates', area: 'updates', label: 'Automatic updates on', expected: 'automatic updates not turned off',
    cis: "Ensure 'Configure Automatic Updates' is set to 'Enabled'", fix: 'Remove the "NoAutoUpdate" policy and set the Windows Update service to Manual or Automatic.',
    judge: c => {
      if (c.facts['no_auto_update'] === 1) return no('turned off by policy (NoAutoUpdate)')
      if (c.facts['update_service_disabled'] === true) return no('Windows Update service disabled')
      return c.facts['update_service_disabled'] == null && c.facts['no_auto_update'] == null ? unread(c, false) : yes('on')
    } },
  { id: 'win.os_supported', area: 'updates', label: 'Windows version still supported', expected: 'a version Microsoft still sends security updates for',
    cis: 'Use a supported operating system version', fix: 'Upgrade to a supported Windows version (Settings > Windows Update).',
    judge: c => supportVerdict(windowsSupport(c.os), c.now) },

  ...secpolRules(),
  { id: 'win.local_admins', area: 'accounts', label: 'Few local administrators', expected: '3 or fewer local administrator accounts',
    cis: 'Limit membership of the local Administrators group', fix: 'Remove everyday accounts from the local Administrators group.',
    judge: c => { const n = num(c.sec['local_admin_count']); return n == null ? unread(c, false) : passIf(n <= 3, plural(n, 'administrator')) } },

  { id: 'win.firewall_on', area: 'firewall', label: 'Firewall on in every profile', expected: 'Domain, Private and Public profiles on',
    cis: "Ensure 'Windows Firewall: <profile>: Firewall state' is set to 'On'", fix: 'Turn Windows Defender Firewall on for all profiles.',
    judge: c => {
      const fw = list(c.sec['firewall'])
      const on = bool(c.sec['firewall_all_enabled'])
      return on == null ? unread(c, false) : passIf(on, fw.map(f => `${f['profile']} ${f['enabled'] ? 'on' : 'off'}`).join(', ') || null)
    } },
  { id: 'win.firewall_inbound', area: 'firewall', label: 'Inbound blocked by default', expected: 'unsolicited inbound connections blocked in every profile',
    cis: "Ensure 'Windows Firewall: <profile>: Inbound connections' is set to 'Block (default)'", fix: 'Set the default inbound action to Block in every firewall profile.',
    judge: c => {
      const fw = list(c.facts['firewall_inbound'])
      if (!fw.length) return unread(c, false)
      const open = fw.filter(f => !['Block', 'NotConfigured'].includes(String(f['action'])))
      return passIf(!open.length, open.length ? `allowed in ${open.map(f => f['profile']).join(', ')}` : 'blocked in every profile')
    } },

  { id: 'win.bitlocker', area: 'disk', label: 'System drive encrypted', expected: 'BitLocker protection on for the system drive',
    cis: 'Encrypt the operating system drive with BitLocker', fix: 'Turn on BitLocker for drive C: (Settings > Privacy & security > Device encryption on Home editions).',
    judge: c => {
      const vols = list(c.sec['bitlocker'])
      if (!Array.isArray(c.sec['bitlocker'])) return unread(c)
      const sys = vols.find(v => String(v['drive'] ?? '').toUpperCase() === 'C:') ?? vols[0]
      return sys ? passIf(String(sys['protection']).toLowerCase() === 'on', `${sys['drive']} protection ${String(sys['protection']).toLowerCase()}`) : unread(c, false)
    } },
  { id: 'win.secure_boot', area: 'disk', label: 'Secure Boot on', expected: 'UEFI Secure Boot enabled', cis: 'Enable Secure Boot',
    fix: 'Turn on Secure Boot in the computer\'s UEFI settings.',
    judge: c => { const v = bool(c.sec['secure_boot']); return v == null ? unread(c, false) : passIf(v, v ? 'on' : 'off') } },
  { id: 'win.tpm', area: 'disk', label: 'TPM present and ready', expected: 'a TPM that is present and ready', cis: 'Use a TPM for BitLocker and credential protection',
    fix: 'Turn on the TPM (or fTPM / PTT) in the UEFI settings.',
    judge: c => {
      const t = c.sec['tpm'] && typeof c.sec['tpm'] === 'object' ? rec(c.sec['tpm']) : null
      return !t ? unread(c) : passIf(t['present'] === true && t['ready'] === true, `${t['present'] ? 'present' : 'absent'}${t['present'] ? `, ${t['ready'] ? 'ready' : 'not ready'}` : ''}`)
    } },

  { id: 'win.rdp', area: 'remote', label: 'Remote Desktop off or with NLA', expected: 'Remote Desktop off, or on with Network Level Authentication',
    cis: "Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'",
    fix: 'Turn Remote Desktop off, or require Network Level Authentication (System > Remote Desktop > Advanced settings).',
    judge: c => {
      const rdp = bool(c.sec['rdp_enabled'])
      if (rdp == null) return unread(c, false)
      if (!rdp) return yes('off')
      const nla = num(c.facts['rdp_nla'])
      return nla == null ? unread(c, false) : passIf(nla === 1, nla === 1 ? 'on, with NLA' : 'on, without NLA')
    } },
  { id: 'win.smb1', area: 'remote', label: 'SMBv1 off', expected: 'the SMBv1 server protocol disabled', cis: "Ensure 'Configure SMB v1 server' is set to 'Disabled'",
    fix: 'Run: Set-SmbServerConfiguration -EnableSMB1Protocol $false',
    judge: c => { const v = bool(c.sec['smb1_enabled']); return v == null ? unread(c) : passIf(!v, v ? 'enabled' : 'disabled') } },
  { id: 'win.smb_signing', area: 'remote', label: 'SMB signing required', expected: 'the SMB server requires signing',
    cis: "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'", fix: 'Run: Set-SmbServerConfiguration -RequireSecuritySignature $true',
    judge: c => { const v = bool(c.facts['smb_signing_required']); return v == null ? unread(c) : passIf(v, v ? 'required' : 'not required') } },
  { id: 'win.llmnr', area: 'remote', label: 'LLMNR off', expected: 'multicast name resolution turned off by policy',
    cis: "Ensure 'Turn off multicast name resolution' is set to 'Enabled'", fix: 'Group Policy: Network > DNS Client > Turn off multicast name resolution = Enabled.',
    judge: c => (hasFacts(c) ? passIf(c.facts['llmnr_policy'] === 0, c.facts['llmnr_policy'] === 0 ? 'off' : 'on (Windows default)') : unread(c, false)) },
  { id: 'win.winrm_basic', area: 'remote', label: 'WinRM Basic authentication off', expected: 'the WinRM service does not accept Basic authentication',
    cis: "Ensure 'Allow Basic authentication' (WinRM Service) is set to 'Disabled'", fix: 'Group Policy: Windows Remote Management > WinRM Service > Allow Basic authentication = Disabled.',
    judge: c => (!hasFacts(c) ? unread(c, false)
      : passIf(c.facts['winrm_basic_policy'] !== 1 && c.facts['winrm_basic_local'] !== 1, c.facts['winrm_basic_policy'] === 1 || c.facts['winrm_basic_local'] === 1 ? 'allowed' : 'not allowed')) },

  { id: 'win.uac', area: 'hardening', label: 'User Account Control on', expected: 'UAC enabled', cis: "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'",
    fix: 'Set UAC to at least the default level (Control Panel > User Accounts).',
    judge: c => { const v = bool(c.sec['uac_enabled']); return v == null ? unread(c, false) : passIf(v, v ? 'on' : 'off') } },
  { id: 'win.uac_secure_desktop', area: 'hardening', label: 'UAC prompts on the secure desktop', expected: 'elevation prompts shown on the secure desktop',
    cis: "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'", fix: 'Set UAC back to the default level, which dims the screen for prompts.',
    judge: c => (!hasFacts(c) ? unread(c, false) : c.facts['uac_secure_desktop'] === 0 ? no('off') : yes('on')) },
  { id: 'win.autorun', area: 'hardening', label: 'AutoRun off for every drive', expected: 'AutoRun turned off for all drive types (255)',
    cis: "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'", fix: 'Group Policy: AutoPlay Policies > Turn off Autoplay = Enabled, All drives.',
    judge: c => {
      if (!hasFacts(c)) return unread(c, false)
      const v = num(c.facts['autorun_drive_types'])
      return passIf(v === 255, v == null ? 'not set (Windows default)' : `drive types ${v}`)
    } },
  { id: 'win.ps_logging', area: 'hardening', label: 'PowerShell script block logging on', expected: 'PowerShell script blocks logged',
    cis: "Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'", fix: 'Group Policy: Windows PowerShell > Turn on PowerShell Script Block Logging = Enabled.',
    judge: c => (!hasFacts(c) ? unread(c, false) : passIf(c.facts['ps_scriptblock_logging'] === 1, c.facts['ps_scriptblock_logging'] === 1 ? 'on' : 'off')) },

  { id: 'win.antivirus', area: 'integrity', label: 'Antivirus on', expected: 'an antivirus product enabled', cis: 'Ensure real-time malware protection is on',
    fix: 'Turn on Microsoft Defender Antivirus or another antivirus.',
    judge: c => {
      const av = list(c.sec['antivirus'])
      const def = rec(c.sec['defender'])
      const on = av.filter(a => a['enabled'] === true).map(a => String(a['name']))
      if (!on.length && def['antivirus_enabled'] === true) on.push('Microsoft Defender')
      if (on.length) return yes(on.join(', '))
      return av.length || def['antivirus_enabled'] === false ? no('none enabled') : unread(c, false)
    } },
  { id: 'win.av_signatures', area: 'integrity', label: 'Antivirus signatures current', expected: 'signatures 7 days old or newer',
    cis: 'Ensure security intelligence updates are current', fix: 'Update the antivirus signatures (Windows Security > Virus & threat protection > Check for updates).',
    judge: c => {
      const def = rec(c.sec['defender'])
      const age = def['antivirus_enabled'] === true ? num(def['signature_age_days']) : null
      if (age != null) return passIf(age <= 7, `Defender signatures ${plural(age, 'day')} old`)
      const active = list(c.sec['antivirus']).filter(a => a['enabled'] === true)
      if (active.some(a => a['up_to_date'] === true)) return yes('up to date')
      return active.some(a => a['up_to_date'] === false) ? no('out of date') : unread(c, false)
    } },
  { id: 'win.smartscreen', area: 'integrity', label: 'SmartScreen on', expected: 'SmartScreen not turned off',
    cis: "Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled'", fix: 'Turn on "Check apps and files" in Windows Security > App & browser control.',
    judge: c => (!hasFacts(c) ? unread(c, false)
      : c.facts['smartscreen_policy'] === 0 || String(c.facts['smartscreen_local'] ?? '').toLowerCase() === 'off' ? no('off') : yes('on')) },

  { id: 'win.audit_logon', area: 'logging', label: 'Logons audited', expected: 'logon success and failure audited',
    cis: "Ensure 'Audit Logon' is set to 'Success and Failure'", fix: 'Run: auditpol /set /subcategory:"Logon" /success:enable /failure:enable',
    judge: c => {
      const v = str(c.facts['audit_logon'])
      if (v == null) return unread(c)
      const s = v.toLowerCase()
      if (s === 'success and failure') return yes(v)
      return ['success', 'failure', 'no auditing'].includes(s) ? no(v) : ['unknown', v]      // a translated answer
    } },
  { id: 'win.security_log', area: 'logging', label: 'Security log large enough', expected: 'Security event log of 196,608 KB or more',
    cis: "Ensure 'Security: Specify the maximum log file size (KB)' is set to '196,608 KB or greater'", fix: 'Run: wevtutil sl Security /ms:201326592',
    judge: c => { const kb = num(c.facts['security_log_kb']); return kb == null ? unread(c) : passIf(kb >= 196608, `${kb.toLocaleString('en')} KB`) } },
]

function hasFacts(c: Ctx): boolean {
  return Object.keys(c.facts).length > 0
}

function secpolRules(): Rule[] {
  const sp = (c: Ctx) => (c.facts['secpol'] && typeof c.facts['secpol'] === 'object' ? rec(c.facts['secpol']) : null)
  const rule = (id: string, label: string, expected: string, cis: string, fix: string, judge: (p: Rec) => Verdict): Rule =>
    ({ id, area: 'accounts', label, expected, cis, fix, judge: c => { const p = sp(c); return p ? judge(p) : unread(c) } })
  const n = (p: Rec, k: string) => num(p[k])
  return [
    rule('win.pw_length', 'Passwords at least 14 characters', 'minimum password length 14 or more', "Ensure 'Minimum password length' is set to '14 or more character(s)'",
      'Local Security Policy: Account Policies > Password Policy > Minimum password length = 14.',
      p => { const v = n(p, 'min_password_length'); return v == null ? ['unknown', null] : passIf(v >= 14, plural(v, 'character')) }),
    rule('win.pw_complexity', 'Password complexity on', 'complexity requirements enabled', "Ensure 'Password must meet complexity requirements' is set to 'Enabled'",
      'Local Security Policy: Password must meet complexity requirements = Enabled.',
      p => { const v = n(p, 'password_complexity'); return v == null ? ['unknown', null] : passIf(v === 1, v === 1 ? 'on' : 'off') }),
    rule('win.pw_max_age', 'Passwords expire within a year', 'maximum password age 1 to 365 days', "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'",
      'Local Security Policy: Maximum password age = 365 or fewer days.',
      p => { const v = n(p, 'max_password_age'); return v == null ? ['unknown', null] : passIf(v >= 1 && v <= 365, v < 1 ? 'never expire' : plural(v, 'day')) }),
    rule('win.lockout_threshold', 'Account lockout after 5 tries', 'locked after 5 or fewer bad passwords', "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'",
      'Local Security Policy: Account Lockout Policy > Account lockout threshold = 5.',
      p => { const v = n(p, 'lockout_threshold'); return v == null ? ['unknown', null] : passIf(v >= 1 && v <= 5, v === 0 ? 'never locks' : plural(v, 'try')) }),
    rule('win.lockout_duration', 'Lockout lasts 15 minutes', 'lockout of 15 minutes or more', "Ensure 'Account lockout duration' is set to '15 or more minute(s)'",
      'Local Security Policy: Account lockout duration = 15 minutes or more.',
      p => {
        if (n(p, 'lockout_threshold') === 0) return no('lockout off')
        const v = n(p, 'lockout_duration'); return v == null ? ['unknown', null] : passIf(v >= 15 || v === -1, v === -1 ? 'until an administrator unlocks' : plural(v, 'minute'))
      }),
    rule('win.guest', 'Guest account disabled', 'the Guest account disabled', "Ensure 'Accounts: Guest account status' is set to 'Disabled'",
      'Run: net user Guest /active:no',
      p => { const v = n(p, 'guest_enabled'); return v == null ? ['unknown', null] : passIf(v === 0, v === 0 ? 'disabled' : 'enabled') }),
    rule('win.admin_account', 'Built-in Administrator disabled or renamed', 'the built-in Administrator account disabled or renamed',
      "Ensure 'Accounts: Administrator account status' is set to 'Disabled' / 'Rename administrator account'", 'Run: net user Administrator /active:no',
      p => {
        const on = n(p, 'admin_enabled'); const name = str(p['admin_name'])
        if (on == null) return ['unknown', null]
        if (on === 0) return yes('disabled')
        return passIf(!!name && name.toLowerCase() !== 'administrator', `enabled as "${name ?? '?'}"`)
      }),
  ]
}

const LINUX_RULES: Rule[] = [
  { id: 'linux.os_supported', area: 'updates', label: 'Distribution version still supported', expected: 'a release that still gets security updates',
    cis: 'Use a supported operating system version', fix: 'Upgrade to a supported release (Ubuntu: do-release-upgrade).',
    judge: c => supportVerdict(linuxSupport(c.os), c.now) },
  { id: 'linux.security_updates', area: 'updates', label: 'No security updates waiting', expected: 'every update from the security channel installed',
    cis: 'Ensure updates, patches, and additional security software are installed', fix: 'Run: sudo apt upgrade (or sudo dnf upgrade --security).',
    judge: c => { const v = num(c.facts['security_updates']); return v == null ? unread(c, false) : passIf(v === 0, v === 0 ? 'none waiting' : `${plural(v, 'security update')} waiting`) } },
  { id: 'linux.auto_updates', area: 'updates', label: 'Automatic security updates on', expected: 'unattended-upgrades or dnf-automatic enabled',
    cis: 'Ensure automatic security updates are configured', fix: 'Run: sudo dpkg-reconfigure -plow unattended-upgrades (or enable dnf-automatic.timer).',
    judge: c => { const v = bool(c.facts['auto_updates']); return v == null ? unread(c, false) : passIf(v, v ? 'on' : 'off') } },

  { id: 'linux.pw_length', area: 'accounts', label: 'Passwords at least 14 characters', expected: 'pam_pwquality with minlen 14 or more',
    cis: 'Ensure password length is configured', fix: 'Install libpam-pwquality and set minlen = 14 in /etc/security/pwquality.conf.',
    judge: c => {
      if (!hasFacts(c)) return unread(c, false)
      const q = c.facts['password_quality'] && typeof c.facts['password_quality'] === 'object' ? rec(c.facts['password_quality']) : null
      if (!q) return no('no password quality module')
      const v = num(q['min_length']); return v == null ? ['unknown', null] : passIf(v >= 14, plural(v, 'character'))
    } },
  { id: 'linux.lockout', area: 'accounts', label: 'Account lockout after 5 tries', expected: 'pam_faillock with deny 5 or fewer',
    cis: 'Ensure password failed attempts lockout is configured', fix: 'Enable pam_faillock (Ubuntu: pam-auth-update) and set deny = 5 in /etc/security/faillock.conf.',
    judge: c => {
      if (!hasFacts(c)) return unread(c, false)
      const l = c.facts['lockout'] && typeof c.facts['lockout'] === 'object' ? rec(c.facts['lockout']) : null
      if (!l) return no('no lockout module')
      const v = num(l['deny']); return v == null ? ['unknown', null] : passIf(v >= 1 && v <= 5, plural(v, 'try'))
    } },
  { id: 'linux.pw_max_age', area: 'accounts', label: 'Passwords expire within a year', expected: 'PASS_MAX_DAYS 365 or fewer',
    cis: 'Ensure password expiration is configured', fix: 'Set PASS_MAX_DAYS 365 in /etc/login.defs (and chage -M 365 for existing users).',
    judge: c => { const v = num(c.facts['pass_max_days']); return v == null ? unread(c, false) : passIf(v >= 1 && v <= 365, v >= 99999 ? 'never expire' : plural(v, 'day')) } },
  { id: 'linux.empty_passwords', area: 'accounts', label: 'No empty passwords', expected: 'no account with an empty password',
    cis: 'Ensure accounts in /etc/shadow use shadowed passwords / no empty password fields', fix: 'Lock or set a password for each account listed: sudo passwd -l <user>.',
    judge: c => { const s = c.facts['shadow']; if (!s || typeof s !== 'object') return unread(c); const v = num(rec(s)['empty_passwords']); return v == null ? ['unknown', null] : passIf(v === 0, v === 0 ? 'none' : plural(v, 'account')) } },
  { id: 'linux.uid0', area: 'accounts', label: 'Only root has UID 0', expected: 'root is the only account with UID 0',
    cis: 'Ensure root is the only UID 0 account', fix: 'Give the other UID 0 accounts their own UID, or remove them.',
    judge: c => { const u = Array.isArray(c.facts['uid0']) ? (c.facts['uid0'] as unknown[]).map(String) : null; return !u ? unread(c, false) : passIf(u.length === 1 && u[0] === 'root', u.join(', ') || 'none') } },
  { id: 'linux.root_locked', area: 'accounts', label: 'Root password locked', expected: 'root signs in only through sudo (password locked)',
    cis: 'Ensure root account access is controlled', fix: 'Run: sudo passwd -l root (administrators use sudo).',
    judge: c => { const s = c.facts['shadow']; if (!s || typeof s !== 'object') return unread(c); const v = bool(rec(s)['root_locked']); return v == null ? ['unknown', null] : passIf(v, v ? 'locked' : 'has a password') } },
  { id: 'linux.sudo_users', area: 'accounts', label: 'Few administrators', expected: '3 or fewer members of sudo / wheel',
    cis: 'Limit membership of the administrative groups', fix: 'Remove everyday accounts from the sudo (or wheel) group.',
    judge: c => { const n = num(c.sec['local_admin_count']); return n == null ? unread(c, false) : passIf(n <= 3, plural(n, 'administrator')) } },

  { id: 'linux.firewall_on', area: 'firewall', label: 'Firewall active', expected: 'ufw, firewalld or nftables rules active',
    cis: 'Ensure a single firewall configuration utility is in use / ufw is enabled', fix: 'Run: sudo ufw enable (after allowing SSH: sudo ufw allow OpenSSH).',
    judge: c => { const on = bool(c.sec['firewall_all_enabled']); const fw = list(c.sec['firewall']); return on == null ? unread(c, false) : passIf(on, fw.map(f => `${f['profile']} ${f['enabled'] ? 'on' : 'off'}`).join(', ') || null) } },
  { id: 'linux.default_incoming', area: 'firewall', label: 'Incoming denied by default', expected: 'traffic no rule allows is dropped',
    cis: 'Ensure ufw default deny firewall policy', fix: 'Run: sudo ufw default deny incoming',
    judge: c => { const v = str(c.facts['default_incoming']); return v == null ? unread(c) : passIf(v === 'deny', v === 'deny' ? 'denied' : 'allowed') } },

  { id: 'linux.disk_encryption', area: 'disk', label: 'Disk encrypted', expected: 'every mounted system volume on LUKS',
    cis: 'Encrypt the disk (full-disk encryption)', fix: 'Reinstall with LUKS encryption (cannot be turned on in place for the root volume).',
    judge: c => {
      if (!Array.isArray(c.sec['disk_encryption'])) return unread(c, false)
      const vols = list(c.sec['disk_encryption'])
      return vols.length ? passIf(vols.every(v => String(v['protection']).toLowerCase() === 'on'), vols.map(v => `${v['volume'] ?? v['drive']} ${String(v['protection']).toLowerCase()}`).join(', ')) : unread(c, false)
    } },
  { id: 'linux.secure_boot', area: 'disk', label: 'Secure Boot on', expected: 'UEFI Secure Boot enabled', cis: 'Enable Secure Boot',
    fix: 'Turn on Secure Boot in the UEFI settings (signed kernels are the default on Ubuntu and RHEL). A machine booting in legacy BIOS mode must be switched to UEFI first.',
    judge: c => {
      const v = bool(c.sec['secure_boot'])
      if (v == null) return unread(c, false)
      return passIf(v, v ? 'on' : c.facts['uefi'] === false ? 'off: legacy BIOS boot (Secure Boot needs UEFI)' : 'off')
    } },
  { id: 'linux.bootloader', area: 'disk', label: 'Boot loader config protected', expected: 'grub.cfg owned by root, no access for group or others',
    cis: 'Ensure access to bootloader config is configured', fix: 'Run: sudo chown root:root /boot/grub/grub.cfg && sudo chmod 0600 /boot/grub/grub.cfg',
    judge: c => {
      if (!hasFacts(c)) return unread(c, false)
      const m = c.facts['bootloader_config'] && typeof c.facts['bootloader_config'] === 'object' ? rec(c.facts['bootloader_config']) : null
      if (!m) return ['na', 'no GRUB configuration']
      const mode = num(m['mode']) ?? 0o777
      return passIf((mode & 0o077) === 0 && m['uid'] === 0, `mode ${octal(mode)}, owner uid ${m['uid']}`)
    } },

  ...sshRules(),
  { id: 'linux.insecure_servers', area: 'remote', label: 'No plain-text remote servers', expected: 'no telnet, rsh, talk, tftp or NIS server installed',
    cis: 'Ensure telnet / rsh / tftp / nis servers are not installed', fix: 'Remove them: sudo apt purge <package>.',
    judge: c => { const v = Array.isArray(c.facts['insecure_servers']) ? (c.facts['insecure_servers'] as unknown[]).map(String) : null; return !v ? unread(c, false) : passIf(!v.length, v.length ? v.join(', ') : 'none') } },
  { id: 'linux.smb1', area: 'remote', label: 'SMBv1 off', expected: 'Samba not accepting SMBv1 (or no Samba)', cis: 'Ensure Samba does not allow SMBv1',
    fix: 'Set "server min protocol = SMB2_02" in /etc/samba/smb.conf.',
    judge: c => { const v = bool(c.sec['smb1_enabled']); return v == null ? unread(c, false) : passIf(!v, v ? 'enabled' : 'off') } },
  { id: 'linux.remote_desktop', area: 'remote', label: 'No remote desktop server', expected: 'no VNC, xrdp or GNOME remote desktop running',
    cis: 'Ensure remote desktop services are not in use', fix: 'Stop and disable it: sudo systemctl disable --now xrdp (or the VNC service).',
    judge: c => { const v = bool(c.sec['rdp_enabled']); return v == null ? unread(c, false) : passIf(!v, v ? 'running' : 'none running') } },

  { id: 'linux.aslr', area: 'hardening', label: 'Address space randomisation full', expected: 'kernel.randomize_va_space = 2',
    cis: 'Ensure address space layout randomization is enabled', fix: 'Set kernel.randomize_va_space = 2 in /etc/sysctl.d/60-hardening.conf.',
    judge: c => { const v = num(c.facts['aslr']); return v == null ? unread(c, false) : passIf(v === 2, `randomize_va_space ${v}`) } },
  { id: 'linux.ip_forward', area: 'hardening', label: 'IP forwarding off', expected: 'net.ipv4.ip_forward = 0 (not a router or container host)',
    cis: 'Ensure ip forwarding is disabled', fix: 'Set net.ipv4.ip_forward = 0 in /etc/sysctl.d/60-hardening.conf.',
    judge: c => {
      const v = num(c.facts['ip_forward'])
      if (v == null) return unread(c, false)
      if (v === 0) return yes('off')
      return c.facts['container_host'] === true ? ['na', 'on: a container host needs it'] : no('on')
    } },
  { id: 'linux.icmp_redirects', area: 'hardening', label: 'ICMP redirects ignored', expected: 'accept_redirects 0 for all and default',
    cis: 'Ensure icmp redirects are not accepted', fix: 'Set net.ipv4.conf.all.accept_redirects = 0 and net.ipv4.conf.default.accept_redirects = 0.',
    judge: c => {
      const v = Array.isArray(c.facts['accept_redirects']) ? (c.facts['accept_redirects'] as unknown[]).map(num) : null
      if (!v || v.some(x => x == null)) return unread(c, false)
      return passIf(v.every(x => x === 0), `all ${v[0]}, default ${v[1]}`)
    } },
  { id: 'linux.mac', area: 'hardening', label: 'AppArmor or SELinux enforcing', expected: 'a mandatory access control system enforcing',
    cis: 'Ensure AppArmor is enabled / SELinux is enforcing', fix: 'Ubuntu: keep AppArmor on (sudo aa-enforce /etc/apparmor.d/*); RHEL: setenforce 1 and SELINUX=enforcing.',
    judge: c => {
      if (!hasFacts(c)) return unread(c, false)
      const m = rec(c.facts['mac'])
      if (m['selinux'] === 'enforcing') return yes('SELinux enforcing')
      if (m['apparmor'] === true) {
        const n = num(m['apparmor_enforcing'])
        return n == null ? yes('AppArmor on') : passIf(n > 0, `AppArmor, ${plural(n, 'profile')} enforcing`)
      }
      return no(m['selinux'] === 'permissive' ? 'SELinux permissive' : 'none')
    } },

  { id: 'linux.aide', area: 'integrity', label: 'File integrity checker installed', expected: 'AIDE installed',
    cis: 'Ensure AIDE is installed', fix: 'Run: sudo apt install aide && sudo aideinit',
    judge: c => { const v = bool(c.facts['aide']); return v == null ? unread(c, false) : passIf(v, v ? 'installed' : 'not installed') } },
  { id: 'linux.shadow_perms', area: 'integrity', label: 'Password hashes protected', expected: '/etc/shadow owned by root, mode 0640 or stricter',
    cis: 'Ensure permissions on /etc/shadow are configured', fix: 'Run: sudo chown root:shadow /etc/shadow && sudo chmod 0640 /etc/shadow',
    judge: c => {
      const m = c.facts['shadow_file'] && typeof c.facts['shadow_file'] === 'object' ? rec(c.facts['shadow_file']) : null
      if (!m) return unread(c, false)
      const mode = num(m['mode']) ?? 0o777
      return passIf((mode & 0o137) === 0 && m['uid'] === 0, `mode ${octal(mode)}`)
    } },

  { id: 'linux.auditd', area: 'logging', label: 'Audit daemon running', expected: 'auditd active', cis: 'Ensure auditd service is enabled and active',
    fix: 'Run: sudo apt install auditd && sudo systemctl enable --now auditd',
    judge: c => { const v = bool(c.facts['auditd']); return v == null ? unread(c, false) : passIf(v, v ? 'running' : 'not running') } },
  { id: 'linux.persistent_logs', area: 'logging', label: 'Logs kept across restarts', expected: 'the journal on disk, or rsyslog running',
    cis: 'Ensure journald is configured to write logfiles to persistent disk', fix: 'Set Storage=persistent in /etc/systemd/journald.conf.',
    judge: c => { const v = bool(c.facts['persistent_logs']); return v == null ? unread(c, false) : passIf(v, v ? 'kept' : 'lost at restart') } },
  { id: 'linux.time_sync', area: 'logging', label: 'Clock synchronised', expected: 'systemd-timesyncd or chrony active',
    cis: 'Ensure time synchronization is in use', fix: 'Run: sudo timedatectl set-ntp true',
    judge: c => { const v = bool(c.facts['time_sync']); return v == null ? unread(c, false) : passIf(v, v ? 'on' : 'off') } },
]

function sshRules(): Rule[] {
  const ssh = (c: Ctx): Rec | null | undefined => {
    if (!hasFacts(c)) return undefined
    const s = c.facts['sshd']
    return s && typeof s === 'object' ? rec(s) : null
  }
  const rule = (id: string, label: string, expected: string, cis: string, fix: string, judge: (s: Rec) => Verdict): Rule => ({
    id, area: 'remote', label, expected, cis, fix,
    judge: c => { const s = ssh(c); return s === undefined ? unread(c, false) : s === null ? ['na', 'no SSH server'] : s['source'] == null ? unread(c) : judge(s) },
  })
  return [
    rule('linux.ssh_root', 'SSH root login off', 'PermitRootLogin no', 'Ensure sshd PermitRootLogin is disabled',
      'Set PermitRootLogin no in /etc/ssh/sshd_config.d/60-hardening.conf and restart ssh.',
      s => passIf(s['permitrootlogin'] === 'no', `PermitRootLogin ${s['permitrootlogin']}`)),
    rule('linux.ssh_empty', 'SSH refuses empty passwords', 'PermitEmptyPasswords no', 'Ensure sshd PermitEmptyPasswords is disabled',
      'Set PermitEmptyPasswords no in the SSH configuration.',
      s => passIf(s['permitemptypasswords'] === 'no', `PermitEmptyPasswords ${s['permitemptypasswords']}`)),
    rule('linux.ssh_tries', 'SSH allows 4 tries', 'MaxAuthTries 4 or fewer', 'Ensure sshd MaxAuthTries is configured',
      'Set MaxAuthTries 4 in the SSH configuration.',
      s => { const v = num(s['maxauthtries']); return v == null ? ['unknown', null] : passIf(v <= 4, `MaxAuthTries ${v}`) }),
  ]
}

// macOS: after the CIS Apple macOS Benchmark (Level 1). Built from Apple's documented settings and tools;
// not yet run on a real Mac (agent-gui/TESTING-MACOS.md lists what a tester confirms).
const off = (v: unknown) => v === false || v === 0
const MAC_RULES: Rule[] = [
  { id: 'mac.updates_recent', area: 'updates', label: 'Updates installed recently', expected: 'a macOS update installed in the last 30 days',
    cis: 'Ensure All Apple-provided Software Is Current', fix: 'Install the waiting updates in System Settings > General > Software Update.', judge: updatesRecent },
  { id: 'mac.auto_updates', area: 'updates', label: 'Automatic updates on', expected: 'checking, downloading and security responses automatic',
    cis: 'Ensure Auto Update / Download New Updates When Available / Install Security Responses Is Enabled',
    fix: 'System Settings > General > Software Update > Automatic updates: turn on every option (or set com.apple.SoftwareUpdate by profile).',
    judge: c => {
      if (!hasFacts(c)) return unread(c, false)
      const su = rec(c.facts['software_update'])
      const turnedOff = [['AutomaticCheckEnabled', 'check'], ['AutomaticDownload', 'download'], ['CriticalUpdateInstall', 'security responses']]
        .filter(([k]) => off(su[k!])).map(([, l]) => l)
      return passIf(!turnedOff.length, turnedOff.length ? `off: ${turnedOff.join(', ')}` : 'on')
    } },
  { id: 'mac.os_supported', area: 'updates', label: 'macOS version still supported', expected: 'a macOS version Apple still sends security updates for',
    cis: 'Use a supported operating system version', fix: 'Upgrade to a current macOS (System Settings > General > Software Update).',
    judge: c => supportVerdict(macosSupport(c.os), c.now) },

  ...macPasswordRules(),
  { id: 'mac.guest', area: 'accounts', label: 'Guest account disabled', expected: 'the Guest user off', cis: 'Ensure Guest Account Is Disabled',
    fix: 'System Settings > Users & Groups > Guest User: off.',
    judge: c => (!hasFacts(c) ? unread(c, false) : passIf(c.facts['guest_enabled'] !== true, c.facts['guest_enabled'] === true ? 'on' : 'off')) },
  { id: 'mac.auto_login', area: 'accounts', label: 'Automatic login off', expected: 'nobody signed in automatically at start-up', cis: 'Ensure Automatic Login Is Disabled',
    fix: 'System Settings > Users & Groups > Automatically log in as: Off.',
    judge: c => (!hasFacts(c) ? unread(c, false) : passIf(!c.facts['auto_login_user'], c.facts['auto_login_user'] ? `on${typeof c.facts['auto_login_user'] === 'string' ? ` (${c.facts['auto_login_user']})` : ''}` : 'off')) },
  { id: 'mac.root_disabled', area: 'accounts', label: 'Root account disabled', expected: 'the root user cannot sign in', cis: 'Ensure the "root" Account Is Disabled',
    fix: 'Directory Utility > Edit > Disable Root User (or: sudo dsenableroot -d).',
    judge: c => { const v = bool(c.facts['root_enabled']); return v == null ? unread(c) : passIf(!v, v ? 'enabled' : 'disabled') } },
  { id: 'mac.local_admins', area: 'accounts', label: 'Few administrators', expected: '3 or fewer administrator accounts',
    cis: 'Limit membership of the admin group', fix: 'Make everyday accounts Standard in System Settings > Users & Groups.',
    judge: c => { const n = num(c.sec['local_admin_count']); return n == null ? unread(c, false) : passIf(n <= 3, plural(n, 'administrator')) } },

  { id: 'mac.firewall_on', area: 'firewall', label: 'Firewall on', expected: 'the Application Firewall on', cis: 'Ensure Firewall Is Enabled',
    fix: 'System Settings > Network > Firewall: on.',
    judge: c => { const v = bool(c.sec['firewall_all_enabled']); return v == null ? unread(c, false) : passIf(v, v ? 'on' : 'off') } },
  { id: 'mac.stealth', area: 'firewall', label: 'Stealth mode on', expected: 'no answer to probes from the network', cis: 'Ensure Firewall Stealth Mode Is Enabled',
    fix: 'System Settings > Network > Firewall > Options: Enable stealth mode.',
    judge: c => { const v = bool(c.facts['stealth']); return v == null ? unread(c, false) : passIf(v, v ? 'on' : 'off') } },

  { id: 'mac.filevault', area: 'disk', label: 'FileVault on', expected: 'the startup disk encrypted with FileVault', cis: 'Ensure FileVault Is Enabled',
    fix: 'System Settings > Privacy & Security > FileVault: Turn On.',
    judge: c => {
      if (!Array.isArray(c.sec['disk_encryption'])) return unread(c, false)
      const v = list(c.sec['disk_encryption'])[0]
      return v ? passIf(String(v['protection']).toLowerCase() === 'on', String(v['protection']).toLowerCase()) : unread(c, false)
    } },
  { id: 'mac.sip', area: 'disk', label: 'System Integrity Protection on', expected: 'SIP enabled', cis: 'Ensure System Integrity Protection Status (SIP) Is Enabled',
    fix: 'Start in Recovery and run: csrutil enable',
    judge: c => { const v = bool(c.facts['sip']); return v == null ? unread(c, false) : passIf(v, v ? 'enabled' : 'disabled') } },
  { id: 'mac.ssv', area: 'disk', label: 'Sealed system volume', expected: 'the signed, sealed system volume in use', cis: 'Ensure Sealed System Volume (SSV) Is Enabled',
    fix: 'Start in Recovery and run: csrutil authenticated-root enable',
    judge: c => { const v = bool(c.facts['ssv']); return v == null ? unread(c, false) : passIf(v, v ? 'enabled' : 'disabled') } },

  ...macServiceRules(),
  { id: 'mac.screen_sharing', area: 'remote', label: 'Screen Sharing off', expected: 'no Screen Sharing or Remote Management answering',
    cis: 'Ensure Screen Sharing Is Disabled / Remote Management Is Disabled', fix: 'System Settings > General > Sharing: Screen Sharing and Remote Management off.',
    judge: c => { const v = bool(c.sec['rdp_enabled']); return v == null ? unread(c) : passIf(!v, v ? 'answering' : 'off') } },
  { id: 'mac.internet_sharing', area: 'remote', label: 'Internet Sharing off', expected: 'this Mac not sharing its connection', cis: 'Ensure Internet Sharing Is Disabled',
    fix: 'System Settings > General > Sharing: Internet Sharing off.',
    judge: c => (!hasFacts(c) ? unread(c, false) : passIf(c.facts['internet_sharing'] !== true, c.facts['internet_sharing'] === true ? 'on' : 'off')) },
  { id: 'mac.smb_guest', area: 'remote', label: 'No guest access to shared folders', expected: 'shared folders closed to guests',
    cis: 'Ensure Guest Access to Shared Folders Is Disabled', fix: 'System Settings > General > Sharing > File Sharing (i): guest access off.',
    judge: c => (!hasFacts(c) ? unread(c, false) : passIf(c.facts['smb_guest'] !== true, c.facts['smb_guest'] === true ? 'allowed' : 'not allowed')) },

  { id: 'mac.system_prefs_admin', area: 'hardening', label: 'Admin password for system settings', expected: 'system-wide settings ask for an administrator',
    cis: 'Ensure an Administrator Password Is Required to Access System-Wide Preferences',
    fix: 'Run: security authorizationdb read system.preferences > /tmp/sp.plist; set shared to false; security authorizationdb write system.preferences < /tmp/sp.plist',
    judge: c => { const v = bool(c.facts['system_prefs_admin']); return v == null ? unread(c) : passIf(v, v ? 'required' : 'not required') } },
  { id: 'mac.sudo_timeout', area: 'hardening', label: 'sudo asks every time', expected: 'Defaults timestamp_timeout=0', cis: 'Ensure the Sudo Timeout Period Is Set to Zero',
    fix: 'Add "Defaults timestamp_timeout=0" to /etc/sudoers.d/10_cissudoconfiguration (visudo -f).',
    judge: c => {
      const v = num(c.facts['sudo_timeout'])
      if (v == null) return c.facts['sudoers_read'] === true ? no('not set (macOS default: 5 minutes)') : unread(c)
      return passIf(v === 0, `${plural(v, 'minute')}`)
    } },
  { id: 'mac.wake_for_network', area: 'hardening', label: 'Wake for network access off', expected: 'the Mac does not wake for network requests',
    cis: 'Ensure Wake for Network Access Is Disabled', fix: 'Run: sudo pmset -a womp 0',
    judge: c => { const v = num(c.facts['wake_on_lan']); return v == null ? unread(c, false) : passIf(v === 0, v === 0 ? 'off' : 'on') } },
  { id: 'mac.login_window', area: 'hardening', label: 'Login window asks for name and password', expected: 'no list of user names at the login window',
    cis: 'Ensure Login Window Displays as Name and Password Is Enabled', fix: 'System Settings > Lock Screen > Login window shows: Name and password.',
    judge: c => (!hasFacts(c) ? unread(c, false) : passIf(c.facts['show_full_name'] === true, c.facts['show_full_name'] === true ? 'name and password' : 'list of users')) },

  { id: 'mac.xprotect', area: 'integrity', label: 'XProtect up to date', expected: 'Apple\'s malware definitions updated in the last 45 days',
    cis: 'Ensure XProtect Is Running and Updated', fix: 'Turn on "Install Security Responses and system files" in Software Update.',
    judge: c => {
      const x = list(c.sec['antivirus']).find(a => String(a['name']).startsWith('XProtect'))
      if (!x) return unread(c, false)
      return x['up_to_date'] == null ? ['unknown', String(x['name'])] : passIf(x['up_to_date'] === true, x['up_to_date'] ? 'up to date' : 'out of date')
    } },
  { id: 'mac.gatekeeper', area: 'integrity', label: 'Gatekeeper on', expected: 'only signed, checked apps run', cis: 'Ensure Gatekeeper Is Enabled',
    fix: 'Run: sudo spctl --master-enable',
    judge: c => { const v = bool(c.facts['gatekeeper']); return v == null ? unread(c, false) : passIf(v, v ? 'on' : 'off') } },

  { id: 'mac.auditd', area: 'logging', label: 'Security auditing on', expected: 'the audit daemon running', cis: 'Ensure Security Auditing Is Enabled',
    fix: 'Run: sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist',
    judge: c => {
      const v = str(c.facts['auditd'])
      if (v == null) return unread(c, false)
      return v === 'absent' ? ['na', 'not part of this macOS'] : passIf(v === 'enabled', v === 'enabled' ? 'running' : 'off')
    } },
  { id: 'mac.install_log', area: 'logging', label: 'Install log kept a year', expected: 'install.log kept 365 days or more', cis: 'Ensure install.log Is Retained for 365 or More Days',
    fix: 'In /etc/asl/com.apple.install set ttl=365 and remove all_max=.',
    judge: c => { const v = num(c.facts['install_log_ttl_days']); return v == null ? (hasFacts(c) ? no('not set') : unread(c, false)) : passIf(v >= 365, plural(v, 'day')) } },
  { id: 'mac.network_time', area: 'logging', label: 'Clock synchronised', expected: 'Set time and date automatically on', cis: 'Ensure Set Time and Date Automatically Is Enabled',
    fix: 'System Settings > General > Date & Time: Set time and date automatically.',
    judge: c => { const v = bool(c.facts['network_time']); return v == null ? unread(c) : passIf(v, v ? 'on' : 'off') } },
]

function macPasswordRules(): Rule[] {
  const rule = (id: string, label: string, expected: string, cis: string, fix: string, judge: (p: Rec) => Verdict): Rule => ({
    id, area: 'accounts', label, expected, cis, fix,
    judge: c => { const p = c.facts['password_policy']; return p && typeof p === 'object' ? judge(rec(p)) : unread(c) },
  })
  return [
    rule('mac.pw_length', 'Passwords at least 14 characters', 'a minimum length of 14 or more', 'Ensure Password Minimum Length Is Configured',
      'Set a passcode policy by configuration profile (minLength), or: pwpolicy -setglobalpolicy',
      p => { const v = num(p['min_length']); return v == null ? no('no minimum set') : passIf(v >= 14, plural(v, 'character')) }),
    rule('mac.lockout', 'Account lockout after 5 tries', 'locked after 5 or fewer bad passwords', 'Ensure Password Account Lockout Threshold Is Configured',
      'Set maxFailedAttempts 5 by configuration profile, or a pwpolicy lockout policy.',
      p => { const v = num(p['max_failed']); return v == null ? no('never locks') : passIf(v >= 1 && v <= 5, plural(v, 'try')) }),
    rule('mac.pw_max_age', 'Passwords expire within a year', 'a maximum age of 365 days or fewer', 'Ensure Password Age Is Configured',
      'Set maxPINAgeInDays 365 by configuration profile, or a pwpolicy expiry policy.',
      p => { const v = num(p['max_age_days']); return v == null ? no('never expire') : passIf(v >= 1 && v <= 365, plural(v, 'day')) }),
  ]
}

function macServiceRules(): Rule[] {
  const svc = (id: string, label: string, key: string, cis: string, fix: string): Rule => ({
    id, area: 'remote', label, expected: `${label.replace(/ off$/, '')} not answering from the network`, cis, fix,
    judge: c => {
      const l = c.facts['listening']
      if (!l || typeof l !== 'object') return unread(c)
      const on = rec(l)[key] === true
      return passIf(!on, on ? 'answering' : 'off')
    },
  })
  return [
    svc('mac.remote_login', 'Remote Login off', 'ssh', 'Ensure Remote Login Is Disabled', 'System Settings > General > Sharing: Remote Login off.'),
    svc('mac.file_sharing', 'File Sharing off', 'smb', 'Ensure File Sharing Is Disabled', 'System Settings > General > Sharing: File Sharing off.'),
    svc('mac.remote_apple_events', 'Remote Apple Events off', 'remote_apple_events', 'Ensure Remote Apple Events Is Disabled',
      'System Settings > General > Sharing: Remote Application Scripting off.'),
  ]
}

export const RULES: Record<BaselineOs, Rule[]> = { windows: WINDOWS, linux: LINUX_RULES, macos: MAC_RULES }

export function baselineOs(inventory: unknown): BaselineOs | null {
  const p = String(rec(inventory)['platform'] ?? '').toLowerCase()
  return p === 'windows' || p === 'linux' ? p : p === 'darwin' ? 'macos' : null
}

// ── stored per asset, and the Below baseline alert (services/securityBaseline.ts) ──
/** What the asset row keeps (assets.security_baseline): the result without the fixed texts. */
export interface StoredBaseline extends Omit<BaselineResult, 'checks'> {
  checks: { id: string; state: BaselineState; found: string | null }[]
}

export function compactBaseline(r: BaselineResult): StoredBaseline {
  const { checks, ...summary } = r
  return { ...summary, checks: checks.map(c => ({ id: c.id, state: c.state, found: c.found })) }
}

/** Asset columns for an inventory (null clears them). numeric comes back from Postgres as a string. */
export function baselineColumns(inventory: unknown | null, collectedAt: Date | null, now: Date = new Date()) {
  const r = inventory == null ? null : evaluateBaseline(inventory, now)
  return {
    securityBaselinePercent: r?.percent != null ? r.percent.toFixed(1) : null,
    securityBaseline: r ? compactBaseline(r) : null,
    securityBaselineAt: r ? collectedAt : null,
  }
}

const LABEL = new Map(Object.values(RULES).flat().map(r => [r.id, { label: r.label, area: r.area }]))
export const HIGH_BELOW = 80

export interface BaselineAlertDetails {
  model: number
  os: BaselineOs
  percent: number
  target: number
  passed: number
  failed: number
  judged: number
  failed_checks: { id: string; label: string; area: BaselineArea; found: string | null }[]
}
export type BaselineAlertPlan =
  | { kind: 'none' }
  | { kind: 'suppressed' }
  | { kind: 'open'; severity: 'high' | 'medium'; details: BaselineAlertDetails }
  | { kind: 'update'; eventId: string; severity: 'high' | 'medium'; details: BaselineAlertDetails }
  | { kind: 'resolve'; eventId: string; note: string }

/**
 * One alert per computer under its tenant's target: high under HIGH_BELOW %, else medium. Resolved
 * when the computer reaches the target. Not assessed (too little readable) leaves things as they are.
 * Closed as false positive or accepted risk: quiet until a check fails that was not failing then.
 */
export function planBaselineAlert(
  stored: StoredBaseline | null, target: number,
  open: { eventId: string } | null,
  lastClosed: { status: string; details: unknown } | null,
): BaselineAlertPlan {
  if (!stored || !stored.assessed || stored.percent == null) return { kind: 'none' }
  if (stored.percent >= target) {
    return open ? { kind: 'resolve', eventId: open.eventId, note: `Auto-resolved: security baseline ${stored.percent}% meets the ${target}% target` } : { kind: 'none' }
  }
  const failing = stored.checks.filter(c => c.state === 'fail')
  const details: BaselineAlertDetails = {
    model: stored.model, os: stored.os, percent: stored.percent, target, passed: stored.passed, failed: stored.failed, judged: stored.judged,
    failed_checks: failing.map(c => ({ id: c.id, label: LABEL.get(c.id)?.label ?? c.id, area: LABEL.get(c.id)?.area ?? 'hardening', found: c.found })),
  }
  const severity = stored.percent < HIGH_BELOW ? 'high' : 'medium'
  if (open) return { kind: 'update', eventId: open.eventId, severity, details }
  if (lastClosed && (lastClosed.status === 'false_positive' || lastClosed.status === 'accepted_risk')) {
    const before = new Set(list(rec(lastClosed.details)['failed_checks']).map(c => String(c['id'])))
    if (failing.every(c => before.has(c.id))) return { kind: 'suppressed' }
  }
  return { kind: 'open', severity, details }
}

/** The baseline for one machine's stored inventory, or null when its platform has none (phones,
 *  macOS for now) or its agent is older than the baseline (no `baseline` section). */
export function evaluateBaseline(inventory: unknown, now: Date = new Date()): BaselineResult | null {
  const os = baselineOs(inventory)
  const inv = rec(inventory)
  if (!os || !('baseline' in inv)) return null
  const ctx: Ctx = {
    inv, sec: rec(inv['security']), facts: rec(inv['baseline']), patches: rec(inv['patches']), os: rec(inv['os']),
    admin: inv['is_admin'] !== false, now,
  }
  const checks = RULES[os].map((r): BaselineCheck => {
    let verdict: Verdict
    try { verdict = r.judge(ctx) } catch { verdict = ['unknown', null] }
    return { id: r.id, area: r.area, label: r.label, expected: r.expected, found: verdict[1], state: verdict[0], cis: r.cis, fix: r.fix }
  })
  const passed = checks.filter(c => c.state === 'pass').length
  const failed = checks.filter(c => c.state === 'fail').length
  const readable = passed + failed + checks.filter(c => c.state === 'na').length
  const judged = passed + failed
  const assessed = readable >= MIN_READABLE && judged > 0
  return {
    model: BASELINE_MODEL, os, passed, failed, judged, readable, total: checks.length, assessed, checks,
    percent: assessed ? Math.floor((1000 * passed) / judged) / 10 : null,
  }
}
