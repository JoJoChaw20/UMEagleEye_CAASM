import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  AREAS, CHECKS_PER_OS, RULES, baselineColumns, compactBaseline, evaluateBaseline, linuxSupport, planBaselineAlert, windowsSupport,
  type BaselineResult,
} from './baseline'

const NOW = new Date('2026-11-23T00:00:00Z')
const state = (r: BaselineResult | null, id: string) => r?.checks.find(c => c.id === id)?.state
const found = (r: BaselineResult | null, id: string) => r?.checks.find(c => c.id === id)?.found

// Recorded 23 Nov 2026 on the developer PC (Windows 11 25H2 Home), collector run as a normal user.
const PC = {
  platform: 'windows', is_admin: false,
  os: { name: 'Microsoft Windows 11 Home Single Language', build: '26200.9974', display_version: '25H2', edition: 'CoreSingleLanguage', role: 'workstation' },
  patches: { days_since_last_patch: 11, pending_reboot: false },
  security: {
    firewall: [{ profile: 'Domain', enabled: true }, { profile: 'Private', enabled: true }, { profile: 'Public', enabled: true }],
    firewall_all_enabled: true,
    defender: { service_enabled: true, antivirus_enabled: true, realtime_enabled: true, signature_age_days: 0 },
    antivirus: [{ name: 'Windows Defender', enabled: true, up_to_date: true }],
    bitlocker: null, tpm: null, secure_boot: true, uac_enabled: true, rdp_enabled: false, smb1_enabled: null, local_admin_count: 2,
  },
  baseline: {
    no_auto_update: null, update_service_disabled: false, secpol: null,
    firewall_inbound: [{ profile: 'Domain', action: 'Block' }, { profile: 'Private', action: 'Block' }, { profile: 'Public', action: 'Block' }],
    rdp_nla: 1, smb_signing_required: null, llmnr_policy: null, winrm_basic_policy: null, winrm_basic_local: null,
    uac_secure_desktop: 1, autorun_drive_types: 221, ps_scriptblock_logging: null, smartscreen_policy: null, smartscreen_local: null,
    audit_logon: null, security_log_kb: null,
  },
}
// The same PC as the service sees it (SYSTEM): the Administrator-only facts filled in with
// Windows 11 Home defaults.
const PC_AS_SERVICE = {
  ...PC, is_admin: true,
  security: { ...PC.security, bitlocker: [{ drive: 'C:', protection: 'Off' }], tpm: { present: true, ready: true }, smb1_enabled: false },
  baseline: {
    ...PC.baseline, smb_signing_required: true, audit_logon: 'Success', security_log_kb: 20480,
    secpol: { min_password_length: 0, password_complexity: 0, max_password_age: 42, lockout_threshold: 10, lockout_duration: 10,
      guest_enabled: 0, admin_enabled: 0, admin_name: 'Administrator' },
  },
}
// Recorded 23 Nov 2026 on the Ubuntu 26.04 lab VM (Docker host), collector run as a normal user.
const VM = {
  platform: 'linux', is_admin: false,
  os: { name: 'Ubuntu 26.04.1 LTS', version: '26.04', build: '7.0.0-43-generic', edition: 'ubuntu', role: 'server' },
  patches: { days_since_last_patch: 0 },
  security: {
    firewall: [{ profile: 'ufw', enabled: false }], firewall_all_enabled: false,
    disk_encryption: [{ volume: '/', protection: 'off' }], secure_boot: false, rdp_enabled: false, smb1_enabled: false, local_admin_count: 1,
  },
  baseline: {
    security_updates: 0, auto_updates: true, password_quality: null, lockout: null, pass_max_days: 99999, shadow: null, uid0: ['root'],
    default_incoming: null, bootloader_config: { mode: 0o600, uid: 0, gid: 0 },
    sshd: { source: 'config files', permitrootlogin: 'prohibit-password', permitemptypasswords: 'no', maxauthtries: 6 },
    insecure_servers: [], aslr: 2, ip_forward: 1, accept_redirects: [0, 1], container_host: true,
    mac: { apparmor: true, apparmor_enforcing: null, selinux: null }, aide: false,
    shadow_file: { mode: 0o640, uid: 0, gid: 42 }, auditd: false, persistent_logs: true, time_sync: true,
  },
}

test('the same number of checks for each OS, in the same areas', () => {
  for (const os of ['windows', 'linux', 'macos'] as const) {
    assert.equal(RULES[os].length, CHECKS_PER_OS, os)
    assert.equal(new Set(RULES[os].map(r => r.id)).size, CHECKS_PER_OS)
    for (const r of RULES[os]) assert.ok(r.area in AREAS && r.cis && r.fix && r.expected, r.id)
  }
  const areas = (os: 'windows' | 'linux' | 'macos') => [...new Set(RULES[os].map(r => r.area))].sort()
  assert.deepEqual(areas('windows'), areas('linux'))
  assert.deepEqual(areas('macos'), areas('linux'))
  assert.equal(areas('windows').length, Object.keys(AREAS).length)
})

// What agent-gui/tests/test_macos_inventory.py's hardened Mac reports (macOS Sonoma 14.5, a MacBook
// answering on 22 and 5900): formats from Apple's tools, not yet from a real Mac.
const MAC = {
  platform: 'darwin', is_admin: true,
  os: { name: 'macOS Sonoma 14.5', version: '14.5', role: 'workstation' },
  patches: { days_since_last_patch: 187 },
  security: {
    firewall: [{ profile: 'Application Firewall', enabled: false }], firewall_all_enabled: false,
    antivirus: [{ name: 'XProtect 5277', enabled: true, up_to_date: true }], disk_encryption: [{ volume: '/', protection: 'on' }],
    rdp_enabled: true, local_admin_count: 2,
  },
  baseline: {
    software_update: { AutomaticCheckEnabled: true, AutomaticDownload: true, CriticalUpdateInstall: true, ConfigDataInstall: null },
    password_policy: { min_length: 15, max_failed: 5, max_age_days: 365 }, guest_enabled: false, auto_login_user: null, show_full_name: true,
    root_enabled: false, stealth: true, sip: true, ssv: true, listening: { ssh: true, smb: false, remote_apple_events: false },
    internet_sharing: false, smb_guest: null, gatekeeper: true, system_prefs_admin: true, sudo_timeout: 0, sudoers_read: true,
    wake_on_lan: 0, network_time: true, auditd: 'enabled', install_log_ttl_days: 365,
  },
}

test('macOS: the same 30 areas of checks, judged from the agent\'s facts', () => {
  const r = evaluateBaseline(MAC, NOW)!
  assert.equal(r.os, 'macos')
  assert.equal(r.readable, 30)
  assert.deepEqual(r.checks.filter(c => c.state === 'fail').map(c => c.id).sort(),
    ['mac.firewall_on', 'mac.remote_login', 'mac.screen_sharing', 'mac.updates_recent'])
  assert.equal(r.percent, Math.floor((1000 * 26) / 30) / 10)
  assert.equal(found(r, 'mac.os_supported'), 'macOS Sonoma: still getting security updates')
  const old = evaluateBaseline({ ...MAC, os: { version: '13.6' }, baseline: { ...MAC.baseline, password_policy: { min_length: null, max_failed: null, max_age_days: null }, sudo_timeout: null, auditd: 'absent' } }, NOW)!
  assert.deepEqual([state(old, 'mac.os_supported'), found(old, 'mac.os_supported')], ['fail', 'macOS Ventura: security updates ended 2025-09-15'])
  assert.deepEqual([state(old, 'mac.pw_length'), found(old, 'mac.pw_length')], ['fail', 'no minimum set'])
  assert.deepEqual([state(old, 'mac.sudo_timeout'), found(old, 'mac.sudo_timeout')], ['fail', 'not set (macOS default: 5 minutes)'])
  assert.equal(state(old, 'mac.auditd'), 'na')
})

test('run without Administrator, the PC is not assessed: unreadable is never a pass', () => {
  const r = evaluateBaseline(PC, NOW)!
  assert.equal(r.os, 'windows')
  assert.equal(r.checks.filter(c => c.state === 'admin').length, 13)
  assert.equal(r.assessed, false)
  assert.equal(r.percent, null)
  assert.equal(state(r, 'win.firewall_inbound'), 'pass')
  assert.equal(state(r, 'win.autorun'), 'fail')                 // 221 is the Windows default, CIS wants 255
  assert.equal(state(r, 'win.av_signatures'), 'pass')
  assert.equal(state(r, 'win.os_supported'), 'pass')
  assert.match(found(r, 'win.os_supported')!, /25H2: security updates until 2027-10-12/)
})

test('as the service sees it, the PC is assessed and scored', () => {
  const r = evaluateBaseline(PC_AS_SERVICE, NOW)!
  assert.equal(r.assessed, true)
  assert.equal(r.checks.filter(c => c.state === 'admin' || c.state === 'unknown').length, 0)
  for (const id of ['win.pw_length', 'win.pw_complexity', 'win.lockout_threshold', 'win.lockout_duration', 'win.bitlocker',
    'win.llmnr', 'win.autorun', 'win.ps_logging', 'win.audit_logon', 'win.security_log']) assert.equal(state(r, id), 'fail', id)
  for (const id of ['win.guest', 'win.admin_account', 'win.smb_signing', 'win.tpm', 'win.rdp', 'win.smb1', 'win.winrm_basic']) assert.equal(state(r, id), 'pass', id)
  assert.equal(r.passed + r.failed, 30)
  assert.equal(r.percent, Math.floor((1000 * r.passed) / 30) / 10)
  assert.equal(found(r, 'win.lockout_threshold'), '10 tries')
})

test('the Ubuntu VM: readable without root, Docker forwarding not counted against it', () => {
  const r = evaluateBaseline(VM, NOW)!
  assert.equal(r.os, 'linux')
  assert.deepEqual(r.checks.filter(c => c.state === 'admin').map(c => c.id).sort(),
    ['linux.default_incoming', 'linux.empty_passwords', 'linux.root_locked'])
  assert.equal(state(r, 'linux.ip_forward'), 'na')
  assert.equal(r.assessed, true)
  assert.equal(r.readable, 27)
  for (const id of ['linux.pw_length', 'linux.lockout', 'linux.pw_max_age', 'linux.firewall_on', 'linux.disk_encryption',
    'linux.secure_boot', 'linux.ssh_root', 'linux.ssh_tries', 'linux.icmp_redirects', 'linux.aide', 'linux.auditd']) assert.equal(state(r, id), 'fail', id)
  for (const id of ['linux.os_supported', 'linux.security_updates', 'linux.auto_updates', 'linux.uid0', 'linux.bootloader', 'linux.ssh_empty',
    'linux.aslr', 'linux.mac', 'linux.shadow_perms', 'linux.persistent_logs', 'linux.time_sync']) assert.equal(state(r, id), 'pass', id)
  assert.equal(found(r, 'linux.pw_max_age'), 'never expire')
  assert.equal(found(r, 'linux.icmp_redirects'), 'all 0, default 1')
  assert.equal(found(r, 'linux.bootloader'), 'mode 0600, owner uid 0')
})

test('percent is rounded down, so a device just under the target never shows the target', () => {
  // 19 of 20 judged = 95.0; 18 of 19 = 94.7 (not 95)
  const r = evaluateBaseline(VM, NOW)!
  assert.equal(r.percent, Math.floor((1000 * r.passed) / r.judged) / 10)
  assert.ok(r.percent! <= (100 * r.passed) / r.judged)
})

test('no SSH server: the SSH checks do not apply; a router-free host with forwarding on fails', () => {
  const r = evaluateBaseline({ ...VM, baseline: { ...VM.baseline, sshd: null, container_host: false } }, NOW)!
  for (const id of ['linux.ssh_root', 'linux.ssh_empty', 'linux.ssh_tries']) assert.equal(state(r, id), 'na', id)
  assert.equal(state(r, 'linux.ip_forward'), 'fail')
})

test('older agents and other platforms have no baseline', () => {
  const { baseline: _b, ...old } = VM
  assert.equal(evaluateBaseline(old, NOW), null)
  assert.equal(evaluateBaseline({ platform: 'android', baseline: {} }, NOW), null)
  assert.equal(evaluateBaseline({ platform: 'darwin' }, NOW), null)                    // a Mac agent older than the baseline
  assert.equal(evaluateBaseline(null, NOW), null)
})

test('supported versions: Home and Enterprise differ, unknown builds are not guessed', () => {
  const now = NOW
  const until = (os: Record<string, unknown>) => windowsSupport(os)?.until
  assert.equal(until({ build: '26100.1', edition: 'Professional', role: 'workstation' }), '2026-10-13')   // ended before 23 Nov
  assert.equal(until({ build: '26100', edition: 'Enterprise', role: 'workstation' }), '2027-10-12')
  assert.equal(until({ build: '26100', edition: 'EnterpriseS', role: 'workstation' }), '2029-10-09')
  assert.equal(until({ build: '20348', edition: 'ServerStandard', role: 'server' }), '2031-10-14')
  assert.equal(windowsSupport({ build: '18363', edition: 'Professional' }), null)              // old and unlisted: not guessed
  // LAB-WIN11, 23 Nov 2026: Windows 11 26H2 Enterprise Evaluation, newer than the table
  const lab = evaluateBaseline({ ...PC, os: { ...PC.os, build: '26300.9711', edition: 'EnterpriseEval' } }, now)!
  assert.equal(state(lab, 'win.os_supported'), 'pass')
  assert.equal(found(lab, 'win.os_supported'), 'Windows build 26300: newer than every release in the lifecycle table')
  const home24h2 = evaluateBaseline({ ...PC, os: { ...PC.os, build: '26100.4000' } }, now)!
  assert.equal(state(home24h2, 'win.os_supported'), 'fail')
  assert.match(found(home24h2, 'win.os_supported')!, /ended 2026-10-13/)
  assert.equal(linuxSupport({ name: 'Ubuntu 25.10', version: '25.10' })?.until, '2026-07-09')
  assert.equal(linuxSupport({ name: 'Rocky Linux 9.4 (Blue Onyx)', version: '9.4' })?.until, '2032-05-31')
  assert.equal(linuxSupport({ name: 'Arch Linux', version: '' }), null)
})

test('secedit values: password never expires and lockout off are failures with plain words', () => {
  const r = evaluateBaseline({ ...PC_AS_SERVICE, baseline: { ...PC_AS_SERVICE.baseline,
    secpol: { ...PC_AS_SERVICE.baseline.secpol, max_password_age: -1, lockout_threshold: 0, lockout_duration: null, admin_enabled: 1, admin_name: 'it-admin' } } }, NOW)!
  assert.equal(found(r, 'win.pw_max_age'), 'never expire')
  assert.equal(found(r, 'win.lockout_threshold'), 'never locks')
  assert.deepEqual([state(r, 'win.lockout_duration'), found(r, 'win.lockout_duration')], ['fail', 'lockout off'])
  assert.deepEqual([state(r, 'win.admin_account'), found(r, 'win.admin_account')], ['pass', 'enabled as "it-admin"'])
})

test('stored per asset: compact, and cleared with the inventory', () => {
  const cols = baselineColumns(VM, new Date('2026-11-23T07:59:35Z'), NOW)
  const r = evaluateBaseline(VM, NOW)!
  assert.equal(cols.securityBaselinePercent, r.percent!.toFixed(1))
  assert.deepEqual(cols.securityBaseline!.checks[0], { id: r.checks[0]!.id, state: r.checks[0]!.state, found: r.checks[0]!.found })
  assert.equal('cis' in cols.securityBaseline!.checks[0]!, false)
  assert.deepEqual(baselineColumns(null, null), { securityBaselinePercent: null, securityBaseline: null, securityBaselineAt: null })
  assert.equal(baselineColumns(PC, new Date(), NOW).securityBaselinePercent, null)          // not assessed: no number
})

test('the Below baseline alert: opened under target, updated, resolved at target, quiet after a false positive', () => {
  const vm = compactBaseline(evaluateBaseline(VM, NOW)!)                                     // 57.6% (15 of 26, without root)
  const open = planBaselineAlert(vm, 95, null, null)
  assert.equal(open.kind, 'open')
  if (open.kind !== 'open') return
  assert.equal(open.severity, 'high')                                                        // under 80%
  assert.equal(open.details.failed_checks.length, vm.failed)
  assert.deepEqual(open.details.failed_checks[0], { id: 'linux.pw_length', label: 'Passwords at least 14 characters', area: 'accounts', found: 'no password quality module' })
  assert.equal(planBaselineAlert(vm, 95, { eventId: 'e1' }, null).kind, 'update')
  assert.equal(planBaselineAlert({ ...vm, percent: 85 }, 95, null, null).kind === 'open' && (planBaselineAlert({ ...vm, percent: 85 }, 95, null, null) as { severity: string }).severity, 'medium')
  assert.equal(vm.percent, 57.6)
  assert.deepEqual(planBaselineAlert(vm, 50, { eventId: 'e1' }, null), { kind: 'resolve', eventId: 'e1', note: 'Auto-resolved: security baseline 57.6% meets the 50% target' })
  assert.equal(planBaselineAlert(vm, 50, null, null).kind, 'none')
  assert.equal(planBaselineAlert({ ...vm, assessed: false, percent: null }, 95, { eventId: 'e1' }, null).kind, 'none')
  // closed as a false positive: quiet while the same checks fail, back when another one fails
  const closed = { status: 'false_positive', details: open.details }
  assert.equal(planBaselineAlert(vm, 95, null, closed).kind, 'suppressed')
  const worse = { ...vm, checks: vm.checks.map(c => (c.id === 'linux.time_sync' ? { ...c, state: 'fail' as const } : c)) }
  assert.equal(planBaselineAlert(worse, 95, null, closed).kind, 'open')
  assert.equal(planBaselineAlert(vm, 95, null, { status: 'resolved', details: open.details }).kind, 'open')
})
