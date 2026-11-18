import { test } from 'node:test'
import assert from 'node:assert/strict'
import { advisoryView, automationLabel, buildContent, mapSteps, type AdvisoryStep, type DeviceInfo } from './advisoryContent'
import { REMEDIATION_ACTIONS, isProtectedApp, isProtectedPort, isProtectedService } from './remediationCatalog'
import type { AdvisoryFacts } from './advisoryKit'

const dev = (o: Partial<DeviceInfo> = {}): DeviceInfo =>
  ({ hasAgent: true, isNetworkDevice: false, remediationEnabled: false, capabilities: [], ...o })

function facts(o: Partial<AdvisoryFacts> = {}): AdvisoryFacts {
  return {
    eventType: 'other', severity: 'high',
    asset: { label: 'h1', type: 'server', os: null, owner: null, criticality: null, internetFacing: false, windows: false, ports: [] },
    neighbours: { total: 0, critical: 0 }, other: {},
    urgency: { level: 'planned', window: 'soon', reasons: [] },
    commands: { upgrade: [], verify: null, rollback: null }, sources: [], ...o,
  }
}
function cveFacts(pkg: string | null, fixTo: string | null, packageType: string | null = 'deb'): AdvisoryFacts {
  return facts({
    eventType: 'cve_detected',
    cve: {
      id: 'CVE-2024-0001', pkg, packageType, installed: '1.0', cvss: 9, epss: 0.5, kev: false, threatIntel: false,
      tiTitles: [], cwe: [], description: null,
      group: { openCves: 1, kevCves: 0, fixTo, fixedCount: 1, noFixCount: 0 },
    },
  })
}
const portFacts = (other: Record<string, unknown>) => facts({ eventType: 'port_opened', other })
const T = (...t: string[]) => t.map(text => ({ text }))

test('attaches the action to the step that names package and version', () => {
  const out = mapSteps(cveFacts('openssl', '3.0.14'), T('Upgrade openssl to 3.0.14 in a window.', 'Rescan.'), dev())
  assert.equal(out.length, 2)
  assert.equal(out[0]!.kind, 'auto')
  assert.deepEqual(out[0]!.action, { key: 'pkg.upgrade', params: { manager: 'apt', package: 'openssl', version: '3.0.14' } })
  assert.equal(out[1]!.kind, 'manual')
  assert.deepEqual(out.map(s => s.id), ['s1', 's2'])
})

test('prepends an upgrade step when no step names it', () => {
  const out = mapSteps(cveFacts('openssl', '3.0.14'), T('Rescan the SBOM.'), dev())
  assert.equal(out.length, 2)
  assert.equal(out[0]!.text, 'Upgrade openssl to 3.0.14.')
  assert.equal(out[0]!.kind, 'auto')
  assert.equal(out[1]!.kind, 'manual')
})

test('package name is matched literally, not as a regex', () => {
  const out = mapSteps(cveFacts('a+b', '1.0'), T('Upgrade aab to 1.0.'), dev())
  assert.equal(out.length, 2)           // no match, so prepended
  assert.equal(out[0]!.text, 'Upgrade a+b to 1.0.')
})

test('unsafe package name stays manual', () => {
  const out = mapSteps(cveFacts('a;rm', '1.0'), T('Upgrade a;rm to 1.0.'), dev())
  assert.equal(out.length, 1)
  assert.ok(out.every(s => s.kind === 'manual' && !s.action))
  const bad = mapSteps(cveFacts('openssl', '1.0; reboot'), T('x'), dev())
  assert.ok(bad.every(s => !s.action))
})

test('no fix version stays manual', () => {
  const out = mapSteps(cveFacts('openssl', null), T('Apply a mitigation.'), dev())
  assert.equal(out.length, 1)
  assert.equal(out[0]!.kind, 'manual')
})

test('unsupported package type stays manual', () => {
  assert.ok(mapSteps(cveFacts('foo', '2.0', 'java-archive'), T('x'), dev()).every(s => !s.action))
  assert.ok(mapSteps(cveFacts('foo', '2.0', null), T('x'), dev()).every(s => !s.action))
})

test('os patch with kb maps to os.updates.apply and needs reboot', () => {
  const f = facts({ eventType: 'os_patch_missing', other: { kb: 'KB5034123' } })
  const out = mapSteps(f, T('Install KB5034123 now.'), dev())
  assert.equal(out.length, 1)
  assert.deepEqual(out[0]!.action, { key: 'os.updates.apply', params: { scope: 'kb', kb: 'KB5034123' } })
  assert.equal(out[0]!.risk, 'medium')
  assert.equal(out[0]!.needs_reboot, true)
  const none = mapSteps(facts({ eventType: 'os_patch_missing', other: { kb: 'bad kb;' } }), T('x'), dev())
  assert.ok(none.every(s => !s.action))
})

test('port 8080 maps to firewall.block_port', () => {
  const out = mapSteps(portFacts({ port: '8080', protocol: 'tcp' }), T('Block port 8080 at the firewall.', 'Rescan.'), dev())
  assert.equal(out.length, 3)
  assert.equal(out[0]!.action, undefined)
  assert.deepEqual(out[2]!.action, { key: 'firewall.block_port', params: { port: 8080, protocol: 'tcp', direction: 'inbound' } })
  const dflt = mapSteps(portFacts({ port: 8080 }), T('Rescan.'), dev())
  assert.equal(dflt[1]!.action!.params.protocol, 'tcp')
  assert.equal(dflt.length, 2)
})

test('port inside a longer number does not attach', () => {
  const out = mapSteps(portFacts({ port: '80' }), T('Close port 18080 at the firewall.'), dev())
  assert.equal(out.length, 2)
  assert.equal(out[1]!.text, 'If the port is not needed, block inbound port 80/tcp at the host firewall.')
})

test('protected port is never blocked', () => {
  for (const o of [{ port: 22 }, { port: '3389' }, { port: 2222, service: 'sshd' }, { port: 2222, service: 'SSHD' },
                   { port: 2222, service_on_port: 'sshd OpenSSH 9.0' }]) {
    const out = mapSteps(portFacts(o), T('Block the port at the firewall.'), dev())
    assert.ok(out.every(s => !s.action && s.kind === 'manual'), JSON.stringify(o))
  }
})

test('bad ports and protocols are refused', () => {
  for (const o of [{ port: 0 }, { port: 70000 }, { port: '80; x' }, { port: 1.5 }, { port: 8080, protocol: 'tcp;x' }, {}]) {
    assert.ok(mapSteps(portFacts(o), T('x'), dev()).every(s => !s.action), JSON.stringify(o))
  }
})

test('device without agent makes auto steps external with the reason', () => {
  const out = mapSteps(cveFacts('openssl', '3.0.14'), T('Upgrade openssl to 3.0.14.'), dev({ hasAgent: false }))
  assert.equal(out[0]!.kind, 'external')
  assert.equal(out[0]!.reason, 'This device has no EagleEye agent.')
  assert.equal(out[0]!.device_blocked, true)
  assert.deepEqual(out[0]!.action, { key: 'pkg.upgrade', params: { manager: 'apt', package: 'openssl', version: '3.0.14' } })
})

test('network device makes auto steps external', () => {
  const out = mapSteps(cveFacts('openssl', '3.0.14'), T('Upgrade openssl to 3.0.14.'), dev({ isNetworkDevice: true }))
  assert.equal(out[0]!.kind, 'external')
  assert.equal(out[0]!.reason, 'Network devices are changed by an engineer or the vendor.')
})

test('risk comes from the catalog', () => {
  const pkg = mapSteps(cveFacts('openssl', '3.0.14'), T('Upgrade openssl to 3.0.14.'), dev())
  assert.equal(pkg[0]!.risk, REMEDIATION_ACTIONS['pkg.upgrade'].risk)
  const fw = mapSteps(portFacts({ port: 8080 }), T('x'), dev())
  assert.equal(fw[1]!.risk, 'medium')
  const manual = mapSteps(facts(), T('Rescan.', 'Reboot the host.', 'Uninstall the tool.'), dev())
  assert.deepEqual(manual.map(s => s.risk), ['low', 'medium', 'medium'])
})

test('expert notes are kept on steps', () => {
  const out = mapSteps(facts(), [{ text: 'a', expert_note: 'note' }, { text: 'b' }], dev())
  assert.equal(out[0]!.expert_note, 'note')
  assert.equal(out[1]!.expert_note, undefined)
})

const step = (kind: AdvisoryStep['kind'], extra: Partial<AdvisoryStep> = {}): AdvisoryStep =>
  ({ id: 's', text: 't', kind, risk: 'low', ...extra })
const autoStep = () => step('auto', { action: { key: 'pkg.upgrade', params: {} } })

test('label: all four labels', () => {
  assert.equal(automationLabel([autoStep()], dev()).label, 'Auto-fixable')
  assert.equal(automationLabel([autoStep(), step('manual')], dev()).label, 'Partly auto-fixable')
  assert.equal(automationLabel([step('manual')], dev()).label, 'Guided fix')
  const ext = automationLabel([autoStep(), step('external', { reason: 'R1' }), step('external', { reason: 'R2' })], dev())
  assert.equal(ext.label, 'Needs outside support')
  assert.equal(ext.reason, 'R1')
})

test('label: check-only steps are ignored', () => {
  const chk = step('manual', { action: { key: 'check.version', params: {} } })
  assert.equal(automationLabel([autoStep(), chk], dev()).label, 'Auto-fixable')
})

test('label: available is false and reason says not switched on', () => {
  const l = automationLabel([autoStep()], dev())
  assert.equal(l.available, false)
  assert.equal(l.reason, 'Automatic fixing is not switched on yet.')
  assert.equal(automationLabel([autoStep(), step('manual')], dev()).reason, 'Automatic fixing is not switched on yet.')
  assert.equal(automationLabel([autoStep()], dev({ remediationEnabled: true })).available, false)
  assert.equal(automationLabel([autoStep()], dev({ remediationEnabled: true, capabilities: ['pkg.upgrade'] })).available, true)
})

test('protected lists', () => {
  assert.ok(isProtectedService('WinDefend') && isProtectedService('sshd') && !isProtectedService('nginx'))
  assert.ok(isProtectedPort(443) && isProtectedPort('22') && !isProtectedPort(8080))
  assert.ok(isProtectedApp('Windows Defender Antivirus') && isProtectedApp('CrowdStrike Falcon') && !isProtectedApp('Firefox'))
})

test('buildContent copies draft and facts and maps steps', () => {
  const f = cveFacts('openssl', '3.0.14'); f.sources = [{ label: 'a', url: 'https://x' }]
  const c = buildContent({
    summary: 'S', steps: ['Upgrade openssl to 3.0.14.', 'Rescan.'], whyNow: 'W', verify: 'V', rollback: null,
    confidence: { level: 'High', reason: 'r' }, stepNotes: ['n1', ''],
  }, f, 'Rule-based', dev())
  assert.equal(c.version, 1); assert.equal(c.basis, 'Rule-based'); assert.equal(c.why_now, 'W')
  assert.equal(c.steps[0]!.expert_note, 'n1'); assert.equal(c.steps[1]!.expert_note, undefined)
  assert.equal(c.steps[0]!.kind, 'auto'); assert.deepEqual(c.sources, f.sources)
})

test('package named eagleeye is never upgraded automatically', () => {
  for (const pkg of ['eagleeye-agent', 'EagleEye']) {
    const out = mapSteps(cveFacts(pkg, '2.0'), T(`Upgrade ${pkg} to 2.0.`), dev())
    assert.ok(out.every(s => !s.action && s.kind === 'manual'), pkg)
  }
  assert.equal(mapSteps(cveFacts('sophos-av', '2.0'), T('x'), dev())[0]!.kind, 'auto')
})

test('inherited object keys as packageType stay manual', () => {
  for (const t of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
    assert.ok(mapSteps(cveFacts('openssl', '3.0.14', t), T('Upgrade openssl to 3.0.14.'), dev()).every(s => !s.action), t)
  }
})

test('attach needs whole-token matches', () => {
  // package "ssl" must not match "openssl"
  let out = mapSteps(cveFacts('ssl', '1.2'), T('Upgrade openssl to 1.2.'), dev())
  assert.equal(out.length, 2); assert.equal(out[0]!.text, 'Upgrade ssl to 1.2.'); assert.equal(out[1]!.action, undefined)
  // package "go" must not match "google"
  out = mapSteps(cveFacts('go', '1.2'), T('Update google chrome to 1.2.'), dev())
  assert.equal(out.length, 2); assert.equal(out[1]!.action, undefined)
  // version 1.0 must not match 11.0 or 1.0.2
  for (const txt of ['Upgrade openssl to 11.0.', 'Upgrade openssl to 1.0.2.']) {
    out = mapSteps(cveFacts('openssl', '1.0'), T(txt), dev())
    assert.equal(out.length, 2, txt); assert.equal(out[1]!.action, undefined, txt)
  }
  // trailing sentence period still matches
  assert.equal(mapSteps(cveFacts('openssl', '1.0'), T('Upgrade openssl to 1.0.'), dev()).length, 1)
  // KB123 must not match KB1234
  const kb = mapSteps(facts({ eventType: 'os_patch_missing', other: { kb: 'KB123456' } }), T('Install KB1234567 now.'), dev())
  assert.equal(kb.length, 2); assert.equal(kb[1]!.action, undefined)
})

test('attach prefers an upgrade-verb step and skips negated steps', () => {
  const f = cveFacts('openssl', '3.0.14')
  let out = mapSteps(f, T('Note the openssl 3.0.14 release notes.', 'Upgrade openssl to 3.0.14.'), dev())
  assert.equal(out.length, 2); assert.equal(out[0]!.action, undefined); assert.ok(out[1]!.action)
  out = mapSteps(f, T('Do not upgrade openssl to 3.0.14 before testing.'), dev())
  assert.equal(out.length, 2); assert.equal(out[0]!.text, 'Upgrade openssl to 3.0.14.'); assert.equal(out[1]!.action, undefined)
})

test('nmap service names of protected services block nothing', () => {
  for (const svc of ['ssh OpenSSH 9.0', 'ms-wbt-server Microsoft Terminal Services', 'domain ISC BIND 9.16',
                     'ldap Microsoft Windows Active Directory LDAP', 'kerberos-sec Microsoft Windows Kerberos',
                     'microsoft-ds', 'msrpc Microsoft Windows RPC', 'winrm', 'bootps']) {
    for (const key of ['service_on_port', 'service']) {
      const out = mapSteps(portFacts({ port: 2222, [key]: svc }), T('Block the port at the firewall.'), dev())
      assert.ok(out.every(s => !s.action), `${key}: ${svc}`)
    }
  }
  assert.ok(mapSteps(portFacts({ port: 8080, service_on_port: 'http nginx 1.2' }), T('x'), dev()).some(s => s.action))
})

test('advisoryView returns null automation for null content', () => {
  assert.deepEqual(advisoryView({ content: null }, dev()), { content: null, automation: null })
})

test('advisoryView recomputes the label from current device info', () => {
  const step: AdvisoryStep = {
    id: 's1', text: 'Upgrade openssl to 3.0.14.', kind: 'auto', risk: 'low',
    action: { key: 'pkg.upgrade', params: { manager: 'apt', package: 'openssl', version: '3.0.14' } },
  }
  const content = { summary: 's', why_now: null, steps: [step], verify: null, rollback: null, confidence: 'high', sources: [], basis: 'b', version: 1 } as const
  const row = { content: content as unknown as import('./advisoryContent').AdvisoryContent }
  assert.equal(advisoryView(row, dev({ hasAgent: false }))!.automation!.label, 'Needs outside support')
  assert.equal(advisoryView(row, dev())!.automation!.label, 'Auto-fixable')
})

test('advisoryView: generated without agent shows Auto-fixable once an agent exists, and the reverse', () => {
  const noAgent = buildContent({ summary: 's', whyNow: null, steps: ['Upgrade openssl to 3.0.14.'], verify: null, rollback: null, confidence: 'high' } as never, cveFacts('openssl', '3.0.14'), 'b', dev({ hasAgent: false }))
  assert.equal(noAgent.steps[0]!.kind, 'external')
  assert.equal(advisoryView({ content: noAgent }, dev({ hasAgent: false })).automation!.label, 'Needs outside support')
  const v = advisoryView({ content: noAgent }, dev())
  assert.equal(v.automation!.label, 'Auto-fixable')
  assert.equal(v.content!.steps[0]!.kind, 'auto')
  assert.equal(v.content!.steps[0]!.reason, undefined)
  const withAgent = buildContent({ summary: 's', whyNow: null, steps: ['Upgrade openssl to 3.0.14.', 'Rescan.'], verify: null, rollback: null, confidence: 'high' } as never, cveFacts('openssl', '3.0.14'), 'b', dev())
  assert.equal(advisoryView({ content: withAgent }, dev()).automation!.label, 'Partly auto-fixable')
  assert.equal(advisoryView({ content: withAgent }, dev({ isNetworkDevice: true })).automation!.label, 'Needs outside support')
})

test('I2: the block step is appended last and conditional when no step qualifies', () => {
  const out = mapSteps(portFacts({ port: 8080, protocol: 'tcp' }), T('Identify the process.', 'Rescan.'), dev())
  assert.equal(out.length, 3)
  assert.equal(out[2]!.text, 'If the port is not needed, block inbound port 8080/tcp at the host firewall.')
  assert.equal(out[2]!.kind, 'auto')
  assert.deepEqual(out[2]!.action, { key: 'firewall.block_port', params: { port: 8080, protocol: 'tcp', direction: 'inbound' } })
  assert.ok(out.slice(0, 2).every(s => !s.action))
})

test('I2: rule-based port draft gets the block step last', async () => {
  const { ruleBasedDraft } = await import('./advisoryKit')
  const f = portFacts({ port: '8080', protocol: 'tcp' })
  const out = buildContent(ruleBasedDraft(f), f, 'Rule-based', dev())
  assert.equal(out.steps.at(-1)!.action!.key, 'firewall.block_port')
  assert.ok(out.steps.slice(0, -1).every(s => !s.action))
})

test('I2: restrict/allow/conditional steps never get the block action', () => {
  for (const txt of [
    'Restrict port 8080 to trusted IPs with a firewall rule instead of closing it.',
    'Allow port 8080 only from the office subnet.',
    'Keep port 8080 open if the service is expected.',
    'If the port is not needed, close port 8080.',
  ]) {
    const out = mapSteps(portFacts({ port: 8080 }), T(txt), dev())
    assert.equal(out.length, 2, txt)
    assert.equal(out[0]!.kind, 'manual', txt); assert.equal(out[0]!.action, undefined, txt)
    assert.equal(out[1]!.text, 'If the port is not needed, block inbound port 8080/tcp at the host firewall.', txt)
  }
})

test('block action is never attached to an existing step, only appended last', () => {
  const out = mapSteps(portFacts({ port: 8080 }), T('Add a firewall rule to block port 8080.', 'Rescan.'), dev())
  assert.equal(out.length, 3)
  assert.equal(out[0]!.kind, 'manual'); assert.equal(out[0]!.action, undefined)
  assert.equal(out[1]!.action, undefined)
  assert.equal(out[2]!.text, 'If the port is not needed, block inbound port 8080/tcp at the host firewall.')
  assert.equal(out[2]!.action!.key, 'firewall.block_port')
})

test('I3: strict package and version per manager', () => {
  const manual = (pkg: string, fix: string, type: string) =>
    assert.ok(mapSteps(cveFacts(pkg, fix, type), T('x'), dev()).every(s => !s.action), `${type} ${pkg} ${fix}`)
  manual('x@https://h/x.whl', '1.0', 'python')
  manual('left-pad', 'https://h/x.tgz', 'npm')
  manual('github:u/r', '1.0', 'npm')
  manual('git+foo', '1.0', 'npm')
  manual('openssl/backports', '1.0', 'deb')
  manual('openssl', '1:2.0', 'apk')
  manual('openssl', '1:2.0', 'python')
  manual('openssl', '1:2.0:3', 'deb')
  manual('@a/b/c', '1.0', 'npm')
  manual('pkg', '1.0@x', 'npm')
  const auto = (pkg: string, fix: string, type: string) =>
    assert.ok(mapSteps(cveFacts(pkg, fix, type), T('x'), dev()).some(s => s.action), `${type} ${pkg} ${fix}`)
  auto('@scope/name', '2.0.1', 'npm')
  auto('openssl', '1:3.0.14-1~deb12u1', 'deb')
  auto('openssl', '1:3.0.14', 'rpm')
  auto('libssl3', '3.0.14', 'deb')
})

test('I3: action version equals the cleaned version the commands use', () => {
  const out = mapSteps(cveFacts('openssl', 'v3.0.14'), T('x'), dev())
  assert.equal(out.find(s => s.action)!.action!.params.version, '3.0.14')
})

test('I3: kb must be KB plus 6 to 8 digits', () => {
  for (const kb of ['KB12', 'KB123456789', 'kb5034123', 'KB50341x3']) {
    assert.ok(mapSteps(facts({ eventType: 'os_patch_missing', other: { kb } }), T('x'), dev()).every(s => !s.action), kb)
  }
  assert.ok(mapSteps(facts({ eventType: 'os_patch_missing', other: { kb: 'KB5034123' } }), T('x'), dev()).some(s => s.action))
})

test('M5: WinRM ports are protected', () => {
  assert.ok(isProtectedPort(5985) && isProtectedPort(5986))
  for (const port of [5985, 5986]) assert.ok(mapSteps(portFacts({ port }), T('Block the port at the firewall.'), dev()).every(s => !s.action))
})

test('I1: content carries commands, note and target', () => {
  const f = cveFacts('openssl', '3.0.14')
  f.commands = { upgrade: ['sudo apt install openssl'], verify: null, rollback: null, note: 'N' }
  f.urgency = { level: 'now', window: 'within 72 hours', reasons: [] }
  const c = buildContent({ summary: 's', steps: ['a'], whyNow: null, verify: null, rollback: null, confidence: { level: 'High', reason: 'r' } }, f, 'b', dev())
  assert.deepEqual(c.commands, ['sudo apt install openssl'])
  assert.equal(c.command_note, 'N')
  assert.equal(c.target, 'within 72 hours')
  const plain = buildContent({ summary: 's', steps: ['a'], whyNow: null, verify: null, rollback: null, confidence: { level: 'High', reason: 'r' } }, facts(), 'b', dev())
  assert.deepEqual(plain.commands, []); assert.equal(plain.command_note, null)
})
