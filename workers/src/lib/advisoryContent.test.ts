import { test } from 'node:test'
import assert from 'node:assert/strict'
import { automationLabel, buildContent, mapSteps, type AdvisoryStep, type DeviceInfo } from './advisoryContent'
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
  assert.equal(out.length, 2)
  assert.deepEqual(out[0]!.action, { key: 'firewall.block_port', params: { port: 8080, protocol: 'tcp', direction: 'inbound' } })
  const dflt = mapSteps(portFacts({ port: 8080 }), T('Rescan.'), dev())
  assert.equal(dflt[0]!.action!.params.protocol, 'tcp')
  assert.equal(dflt.length, 2)
})

test('port inside a longer number does not attach', () => {
  const out = mapSteps(portFacts({ port: '80' }), T('Close port 18080 at the firewall.'), dev())
  assert.equal(out.length, 2)
  assert.equal(out[0]!.text, 'Block inbound port 80/tcp at the firewall.')
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
  assert.equal(out[0]!.action, undefined)
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
  assert.equal(fw[0]!.risk, 'medium')
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
