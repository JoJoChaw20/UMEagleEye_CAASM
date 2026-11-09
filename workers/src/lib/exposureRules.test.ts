import { test } from 'node:test'
import assert from 'node:assert/strict'
import { exposuresOf, planExposure, weighted, type DeviceContext } from './exposureRules'

const now = new Date('2026-11-09T00:00:00Z')
const pc: DeviceContext = { internetFacing: false, criticality: 4, deviceType: 'workstation', now }
const rules = (ports: unknown, ctx: DeviceContext = pc) => exposuresOf(ports, ctx).map((f) => `${f.rule}:${f.port}:${f.severity}`)

test('port-only rules: Telnet, FTP and VNC, with or without the agent facts', () => {
  assert.deepEqual(rules([{ port: 23, service: 'telnet' }, { port: 21, service: 'ftp' }, { port: 5900 }, { port: 22, service: 'ssh' }]),
    ['telnet:23:high', 'ftp_cleartext:21:medium', 'vnc:5900:high'])
  assert.deepEqual(rules([{ port: 21, service: 'ftp', facts: { tls: { version: 'TLSv1.3' } } }]), [])     // FTPS
  assert.deepEqual(rules([{ port: 53, protocol: 'udp', service: 'telnet' }]), [])                         // TCP only
})

test('a login page over plain HTTP, but not over HTTPS', () => {
  assert.deepEqual(rules([{ port: 80, service: 'http', facts: { http: { status: 401, realm: 'Router' } } }]),
    ['http_login_cleartext:80:medium'])
  assert.deepEqual(rules([{ port: 8080, service: 'http', facts: { http: { status: 200, title: 'Admin Login' } } }]),
    ['http_login_cleartext:8080:medium'])
  assert.deepEqual(rules([{ port: 443, service: 'https', facts: { http: { status: 401, realm: 'x' }, tls: {} } }]), [])
  assert.deepEqual(rules([{ port: 80, service: 'http', facts: { http: { status: 200, title: 'Welcome to nginx' } } }]), [])
})

test('a database answering without a password is critical', () => {
  assert.deepEqual(rules([{ port: 6379, service: 'redis', facts: { auth: 'none' } }]), ['db_no_auth:6379:critical'])
  assert.deepEqual(rules([{ port: 6379, service: 'redis', facts: { auth: 'required' } }]), [])
})

test('SMB signing only on servers; RDP without NLA anywhere; RDP and admin ports to the internet', () => {
  const smb = [{ port: 445, service: 'microsoft-ds', facts: { smb: { dialect: 'SMB 3.1.1', signing_required: false } } }]
  assert.deepEqual(rules(smb), [])
  assert.deepEqual(rules(smb, { ...pc, deviceType: 'server' }), ['smb_signing_off:445:medium'])
  assert.deepEqual(rules(smb, { ...pc, osName: 'Windows Server 2022 Datacenter' }), ['smb_signing_off:445:medium'])
  const samba = [{ port: 139, service: 'netbios-ssn', facts: { smb: { signing_required: false } } }, ...smb]
  assert.deepEqual(rules(samba, { ...pc, deviceType: 'server' }), ['smb_signing_off:445:medium'])      // once per device
  assert.deepEqual(rules([{ port: 3389, service: 'ms-wbt-server', facts: { rdp: { security: 'credssp', nla_required: false } } }]),
    ['rdp_no_nla:3389:high'])
  assert.deepEqual(rules([{ port: 3389, service: 'ms-wbt-server', facts: { rdp: { security: 'credssp', nla_required: true } } }]), [])
  assert.deepEqual(rules([{ port: 3389, service: 'ms-wbt-server', facts: { rdp: { security: 'tls' } } }]), ['rdp_no_nla:3389:high'])
  const exposed = { ...pc, internetFacing: true }
  assert.deepEqual(rules([{ port: 3389, service: 'ms-wbt-server' }, { port: 3306, service: 'mysql' }, { port: 443, service: 'https' }], exposed),
    ['rdp_internet:3389:critical', 'internet_admin_port:3306:critical'])
})

test('TLS certificates: expired, expiring within 30 days, fine', () => {
  const cert = (not_after: string) => [{ port: 443, service: 'https', facts: { tls: { not_after, subject_cn: 'nas.lab' } } }]
  assert.deepEqual(rules(cert('2026-11-01T00:00:00Z')), ['tls_expired:443:medium'])
  assert.deepEqual(rules(cert('2026-11-20T00:00:00Z')), ['tls_expiring:443:low'])
  assert.deepEqual(rules(cert('2027-06-01T00:00:00Z')), [])
  assert.equal(exposuresOf(cert('2026-11-01T00:00:00Z'), pc)[0]!.evidence.days_left, -8)
})

test('severity rises with internet exposure and high criticality, never above critical', () => {
  assert.equal(weighted('medium', { internetFacing: true, criticality: 2 }), 'high')
  assert.equal(weighted('medium', { internetFacing: true, criticality: 9 }), 'critical')
  assert.equal(weighted('high', { internetFacing: true, criticality: 9 }), 'critical')
  assert.equal(weighted('low', { internetFacing: false, criticality: null }), 'low')
})

test('the lifecycle: new, refreshed, reopened, closed only when the port was checked', () => {
  const telnet = exposuresOf([{ port: 23, service: 'telnet' }], pc)
  const existing = [
    { eventId: 'e-telnet', status: 'resolved', rule: 'telnet', port: 23 },
    { eventId: 'e-vnc', status: 'open', rule: 'vnc', port: 5900 },
    { eventId: 'e-ftp', status: 'open', rule: 'ftp_cleartext', port: 21 },
    { eventId: 'e-cert', status: 'accepted_risk', rule: 'tls_expired', port: 443 },
  ]
  const plan = planExposure([...telnet, ...exposuresOf([{ port: 443, service: 'https', facts: { tls: { not_after: '2026-01-01' } } }], pc)],
    existing, new Set([21, 23, 443]))
  assert.deepEqual(plan.refresh.map((r) => [r.eventId, r.reopen]), [['e-telnet', true]])   // seen again: reopened
  assert.deepEqual(plan.resolve, ['e-ftp'])            // 21 checked and closed; 5900 was not checked: VNC stays open
  assert.deepEqual(plan.create, [])                    // the accepted risk is not raised again
  assert.deepEqual(planExposure([], existing, null).resolve, [])      // no checked-port list: nothing closes
  assert.equal(planExposure(exposuresOf([{ port: 5900 }], pc), [], null).create[0]!.rule, 'vnc')
})

test('two alerts for the same rule and port on one device (after a merge): the extra one closes', () => {
  const dupes = [{ eventId: 'a', status: 'open', rule: 'telnet', port: 23 }, { eventId: 'b', status: 'open', rule: 'telnet', port: 23 }]
  const plan = planExposure(exposuresOf([{ port: 23, service: 'telnet' }], pc), dupes, new Set([23]))
  assert.deepEqual(plan.refresh.map((r) => r.eventId), ['a'])
  assert.deepEqual(plan.resolve, ['b'])
  const gone = planExposure([], dupes, new Set([23]))
  assert.deepEqual(gone.resolve.sort(), ['a', 'b'])
})

test('facts from the network are kept to known fields and capped', async () => {
  const { cleanFacts } = await import('./exposureRules')
  const f = cleanFacts({ tls: { not_after: '2026-11-01T00:00:00Z', subject_cn: 'x'.repeat(500), evil: 'drop me' },
    http: { status: 401, title: 'Login', script: '<script>' }, auth: 'none', other: { a: 1 } })
  assert.deepEqual(Object.keys(f!).sort(), ['auth', 'http', 'tls'])
  assert.equal(f!.tls!.subject_cn!.length, 120)
  assert.equal((f!.tls as Record<string, unknown>).evil, undefined)
  assert.deepEqual(f!.http, { status: 401, title: 'Login' })
  assert.equal(cleanFacts({ auth: 'maybe' }), undefined)
  assert.equal(cleanFacts('nonsense'), undefined)
})
